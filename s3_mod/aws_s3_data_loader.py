import threading
import Queue
import traceback
import time

from splunktalib.common import log

import taaws.ta_aws_consts as tac
import taaws.ta_aws_common as tacommon
import s3_mod.aws_s3_consts as asc
import s3_mod.aws_s3_common as s3common
import s3_mod.aws_s3_checkpointer as s3ckpt
import s3_mod.s3_key_reader as skr
import s3_mod.s3_key_processer as skp


logger = log.Logs().get_logger(asc.s3_log)


class S3DataLoader(object):

    def __init__(self, config):
        """
        :task_config: dict
        {
           bucket_name: xxx,
           host: xxx,
           prefix: xxx,
           after: xxx,
           key_character_set: xxx,
           secret_key: xxx,
           checkpoint_dir: xxx,
           server_uri: xxx,
           session_key: xxx,
           use_kv_store: xxx,
           is_secure: xxx,
           proxy_hostname: xxx,
           proxy_port: xxx,
           proxy_username: xxx,
           proxy_password: xxx,
           data_loader: xxx,
        }
        """

        self._config = config
        self._lock = threading.Lock()
        self._config[asc.bucket_name] = str(self._config[asc.bucket_name])
        self._stopped = False

    def get_interval(self):
        return self._config[tac.interval]

    def get_props(self):
        return self._config

    def stop(self):
        self._stopped = True

    def __call__(self):
        self.index_data()

    def index_data(self):
        try:
            self._do_index_data()
        except Exception:
            logger.error("Failed to collect S3 data from bucket_name=%s, "
                         "error=%s", self._config[asc.bucket_name],
                         traceback.format_exc())

    def _do_index_data(self):
        if self._lock.locked():
            logger.info("Previous run is not done yet")
            return

        logger.info("Start processing bucket=%s",
                    self._config[asc.bucket_name])
        with self._lock:
            self.collect_data()
        logger.info("End of processing bucket=%s",
                    self._config[asc.bucket_name])

    def collect_data(self):
        conn = s3common.create_s3_connection(self._config)
        bucket = conn.get_bucket(self._config[asc.bucket_name])
        loader_service = self._config[tac.data_loader_mgr]
        index_store = s3ckpt.S3IndexCheckpointer(self._config)
        last_modified = index_store.last_modified()

        logger.info("Start from last_modified=%s for bucket_name=%s",
                    last_modified, self._config[asc.bucket_name])
        exceptions = index_store.outstanding_keys()
        keys = s3common.get_keys(
            bucket, self._config.get(asc.prefix, ""),
            self._config.get(asc.whitelist), self._config.get(asc.blacklist),
            last_modified, exceptions)

        max_last_modified = ""
        for key in keys:
            if self._stopped:
                break

            if key.name.endswith("/"):
                continue

            if key.last_modified > max_last_modified:
                max_last_modified = key.last_modified

            key_store = self._create_ckpts_for_key(key, index_store)
            if not key_store:
                continue

            config = {asc.key_object: key,
                      asc.max_retries: self._config[asc.max_retries]}
            try:
                reader = skr.create_s3_key_reader(config, logger)
            except Exception:
                logger.error("Failed to create S3 reader for key_name=%s, "
                             "bucket_name=%s, error=%s",
                             key.name, key.bucket.name, traceback.format_exc())
                skp.increase_error_count(
                    key_store, self._config[asc.max_retries], key, logger)
                continue
            self._do_collect_data(loader_service, reader, key)

        if max_last_modified and max_last_modified > last_modified:
            index_store.set_last_modified(max_last_modified)
        self._poll_progress(index_store)
        index_store.save()

    def _poll_progress(self, index_store):
        keys = index_store.keys()
        if not keys:
            return

        logger.info("Poll data collection progress for bucket_name=%s",
                    index_store.bucket_name())
        sleep_time = min(20, self._config[asc.polling_interval])
        while 1:
            if tacommon.sleep_until(sleep_time, self.stopped):
                return

            done, errors, total = 0, 0, len(keys)
            for key_name, key_ckpt in keys.items():
                ckpt_key = key_ckpt[asc.key_ckpt]
                key_ckpt = index_store.get_state(ckpt_key)
                # Note when finished data collection, the data collection
                # thread deletes the key ckpt
                if key_ckpt is None:
                    del keys[key_name]
                    done += 1
                elif key_ckpt[asc.state] == asc.failed:
                    errors += 1

            if done + errors == total:
                break
            else:
                logger.info("There are still %s data collection going on for "
                            "bucket_name=%s", total - done - errors,
                            index_store.bucket_name())

    def _create_ckpts_for_key(self, key, index_store):
        """
        :return: key_store if doing data collection for this key,
                 otherwise return None which means ignoring this key
        """

        key_store = s3ckpt.S3KeyCheckpointer(self._config, key)
        if key_store.data_input() != self._config[asc.data_input]:
            logger.warn("key_name=%s has already been doing data collection "
                        "by datainput=%s", self._config[asc.data_input],
                        key.name)
            return None

        if key_store.state() == asc.new:
            # key ckpt doesn't exists, but in index ckpt which means this key
            # has been done data collection last round check if its last
            # modified time is newer than its previous last modified time
            index_entry = index_store.get(key.name)
            if index_entry:
                if key_store.last_modified() <= index_entry[asc.last_modified]:
                    logger.debug("key_name=%s, bucket_name=%s has been done "
                                 "data collection last round, skip it",
                                 key.name, key.bucket.name)
                    return None

        key_store.set_state(asc.started)

        # Register this key in the index ckpt
        index_store.add(key.name, key_store.ckpt_key(), key.last_modified)
        return key_store

    def _do_collect_data(self, loader_service, reader, key):
        index_func = skp.create_s3_key_processer(
            self._config, loader_service, reader, logger)

        while 1:
            try:
                return loader_service.run_io_jobs((index_func,), block=False)
            except Queue.Full:
                logger.debug("Job Queue is full")
                if key.size < 1024 * 1024 * 8:
                    # Do data collection in dispatching thread only if
                    # the key is not too big
                    logger.debug("Dispatch function pigback")
                    return index_func()
                else:
                    time.sleep(2)
            except Exception:
                logger.error("Failed to run io jobs, error=%s",
                             traceback.format_exc())
                time.sleep(2)

    def stopped(self):
        return self._stopped
