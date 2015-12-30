import json
import re
import traceback

import splunktalib.common.util as scutil
import taaws.ta_aws_consts as tac
import s3_mod.aws_s3_consts as asc
import s3_mod.aws_s3_common as s3common
import s3_mod.aws_s3_checkpointer as s3ckpt
# import xml.sax.saxutils as xss


def increase_error_count(key_store, max_retries, key, logger):
    key_store.increase_error_count()
    if key_store.error_count() > max_retries:
        logger.error("Data collection has failed more than %s times "
                     "for key_name=%s bucket_name=%s",
                     max_retries, key.name, key.bucket.name)
        key_store.delete()


class S3KeyProcesser(object):

    base_fmt = ("""<stream><event{unbroken}>"""
                "<source>{source}</source>"
                "<sourcetype>{sourcetype}</sourcetype>"
                "<index>{index}</index>"
                "<data><![CDATA[{data}]]></data>{done}</event></stream>")

    event_fmt = base_fmt.replace("{unbroken}", "").replace("{done}", "")
    unbroken_fmt = base_fmt.replace("{unbroken}", ' unbroken="1"').replace(
        "{done}", "")
    done_fmt = base_fmt.replace("{unbroken}", ' unbroken="1"').replace(
        "{done}", "<done/>")

    def __init__(self, loader_service, reader, config, logger):
        self._loader_service = loader_service
        self._reader = reader
        self._config = config
        self._key = reader.key_object()
        self._key_store = s3ckpt.S3KeyCheckpointer(config, self._key)
        self._logger = logger

    def __call__(self):
        try:
            self._do_call()
        except Exception:
            self._logger.error(
                "Exception happened when reading key_name=%s bucket_name=%s, "
                "error=%s", self._key.name, self._key.bucket.name,
                traceback.format_exc())

    def _do_call(self):
        logger = self._logger
        bucket_name, key_name = self._key.bucket.name, self._key.name
        self._logger.debug("Start processing bucket_name=%s, key_name=%s",
                           bucket_name, key_name)

        self._key_store.set_state(asc.processing)
        source = "s3://{bucket_name}/{key_name}".format(
            bucket_name=bucket_name, key_name=key_name)

        if self._key_store.etag() != self._key.etag:
            logger.warning("bucket_name=%s, key_name=%s has not finished "
                           "data collection last round, and detected its "
                           "etag changed this round, start from beginning",
                           bucket_name, key_name)
            self._key_store.set_offset(0, commit=False)
            self._key_store.set_eof(eof=False)
        elif self._key_store.eof():
            self.set_eof()
            return

        try:
            offset = self._key_store.offset()
            if not self._key_store.eof() and offset:
                logger.info("Seeking offset=%s for key_name=%s",
                            offset, key_name)
                self._reader.seek(offset)

            self._do_index(source)
        except Exception:
            increase_error_count(
                self._key_store, self._config[asc.max_retries],
                self._key, logger)
            logger.error("Exception happened when reading key_name=%s "
                         "bucket_name=%s, error=%s",
                         key_name, bucket_name, traceback.format_exc())

        logger.debug("End of processing bucket_name=%s, key_name=%s",
                     bucket_name, key_name)

    def _get_decoder(self):
        encoding = self._config.get(asc.character_set)
        if not encoding or encoding == "auto":
            encoding = self._key_store.encoding()

        previous_chunk = ""
        for previous_chunk in self._reader:
            break

        decoder, encoding = s3common.get_decoder(encoding, previous_chunk)
        self._logger.debug("Use %s to do decoding", encoding)
        self._key_store.set_encoding(encoding)
        return decoder, previous_chunk

    def _encode_to_utf8(self, decoder, chunk):
        try:
            data = decoder.decode(chunk)
            return scutil.escape_cdata(data)
            # return xss.escape(data)
        except Exception:
            self._logger.error(
                "Failed to decode data by using encoding=%s, error=%s",
                self._config[asc.character_set], traceback.format_exc())
            return None

    def _do_index(self, source):
        decoder, previous_chunk = self._get_decoder()
        chunk = previous_chunk

        for chunk in self._reader:
            if self._loader_service.stopped():
                break

            size = len(previous_chunk)
            data = self._encode_to_utf8(decoder, previous_chunk)
            if data is not None:
                data = self.unbroken_fmt.format(
                    source=source, sourcetype=self._config[tac.sourcetype],
                    index=self._config[tac.index], data=data)
                self._loader_service.write_events(data)
                self._key_store.increase_offset(size)
            previous_chunk = chunk

        if not self._loader_service.stopped():
            size = len(chunk)
            data = self._encode_to_utf8(decoder, chunk)
            if not data.endswith("\n"):
                data += "\n"

            data = self.done_fmt.format(
                source=source, sourcetype=self._config[tac.sourcetype],
                index=self._config[tac.index], data=data)
            self._loader_service.write_events(data)
            self._key_store.increase_offset(size)
            self.set_eof()

    def set_eof(self):
        self._key_store.set_eof(eof=True)
        self._key_store.delete()
        self._reader.close()


class S3KeyCloudTrailProcesser(S3KeyProcesser):

    def __init__(self, loader_service, reader, config, logger):
        super(S3KeyCloudTrailProcesser,  self).__init__(
            loader_service, reader, config, logger)

    def _do_index(self, source):
        logger = self._logger
        all_data = [data for data in self._reader]
        if not all_data:
            self.set_eof()
            return

        try:
            all_data = json.loads("".join(all_data))
        except ValueError:
            logger.error("key_name=%s is not valid CloudTail log",
                         self._key.name)
            self.set_eof()
            return

        records = all_data.get("Records", [])
        blacklist = self._config[asc.ct_blacklist]
        if blacklist:
            blacklist = re.compile(blacklist)
        else:
            blacklist = None

        loader_service = self._loader_service

        events = []
        for record in records:
            if loader_service.stopped():
                break

            if blacklist is not None and blacklist.search(record["eventName"]):
                continue

            data = self.event_fmt.format(
                source=source, sourcetype=self._config[tac.sourcetype],
                index=self._config[tac.index], data=json.dumps(record))
            events.append(data)

        if events:
            logger.debug("Indexed %s cloudtrail records in bucket_name=%s, "
                         "key_name=%s", len(records), self._key.bucket.name,
                         self._key.name)
            loader_service.write_events("".join(events))

        if not loader_service.stopped():
            self._key_store.increase_offset(len(all_data))
            self.set_eof()


sourcetype_to_indexer = {
    asc.aws_s3: S3KeyProcesser,
    asc.aws_elb_accesslogs: S3KeyProcesser,
    asc.aws_cloudfront_accesslogs: S3KeyProcesser,
    asc.aws_s3_accesslogs: S3KeyProcesser,
    asc.aws_cloudtrail: S3KeyCloudTrailProcesser,
}


def create_s3_key_processer(config, loader_service, reader, logger):
    Cls = sourcetype_to_indexer.get(
        config[tac.sourcetype], S3KeyProcesser)
    return Cls(loader_service, reader, config, logger)
