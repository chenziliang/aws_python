import hashlib
import copy

import splunktalib.conf_manager.conf_manager as cm
import splunktalib.state_store as ss
import taaws.ta_aws_consts as tac
import s3_mod.aws_s3_consts as asc

from splunktalib.common import log
logger = log.Logs().get_logger(asc.s3_log)


def get_key_ckpt_key(bucket_name, key_name):
    return hashlib.md5("{bucket_name}${key_name}".format(
        bucket_name=bucket_name, key_name=key_name)).hexdigest()


def create_state_store(config):
    store = ss.get_state_store(
        config, config[tac.app_name],
        collection_name="aws_s3_" + config[asc.data_input],
        use_kv_store=config.get(tac.use_kv_store))
    return store


class S3IndexCheckpointer(object):

    def __init__(self, config, new=True):
        self._config = config
        self._store = create_state_store(config)
        self._ckpt_key = "{}.ckpt".format(config[asc.data_input])
        self._index_ckpt = self._pop_index_ckpt(new)

    def _pop_index_ckpt(self, new):
        index_ckpt = self._store.get_state(self._ckpt_key)
        if not index_ckpt and new:
            logger.info("Index ckpt for datatinput=%s doesn't exist",
                        self._config[asc.data_input])
            index_ckpt = {
                asc.latest_last_modified: self._config.get(asc.last_modified),
                asc.bucket_name: self._config[asc.bucket_name],
                asc.version: 2,
                asc.keys: {}
            }
        return index_ckpt

    def index_ckpt(self):
        return self._index_ckpt

    def set_index_ckpt(self, ckpt, commit=True):
        self._index_ckpt = ckpt
        if commit:
            self.save()

    def keys(self):
        return self._index_ckpt[asc.keys]

    def add(self, key_name, ckpt_key, last_modified, commit=True):
        index_entry = {
            asc.key_ckpt: ckpt_key,
            asc.last_modified: last_modified,
        }
        self._index_ckpt[asc.keys][key_name] = index_entry
        if commit:
            self.save()

    def get(self, key_name):
        return self._index_ckpt[asc.keys].get(key_name)

    def bucket_name(self):
        return self._index_ckpt[asc.bucket_name]

    def last_modified(self):
        return self._index_ckpt[asc.latest_last_modified]

    def set_last_modified(self, last_modified, commit=True):
        self._index_ckpt[asc.latest_last_modified] = last_modified
        if commit:
            self.save()

    def outstanding_keys(self):
        return set(self._index_ckpt[asc.keys].iterkeys())

    def save(self):
        self._store.update_state(self._ckpt_key, self._index_ckpt)

    def get_state(self, key):
        """
        Generic get, proxy for StateStore
        """

        return self._store.get_state(key)

    def delete_state(self, key):
        """
        Generic delete, proxy for StateStore
        """

        self._store.delete_state(key)
        logger.debug("Remove ckpt=%s", key)

    def delete(self):
        self.delete_state(self._ckpt_key)
        logger.debug("Remove ckpt=%s", self._ckpt_key)


class S3KeyCheckpointer(object):

    def __init__(self, config, key):
        self._config = config
        self._store = create_state_store(config)
        self._ckpt_key = get_key_ckpt_key(key.bucket.name, key.name)
        self._key_ckpt = self._pop_key_ckpt(key)

    def _pop_key_ckpt(self, key):
        key_ckpt = self._store.get_state(self._ckpt_key)
        if not key_ckpt:
            key_ckpt = {
                asc.etag: key.etag,
                asc.last_modified: key.last_modified,
                asc.offset: 0,
                asc.eof: False,
                asc.data_input: self._config[asc.data_input],
                asc.error_count: 0,
                asc.encoding: None,
                asc.state: asc.new,
                asc.version: 2
            }
        return key_ckpt

    def ckpt_key(self):
        return self._ckpt_key

    def encoding(self):
        return self._key_ckpt[asc.encoding]

    def set_encoding(self, encoding, commit=True):
        self._key_ckpt[asc.encoding] = encoding
        if commit:
            self.save()

    def data_input(self):
        return self._key_ckpt[asc.data_input]

    def etag(self):
        return self._key_ckpt[asc.etag]

    def last_modified(self):
        return self._key_ckpt[asc.last_modified]

    def eof(self):
        return self._key_ckpt[asc.eof]

    def set_eof(self, eof, commit=True):
        self._key_ckpt[asc.eof] = eof
        if commit:
            self.save()

    def offset(self):
        return self._key_ckpt[asc.offset]

    def increase_offset(self, increment, commit=True):
        self._key_ckpt[asc.offset] += increment
        if commit:
            self.save()

    def increase_error_count(self, commit=True):
        self._key_ckpt[asc.error_count] += 1
        self._key_ckpt[asc.state] = asc.failed
        if commit:
            self.save()

    def error_count(self):
        return self._key_ckpt[asc.error_count]

    def set_offset(self, offset, commit=True):
        self._key_ckpt[asc.offset] = offset
        if commit:
            self.save()

    def set_state(self, state, commit=True):
        self._key_ckpt[asc.state] = state
        if commit:
            self.save()

    def state(self):
        return self._key_ckpt[asc.state]

    def save(self):
        self._store.update_state(self._ckpt_key, self._key_ckpt)

    def delete(self):
        self._store.delete_state(self._ckpt_key)
        logger.debug("Remove ckpt=%s", self._ckpt_key)


def _get_legacy_ckpt_key(stanza_name, bucket_name):
    start_offset = 0
    if stanza_name.startswith("aws-s3://"):
        start_offset = len("aws-s3://")

    replaced_stanza_name = [
        c if c.isalnum() else "_"
        for c in stanza_name[start_offset:start_offset + 20]]
    safe_filename_prefix = "".join(replaced_stanza_name)
    stanza_and_bucket = "{}_{}".format(stanza_name, bucket_name)
    stanza_hexdigest = hashlib.md5(stanza_and_bucket).hexdigest()
    ckpt_key = "cp_{}_{}.json".format(safe_filename_prefix, stanza_hexdigest)
    return ckpt_key


def convert_one_legacy_ckpt(store, stanza, legacy_state):
    logger.info("Start converting legacy ckpt to new ckpt for stanza=%s, "
                "bucket_name=%s", stanza[tac.name],
                stanza[asc.bucket_name])
    # 1) index ckpt
    index_ckpt = S3IndexCheckpointer(stanza)
    index_ckpt.set_last_modified(legacy_state["last_completed_scan_datetime"])
    encoding = stanza.get(asc.character_set)
    if not encoding or encoding == "auto":
        encoding = "UTF-8"

    # 2) key ckpt
    for key_name, key_state in legacy_state["items"].iteritems():
        ckpt_key = get_key_ckpt_key(
            stanza[asc.bucket_name], key_name)
        index_ckpt.add(key_name, ckpt_key, key_state[1])
        key_ckpt = {
            asc.data_input: stanza[asc.data_input],
            asc.version: 2,
            asc.etag: key_state[0],
            asc.last_modified: key_state[1],
            asc.offset: key_state[2],
            asc.eof: key_state[3],
            asc.error_count: key_state[4],
            asc.encoding: encoding,
        }
        store.update_state(ckpt_key, key_ckpt)
    logger.info("End of converting legacy ckpt to new ckpt for stanza=%s, "
                "bucket_name=%s", stanza[tac.name],
                stanza[asc.bucket_name])


def convert_legacy_ckpt_to_new_ckpts(tasks):
    conversion_done = "conversion_done"
    conversion_ckpt_key = "aws_s3_ckpt_conversion.ckpt"
    store = create_state_store(tasks[0])
    state = store.get_state(conversion_ckpt_key)
    if state and state[conversion_done]:
        logger.info("Ckpt conversion has already been done")
        return

    for stanza in tasks:
        legacy_key = _get_legacy_ckpt_key(
            stanza[tac.name], stanza[asc.bucket_name])
        legacy_state = store.get_state(legacy_key)
        if not legacy_state:
            logger.info("Legacy ckpt is not found for stanza=%s, "
                        "bucket_name=%s", stanza[tac.name],
                        stanza[asc.bucket_name])
            continue

        convert_one_legacy_ckpt(store, stanza, legacy_state)
    state = store.update_state(conversion_ckpt_key, {conversion_done: True})


def delete_ckpts_for_removed_data_inputs(tasks):
    # All datainputs including disabled
    mgr = cm.ConfManager(tasks[0][tac.server_uri], tasks[0][tac.session_key])
    s3_stanzas = mgr.all_data_input_stanzas("aws_s3", do_reload=False)
    new_data_inputs = set(stanza[tac.stanza_name] for stanza in s3_stanzas)

    data_inputs = "data_inputs"
    data_inputs_ckpt_key = "aws_s3_data_inputs.ckpt"
    store = create_state_store(tasks[0])
    state = store.get_state(data_inputs_ckpt_key)
    if not state or not state.get(data_inputs):
        store.update_state(
            data_inputs_ckpt_key, {data_inputs: list(new_data_inputs)})
        return

    config = copy.copy(tasks[0])
    old_data_inputs = set(state[data_inputs])
    for removed_data_input in (old_data_inputs - new_data_inputs):
        config[asc.data_input] = removed_data_input
        index_ckpt = S3IndexCheckpointer(config, new=False)
        if not index_ckpt.index_ckpt():
            logger.warn("index ckpt for datainput=%s doesn't exist",
                        removed_data_input)
            continue

        # 1) Remove ckpts for keys
        for key_name, key_ckpt in index_ckpt.keys().iteritems():
            index_ckpt.delete_state(key_ckpt[asc.key_ckpt])

        # 2) Remove index ckpt for data input
        index_ckpt.delete()

        logger.warn("Remove ckpt for datainput=%s bucket_name=%s, since the "
                    "datainput has been deleted", removed_data_input,
                    index_ckpt.bucket_name())
    store.update_state(
        data_inputs_ckpt_key, {data_inputs: list(new_data_inputs)})


def handle_ckpts(tasks):
    """
    1. Convert legacy ckpt to new ckpt
    2. Deleted ckpts for removed data inputs
    3. Save ckpts for data inputs
    """

    if not tasks:
        return

    convert_legacy_ckpt_to_new_ckpts(tasks)
    delete_ckpts_for_removed_data_inputs(tasks)
