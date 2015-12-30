import os.path as op
import datetime

# FIXME Legacy code started
import taaws.proxy_conf as tpc
# Legacy code done

import taaws.ta_aws_consts as tac
import s3_mod.aws_s3_consts as asc

import splunktalib.file_monitor as fm
import splunktalib.conf_manager.conf_manager as cm

from splunktalib.common import log
import splunktalib.common.util as scutil
import taaws.ta_aws_common as tacommon
import s3_mod.aws_s3_common as s3common
import s3_mod.aws_s3_checkpointer as s3ckpt


logger = log.Logs().get_logger(asc.s3_log)


def create_conf_monitor(callback):
    files = (AWSS3Conf.app_file,
             AWSS3Conf.task_file_w_path,
             AWSS3Conf.passwords_file_w_path,
             AWSS3Conf.log_info_w_path)

    return fm.FileMonitor(callback, files)


class AWSS3Conf(object):

    app_dir = op.dirname(op.dirname(op.dirname(op.abspath(__file__))))
    app_file = op.join(app_dir, "local", "app.conf")
    task_file = "inputs"
    task_file_w_path = op.join(app_dir, "local", task_file + ".conf")
    passwords = "passwords"
    passwords_file_w_path = op.join(app_dir, "local", passwords + ".conf")
    log_info = "log_info"
    log_info_w_path = op.join(app_dir, "local", log_info + ".conf")

    def __init__(self):
        self.metas, self.stanza_configs = tacommon.get_modinput_configs()
        self.metas[tac.app_name] = tac.splunk_ta_aws

    def get_tasks(self):
        if not self.stanza_configs:
            return None

        conf_mgr = cm.ConfManager(self.metas[tac.server_uri],
                                  self.metas[tac.session_key])
        logging = conf_mgr.get_stanza(
            self.log_info, asc.log_stanza, do_reload=True)

        proxy_info = tpc.get_proxy_info(self.metas[tac.session_key])
        tasks, creds = [], {}
        for stanza in self.stanza_configs:
            task = {}
            task.update(stanza)
            task.update(self.metas)
            task.update(proxy_info)
            key_id, secret_key = tacommon.get_aws_creds(
                stanza, self.metas, creds)
            task[tac.log_level] = logging[asc.log_level]
            task[tac.key_id] = key_id
            task[tac.secret_key] = secret_key
            task[tac.interval] = tacommon.get_interval(task, 3600)
            task[asc.max_retries] = int(task.get(asc.max_retries, 10))
            task[asc.prefix] = task.get(asc.key_name)
            task[asc.last_modified] = self._get_last_modified_time(
                task[asc.initial_scan_datetime])
            input_name = scutil.extract_datainput_name(task[tac.name])
            task[asc.data_input] = input_name
            task[tac.sourcetype] = task.get(tac.sourcetype, "aws:s3")
            task[asc.bucket_name] = str(task[asc.bucket_name])
            if not task.get(asc.whitelist):
                task[asc.whitelist] = s3common.sourcetype_to_keyname_regex.get(
                    task[tac.sourcetype])
            tasks.append(task)
        s3ckpt.handle_ckpts(tasks)
        return tasks

    def _get_last_modified_time(self, scan_datetime):
        if not scan_datetime or scan_datetime.strip() == "default":
            stime = datetime.datetime.utcnow() + datetime.timedelta(days=-7)
        else:
            stime = tacommon.parse_datetime(
                self.metas[tac.server_uri], self.metas[tac.session_key],
                scan_datetime)
        return stime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
