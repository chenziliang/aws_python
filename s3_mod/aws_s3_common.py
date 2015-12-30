import traceback
import json
import os
import re
import codecs

import boto
import boto.s3 as bs
import boto.s3.connection as bsc
from boto.exception import S3ResponseError

import taaws.ta_aws_consts as tac
import s3_mod.aws_s3_consts as asc
from splunktalib.common import log


logger = log.Logs().get_logger(asc.s3_log)


sourcetype_to_keyname_regex = {
    asc.aws_cloudtrail: r"\d+_CloudTrail_[\w-]+_\d{4}\d{2}\d{2}T\d{2}\d{2}Z_.{16}\.json\.gz$",
    asc.aws_elb_accesslogs: r".*\d+_elasticloadbalancing_[\w-]+_.+\.log$",
    asc.aws_cloudfront_accesslogs: r".+\.\d{4}-\d{2}-\d{2}-\d{2}\..+\.gz$",
    asc.aws_s3_accesslogs: r".+\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-.+$",
}


def _create_s3_connection(config, region):
    calling_format = bsc.OrdinaryCallingFormat()
    if region:
        conn = bs.connect_to_region(
            region,
            aws_access_key_id=config[tac.key_id],
            aws_secret_access_key=config[tac.secret_key],
            proxy=config.get(tac.proxy_hostname),
            proxy_port=config.get(tac.proxy_port),
            proxy_user=config.get(tac.proxy_username),
            proxy_pass=config.get(tac.proxy_password),
            is_secure=True,
            validate_certs=True,
            calling_format=calling_format)
    else:
        if (not os.environ.get("S3_USE_SIGV4") and
                not config.get(asc.bucket_name)):
            calling_format = bsc.SubdomainCallingFormat()

        conn = boto.connect_s3(
            host=config[asc.host_name],
            aws_access_key_id=config[tac.key_id],
            aws_secret_access_key=config[tac.secret_key],
            proxy=config.get(tac.proxy_hostname),
            proxy_port=config.get(tac.proxy_port),
            proxy_user=config.get(tac.proxy_username),
            proxy_pass=config.get(tac.proxy_password),
            is_secure=True,
            validate_certs=True,
            calling_format=calling_format)
    return conn


def _extract_region(e, config):
    if e.status == 301:
        try:
            headers = json.loads(e.reason)
        except ValueError:
            raise e
        else:
            if isinstance(headers, list):
                for header in headers:
                    if header[0] == "x-amz-bucket-region":
                        return header[1]
            raise e
    else:
        logger.error("Failed to detect region for bucket=%s, reason=%s",
                     config[asc.bucket_name], traceback.format_exc())
        raise


def try_special_regions(config):
    last_exception = Exception()
    for region in ("cn-north-1", "us-gov-west-1"):
        conn = _create_s3_connection(config, region)
        try:
            conn.get_bucket(config[asc.bucket_name])
            return region
        except Exception as e:
            last_exception = e

    raise last_exception


def _key_id_not_in_records(e):
    no_keyid = ("The AWS Access Key Id you provided does not exist "
                "in our records")
    return e.status == 403 and no_keyid in e.body


def validate_region_and_bucket(region, config):
    conn = _create_s3_connection(config, region)
    try:
        conn.get_bucket(config[asc.bucket_name])
    except Exception:
        return False
    return True


def get_region_for_bucketname(config):
    """
    :config: dict
    {
        key_id: xxx (required),
        secret_key: xxx (required),
        host: xxx,
        bucket_name: xxx,
        proxy_hostname: xxx,
        proxy_port: xxx,
        proxy_username: xxx,
        proxy_password: xxx,
    }
    """

    if not config.get(asc.bucket_name):
        if config.get(tac.region):
            return config[tac.region]
        return ""

    if config.get(tac.region):
        res = validate_region_and_bucket(config[tac.region], config)
        if res:
            return config[tac.region]

    conn = _create_s3_connection(config, "us-east-1")
    try:
        conn.get_bucket(config[asc.bucket_name])
    except S3ResponseError as e:
        if e.status == 403:
            return try_special_regions(config)
        else:
            return _extract_region(e, config)
    except Exception:
        logger.error("Failed to detect region for bucket=%s, reason=%s",
                     config[asc.bucket_name], traceback.format_exc())
        raise
    else:
        return ""


def create_s3_connection(config):
    """
    :config: dict
    {
        key_id: xxx (required),
        secret_key: xxx (required),
        host_name: xxx,
        bucket_name: xxx,
        region: xxx,
        proxy_hostname: xxx,
        proxy_port: xxx,
        proxy_username: xxx,
        proxy_password: xxx,
    }
    """

    if not config.get(asc.host_name):
        config[asc.host_name] = asc.default_host

    if config[asc.host_name] == asc.default_host:
        config[tac.region] = get_region_for_bucketname(config)
    else:
        pattern = r"s3[.-]([\w-]+)\.amazonaws.com"
        m = re.search(pattern, config[asc.host_name])
        if m:
            config[tac.region] = m.group(1)
        else:
            config[tac.region] = "us-east-1"
    return _create_s3_connection(config, config[tac.region])


def _build_regex(regex_str):
    if regex_str:
        exact_str = regex_str if regex_str[-1] == "$" else regex_str + "$"
        return re.compile(exact_str)
    else:
        return None


def _match_regex(white_matcher, black_matcher, key):
    if white_matcher is not None:
        if white_matcher.search(key.name):
            return True
    else:
        if black_matcher is None or not black_matcher.search(key.name):
            return True
    return False


def get_keys(bucket, prefix="", whitelist=None, blacklist=None,
             last_modified="", exceptions=None,
             storage_classes=("STANDARD", "REDUCED_REDUNDANCY")):
    """
    exceptions overrides all
    whitelist overrides blacklist
    last_modified overrides whitelist
    """

    black_matcher = _build_regex(blacklist)
    white_matcher = _build_regex(whitelist)

    keys = bucket.list(prefix=prefix)
    for key in keys:
        if storage_classes and key.storage_class not in storage_classes:
            continue

        if exceptions and key.name in exceptions:
            yield key
        elif last_modified:
            if key.last_modified > last_modified:
                matched = _match_regex(white_matcher, black_matcher, key)
                if matched:
                    yield key
        else:
            matched = _match_regex(white_matcher, black_matcher, key)
            if matched:
                yield key


def detect_unicode_by_bom(data):
    if data[:2] == "\xFE\xFF":
        return "UTF-16BE"
    if data[:2] == "\xFF\xFE":
        return "UTF-16LE"
    if data[:4] == "\x00\x00\xFE\xFF":
        return "UTF-32BE"
    if data[:4] == "\xFF\xFE\x00\x00":
        return "UTF-32LE"
    return "UTF-8"


def get_decoder(encoding, data):
    if not encoding:
        if data:
            encoding = detect_unicode_by_bom(data)
        else:
            encoding = "UTF-8"

    try:
        decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
        return decoder, encoding
    except LookupError:
        decoder = codecs.getincrementaldecoder("UTF-8")(errors="replace")
        return decoder, encoding


if __name__ == "__main__":
    aws_hosts = [asc.default_host, "s3-ap-southeast-1.amazonaws.com"]
    bucket_names = ["ken.chen.splunk", "ken-s3-testing"]
    use_sigv4s = ["", "True"]

    config = {
        asc.host_name: asc.default_host,
        tac.key_id: os.environ[tac.key_id],
        tac.secret_key: os.environ[tac.secret_key],
        asc.bucket_name: None,
    }

    for host in aws_hosts:
        for bucket_name in bucket_names:
            for use_sigv4 in use_sigv4s:
                # 1) not specify bucket name
                config[asc.bucket_name] = None
                config[tac.region] = None
                os.environ["S3_USE_SIGV4"] = use_sigv4
                config[asc.host_name] = host

                conn = create_s3_connection(config)
                if "." in bucket_name and host == asc.default_host:
                    try:
                        bucket = conn.get_bucket(bucket_name)
                    except boto.exception.S3ResponseError:
                        if use_sigv4:
                            print ("Exception: dot, no bucket name, "
                                   "default hostname, and use_sigv4")
                        else:
                            raise
                    except boto.https_connection.InvalidCertificateException:
                        if not use_sigv4:
                            print ("Exception: dot, no bucket name, "
                                   "default hostname, and not use_sigv4")
                        else:
                            raise
                    else:
                        assert 0
                elif use_sigv4 and host == asc.default_host:
                    try:
                        bucket = conn.get_bucket(bucket_name)
                    except boto.exception.S3ResponseError as e:
                        if e.status == 301:
                            print ("Exception: no bucket name, default "
                                   "hostname and use sigv4")
                        else:
                            raise
                else:
                    bucket = conn.get_bucket(bucket_name)
                    k = bucket.get_key("audit.log")
                    print k.read(100)

                # 2) specify bucket name
                config[asc.bucket_name] = bucket_name
                conn = create_s3_connection(config)
                bucket = conn.get_bucket(bucket_name)
                k = bucket.get_key("audit.log")
                print k.read(100)

    """
    config[asc.bucket_name] = "ta-cloudtrail-singapore"
    config[asc.prefix] = "AWSLogs/063605715280/"
    del config[tac.region]
    conn = create_s3_connection(config)
    bucket = conn.get_bucket(config[asc.bucket_name])

    keys = get_keys(bucket, config[asc.prefix], whitelist=".*2015/12/05.*")
    for key in keys:
        print key.name

    # config[asc.prefix] = "unicode/"
    config[asc.prefix] = ""
    config[asc.bucket_name] = "ta-aws-azhang-s3"
    del config[tac.region]
    conn = create_s3_connection(config)
    bucket = conn.get_bucket(config[asc.bucket_name])
    keys = get_keys(bucket, config[asc.prefix])
    for key in keys:
        print key.name, key.storage_class
        if "bl" in key.name:
            print key.read(4096)

    # Bucket in China region
    config[asc.bucket_name] = "splunk-aws-cn-logs"
    del config[tac.region]
    conn = create_s3_connection(config)
    bucket = conn.get_bucket(config[asc.bucket_name])
    for key in bucket.list():
        print key.name
        print key.read()
    """
