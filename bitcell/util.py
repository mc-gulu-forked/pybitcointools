
import os
import sys
import base64
import logging
import time
import json
import pprint

log = logging.getLogger(__name__)


def init_logging(logDir, isDebugging=False):
    ''' initialize logging
    '''
    if not os.path.exists(logDir):
        os.mkdir(logDir)

    log_file = os.path.join(logDir, "{}.log".format(time.strftime("%Y-%m-%d", time.localtime())))
    log_format = '%(asctime)-15s %(levelname)-5s %(name)5s: %(message)s'
    log_level = isDebugging and logging.DEBUG or logging.INFO
    logging.basicConfig(filename=log_file, level=log_level, format=log_format)

    # errors should also go to stderr
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.ERROR)
    ch.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(ch)

# def decode_wallet(args):
#     data = args["--wallet"]
#     j = base64.b64decode(data.encode('utf-8'))
#     w = bitcell.BcWallet()
#     w.fromJson(j.decode('utf-8'))
#     return w

def stdout_write(data, b64Encode=False, jsonPretty=False):
    output = ""

    if isinstance(data, dict):
        output = pprint.PrettyPrinter(indent=4).pformat(data)
    else:
        output = isinstance(data, str) and data or str(data)

    if b64Encode:
        c = base64.b64encode(output.encode('utf-8'))
        output = c.decode('utf-8')

    if jsonPretty:
        output = json.dumps(json.loads(output), indent=4, sort_keys=True)

    sys.stdout.write(output or "")


class Result:
    def __init__(self, code, msg, data=None):
        self.code = code
        self.msg = msg

        if data is None:
            self.data = {}
        elif isinstance(data, dict):
            self.data = data
        else:
            self.data = {"detail": {"text": data}}

    def toJson(self):
        return json.dumps(self.__dict__)


class Error (Exception):
    def __init__(self, err_code, err_msg, err_info=""):
        self.code = err_code
        self.msg = err_msg
        self.data = {"detail": {"text": err_info}}

    def toJson(self):
        return json.dumps(self.__dict__)

class UnexpectedError (Error):
    def __init__(self, e):
        detailedInfo = "BUnexpectedError: " + repr(e)
        super(UnexpectedError, self).__init__(-1, "BUnexpectedError", detailedInfo)
        log.debug(detailedInfo, exc_info=True)
