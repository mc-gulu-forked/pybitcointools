
import os
import sys
import base64
import logging
import time 

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

def stdout_write(data, b64Encode=False):
    output = isinstance(data, str) and data or str(data)
    if b64Encode:
        c = base64.b64encode(output.encode('utf-8'))
        output = c.decode('utf-8')
    sys.stdout.write(output)

