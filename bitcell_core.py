# This Python file uses the following encoding: utf-8
""" @package bitcell_core
Usage:
    bitcell_core.py new_wallet [--coin_type=(btc|bch|doge) --testnet]
    bitcell_core.py get_balance [--coin_type=(btc|bch|doge) --testnet] --addr=<addr>
    bitcell_core.py sign [--coin_type=(btc|bch|doge) --testnet] --priv_key=<privkey> --dest_addr=<dest_addr> --coin_value=<coin_value> --fee=<tx_fee>
    bitcell_core.py broadcast [--coin_type=(btc|bch|doge) --testnet] --pub_key=<pubkey> --transaction=<tx>
    bitcell_core.py get_confirm_count [--coin_type=(btc|bch|doge) --testnet] --transaction=<tx>
    bitcell_core.py verify [--coin_type=(btc|bch|doge) --testnet] --pub_key=<pubkey> --msg=<msg> --sig=<sig>
    bitcell_core.py pub_2_addr [--coin_type=(btc|bch|doge) --testnet] --pub_key=<pubkey> 
    bitcell_core.py -h | --help
    
Options:
    --coin_type=(btc|bch|doge)  # 当前处理的币的类型
    --testnet                   # 测试网络还是正式网络  
    --debug                     # 是否为调试模式
    --addr=<addr>               # 一个标准的字符串地址
    --dest_addr=<dest_addr>     # The target btc address to receive payment.
    --coin_value=<coin_value>   # coins to pay
    --transaction=<tx>          
    -h --help                   Show this screen.
"""

import logging
import sys
import shutil
import os
import docopt
import base64
import hashlib

import cryptos
import bitcell

log = logging.getLogger(__name__)

#-----------------------------------------
# global vars

g_logDir = "logs"
g_isDebugging = False

#-----------------------------------------
# cmd handlers

class CmdHandlers:
    _coinType = bitcell.CT_BTC
    _coinNet = None

    def pre_config(cls, args):
        cls._coinType = bitcell.getType(args['--coin_type'])
        cls._coinNet = bitcell.getNet(cls._coinType, args['--testnet'])

    def new_wallet(cls, args):
        w = bitcell.BcWallet()
        w.generate(cls._coinType, cls._coinNet) 
        bitcell.stdout_write(w.toJson())
        log.debug("wallet created. (%s)", w.toJson())

    def get_balance(cls, args):
        unspents = cls._coinNet.unspent(args['--addr'])
        v = sum(unspent['value'] for unspent in unspents)
        bitcell.stdout_write(v)

    def sign(cls, args):
        priv = args['--priv_key']
        dest = args['--dest_addr']
        v = int(float(args["--coin_value"]) * 100000000)
        tx_fee = int(float(args["--fee"]) * 100000000)
        log.debug("tx. (v=%d, fee=%d)", v-tx_fee, tx_fee)
        tx = cls._coinNet.preparesignedtx(priv, dest, v-tx_fee, fee=tx_fee)
        bitcell.stdout_write(tx)

    def broadcast(cls, args):
        crypto.pushtx(args['--transaction'])

    def get_confirm_count(cls, args):
        pass

    def verify(cls, args):
        pubkey = args['--pub_key']
        sig = args['--sig']
        # sig = base64.b64encode(cryptos.from_string_to_bytes(args['--sig']))

        msgbytes = cryptos.from_string_to_bytes(args['--msg'])
        msg_hashed = hashlib.sha256(msgbytes).digest()

        log.debug("params: (%s, %s, %s)", pubkey, sig, msg_hashed)

        result = cryptos.ecdsa_raw_verify(msg_hashed, cryptos.decode_sig(sig), pubkey) 
        bitcell.stdout_write(result and 1 or 0)

    def pub_2_addr(cls, args):
        pubkey = args['--pub_key']
        address = cls._coinNet.pubtoaddr(pubkey)
        bitcell.stdout_write(address)

#-----------------------------------------
# main

def main():
    # parsing args
    args = docopt.docopt(__doc__)

    # initialize logging
    bitcell.init_logging(g_logDir, g_isDebugging)

    # executing command
    CmdHandlers.pre_config(CmdHandlers, args)
    for k,v in CmdHandlers.__dict__.items():
        if k in args and args[k]:
            try:
                v(CmdHandlers, args)
                return 0
            except Exception as e:
                log.error("command ('%s') executing failed: " % ' '.join(sys.argv), exc_info=True)
                return -1

    log.error("command ('%s') handler not found: " % ' '.join(sys.argv))
    return -1
 
if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
