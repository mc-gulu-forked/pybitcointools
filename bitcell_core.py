# This Python file uses the following encoding: utf-8
""" @package bitcell_core
Usage:
    bitcell_core.py new_wallet [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)]
    bitcell_core.py get_balance [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)] --addr=<addr>
    bitcell_core.py make_tx [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)] --priv_key=<privkey> --dest_pairs=<dest_pairs> --fee=<tx_fee>
    bitcell_core.py push_tx [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)] --tx=<tx>
    bitcell_core.py get_tx [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)] --txid=<txid>
    bitcell_core.py pub_2_addr [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)] --pub_key=<pubkey>
    bitcell_core.py priv_2_pub [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)] --priv_key=<privkey>
    bitcell_core.py sign --priv_key=<privkey> --msg=<msg>
    bitcell_core.py verify --pub_key=<pubkey> --msg=<msg> --sig=<sig>
    bitcell_core.py test [--net_type=(btc|bch|doge|btctest|bchtest|dogetest)]
    bitcell_core.py -h | --help

Options:
    --net_type=(btc|bch|doge|btctest|bchtest|dogetest)  # 当前处理的币的类型
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
import traceback
import json

import cryptos
from cryptos.transaction import public_txhash
import binascii

import bitcell

import pprint

log = logging.getLogger(__name__)

#-----------------------------------------
# global vars

g_logDir = "logs"
g_isDebugging = True

#-----------------------------------------
# cmd handlers

class CmdHandlers:
    #pylint: disable=E0213
    #  Method should have "self" as first argument

    _coinType = bitcell.CT_BTC
    _coinNet = None

    def pre_config(cls, args):
        if "--net_type" in args and args['--net_type'] != None:
            cls._coinType = bitcell.getType(args['--net_type'])
            cls._coinNet = bitcell.getNet(cls._coinType, bitcell.isTestnetName(args['--net_type']))

    def new_wallet(cls, args):
        w = bitcell.BcWallet()
        w.generate(cls._coinType, cls._coinNet)
        return bitcell.Result(bitcell.SUCCESS, "success",
                              {"net_type": args['--net_type'],
                               "words": w.words,
                               "addr": w.addr,
                               "privkey": w.privkey,
                               "pubkey": w.pubkey }).toJson()

    def get_balance(cls, args):
        unspents = cls._coinNet.unspent(args['--addr'])
        v = sum(unspent['value'] for unspent in unspents)
        return bitcell.Result(bitcell.SUCCESS, "success",
                              { 'value': v }).toJson()

    def make_tx(cls, args):
        priv = args['--priv_key']
        dest_pairs = args['--dest_pairs'].split(',')
        if not dest_pairs:
            raise bitcell.Error(bitcell.ERROR_CMD_PARAMS,
                                "no valid pairs found in '--dest_pairs'")

        targets = []
        for p in dest_pairs:
            try:
                addr, v = p.split(':')
                value = int(float(v) * 100000000)
                targets.append("{}:{}".format(addr, value))
            except:
                raise bitcell.Error(bitcell.ERROR_CMD_PARAMS,
                                    "'--dest_pairs' element parsing error: " + p)

        try:
            tx_fee = int(float(args["--fee"]) * 100000000)
        except:
            raise bitcell.Error(bitcell.ERROR_CMD_PARAMS,
                                "'--fee' parsing error: " + args["--fee"])

        tx = cls._coinNet.preparesignedmultitx(priv, *targets, tx_fee)
        txid = public_txhash(tx)
        return bitcell.Result(bitcell.SUCCESS, "success",
                              { 'tx': tx, 'txid': txid }).toJson()

    def push_tx(cls, args):
        tx = args['--tx']
        result = cls._coinNet.pushtx(tx)
        return bitcell.Result(result['code'],
                              result['msg'],
                              result['data']).toJson()

    def get_tx(cls, args):
        txid = args['--txid']
        fetched = None
        try:
            fetched = cls._coinNet.fetchtx(txid)
        except Exception as e:
            raise bitcell.Error(bitcell.ERROR_NETWORK,
                                "fetchtx() failed: %s" % repr(e))

        if not isinstance(fetched, dict):
            raise bitcell.Error(bitcell.ERROR_NETWORK,
                                "invalid fetchtx() result: %s" % repr(fetched))

        # pp = pprint.PrettyPrinter(width=41, compact=True)
        # pp.pprint(fetched)

        outputs = {}
        if cls._coinType == bitcell.CT_BTC:
            for o in fetched['out']:
                outputs[o['addr']] = float(o['value']) / 100000000.0
        elif cls._coinType == bitcell.CT_DOGE:
            if "outputs" not in fetched:
                raise bitcell.Error(bitcell.ERROR_GET_TX_FAILED,
                                    "get tx failed")

            for o in fetched['outputs']:
                outputs[o['address']] = float(o['value'])
        else:
            raise bitcell.Error(bitcell.ERROR_NET_TYPE_NOT_SUPPORTED,
                                "not implemented yet for other coins!")

        confirmations = 0
        if 'confirmations' in fetched:
            confirmations = fetched['confirmations']
        if 'block_height' in fetched:
            height = fetched['block_height']
            confirmations = cls._coinNet.current_block_height() - height + 1

        return bitcell.Result(bitcell.SUCCESS, "success",
                      { 'confirmations': confirmations, 'output': outputs }).toJson()

    def pub_2_addr(cls, args):
        pubkey = args['--pub_key']
        address = cls._coinNet.pubtoaddr(pubkey)
        return bitcell.Result(bitcell.SUCCESS, "success",
                              { 'addr': address }).toJson()

    def priv_2_pub(cls, args):
        priv = args['--priv_key']
        pubkey = cls._coinNet.privtopub(priv)
        return bitcell.Result(bitcell.SUCCESS, "success", { 'pubkey': pubkey }).toJson()


    def sign(cls, args):
        priv = args['--priv_key']
        msgbytes = cryptos.from_string_to_bytes(args['--msg'])
        msg_hashed = hashlib.sha256(msgbytes).digest()

        v, r, s = cryptos.ecdsa_raw_sign(msg_hashed, priv)
        sig = cryptos.encode_sig(v, r, s)
        return bitcell.Result(bitcell.SUCCESS, "success", { 'sig': sig }).toJson()


    def verify(cls, args):
        pubkey = args['--pub_key']
        sig = args['--sig']
        # sig = base64.b64encode(cryptos.from_string_to_bytes(args['--sig']))

        msgbytes = cryptos.from_string_to_bytes(args['--msg'])
        msg_hashed = hashlib.sha256(msgbytes).digest()

        log.debug("params: (%s, %s, %s)", pubkey, cryptos.decode_sig(sig), binascii.hexlify(msg_hashed))

        result = cryptos.ecdsa_raw_verify(msg_hashed, cryptos.decode_sig(sig), pubkey)
        if result:
            return bitcell.Result(bitcell.SUCCESS, "success", { 'value': 1 }).toJson()
        else:
            return bitcell.Result(bitcell.ERROR_VERIFY_SIG_FAILED, "verify failed", { 'value': 0 }).toJson()


    def test(cls, args):
        pass


#-----------------------------------------
# main

def protected_main():
    # parsing args
    args = docopt.docopt(__doc__)

    # initialize logging
    bitcell.init_logging(g_logDir, g_isDebugging)

    # executing command
    CmdHandlers.pre_config(CmdHandlers, args)
    for k,v in CmdHandlers.__dict__.items():
        if k in args and args[k]:
            return v(CmdHandlers, args)

    # command handler not found
    raise bitcell.Error(bitcell.ERROR_CMD_PARAMS,
                        "No handler registered for command: '%s'" % ' '.join(sys.argv))

def main():
    try:
        output_on_succ = protected_main()
        if not output_on_succ:
            raise bitcell.Error(bitcell.ERROR_UNFINISHED_CODE,
                                "BAD_CODE: no return from main on success (json expected)")

        bitcell.stdout_write(output_on_succ)
        return 0
    except bitcell.Error as e:
        bitcell.stdout_write(e.toJson())
        return -1
    except Exception as e:
        bitcell.stdout_write(bitcell.UnexpectedError(e).toJson())
        return -1
    except:
        exc_info = sys.exc_info()
        if exc_info:
            bitcell.stdout_write(bitcell.UnexpectedError(exc_info[1]).toJson())
        else:
            bitcell.stdout_write(bitcell.UnexpectedError(Exception("unknown")).toJson())
            log.debug("unknown BaseException", stack_info=True)
        return -1

if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
