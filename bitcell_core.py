# This Python file uses the following encoding: utf-8
""" @package bitcell_core
Usage:
    bitcell_core.py new_wallet [--coin_type=(btc|bch|doge) --testnet]
    bitcell_core.py get_balance [--coin_type=(btc|bch|doge) --testnet] --addr=<addr>
    bitcell_core.py make_tx [--coin_type=(btc|bch|doge) --testnet] --priv_key=<privkey> --dest_pairs=<dest_pairs> --fee=<tx_fee>
    bitcell_core.py push_tx [--coin_type=(btc|bch|doge) --testnet] --tx=<tx>
    bitcell_core.py get_tx [--coin_type=(btc|bch|doge) --testnet] --txid=<txid>
    bitcell_core.py pub_2_addr [--coin_type=(btc|bch|doge) --testnet] --pub_key=<pubkey> 
    bitcell_core.py verify [--coin_type=(btc|bch|doge) --testnet] --pub_key=<pubkey> --msg=<msg> --sig=<sig>
    bitcell_core.py test [--coin_type=(btc|bch|doge) --testnet]
    bitcell_core.py -h | --help
    
Options:
    --coin_type=(btc|bch|doge)  # 当前处理的币的类型
    --testnet                   # 测试网络还是正式网络  
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
        cls._coinType = bitcell.getType(args['--coin_type'])
        cls._coinNet = bitcell.getNet(cls._coinType, args['--testnet'])

    def new_wallet(cls, args):
        w = bitcell.BcWallet()
        w.generate(cls._coinType, cls._coinNet) 
        return w.toJson()

    def get_balance(cls, args):
        unspents = cls._coinNet.unspent(args['--addr'])
        v = sum(unspent['value'] for unspent in unspents)
        return json.dumps({ 'value': v })

    def make_tx(cls, args):
        priv = args['--priv_key']
        dest_pairs = args['--dest_pairs'].split(',')
        if not dest_pairs:
            raise bitcell.Error("no valid pairs found in '--dest_pairs'")

        targets = []
        for p in dest_pairs:
            try:
                addr, v = p.split(':')
                value = int(float(v) * 100000000)
                targets.append("{}:{}".format(addr, value))
            except:
                raise bitcell.Error("'--dest_pairs' element parsing error: " + p)

        try:
            tx_fee = int(float(args["--fee"]) * 100000000)
        except:
            raise bitcell.Error("'--fee' parsing error: " + args["--fee"])
            
        tx = cls._coinNet.preparesignedmultitx(priv, *targets, tx_fee)
        return json.dumps({ 'tx': tx })

    def push_tx(cls, args):
        tx = args['--tx']
        return json.dumps(cls._coinNet.pushtx(tx))

    def get_tx(cls, args):
        txid = args['--txid']
        fetched = None
        try:
            fetched = cls._coinNet.fetchtx(txid)
        except Exception as e:
            raise bitcell.Error("fetchtx() failed: %s" % repr(e))
            
        if not isinstance(fetched, dict):
            raise bitcell.Error("invalid fetchtx() result: %s" % repr(fetched))

        # pp = pprint.PrettyPrinter(width=41, compact=True)
        # pp.pprint(fetched)

        outputs = {}
        for o in fetched['out']:
            outputs[o['addr']] = float(o['value']) / 100000000.0
        
        if 'block_height' not in fetched:
            return json.dumps({ 'confirmations': 0, 'value': rcv })
                
        height = fetched['block_height']
        cur_height = cls._coinNet.current_block_height()
        return json.dumps({ 'confirmations': cur_height - height + 1, 'output': outputs })

    def pub_2_addr(cls, args):
        pubkey = args['--pub_key']
        address = cls._coinNet.pubtoaddr(pubkey)
        return json.dumps({ 'addr': address })

    def verify(cls, args):
        pubkey = args['--pub_key']
        sig = args['--sig']
        # sig = base64.b64encode(cryptos.from_string_to_bytes(args['--sig']))

        msgbytes = cryptos.from_string_to_bytes(args['--msg'])
        msg_hashed = hashlib.sha256(msgbytes).digest()

        log.debug("params: (%s, %s, %s)", pubkey, sig, msg_hashed)

        result = cryptos.ecdsa_raw_verify(msg_hashed, cryptos.decode_sig(sig), pubkey) 
        return json.dumps({ 'value': result and 1 or 0 })

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
    raise bitcell.Error("No handler registered for command: '%s'" % ' '.join(sys.argv))

def main():
    try:
        output_on_succ = protected_main()
        if not output_on_succ:
            raise bitcell.Error("BAD_CODE: no return from main on success (json expected)")

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
