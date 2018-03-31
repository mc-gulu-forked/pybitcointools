
import logging
import os
import sys
import json

import cryptos

log = logging.getLogger(__name__)

CT_BTC = 0
CT_BCH = 1
CT_DOGE = 2

BTC_MainNet = cryptos.Bitcoin(testnet=False)
BTC_TestNet = cryptos.Bitcoin(testnet=True)

BCH_MainNet = cryptos.BitcoinCash(testnet=False)
BCH_TestNet = cryptos.BitcoinCash(testnet=True)

DOGE_MainNet = cryptos.Doge(testnet=False)
DOGE_TestNet = cryptos.Doge(testnet=True)

def getType(typeStr):
    if typeStr == 'btc':
        return CT_BTC
    elif typeStr == 'bch':
        return CT_BCH
    elif typeStr == 'doge':
        return CT_DOGE
    else:
        raise Exception("unkown net: type-{}".format(typeStr))

def getNet(type, isTestnet):
    if type == CT_BTC:
        return isTestnet and BTC_TestNet or BTC_MainNet
    elif type == CT_BCH:
        return isTestnet and BCH_TestNet or BCH_MainNet
    elif type == CT_DOGE:
        return isTestnet and DOGE_TestNet or DOGE_MainNet
    else:
        raise Exception("unkown net: type-{}".format(type))

def isTestnet(type, net):
    if type == CT_BTC:
        return net != BTC_MainNet 
    elif type == CT_BCH:
        return net != BCH_MainNet 
    elif type == CT_DOGE:
        return net != DOGE_MainNet 
    else:
        raise Exception("unkown net: type-{}".format(type))

class BcWallet(object):
    def __init__(self):
        self.coinType = CT_BTC
        self.coinNet = None
        self.words = ""
        self.isTestnet = False
        self.wallet = None
        self.addr = ""
        self.privkey = ""
        self.pubkey = ""

    def generate(self, type, net):
        self.coinType = type
        self.coinNet = net
        log.info("coinType: {}, coinNet: {}".format(self.coinType, self.coinNet))
        self.isTestnet = isTestnet(self.coinType, net)

        entropy = os.urandom(16)
        self.words = cryptos.entropy_to_words(entropy) 
        self.wallet = self.coinNet.wallet(self.words)
        self.addr = self.wallet.new_receiving_address()
        self.privkey = self.wallet.privkey(self.addr)
        self.pubkey = self.coinNet.privtopub(self.privkey)       # should equal 'self.wallet.pubkey_receiving(0)'

    def toJson(self):
        c = self.__dict__.copy()
        c.pop('wallet', None)
        c.pop('coinNet', None)
        return json.dumps(c)

    def fromJson(self, jsonStr):
        self.__dict__ = json.loads(jsonStr)
        self.coinNet = getNet(self.coinType, self.isTestnet)
        self.wallet = self.coinNet.wallet(self.words)

    def getBalance(self):
        unspents = self.coinNet.unspent(self.addr)
        return sum(unspent['value'] for unspent in unspents)
