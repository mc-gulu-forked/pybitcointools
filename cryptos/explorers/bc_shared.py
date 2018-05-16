
import requests

from cryptos.transaction import public_txhash

ERR_Unknown = -1
ERR_OK = 0
ERR_TxPublished = 1
ERR_TxIsDust = 2
ERR_FeeNotEnough = 3

ErrText = {
    ERR_OK:             "success",
    ERR_Unknown:        "unknown",
    ERR_FeeNotEnough:   "fee not enough",
    ERR_TxPublished:     "tx published",
}

def request_push_tx(url, tx, coin_symbol, txName):
    hash = public_txhash(tx)
    response = requests.post(url, {txName: tx})
    if response.status_code == 200:
        return {
            'code': ERR_OK,
            'msg': ErrText[ERR_OK],
            'data': { 'txid': hash,
                      'network': coin_symbol
            }
        }
    else:
        err = ERR_Unknown
        if response.status_code == 500 and 'min relay fee not met' in response.text:
            err = ERR_FeeNotEnough
        if response.status_code == 404 and 'A valid signed transaction hexadecimal string is required' in response.text:
            err = ERR_TxPublished

        return {
            'code': err,
            'msg': ErrText[err],
            'data': {
                'txid': hash,
                'network': coin_symbol,
                'detail': {
                    'status_code': response.status_code,
                    'text': response.text,
                    'reason': response.reason,
                    'url': response.url,
                },
            },
        }
