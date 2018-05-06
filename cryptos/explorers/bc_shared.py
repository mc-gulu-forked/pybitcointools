
import requests

from cryptos.transaction import public_txhash

ERR_OK = 0
ERR_Unknown = 1
ERR_FeeNotEnough = 2

ErrText = {
    ERR_OK:             "ok",
    ERR_Unknown:        "unknown",
    ERR_FeeNotEnough:   "fee not enough",
}

def request_push_tx(url, tx, coin_symbol, txName):
    hash = public_txhash(tx)
    response = requests.post(url, {txName: tx})
    if response.status_code == 200:
        return {'status': 'success',
                'data': {
                    'txid': hash,
                    'network': coin_symbol
                    },
                'detail': {
                    'error_code': ERR_OK, 
                    'error_text': ErrText[ERR_OK], 
                    },
                }
    else:
        err = ERR_Unknown
        if response.status_code == 500 and 'min relay fee not met' in response.text:
            err = ERR_FeeNotEnough
            
        return {'status': 'fail',
                'data': {
                    'txid': hash,
                    'network': coin_symbol
                    },
                'detail': {
                    'error_code': err, 
                    'error_text': ErrText[err], 
                    'status_code': response.status_code, 
                    'text': response.text,
                    'reason': response.reason,
                    'url': response.url,
                    },
                }
