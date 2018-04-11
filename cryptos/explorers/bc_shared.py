
import requests

from cryptos.transaction import public_txhash

def request_push_tx(url, tx, coin_symbol):
    hash = public_txhash(tx)
    response = requests.post(url, {'tx': tx})
    if response.status_code == 200:
        return {'status': 'success',
                'data': {
                    'txid': hash,
                    'network': coin_symbol
                    }
                }
    else:
        return {'status': 'fail',
                'data': {
                    'txid': hash,
                    'network': coin_symbol
                    },
                'detail': {
                    'status_code': response.status_code, 
                    'text': response.text,
                    'reason': response.reason,
                    'url': response.url,
                    },
                }
