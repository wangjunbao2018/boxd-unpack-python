#!/usr/bin/env python

import time

from boxd_client.protocol.rpc.boxd_client import BoxdClient
boxd = BoxdClient("39.97.169.1", 19111)

priv_key_hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
addr = "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"
amount = 10000
fee = 100

to = {}
to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 300
to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 400

boxd.faucet(addr, amount)
time.sleep(3)


def view_tx(hash):
    tx_detail = boxd.view_tx_detail(hash, False)
    print(tx_detail)


def transfer(addr, to, fee, priv_key_hex):
    unsigned_tx = boxd.make_unsigned_tx(addr, to, fee)
    signed_tx = boxd.sign_transaction(unsigned_tx.tx, priv_key_hex, unsigned_tx.rawMsgs)
    hash = boxd.send_transaction(signed_tx)
    return hash


if __name__ == "__main__":

    hash = transfer(addr, to, fee, priv_key_hex)
    print(hash, type(hash))

    view_tx(hash)

