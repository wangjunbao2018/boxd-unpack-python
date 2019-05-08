#!/usr/bin/env python

import time

from boxd_client.protocol.rpc.boxd_client import BoxdClient
boxd = BoxdClient("39.97.169.1", 19111)

priv_key_hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
addr = "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"
amount = 10000

boxd.faucet(addr, amount)
time.sleep(3)

# create split addr
fee = 100
split_addr_info = {
    #"b1k9dMK6xrsXYCBuJfjTN9eTsMCiRb18Hnt": 6,
    "b1g8TPMT4mFZEcDZWomPJWXit4suGHs1eoq": 10
}
split_tx = boxd.make_unsigned_split_addr_tx(addr, split_addr_info, 100)
print(split_tx)

tx = boxd.sign_transaction(split_tx.tx, priv_key_hex=priv_key_hex, rawMsgs=split_tx.rawMsgs)
hash = boxd.send_transaction(tx)
print(hash)

tx_detail_resp = boxd.view_tx_detail(hash=hash)
print(tx_detail_resp)

time.sleep(3)

# transfer box to splitadd
transfer_tx = boxd.make_unsigned_tx(addr, {split_tx.splitAddr:100}, 100)
tx = boxd.sign_transaction(transfer_tx.tx, priv_key_hex=priv_key_hex, rawMsgs=transfer_tx.rawMsgs)
hash = boxd.send_transaction(tx)

time.sleep(3)

tx_detail_resp = boxd.view_tx_detail(hash = hash)
print(tx_detail_resp)
