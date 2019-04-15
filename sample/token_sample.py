#!/usr/bin/env python

import time

from boxd_client.boxd_client import BoxdClient
boxd = BoxdClient("39.97.169.1", 19111)


priv_key_hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
addr = "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"
amount = 10000

faucet_hash = boxd.faucet(addr, amount)
print(faucet_hash)

# create token
name = "TEST token"
symbol = "TEST"
supply = 10000
decimal = 8
token_tx = boxd.make_unsigned_token_issue_transaction(name, symbol, supply, decimal, addr, addr, fee = 100)

tx = boxd.sign_unsigned_transaction(token_tx.tx, priv_key_hex=priv_key_hex, rawMsgs = token_tx.rawMsgs)
hash = boxd.send_transaction(tx)
print (hash)

tx_detail_resp = boxd.view_tx_detail(hash = hash.hash)
print (tx_detail_resp)

time.sleep(3)

# token transfer
transfer_tx = boxd.make_unsigned_token_transfer_transaction(addr, {"b1ZEo29kfzZNUi411vVVAtzqShLmkyiW23o":100}, hash.hash, 0, 10)
tx = boxd.sign_unsigned_transaction(transfer_tx.tx, priv_key_hex=priv_key_hex, rawMsgs = transfer_tx.rawMsgs)
hash = boxd.send_transaction(tx)
print (hash)

time.sleep(3)

tx_detail_resp = boxd.view_tx_detail(hash = hash.hash)
print (tx_detail_resp)


if __name__ == "__main__":
    pass