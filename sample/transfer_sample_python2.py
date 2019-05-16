#!/usr/bin/env python

import sys
import time

from boxd_client.protocol.rpc.boxd_client import BoxdClient
from boxd_client.util.hexadecimal import bytes_to_hex

boxd = BoxdClient("39.97.169.1", 19111)

priv_key_hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
addr = "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"
amount = 700
fee = 100

to = {}
to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
# to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 200
to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 300

boxd.faucet(addr, amount)
time.sleep(3)


def send_transaction(addr, to, fee):
    unsigned_tx = boxd.make_unsigned_tx(addr, to, fee)
    print("unsigned:")
    print(unsigned_tx)
    signed_tx = boxd.sign_transaction(unsigned_tx.tx, priv_key_hex, unsigned_tx.rawMsgs)
    print("signed:")
    print(signed_tx)
    print(bytes_to_hex(signed_tx.SerializeToString()))
    hash = boxd.send_transaction(signed_tx)
    return hash


def get_raw_tx(addr, to, fee):
    unsigned_tx = boxd.make_unsigned_tx(addr, to, fee)
    signed_tx = boxd.sign_transaction(unsigned_tx.tx, priv_key_hex, unsigned_tx.rawMsgs)
    return bytes_to_hex(signed_tx.SerializeToString())


def send_raw_transaction(raw_tx):
    return boxd.send_raw_transaction(raw_tx)


def send_offline_signed_transaction(addr, to, fee):
    balance = boxd.get_balance(addr)
    print(balance)
    if balance[addr] < amount + fee:
        print("low balance")
        sys.exit(0)

    utxos = boxd.fetch_utxos(addr, amount)
    print("\nuntxos:")
    print(utxos)

    unsigned_tx = boxd.create_raw_transaction(addr, utxos, to, fee)
    print("\nunsigned_tx:")
    print(unsigned_tx)

    signed_tx = boxd.sign_transaction(unsigned_tx, priv_key_hex)
    print("\nsigned_tx:")
    print(signed_tx)
    print(bytes_to_hex(signed_tx.SerializeToString()))

    return boxd.send_transaction(signed_tx)


def view_tx(hash):
    tx_detail = boxd.view_tx_detail(hash, False)
    print(tx_detail)



if __name__ == "__main__":

    hash = send_transaction(addr, to, fee)
    time.sleep(1)
    view_tx(hash)

    raw_tx = get_raw_tx(addr, to, fee)
    raw_tx_hash = send_raw_transaction(raw_tx)
    time.sleep(1)
    view_tx(raw_tx_hash)


# vin {
#     prev_out_point {
#     hash: "\000\016\266\212_\264\377\257\020\037\251\364\32176\325\226\036\252G\'\317G\3328)\304\266\361\035\251^"
# }
# script_sig: "v\251\024\007\005m\005\000\341\301\002\275\263\202\3013\236\326\367]\265\314\307\210\254"
# }
# vout {
#     value: 100
#     script_pub_key: "v\251\024\001Ks\372$\272\003\254\263\000\306N\321,\014N\274\006\302R\210\254"
# }


# tx {
#     vin {
#     prev_out_point {
#     hash: "$\341\036=\335]\034\312\374UK\031\301\236\223\007q6&Tz\2776_o\001\024/\224V#F"
# }
# }
# vout {
#     value: 100
#     script_pub_key: "v\251\024\001Ks\372$\272\003\254\263\000\306N\321,\014N\274\006\302R\210\254"
# }
# }



    # hash = transfer2(addr, to, fee)
    # time.sleep(1)
    # print("hash:" + hash)
    # view_tx(hash)

# signed_tx:
# vin {
#     prev_out_point {
#     hash: "\376\2264\317H\372\\\331\022\242G\205\351uj\000 0\257\364\341\2433\216\345\344}Z\024E\004X"
# }
# script_sig: "F0D\002 .{\r\247\240\226\035\226\020\323\241\022;G{0\213\347\030\304:\316\022\234\215\236\302\246A\036\210\225\002 aboz\344\2679\037\326\220\002\202\252a\376?\211\3735\344\'X}w\370\347s\335\235\020\221&!\003\037^\024\276m\r\0268\371\355Bf2\245\017\025\254/G\343\272S20n\317>N2\310\323\033"
# }
# vout {
#     value: 100
#     script_pub_key: "v\251\024\001Ks\372$\272\003\254\263\000\306N\321,\014N\274\006\302R\210\254"
# }
# 128f010a220a20fe9634cf48fa5cd912a24785e9756a002030aff4e1a3338ee5e47d5a14450458126946304402202e7b0da7a0961d9610d3a1123b477b308be718c43ace129c8d9ec2a6411e8895022061626f7ae4b7391fd6900282aa61fe3f89fb35e427587d77f8e773dd9d10912621031f5e14be6d0d1638f9ed426632a50f15ac2f47e3ba5332306ecf3e4e32c8d31b1a1d0864121976a914014b73fa24ba03acb300c64ed12c0c4ebc06c25288ac

# vin {
#     prev_out_point {
#     hash: "\363\"\207\271\257\215R\246&\230>\233k\254E\251\342\222(\264\373\256\317\301\033_C\227&\303i\037"
# }
# script_sig: "F0D\002 <\022\306E\200\222\031\304\301\260,y\301\325\213\254\252\3133\204n\035\275\205\235\033YD\2512=\377\002 \"T\367\334\255\205\326~p\026]\251\233\311l\266Gm;Q\272\267\202\324\301\266\r\213{\\\246)!\003\037^\024\276m\r\0268\371\355Bf2\245\017\025\254/G\343\272S20n\317>N2\310\323\033"
# }
# vout {
#     value: 100
#     script_pub_key: "v\251\024\001Ks\372$\272\003\254\263\000\306N\321,\014N\274\006\302R\210\254"
# }
