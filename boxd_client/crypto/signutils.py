#!/usr/bin/env python
# -*- coding: utf-8 -*-


from secp256k1 import PrivateKey
from boxd_client.util.hexadecimal import hex_to_bytes


def calc_tx_hash_for_sig(script_pub_key, tx, index):
    for i in range(len(tx.vin)):
        if i != index:
            tx.vin[index].script_sig = b''
        else:
            tx.vin[index].script_sig = script_pub_key
    return tx.SerializeToString()


def sign(priv_hex, msg_hex):
    privKey = PrivateKey(hex_to_bytes(priv_hex), raw=True)
    sig_check = privKey.ecdsa_sign(hex_to_bytes(msg_hex), raw=True)
    sig_ser = privKey.ecdsa_serialize(sig_check)
    return sig_ser
