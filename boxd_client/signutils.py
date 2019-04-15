#!/usr/bin/env python

from secp256k1 import PrivateKey
import binascii, hashlib, base58


def format_ret(t):
    ser = t.SerializeToString()
    return ser

def calc_tx_hash_for_sig(script_pub_key, tx, index):
    for i in range(len(tx.vin)):
        if i != index:
            tx.vin[index].script_sig = bytes()
        else:
            tx.vin[index].script_sig = script_pub_key
    return   format_ret(tx)


def get_pub_key_hash(addr):
    if len(addr) != 35 or not addr.startswith("b1"):
        return None
    pkh = base58.b58decode_check(addr)
    if len(pkh) != 22:
        return None
    return pkh[2:]

def get_pub_key(priv_hex):
    privKey = PrivateKey(bytes(bytearray.fromhex(priv_hex)), raw = True)
    pub_key = privKey.pubkey
    return pub_key.serialize()

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def get_addr(pubkey):
    publ_key = binascii.hexlify(pubkey).decode()
    hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
    publ_addr_a = b"\x13\x26" + hash160
    checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
    publ_addr_b = base58.b58encode(publ_addr_a + checksum)
    return publ_addr_b

def sign(priv_hex, msg_hex):
    privKey = PrivateKey(bytes(bytearray.fromhex(priv_hex)), raw = True)
    sig_check = privKey.ecdsa_sign(bytes(bytearray.fromhex(msg_hex)), raw = True)
    sig_ser = privKey.ecdsa_serialize(sig_check)
    return sig_ser