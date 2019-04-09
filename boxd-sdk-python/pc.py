from secp256k1 import PrivateKey
import base58

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

from hashlib import new, sha256 as _sha256
def double_sha256_checksum(bytestr):
    return double_sha256(bytestr)[:4]
def sha256(bytestr):
    return _sha256(bytestr).digest()

def double_sha256(bytestr):
    return _sha256(_sha256(bytestr).digest()).digest()


import binascii, hashlib, base58
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


if __name__ == "__main__":
    priv_key_hex = "29fbf01166fc31c941cadc1659a5f684f81c22c1113e5aa5b0af28b7dd453269"
    pubkey = get_pub_key(priv_key_hex)
    addr = get_addr(pubkey)
    print (addr)
    # b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m
    # b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m
    # b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m