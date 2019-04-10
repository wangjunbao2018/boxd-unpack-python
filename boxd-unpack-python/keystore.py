#!/usr/bin/env python3

import hmac

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Counter

from eth_utils import (
    big_endian_to_int,
    decode_hex,
    encode_hex,
    int_to_big_endian,
    is_dict,
    is_string,
    keccak,
    remove_0x_prefix,
    to_dict,
)
from secp256k1 import PrivateKey
import binascii, hashlib, base58

def encode_hex_no_prefix(value):
    return remove_0x_prefix(encode_hex(value))

def create_keyfile_json(private_key, password):
    if version == 3:
        return create_new_keyfile_json(password, private_key)
    else:
        raise NotImplementedError("Not yet implemented")

DKLEN = 32
SCRYPT_R = 1
SCRYPT_P = 8
N = 262144

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def get_pub_key(priv_hex):
    privKey = PrivateKey(bytes(bytearray.fromhex(priv_hex)), raw = True)
    pub_key = privKey.pubkey
    return pub_key.serialize()

def get_addr(pubkey):
    publ_key = binascii.hexlify(pubkey).decode()
    hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
    publ_addr_a = b"\x13\x26" + hash160

    checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
    publ_addr_b = base58.b58encode(publ_addr_a + checksum)
    return publ_addr_b

def newaccount(password):
    private_key = binascii.hexlify(os.urandom(32)).decode()
    return dumpkeystore(password, private_key)


def dumpkeystore(password, priv_key):
    salt = Random.get_random_bytes(32)

    derived_key = _scrypt_hash(password, salt=salt, buflen=DKLEN, r=SCRYPT_R, p=SCRYPT_P, n=N)

    encrypt_key = derived_key[:16]

    iv = big_endian_to_int(Random.get_random_bytes(16))

    ciphertext = encrypt_aes_ctr(decode_hex(priv_key), encrypt_key, iv)

    import hashlib
    m = hashlib.sha256()
    m.update(derived_key[16:])
    m.update(ciphertext)
    mac = m.hexdigest()

    addr = get_addr(get_pub_key(priv_key))

    return {
        "id":"",
        "address": addr.decode(),
        "crypto":{
            "ciphertext": encode_hex_no_prefix(ciphertext),
            "cipher":"aes-128-ctr",
            "cipherparams":{
                "iv": encode_hex_no_prefix(int_to_big_endian(iv))
            },
            "mac": mac,
            "kdfparams":{
                "salt": encode_hex_no_prefix(salt),
                "dklen": DKLEN,
                "n": N,
                "r": SCRYPT_R,
                "p": SCRYPT_P
            }
        },
        "version":"0.1.0"
    }

def dumpprivkey(keyfile_json, password):
    crypto = keyfile_json['crypto']
    derived_key = _derive_scrypt_key(crypto, password)
    ciphertext = decode_hex(crypto['ciphertext'])

    import hashlib
    m = hashlib.sha256()
    m.update(derived_key[16:])
    m.update(ciphertext)
    mac = m.hexdigest()
    expected_mac =  crypto['mac']

    if not hmac.compare_digest(decode_hex("0x" + mac), decode_hex("0x" + expected_mac)):
        raise ValueError("Passphrase may be error")

    # Decrypt the ciphertext using the derived encryption key to get the
    # private key.
    encrypt_key = derived_key[:16]

    cipherparams = crypto['cipherparams']
    iv = big_endian_to_int(decode_hex(cipherparams['iv']))
    private_key = decrypt_aes_ctr(ciphertext, encrypt_key, iv)
    return remove_0x_prefix(encode_hex(private_key))

def _derive_scrypt_key(crypto, password):
    kdf_params = crypto['kdfparams']
    salt = decode_hex(kdf_params['salt'])
    p = kdf_params['p']
    r = kdf_params['r']
    n = kdf_params['n']
    buflen = kdf_params['dklen']

    derived_scrypt_key = _scrypt_hash(
        password,
        salt=salt,
        n=n,
        r=r,
        p=p,
        buflen=buflen,
    )
    return derived_scrypt_key

def _scrypt_hash(password, salt, n, r, p, buflen):
    derived_key = scrypt(
        password,
        salt=salt,
        key_len=buflen,
        N=n,
        r=r,
        p=p,
        num_keys=1,
    )
    return derived_key

def decrypt_aes_ctr(ciphertext, key, iv):
    ctr = Counter.new(128, initial_value=iv, allow_wraparound=True)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    return encryptor.decrypt(ciphertext)

def encrypt_aes_ctr(value, key, iv):
    ctr = Counter.new(128, initial_value=iv, allow_wraparound=True)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = encryptor.encrypt(value)
    return ciphertext
