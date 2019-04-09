import hashlib
import hmac
import json
import uuid

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Counter

from eth_keys import keys

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


def encode_hex_no_prefix(value):
    return remove_0x_prefix(encode_hex(value))


def load_keyfile(path_or_file_obj):
    if is_string(path_or_file_obj):
        with open(path_or_file_obj) as keyfile_file:
            return json.load(keyfile_file)
    else:
        return json.load(path_or_file_obj)


def create_keyfile_json(private_key, password, version=3, kdf="scrypt", iterations=None):
    if version == 3:
        return _create_v3_keyfile_json(private_key, password, kdf, iterations)
    else:
        raise NotImplementedError("Not yet implemented")


def decode_keyfile_json(raw_keyfile_json, password):
    keyfile_json = normalize_keys(raw_keyfile_json)

    if "version" in keyfile_json:
        version = keyfile_json['version']
    return _decode_keyfile_json_v3(keyfile_json, password)


def extract_key_from_keyfile(path_or_file_obj, password):
    keyfile_json = load_keyfile(path_or_file_obj)
    private_key = decode_keyfile_json(keyfile_json, password)
    return private_key


@to_dict
def normalize_keys(keyfile_json):
    for key, value in keyfile_json.items():
        if is_string(key):
            norm_key = key.lower()
        else:
            norm_key = key

        if is_dict(value):
            norm_value = normalize_keys(value)
        else:
            norm_value = value

        yield norm_key, norm_value


#
# Version 3 creators
#
DKLEN = 32
SCRYPT_R = 1
SCRYPT_P = 8
N = 262144



import binascii, hashlib, base58
def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d


from secp256k1 import PrivateKey
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


def create_new_keyfile_json(password, priv_key):
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

    addr = get_addr(get_pub_key(priv_key_hex))

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

#
# Verson 3 decoder
#
def _decode_keyfile_json_v3(keyfile_json, password):
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
        raise ValueError("MAC mismatch")

    # Decrypt the ciphertext using the derived encryption key to get the
    # private key.
    encrypt_key = derived_key[:16]

    cipherparams = crypto['cipherparams']
    iv = big_endian_to_int(decode_hex(cipherparams['iv']))
    private_key = decrypt_aes_ctr(ciphertext, encrypt_key, iv)
    return private_key


#
# Key derivation
#
def _derive_pbkdf_key(crypto, password):
    kdf_params = crypto['kdfparams']
    salt = decode_hex(kdf_params['salt'])
    dklen = kdf_params['dklen']
    should_be_hmac, _, hash_name = kdf_params['prf'].partition('-')
    assert should_be_hmac == 'hmac'
    iterations = kdf_params['c']

    derive_pbkdf_key = _pbkdf2_hash(password, hash_name, salt, iterations, dklen)

    return derive_pbkdf_key


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


def _pbkdf2_hash(password, hash_name, salt, iterations, dklen):
    derived_key = hashlib.pbkdf2_hmac(
        hash_name=hash_name,
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=dklen,
    )

    return derived_key


#
# Encryption and Decryption
#
def decrypt_aes_ctr(ciphertext, key, iv):
    ctr = Counter.new(128, initial_value=iv, allow_wraparound=True)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    return encryptor.decrypt(ciphertext)


def encrypt_aes_ctr(value, key, iv):
    ctr = Counter.new(128, initial_value=iv, allow_wraparound=True)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = encryptor.encrypt(value)
    return ciphertext


def privkey_to_pubkey(priv_key):
    pubkey = keys.PrivateKey(priv_key_hex).public_key


#
# Utility
#
def get_default_work_factor_for_kdf(kdf):
    if kdf == 'pbkdf2':
        return 1000000
    elif kdf == 'scrypt':
        return 262144
    else:
        raise ValueError("Unsupported key derivation function: {0}".format(kdf))

import sys
import os
if __name__ == "__main__":
                    # e1d0404f6e6d07cb4d3eaf2893d88a2f39f616b66051cf9eb7b1dd9c9fbd8171
    # priv_key_hex = "29fbf01166fc31c941cadc1659a5f684f81c22c1113e5aa5b0af28b7dd453269"

    private_key = binascii.hexlify(os.urandom(32)).decode()
    #print (private_key)
    priv_key_hex = private_key

    # path = "/Users/apple/workspace/box-hi/boxd/.devconfig/pre.keystore"
    password = "1"

    ret = create_new_keyfile_json(password, priv_key_hex);
    print (ret)


    #
    # keyfile_json = {
    #     "id":"",
    #     "address":"b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m",
    #     "crypto":{
    #         "ciphertext":"b5394a7a865e09849b8df0906dbb3a070c8e891c0a6d9e1af13942fb7ff289c8",
    #         "cipher":"aes-128-ctr",
    #         "cipherparams":{
    #             "iv":"bd5eff35efca14f287305391e9a83f73"
    #         },
    #         "mac":"2e0ffb820f63b6b2c1785072458bf3ca03d7bf3c0134910da556306f137e3aa4",
    #         "kdfparams":{
    #             "salt":"c4d2164ad8e8d4e07b787953f83c45d2c088c3558ab4f2985fd939d163fa661b",
    #             "dklen":32,
    #             "n":262144,
    #             "r":8,
    #             "p":1
    #         }
    #     }
    # }
    #
    # keyfile_json = {
    #     "id":"",
    #     "address":"b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m",
    #     "crypto":{
    #         "ciphertext":"4a051a99ee9b307653c3d29aec1032ca6e806347baea2a78891c1eb5514fd296",
    #         "cipher":"aes-128-ctr",
    #         "cipherparams":{
    #             "iv":"ea537ec3d3cb433453ee76c539a4ccea"
    #         },
    #         "mac":"de79378181cdd993648fb2fd242f6cf8b77283842d411ea3fed8629d1d16b276",
    #         "kdfparams":{
    #             "salt":"ec0ffbde07e523305ae707cd6427a6056bf3246735cb5b44d77071348c2d7259",
    #             "dklen":32,
    #             "n":262144,
    #             "r":8,
    #             "p":1
    #         }
    #     },
    #     "version":"0.1.0"
    # }
    #
    # priv_key = decode_keyfile_json(keyfile_json, password)
    # print (encode_hex(priv_key))
    # print (remove_0x_prefix(encode_hex(priv_key)))

    kf_json = {
        "id": "",
        "address": "",
        "crypto": {
            "ciphertext": "58903c5a4a2aab0bb0ef029d13eb2f465d21adf2ba018df79b3e9085a8d7efdd",
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "3b9233c10b8c353b64a1bd640a8729d6"
            },
            "mac": "482fd8ebc068ec3455f9666bbc3eea59e78c5145262c7017b40c4973aceb3c74",
            "kdfparams": {
                "salt": "3fc209c8df337a59f10bdda61e4c48b473967d2f5b09f8aa8ce4a84088aed8fa",
                "dklen": 32,
                "n": 262144,
                "r": 8,
                "p": 8
            }
        },
        "version": "0.1.0"
    }
    priv_key = decode_keyfile_json(ret, password)
    print (encode_hex(priv_key))
    print (remove_0x_prefix(encode_hex(priv_key)))


