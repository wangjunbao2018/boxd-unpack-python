#!/usr/bin/env python

import os
import sys

from boxd_client.util.hexadecimal import bytes_to_hex

from boxd_client.account.account_manager import AccountManager
boxd = AccountManager()


def new_account(passphrase, keystore_file_path):
    if os.path.exists(keystore_file_path):
        # os.remove(keystore_file_path)
        pass
    else:
        boxd.new_account(passphrase, keystore_file_path)


def dump_privkey_from_keystore(file, passphrase):
    return boxd.dump_privkey_from_keystore(file, passphrase)


def dump_keytore_from_privkey(priv_key, passphrase, path):
    if os.path.exists(path):
        pass
    else:
        boxd.dump_keystore_from_privkey(priv_key, passphrase, path)


def dump_pubkey_from_privkey(priv_key):
    return bytes_to_hex(boxd.dump_pubkey_from_privkey(priv_key))


def dump_addr_from_privkey(priv_key):
    return boxd.dump_addr_from_privkey(priv_key)


def dump_pubkeyhash_from_privkey(priv_key):
    return boxd.dump_pubkeyhash_from_privkey(priv_key)


def dump_pubkeyhash_from_addr(addr):
    return boxd.dump_pubkeyhash_from_addr(addr)


if __name__ == "__main__":
    pass

    passphrase = "1"
    keystore_file_path = "new_account.keystore"

    print("\n\n===================================new account      ===========================")
    new_account(passphrase, keystore_file_path)

    print("\n\n==========================dump_privkey_from_keystore===========================")
    privkey = dump_privkey_from_keystore(keystore_file_path, passphrase)
    print(privkey,  type(privkey))

    print("\n\n==========================dump_keystore_from_privkey===========================")
    new_keystore_path = "new_generated_keystore.keystore"
    dump_keytore_from_privkey(privkey, passphrase, new_keystore_path)

    print("\n\n===========================dump_privkey_from_keystore==========================")
    privkey1 = dump_privkey_from_keystore(new_keystore_path, passphrase)
    print(privkey)
    print(privkey == privkey1)

    print("\n\n============================dump_pubkey_from_privkey===========================")
    pubkey = dump_pubkey_from_privkey(privkey)
    print(pubkey, type(pubkey))

    print("\n\n============================dump_addr_from_privkey=============================")
    addr = dump_addr_from_privkey(privkey)
    print(addr, type(addr))
    print(addr)

    print("\n\n=============================dump_pubkeyhash_from_privkey=======================")
    pubkeyhash = dump_pubkeyhash_from_privkey(privkey)
    print(pubkeyhash, type(pubkeyhash))


    print("\n\n=============================dump_pubkeyhash_from_addr==========================")
    pubkeyhash1 = dump_pubkeyhash_from_addr(addr)
    print(pubkeyhash1, type(pubkeyhash1))
