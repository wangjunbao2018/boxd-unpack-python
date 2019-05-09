#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import

import os
import json

from boxd_client.crypto.keystore import (
    to_privkey as dump_priv_key,
    to_keystore as dump_key_store,
    get_addr,
    get_pub_key as kgpk,
    get_pub_key_hash as get_pubkeyhash_from_addr,
    newaccount
)

from boxd_client.util.types import is_bytes
from boxd_client.exception.exceptions import ValidationError

from boxd_client.util.hexadecimal import bytes_to_hex


def format_json(j):
    ciphertext = j["crypto"]["ciphertext"]
    if is_bytes(ciphertext):
        j["crypto"]["ciphertext"] = ciphertext.decode()

    iv = j["crypto"]["cipherparams"]["iv"]
    if is_bytes(iv):
        j["crypto"]["cipherparams"]["iv"] = iv.decode()

    salt = j["crypto"]["kdfparams"]["salt"]
    j["crypto"]["kdfparams"]["salt"] = salt

    return j


class AccountManager:
    """
    Account manager class.
    """

    def __init__(self):
        pass

    def dump_keystore_from_privkey(self, priv_key, passphrase, path):
        """
        Generate a keystore file based on privkey

        :param priv_key:
        :param passphrase:
        :param path:
        :return:
        """

        if priv_key is None:
            raise ValidationError("Private key input err")

        if passphrase is None:
            raise ValidationError("Passphrase input err")

        if path is None:
            raise ValidationError("KeyStore file path input err")

        if os.path.isdir(path):
            raise ValidationError("Path can't be dir")

        if os.path.exists(path):
            raise ValidationError("Path already exists")

        key_store_json = dump_key_store(passphrase, priv_key)

        encoded_json = format_json(key_store_json)
        with open(path, 'w') as outfile:
            json.dump(encoded_json, outfile)
        return True

    def dump_privkey_from_keystore(self, file, passphrase):
        """
        Export privkey from a keystore file and given passphrase

        :param file:
        :param passphrase:
        :return:
        """
        if passphrase is None or passphrase == "":
            raise ValidationError("Passphrase is empty")

        if file is None:
            raise ValidationError("KeyStore file path input err")

        if os.path.isdir(file):
            raise ValidationError("Path can't be dir")

        if not os.path.exists(file):
            raise ValidationError("Path doesn't exists")

        def load_keyfile(path_or_file_obj):
            try:
                with open(path_or_file_obj) as keyfile_file:
                    return json.load(keyfile_file)
            except:
                raise IOError("Keystore input error")

        keyfile_json = load_keyfile(file)
        return dump_priv_key(keyfile_json, passphrase)

    def dump_addr_from_privkey(self, priv_key):
        """
        Export addr from privkey

        :param priv_key:
        :return:
        """
        if priv_key is None:
            raise ValidationError("Private key input err")
        return get_addr(kgpk(priv_key))

    def dump_pubkeyhash_from_privkey(self, priv_key):
        """
        Export pubkey hash from privkey

        :param priv_key:
        :return:
        """
        addr = get_addr(kgpk(priv_key))
        return self.dump_pubkeyhash_from_addr(addr)

    def dump_pubkeyhash_from_addr(self, addr):
        """
        Export pubkey from addr

        :param addr:
        :return:
        """
        return bytes_to_hex(get_pubkeyhash_from_addr(addr))

    def dump_pubkey_from_privkey(self, priv_key):
        """
        Export pubkey from privkey

        :param priv_key:
        :return:
        """
        if priv_key is None:
            raise ValidationError("Private key input err")
        return kgpk(priv_key)

    def new_account(self, passphrase, keystore_file_path):
        """
        Create a new account. It will create a keystore according to the passphrase

        :param passphrase:
        :param keystore_file_path:
        :return:
        """
        if keystore_file_path is None:
            raise ValidationError("KeyStore file path input err")

        if os.path.isdir(keystore_file_path):
            raise ValidationError("Path can't be dir")

        if os.path.exists(keystore_file_path):
            raise ValidationError("Path already exists")

        key_store_json = newaccount(passphrase)

        encoded_json = format_json(key_store_json)
        with open(keystore_file_path, 'w') as outfile:
            json.dump(encoded_json, outfile)
        return True
