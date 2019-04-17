#!/usr/bin/env python

from .utils import is_bytes

def encode_json(j):

    ciphertext = j["crypto"]["ciphertext"]
    if is_bytes(ciphertext):
        j["crypto"]["ciphertext"] = ciphertext.decode()

    iv = j["crypto"]["cipherparams"]["iv"]
    if is_bytes(iv):
        j["crypto"]["cipherparams"]["iv"] = iv.decode()

    salt = j["crypto"]["kdfparams"]["salt"]
    j["crypto"]["kdfparams"]["salt"] = salt.decode()

    return j