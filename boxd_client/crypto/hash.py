#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
from binascii import hexlify, unhexlify
from utilitybelt import is_hex


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d.digest()


def bin_sha256(bin_s):
    return hashlib.sha256(bin_s).digest()


def bin_double_sha256(bin_s):
    return bin_sha256(bin_sha256(bin_s))


def bin_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hashlib.new('ripemd160', bin_sha256(s)).digest()


def hex_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hexlify(bin_hash160(s))
