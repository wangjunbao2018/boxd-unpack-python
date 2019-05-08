#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d.digest()


def bin_sha256(bin_s):
    return hashlib.sha256(bin_s).digest()


def bin_double_sha256(bin_s):
    return bin_sha256(bin_sha256(bin_s))

