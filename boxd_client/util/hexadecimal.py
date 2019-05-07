#!/usr/bin/env python
# -*- coding: utf-8 -*-

import six

def hex_to_bytes(value):
    if six.PY2:
        return value.decode("hex")
    else:
        return bytes.fromhex(value)

def bytes_to_hex(value):
    if six.PY2:
        return value.encode("hex")
    else:
        return value.hex()
