#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base58

def is_valid_addr(addr):
    if addr == None  or addr == "":
        return False

    if len(addr) != 35  or  (not addr.startswith("b1") and not addr.startswith("b2")):
        return False

    try:
        ret = base58.b58decode_check(addr)
        if ret is None  or len(ret) != 22:
            return False
    except:
        return False

    return True