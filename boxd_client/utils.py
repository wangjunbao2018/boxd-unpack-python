#!/usr/bin/env python

import base58

text_types = (str, )
integer_types = (int, )

def is_addr_valid(addr):
    if addr == None  or addr == "":
        return False

    if len(addr) != 35  or  (not addr.startswith("b1") and not addr.startswith("b2")):
        return False

    try:
        ret = base58.b58decode_check(addr)
        if ret is None  or  len(ret) != 22:
            return False
    except:
        return False

    return True

def is_str(value):
    return isinstance(value, text_types)

def is_list(value):
    return isinstance(value, list)

def is_number(value):
    return isinstance(value, integer_types) and not isinstance(value, bool)

def is_dict(value):
    return isinstance(value, dict)