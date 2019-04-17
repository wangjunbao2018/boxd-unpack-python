#!/usr/bin/env python

import base58
import struct
import codecs
from binascii import unhexlify

text_types = (str, )
integer_types = (int, )

def is_addr_valid(addr):
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


def int_to_big_endian(val):
    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    # if endianness == 'little':
    #     # see http://stackoverflow.com/a/931095/309233
    #     s = s[::-1]

    return s

def big_endian_to_int(value):
    return int(codecs.encode(value, 'hex'), 16)

def remove_0x_prefix(hex):
    if hex.startswith("0x") or hex.startswith("0X"):
        return hex[2:]
    return hex

def is_bytes(value):
    return isinstance(value, bytes)

def is_str(value):
    return isinstance(value, text_types)

def is_list(value):
    return isinstance(value, list)

def is_number(value):
    return isinstance(value, integer_types) and not isinstance(value, bool)

def is_dict(value):
    return isinstance(value, dict)