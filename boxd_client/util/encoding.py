#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
from binascii import unhexlify

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
    return s

def int_to_little_endian(val):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    fmt = '%%0%dx' % (width // 4)
    s = unhexlify(fmt % val)

    # see http://stackoverflow.com/a/931095/309233
    s = s[::-1]
    return s

def big_endian_to_int(value):
    return int(codecs.encode(value, 'hex'), 16)
