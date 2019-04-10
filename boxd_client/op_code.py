#!/usr/bin/env python3

import binary

class Opcode(object):
    '''
    op_code enum and operators
    '''
    
    OP0 = 0x00;         # 0
    OPPUSHDATA1 = 0x4c; # 76
    OPPUSHDATA2 = 0x4d; # 77
    OPPUSHDATA4 = 0x4e; # 78

    OPDUP          = 0x76; # 118
    OPHASH160      = 0xa9; # 169
    OPEQUALVERIFY  = 0x88; # 136
    OPCHECKSIG     = 0xac; # 172

    def __init__(self):
        self._r = []
        self.OP0 = 0x00;         # 0
        self.OPPUSHDATA1 = 0x4c; # 76
        self.OPPUSHDATA2 = 0x4d; # 77
        self.OPPUSHDATA4 = 0x4e; # 78

        self.OPDUP          = 0x76; # 118
        self.OPHASH160      = 0xa9; # 169
        self.OPEQUALVERIFY  = 0x88; # 136
        self.OPCHECKSIG     = 0xac; # 172
        pass

    def add_opcode(self, b):
        self._r.append(b)

    def add_operand(self, b):
        l = len(b)
        tmp = self.get_data(l) + b
        self._r += tmp

    def reset(self):
        self._r = []

    def get_result(self):
        return self._r

    def get_data(self, l):
        if l < self.OPPUSHDATA1:
            return [l]
        elif l <= 0xff:
            return [self.OPPUSHDATA1, l, 16]
        elif l <= 0xffff:
            b = binary.put_uint16(l)
            return [self.OPPUSHDATA2, b[0], b[1]]
        else:
            b = binary.put_uint32(l)
            return [self.OPPUSHDATA4, b[0], b[1], b[2], b[3], b[4]]