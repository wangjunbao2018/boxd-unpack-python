#!/usr/bin/env python3

def uint16(b):
    return b[0] | b[1] << 8


def put_uint16(uint16):
    return [uint16, uint16 >> 8]


def uint32(b):
    return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;


def put_uint32(uint32):
    return [uint32, uint32 >> 8, uint32 >> 16, uint32 >> 24]


def uint64(b):
    return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24 | b[4] << 32 | b[5] << 40 | b[6] << 48 | b[7] << 56


def put_uint64(uint64):
    return [uint64, uint64 >> 8, uint64 >> 16, uint64 >> 24, uint64 >> 32, uint64 >> 40, uint64 >> 48, uint64 >> 56]
