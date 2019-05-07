#!/usr/bin/env python
# -*- coding: utf-8 -*-


def remove_0x_prefix(hex):
    if hex.startswith("0x") or hex.startswith("0X"):
        return hex[2:]
    return hex
