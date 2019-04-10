#!/bin/pyhton

import base58

text_types = (str, )
integer_types = (int, )

def is_addr_valid(addr):
    if addr == None  or addr == "":
        return False

    if len(addr) != 35  or  not addr.startswith("b1"):
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


if __name__ == "__main__":

    a = "238u9jdjfjfd99e94*"
    print (is_str(a))

    b = [1]
    print (is_list(b))
    print (is_list(a))

    c = 100
    print (is_number(c))
    d = True
    print (is_number(d))

    print ("" is None)

    addr = "b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq41"
    print (is_addr_valid(addr))

