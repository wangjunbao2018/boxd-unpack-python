#!/usr/bin/env python

import time
import os

from boxd_client.boxd_client import BoxdClient

boxd = BoxdClient("39.97.169.1", 19111)


priv_key_hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
addr = "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"
password = "1"
path = "import.keystore"
if os.path.exists(path):
    os.remove(path)

boxd.dumpkeystore(priv_key_hex, password, path)

new_account_path = "demo.keystore"
if os.path.exists(new_account_path):
    os.remove(new_account_path)
boxd.newaccount(password, new_account_path)


priv_key_hex = boxd.dumpprivkey(new_account_path, "1")
print (priv_key_hex)

addr = boxd.privkey_to_addr(priv_key_hex)
print (addr)

