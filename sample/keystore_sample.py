#!/usr/bin/env python3

import time

from boxd_client.boxd_client import BoxdClient
boxd = BoxdClient("39.97.169.1", 19111)


priv_key_hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
addr = "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"
password = "1"

path = "1.keystore"
boxd.dumpkeystore(priv_key_hex, password, path)


priv_key_hex_exspect = boxd.dumpprivkey(path, password)
print (priv_key_hex == priv_key_hex_exspect)


new_account_path = "9.keystore"
boxd.newaccount(password, new_account_path)

