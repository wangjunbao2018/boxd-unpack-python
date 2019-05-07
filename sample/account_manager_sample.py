#!/usr/bin/env python

#!/usr/bin/env python

import os
from boxd_client.util.hexadecimal import bytes_to_hex

from boxd_client.account.account_manager import AccountManager as boxd

# priv_key_hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
priv_key_hex = "4fd7346602d5fae2404efca9a35ba2ba470fffed1672d52f8581845e424179be"
print (priv_key_hex)

addr  = boxd.dump_addr_from_privkey(priv_key_hex)
print(addr)

pubkey = boxd.dump_pubkey_from_privkey(priv_key_hex)
print (bytes_to_hex(pubkey))

pubkeyhash = boxd.dump_pubkeyhash_from_addr(addr)
pubkeyhash2 = boxd.dump_pubkeyhash_from_privkey(priv_key_hex)
print (bytes_to_hex(pubkeyhash))
print (bytes_to_hex(pubkeyhash2))


print ("\n\n\n-----------------------------------------------")
addr = "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"
password = "1"
path = "import.keystore"
if os.path.exists(path):
    os.remove(path)
boxd.dump_keytore_from_privkey(priv_key_hex, password, path)

new_account_path = "demo.keystore"
if os.path.exists(new_account_path):
    os.remove(new_account_path)
boxd.new_account(password, new_account_path)


priv_key_hex = boxd.dump_privkey_from_keystore(new_account_path, password)
print (priv_key_hex)

addr = boxd.dump_addr_from_privkey(priv_key_hex)
print (addr)