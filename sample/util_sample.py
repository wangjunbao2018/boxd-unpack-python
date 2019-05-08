
from boxd_client.util.address import is_valid_addr
from boxd_client.util.encoding import big_endian_to_int, int_to_big_endian, int_to_little_endian
from boxd_client.util.utils import remove_0x_prefix
from boxd_client.util.hexadecimal import hex_to_bytes, bytes_to_hex

# address
print("\n\n================================")
addr = "b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"
error_addr1 = addr[1:]  # err lenght
error_addr2 = addr.lower()
error_addr3 = addr.replace("xy", "mn")

is_valid =  is_valid_addr(addr)

is_valid1 = is_valid_addr(error_addr1)
is_valid2 = is_valid_addr(error_addr2)
is_valid3 = is_valid_addr(error_addr3)

print (is_valid, is_valid1, is_valid2, is_valid3)


# encoding
print("\n\n================================")
i = 100
big_endian = int_to_big_endian(i)
little_endian = int_to_little_endian(i)
print (big_endian, little_endian)

b = big_endian_to_int(big_endian)
print (b)


# utils
print("\n\n================================")
addr = "0xVc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"
addr1 = "0XVc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"

addr_ret = remove_0x_prefix(addr)
addr_ret1 = remove_0x_prefix(addr1)
print(addr_ret, addr_ret1)

# hexadecimal
print("\n\n================================")
hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
bs = hex_to_bytes(hex)
hex2 = bytes_to_hex(bs)
print(hex2)


# hash
print("\n\n================================")
bs1 = hex_to_bytes(hex)
bs2 = hex_to_bytes("cf4017dd4d8c981be5cefaacc7cb3e5eee4f7f3006e6eb48dbc6f25d4e11e16c")
import hashlib
m = hashlib.sha256()
m.update(bs1)
m.update(bs2)
mac = m.hexdigest()
print(mac)

n = hashlib.sha256()
n.update(bs1 + bs2)
mac2 = n.hexdigest()
print (mac2)










