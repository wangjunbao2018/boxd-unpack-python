
from boxd_client.util.address import is_valid_addr
from boxd_client.util.encoding import big_endian_to_int, int_to_big_endian, int_to_little_endian
from boxd_client.util.utils import remove_0x_prefix
from boxd_client.util.hexadecimal import hex_to_bytes, bytes_to_hex

# address

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

i = 100
big_endian = int_to_big_endian(i)
little_endian = int_to_little_endian(i)
print (big_endian, little_endian)

b = big_endian_to_int(big_endian)
print (b)


# utils
addr = "0xVc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"
addr1 = "0XVc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"

addr_ret = remove_0x_prefix(addr)
addr_ret1 = remove_0x_prefix(addr1)
print(addr_ret, addr_ret1)

# hexadecimal
hex = "5ace780e4a6e17889a6b8697be6ba902936c148662cce65e6a3153431a1a77c1"
bs = hex_to_bytes(hex)
hex2 = bytes_to_hex(bs)
print(hex2)










