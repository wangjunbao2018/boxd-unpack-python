import hashlib
from hashlib import sha256
from binascii import hexlify, unhexlify
from utilitybelt import is_hex

def bytes_to_hex(b):
    return hexlify(bytearray(b))

def hex_to_bytes(v):
    return  v.decode("hex")


def bin_sha256(bin_s):
    return sha256(bin_s).digest()


def bin_checksum(bin_s):
    """ Takes in a binary string and returns a checksum. """
    return bin_sha256(bin_sha256(bin_s))[:4]


def bin_double_sha256(bin_s):
    return bin_sha256(bin_sha256(bin_s))


def bin_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hashlib.new('ripemd160', bin_sha256(s)).digest()


def hex_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hexlify(bin_hash160(s))


def reverse_hash(hash, hex_format=True):
    """ hash is in hex or binary format
    """
    if not hex_format:
        hash = hexlify(hash)
    return "".join(reversed([hash[i:i+2] for i in range(0, len(hash), 2)]))


if __name__ == "__main__":
    hex = "123f0a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b54121976a914816666b318349468f8146e76e4e3751d937c14cb88ac1a1d0864121976a914708ad1a5ed3a8b4966587d59bbcbce6a93d25d6d88ac1a1e08c801121976a9147e2d5d890288663fe6c3447ce3dd265f4ea2f23988ac1a1e08ac02121976a9147ee4ec74695a42bf6e3bb88da2641ccb384f021d88ac1a1e089003121976a914c841d40ededa1aca576b815d08da5b3545abc84288ac1a2408e6f7d9ecb3aacf3a121976a914816666b318349468f8146e76e4e3751d937c14cb88ac"

    # import binascii
    # sig_hash = bin_double_sha256(hex.decode("hex"))
    # print (binascii.hexlify(bytearray(sig_hash)))


