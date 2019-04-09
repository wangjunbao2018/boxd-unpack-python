from hashlib import sha256
from binascii import hexlify, unhexlify
from utilitybelt import is_hex


# Type ignored for `codecs.decode()` due to lack of mypy support for 'hex' encoding
# https://github.com/python/typeshed/issues/300
def hex_to_bytes(value):
    # return codecs.decode(remove_0x_prefix(value), "hex")  # type: ignore
    return bytes.fromhex(value)

def bytes_to_hex(value):
    # binary_hex = codecs.encode(value, "hex")  # type: ignore
    # return add_0x_prefix(binary_hex.decode("ascii"))
    return  ''.join( [ "%02X" % x for x in value ] ).strip()

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
    pass
