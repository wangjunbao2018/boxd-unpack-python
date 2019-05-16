#!/usr/bin/env python

from boxd_client.protocol.rpc.boxd_client import BoxdClient
boxd = BoxdClient("39.97.169.1", 19111)
addr = "b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"

to = {}
to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 300
to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 400


def get_block_height():
    return boxd.get_block_height()


def get_block_hash(height):
    return boxd.get_block_hash(height)


def get_block_header(hash):
    return boxd.get_block_header(hash)


def get_block(hash):
    return boxd.get_block(hash)


def get_network_id():
    return boxd.get_network_id()


def get_node_info():
    return boxd.get_node_info()


def get_balance(addr):
    return boxd.get_balance(addr)


def fetch_utxo(addr, amount):
    return boxd.fetch_utxos(addr, amount)


def add_node_id(node_id):
    return boxd.add_node(node_id)


if __name__ == "__main__":

    # get_block_height
    height = get_block_height()
    print(height)

    # get_block_hash
    hash = get_block_hash(height)
    print (hash)

    # get_block_header
    header_resp = get_block_header(hash)
    print(header_resp)

    # get_block
    block = get_block(hash)
    print(block)

    # get_network_id
    network_id = get_network_id()
    print (network_id)

    # get_node_info
    node_info = get_node_info()
    print(node_info)

    # get_balance
    balance = get_balance(addr)
    print (balance)

    # fetch_utxo
    utxos = fetch_utxo(addr, 100)
    print (utxos)

    # get_fee_price
    fee_price = boxd.get_fee_price()
    print(fee_price)
