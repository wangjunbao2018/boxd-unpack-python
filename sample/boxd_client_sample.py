#!/usr/bin/env python

from boxd_client.protocol.rpc.boxd_client import BoxdClient
from google.protobuf.json_format import MessageToJson

boxd = BoxdClient("39.97.169.1", 19111)


def get_block_height():
    return boxd.get_block_height()

def get_block_hash(height):
    return boxd.get_block_hash(height)

def get_block_header(hash):
    header_resp = boxd.get_block_header(hash)
    return header_resp

def get_block(hash):
    block = boxd.get_block(hash)
    return block

def get_networkid():
    network_id = boxd.get_network_id()
    return network_id

def get_node_info():
    node_info = boxd.get_node_info()
    return node_info


def view_tx_detail(hash):
    tx_detail_resp = boxd.view_tx_detail(hash)
    return tx_detail_resp

def view_block_detail(hash):
    block_detail = boxd.view_block_detail(hash)
    return block_detail


def get_balance(addr):
    return boxd.get_balance(addr)

def fetch_utxos(addr, amount, tokenHash = None, tokenIndex=0):
    utxos = boxd.fetch_utxos(addr, amount, tokenHash, tokenIndex)
    return utxos


def get_fee_price():
    fee_price = boxd.get_fee_price()
    return fee_price


if __name__ == "__main__":

    addr = "b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"

    to = {}
    to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
    to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
    to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 300
    to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 400

    # get_block_height
    print("\n\n=============get_block_height============")
    height = get_block_height()
    print(height)

    # get_block_hash
    print("\n\n=============get_block_hash============")
    block_hash = get_block_hash(height)
    print (block_hash)

    # get_block_header
    print("\n\n=============get_block_header============")
    block_header = get_block_header(block_hash)
    print(block_header)

    # get_block
    print("\n\n=============get_block============")
    block = get_block(block_hash)
    print(block)

    # get_network_id
    print("\n\n=============get_networkid============")
    networkid = get_networkid()
    print(networkid)

    # get_node_info
    print("\n\n=============get_node_info============")
    node_info = get_node_info()
    print(node_info)

    # fetch_utxo
    print("\n\n=============fetch_utxo============")
    utxos = fetch_utxos(addr, 100)
    print (utxos)

    # get_fee_price
    print("\n\n=============get_fee_price============")
    fee_price = get_fee_price()
    print(fee_price)

    # get_balance
    print("\n\n=============get_balance============")
    balances = get_balance([addr])
    print(balances)

    print("\n\n=============view_block_detail============")
    block_detail = view_block_detail(block_hash)
    print (block_detail)

    tx_hash = "62dceb71cf6114af199bb7c7cc04e058104e52d48878511fb08955542cf76e06"
    print("\n\n=============view_tx_hash============")
    tx_detail = view_tx_detail(tx_hash)
    print (tx_detail)


    # more fetch_utxos samples
    token_hash = "afd58e7dc5d21f37bc17d5f5295391b770cd5aaa7467c3443d65c1055cf5aa31"
    token_index = 0
    # fetch_token_utxo
    print("\n\n=============more fetch_token_utxo============")
    utxos = fetch_utxos("b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT", 100, token_hash, token_index)
    print (utxos)


    error_token_hash = "afd58e7dc5d21f37bc17d5f5295391b770cd5aaa7467c3443d65c1055cf5aa32"
    utxos = fetch_utxos(addr, 100, error_token_hash, token_index)
    print (utxos)

    utxos = fetch_utxos(addr, 100)
    print (utxos)

    # more balance samples
    print("\n\n============= more balances============")
    balances = get_balance([addr, "b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT", "b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"])
    print (balances)

    balances = get_balance([addr])
    print (balances)

    balances = get_balance("b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy")
    print (balances)

