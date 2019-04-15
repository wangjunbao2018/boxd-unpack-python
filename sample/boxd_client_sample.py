#!/usr/bin/env python

from boxd_client.boxd_client import BoxdClient

if __name__ == "__main__":

    addr = "b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"

    to = {}
    to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
    to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
    to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 300
    to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 400

    boxd = BoxdClient("39.97.169.1", 19111)

    # get_block_height
    height_resp = boxd.get_block_height()
    height = height_resp.height
    print (height)

    # get_block_hash
    hash_resp = boxd.get_block_hash(height)
    hash = hash_resp.hash
    print (hash)

    # get_block_header
    header_resp = boxd.get_block_header(hash)
    print(header_resp)

    # get_block
    block = boxd.get_block(hash)
    print(block)

    # get_network_id
    network_id = boxd.get_network_id()
    print (network_id)

    # get_node_info
    node_info = boxd.get_node_info()
    print(node_info)

    # view_tx_detail
    tx_hash = "6c01338d69cf9ba33ae1ae5efbd1420fee5d3af38d7bf2168bb48d4d416cc4c1"
    tx_detail_resp = boxd.view_tx_detail(hash = tx_hash)
    print (tx_detail_resp)

    # view_block_detail
    block_detail = boxd.view_block_detail(hash)
    print (block_detail)

    # get_balance
    balance = boxd.get_balance([addr])
    print (balance)

    # fetch_utxo
    utxos = boxd.fetch_utxos(addr, 100000000000, None, 0)
    print (utxos)

    # get_fee_price
    fee_price = boxd.get_fee_price()
    print(fee_price)

    # get_raw_transaction
    # raw_tx = boxd.get_raw_transaction(tx_hash)
    # print (raw_tx)

    # faucet
    faucet_resp  =boxd.faucet(addr = addr, amount = 100)
    tx_hash = faucet_resp.hash
    print(faucet_resp)
    print(tx_hash)

    tx_detail_resp = boxd.view_tx_detail(hash = tx_hash)
    print (tx_detail_resp)