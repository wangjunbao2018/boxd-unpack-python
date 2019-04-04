#!/bin/python

from __future__ import print_function

import grpc

import proto.block_pb2 as block

import proto.control_pb2 as control
import proto.control_pb2_grpc as control_rpc

import proto.transaction_pb2 as tx
import proto.transaction_pb2_grpc as tx_rpc

import proto.web_pb2 as web
import proto.web_pb2_grpc as web_rpc

import proto.faucet_pb2 as faucet
import proto.faucet_pb2_grpc as faucet_rpc

from hash import bytes_to_hex
from hash import hex_to_bytes
from pc import get_pub_key_hash
from client import calc_tx_hash_for_sig
from hash import bin_double_sha256
from pc import sign, get_pub_key

class Boxd(object):
    '''
    Boxd client wrapper
    '''

    def __init__(self, host = "localhost", port=19111):
        self.channel = grpc.insecure_channel(":".join([host, str(port)]))
        self.tx_stub = tx_rpc.TransactionCommandStub(self.channel)
        self.control_stub = control_rpc.ContorlCommandStub(self.channel);
        self.web_stub = web_rpc.WebApiStub(self.channel);
        self.faucet_stub = faucet_rpc.FaucetStub(self.channel);


    #################################################################
    ####   control related rpc
    #################################################################
    def get_block(self, hash):
        '''
        Get block info by the block hash

        :param hash:
        :return:
        '''
        return self.control_stub.GetBlock(control.GetBlockRequest(block_hash = hash));

    def get_block_hash(self, height):
        '''
        Get block hash of the block by height

        :param height:
        :return:
        '''
        return self.control_stub.GetBlockHash(control.GetBlockHashRequest(height= height))

    def get_block_height(self):
        '''
        Get the height of the last block

        :return:
        '''
        return self.control_stub.GetBlockHeight(control.GetBlockHeightRequest())

    def get_block_header(self, hash):
        '''
        Get header info of a block by the block hash

        :param hash:
        :return:
        '''
        return self.control_stub.GetBlockHeader(control.GetBlockRequest(block_hash = hash))

    def set_debug_level(self, level):
        '''


        :param level:
        :return:
        '''
        return self.control_stub.SetDebugLevel(control.DebugLevelRequest(level = level))

    def update_network_id(self, id):
        '''
        Update network id

        :param id:
        :return:
        '''
        return self.control_stub.UpdateNetworkID(control.UpdateNetworkIDRequest(id = id))

    def get_network_id(self):
        '''
        Get network id

        :return:
        '''
        return self.control_stub.GetNetworkID(control.GetNetworkIDRequest())

    def add_node(self, node):
        '''
        Sets the debug level of blockchain server, the value of parameter level must be one of the following: \n
        debug|info|warning|error|fatal.

        :param node:
        :return:
        '''
        return self.control_stub.AddNode(control.AddNodeRequest(node = node))

    def get_node_info(self):
        '''
        Get rpc node info

        :return:
        '''
        return self.control_stub.GetNodeInfo(control.GetNodeInfoRequest())

    #################################################################
    ####   faucet related rpc
    #################################################################
    def faucet(self, addr, amount):
        '''
        Get test box coin by this api

        :param addr:
        :param amount:
        :return:
        '''
        return self.faucet_stub.Claim(faucet.ClaimReq(addr = addr, amount = amount))


    #################################################################
    ####   web related rpc
    #################################################################
    def view_tx_detail(self, hash, spread_split = False):
        '''
        Get transaction info by the given transaction hash

        :param hash:
        :param spread_split:
        :return:
        '''
        return self.web_stub.ViewTxDetail(web.ViewTxDetailReq(hash = hash, spread_split = spread_split))

    def view_block_detail(self, hash):
        '''
        Get block info by the given block hash

        :param hash:
        :return:
        '''
        return self.web_stub.ViewBlockDetail(web.ViewBlockDetailReq(hash = hash))

    #################################################################
    ####   tx related rpc
    #################################################################
    def get_balance(self, addrs):
        '''
        Get the balance of the given address

        :param addrs:
        :return:
        '''
        return self.tx_stub.GetBalance(tx.GetBalanceReq(addrs = addrs))

    def get_token_balance(self, addrs, token_hash, token_index):
        '''
        Get the token balance by the given address, tokenHash and tokenIndex

        :param addrs:
        :param token_hash:
        :param token_index:
        :return:
        '''
        return self.tx_stub.GetTokenBalance(tx.GetTokenBalanceReq(addrs = addrs, token_hash = token_hash, token_index = token_index))

    def fetch_utxos(self, addr, amount, token_hash, token_index):
        '''
        Get UTXOs by the given address, tokenHash and tokenIndex

        :param addr:
        :param amount:
        :param token_hash:
        :param token_index:
        :return:
        '''
        return self.tx_stub.FetchUtxos(tx.FetchUtxosReq(addr = addr, amount = amount, token_hash = token_hash, token_index = token_index))

    def send_transaction(self, _tx):
        '''
        Send transaction to the chain, it will come into the memory pool

        :param _tx:
        :return:
        '''
        req = tx.SendTransactionReq(tx = _tx)
        return self.tx_stub.SendTransaction(req)

    def get_raw_transaction(self, hash):
        '''
        et raw transaction info by transaction hash

        :param hash:
        :return:
        '''
        return self.tx_stub.GetRawTransaction(tx.GetRawTransactionRequest(hash = hash))

    def get_fee_price(self):
        '''
        Get fee price on-chain

        :return:
        '''
        return self.tx_stub.GetFeePrice(tx.GetFeePriceRequest())

    def make_unsigned_transaction(self, _from, to, fee):
        '''
        Use rpc api to create unsigned transaction
        :param _from:
        :param to:
        :param fee:
        :return:
        '''
        req = tx.MakeTxReq()
        to_addrs = []
        amounts = []
        for k, v in to.items():
            to_addrs.append(k)
            amounts.append(v)
        req.to.extend(to_addrs)
        req.amounts.extend(amounts)
        setattr(req, 'from', _from)
        setattr(req, 'fee', fee)
        return self.tx_stub.MakeUnsignedTx(req)

    def make_unsigned_splitdddr_transaction(self, _from, split_addr_info, fee):
        '''
        Use rpc api to create unsigned split address transaction

        :param _from:
        :param split_addr_info:
        :param fee:
        :return:
        '''
        req = tx.MakeSplitAddrTxReq()
        setattr(req, 'from', _from)
        setattr(req, 'fee', fee)
        addrs = []
        weights = []
        for k, v  in split_addr_info:
            addrs.append(k)
            weights.append(v)
        req.addrs.extend(addrs)
        req.weights.extend(weights)
        return self.tx_stub.MakeUnsignedSplitAddrTx(req)

    def make_unsigned_token_issue_transaction(self, name, symbol, supply, decimal, issuer, issuee, fee):
        '''
        Use rpc api to create unsigned transaction to issue a token

        :param name:
        :param symbol:
        :param supply:
        :param decimal:
        :param issuer:
        :param issuee:
        :param fee:
        :return:
        '''
        token = tx.TokenTag(name = name, symbol = symbol, supply = supply, decimal = decimal)
        req = tx.MakeTokenIssueTxReq(issuer = issuer, issuee = issuee, tag = token, fee = fee)
        return self.tx_stub.MakeUnsignedTokenIssueTx(req)


    def MakeUnsignedTokenTransferTx(self, _from, to, token_hash, token_index, fee):
        '''
        Use rpc api to create unsigned transaction to transfer a token

        :param _from:
        :param to:
        :param token_hash:
        :param token_index:
        :param fee:
        :return:
        '''
        to_addrs = []
        amounts = []
        for k, v in to.items():
            to_addrs.append(k)
            amounts.append(v)
        req = tx.MakeTokenTransferTxReq()
        setattr(req, 'from', _from)
        setattr(req, 'fee', fee)
        req.to.extend(to_addrs)
        req.amounts.extend(amounts)
        setattr(req, 'token_hash', token_hash)
        setattr(req, 'token_index', token_index)
        return self.tx_stub.MakeUnsignedTokenTransferTx(req)


    #################################################################
    ####   utils related api
    #################################################################
    def create_unsigned_transaction(self, _from, utxos, to, fee):
        '''
        Create unsigned transaction using utxos

        :param _from:
        :param utxos:
        :param to:
        :param fee:
        :return:
        '''
        _u_tx = block.Transaction()

        # init vin
        total_utxo = 0
        for utxo in utxos:
            total_utxo += utxo.tx_out.value
            vin = block.TxIn(prev_out_point = block.OutPoint(hash=utxo.out_point.hash, index = utxo.out_point.index), script_sig = utxo.tx_out.script_pub_key)
            _u_tx.vin.extend([vin])

        # init vout
        to_value = 0
        from opcode import Opcode
        for k, v in to.items():
            to_value += v

            pkh = get_pub_key_hash(k)
            pkbb = [ord(x) for x in pkh]

            oc = Opcode()
            oc.add_opcode(oc.OPDUP)
            oc.add_opcode(oc.OPHASH160)
            oc.add_operand(pkbb)
            oc.add_opcode(Opcode.OPEQUALVERIFY)
            oc.add_opcode(Opcode.OPCHECKSIG)
            script_pk = oc.get_result()
            oc.reset()

            script_pk_bytes = hex_to_bytes(bytes_to_hex(script_pk))
            vout =  block.TxOut(value = v, script_pub_key = script_pk_bytes)
            _u_tx.vout.extend([vout])

        # init charge, if not, all the balance more than amount will be fee
        if total_utxo - to_value - fee > 0:
            oc = Opcode()
            oc.add_opcode(oc.OPDUP)
            oc.add_opcode(oc.OPHASH160)

            pkh = get_pub_key_hash(k)
            pkbb = [ord(x) for x in pkh]

            oc.add_operand(pkbb)
            oc.add_opcode(Opcode.OPEQUALVERIFY)
            oc.add_opcode(Opcode.OPCHECKSIG)
            script_pk = oc.get_result()
            oc.reset()
            script_pk_bytes = hex_to_bytes(bytes_to_hex(script_pk))
            vout =  block.TxOut(value = total_utxo - to_value - fee, script_pub_key = script_pk_bytes)
            _u_tx.vout.extend([vout])

        return _u_tx

    def sign_unsigned_transaction(self, tx, priv_key_hex):
        '''
        Sign the unsigned transaction using private key which is in hex format

        :param tx: unsigned transaction
        :param priv_key_hex:  private key in hex format
        :return:
        '''

        for i in range(len(tx.vin)):
            vin = tx.vin[i]
            script_sig = vin.script_sig

            rawMsg = calc_tx_hash_for_sig(script_sig, tx, i)

            # sig hash
            sigHash = bin_double_sha256(rawMsg)

            # sign
            sig_bytes_hex = sign(priv_key_hex, bytes_to_hex(sigHash))

            sbs = [ord(item) for item in sig_bytes_hex]

            from opcode import Opcode
            oc = Opcode()
            oc.reset()
            oc.add_operand(sbs)
            pk = get_pub_key(priv_key_hex)
            pkbs = [ord(item) for item in pk]
            oc.add_operand(pkbs)
            script_sig_signed = oc.get_result()
            oc.reset()

            vin.script_sig = hex_to_bytes(bytes_to_hex(script_sig_signed))
        return tx


    def create_account(self, path, passphrase):
        pass


    def load_keystore(self, path, passphrase):
        pass


if __name__ == "__main__":


    to = {}
    to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
    to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
    to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 300
    to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 400


    _from = "b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m"
    priv_key_hex = "29fbf01166fc31c941cadc1659a5f684f81c22c1113e5aa5b0af28b7dd453269"
    amount = 1500
    fee = 100

    boxd = Boxd("localhost", 19111)
    utxo_resp = boxd.fetch_utxos(_from, amount, None, 0)
    utxos = utxo_resp.utxos
    if len(utxos) < 1:
        import sys
        print ("bad utxo")
        sys.exit(0)


    unsigned_tx = boxd.create_unsigned_transaction(_from, utxos, to, fee)
    print (type(unsigned_tx))
    print (unsigned_tx)

    signed_tx = boxd.sign_unsigned_transaction(unsigned_tx, priv_key_hex)
    print (signed_tx)
    print (type(signed_tx))

    send_resp = boxd.send_transaction(signed_tx)
    print (send_resp)
    print (send_resp.hash)



