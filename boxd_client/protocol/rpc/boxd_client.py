#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import

import sys
import grpc

from google.protobuf.json_format import MessageToJson

from boxd_client.protocol.generated import (
    block_pb2 as block,
    faucet_pb2 as _faucet,
    transaction_pb2 as tx,
    control_pb2 as control,
    web_pb2_grpc as web_rpc,
    control_pb2_grpc as control_rpc,
    transaction_pb2_grpc as tx_rpc,
    faucet_pb2_grpc as faucet_rpc,
    web_pb2 as web
)

from boxd_client.crypto.hash import bin_double_sha256

from boxd_client.crypto.signutils import (
    calc_tx_hash_for_sig,
    sign
)

from boxd_client.crypto.keystore import get_pub_key, get_pub_key_hash

from boxd_client.util.types import (
    is_list,
    is_number,
    is_dict,
    is_str,
    is_bytes
)

from boxd_client.util.address import is_valid_addr
from boxd_client.util.hexadecimal import (
    bytes_to_hex,
    hex_to_bytes
)

from boxd_client.exception.exceptions import (
    ValidationError,
    BoxdError
)


def format_json(j):
    ciphertext = j["crypto"]["ciphertext"]
    if is_bytes(ciphertext):
        j["crypto"]["ciphertext"] = ciphertext.decode()

    iv = j["crypto"]["cipherparams"]["iv"]
    if is_bytes(iv):
        j["crypto"]["cipherparams"]["iv"] = iv.decode()

    salt = j["crypto"]["kdfparams"]["salt"]
    j["crypto"]["kdfparams"]["salt"] = salt.decode()
    return j


class BoxdClient:
    """
    Boxd client wrapper.
    """

    def __init__(self, host = "localhost", port=19111):
        self.channel = grpc.insecure_channel(":".join([host, str(port)]))
        self.tx_stub = tx_rpc.TransactionCommandStub(self.channel)
        self.control_stub = control_rpc.ContorlCommandStub(self.channel)
        self.web_stub = web_rpc.WebApiStub(self.channel)
        self.faucet_stub = faucet_rpc.FaucetStub(self.channel)


    #################################################################
    ####   control related rpc
    #################################################################
    def get_block(self, block_hash):
        '''
        Get block info by the block hash

        :param hash:
        :return:
        '''
        if not is_str(block_hash):
            raise ValidationError("Hash input error")

        resp = self.control_stub.GetBlock(control.GetBlockRequest(block_hash = block_hash))
        if resp.code == 0:
            return MessageToJson(resp.block)
        else:
            raise BoxdError(resp.message)

    def get_block_hash(self, block_height):
        '''
        Get block hash of the block by height

        :param height:
        :return:
        '''
        if not is_number(block_height):
            raise ValidationError("Height input error")

        resp =  self.control_stub.GetBlockHash(control.GetBlockHashRequest(height= block_height))
        if resp.code == 0:
            return resp.hash
        else:
            raise BoxdError(resp.message)

    def get_block_height(self):
        '''
        Get the height of the last block

        :return:
        '''

        resp = self.control_stub.GetBlockHeight(control.GetBlockHeightRequest())
        if resp.code == 0:
            return resp.height
        else:
            raise BoxdError(resp.message)

    def get_block_header(self, hash):
        '''
        Get header info of a block by the block hash

        :param hash:
        :return:
        '''
        if not is_str(hash):
            raise ValidationError("Hash input error")

        resp = self.control_stub.GetBlockHeader(control.GetBlockRequest(block_hash = hash))
        if resp.code == 0:
            return MessageToJson(resp.header)
        else:
            raise BoxdError(resp.message)

    def get_network_id(self):
        '''
        Get network id

        :return:
        '''

        resp = self.control_stub.GetNetworkID(control.GetNetworkIDRequest())
        if resp:
            return MessageToJson(resp)
        else:
            raise BoxdError("Request error")

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

        resp = self.control_stub.GetNodeInfo(control.GetNodeInfoRequest())
        if resp:
            return MessageToJson(resp)
        else:
            raise BoxdError("Request error")

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
        if not is_valid_addr(addr):
            raise ValidationError("Not a valid addr")

        if not is_number(amount):
            raise ValidationError("Amount must be a number")

        if  amount <= 0:
            raise ValidationError("Amount should > 0")

        return self.faucet_stub.Claim(_faucet.ClaimReq(addr = addr, amount = amount))


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
        if not is_str(hash):
            raise ValidationError("Hash param error")

        resp =  self.web_stub.ViewTxDetail(web.ViewTxDetailReq(hash = hash, spread_split = spread_split))
        if resp.code == 0:
            return MessageToJson(resp)
        else:
            raise BoxdError(resp.message)

    def view_block_detail(self, hash):
        '''
        Get block info by the given block hash

        :param hash:
        :return:
        '''
        if not is_str(hash):
            raise ValidationError("Hash param error")

        resp = self.web_stub.ViewBlockDetail(web.ViewBlockDetailReq(hash = hash))
        if resp.code == 0:
            return  MessageToJson(resp.detail)
        else:
            raise BoxdError(resp.message)

    #################################################################
    ####   tx related rpc
    #################################################################
    def get_balance(self, addrs):
        '''
        Get the token balance by the given address, tokenHash and tokenIndex

        :param addrs:
        :param token_hash:
        :param token_index:
        :return:
        '''
        if not is_list(addrs) and not is_str(addrs):
            raise ValidationError("Addrs input is not a list/str")

        if is_str(addrs):
            addrs = [addrs]

        for addr in addrs:
            if not is_valid_addr(addr):
                raise ValidationError("Not a valid addr")

        resp =  self.tx_stub.GetBalance(tx.GetTokenBalanceReq(addrs = addrs))
        if resp.code == 0:
            balances = resp.balances
            if len(addrs) !=  len(balances):
                raise BoxdError("Balances don't match addrs")

            ret = {}
            for i in range(len(addrs)):
                ret[addrs[i]] = balances[i]
            return ret
        else:
            raise BoxdError(resp.message)

    def get_token_balance(self, addrs, token_hash, token_index):
        '''
        Get the token balance by the given address, tokenHash and tokenIndex

        :param addrs:
        :param token_hash:
        :param token_index:
        :return:
        '''
        if not is_list(addrs) and not is_str(addrs):
            raise ValidationError("Addrs input is not a list/str")

        if not token_hash:
            raise ValidationError("TokenHash can't be empty")

        if is_str(addrs):
            addrs = [addrs]

        for addr in addrs:
            if not is_valid_addr(addr):
                raise ValidationError("Not a valid addr")

        resp =  self.tx_stub.GetTokenBalance(tx.GetTokenBalanceReq(addrs = addrs, token_hash= token_hash, token_index = token_index))
        if resp.code == 0:
            balances = resp.balances
            if len(addrs) !=  len(balances):
                raise BoxdError("Balances don't match addrs")

            ret = {}
            for i in range(len(addrs)):
                ret[addrs[i]] = balances[i]
            return ret
        else:
            raise BoxdError(resp.message)

    def fetch_utxos(self, addr, amount, token_hash = None,  token_index = 0):
        '''
        Get UTXOs by the given address, tokenHash and tokenIndex

        :param addr:
        :param amount:
        :param token_hash:
        :param token_index:
        :return:
        '''
        if not is_valid_addr(addr):
            raise ValidationError("Not a valid addr")

        if not is_number(amount):
            raise ValidationError("Amount must be a number")

        if amount <= 0:
            raise ValidationError("Amount should > 0")

        resp = self.tx_stub.FetchUtxos(tx.FetchUtxosReq(addr = addr, amount = amount, token_hash = token_hash, token_index = token_index))
        if resp.code == 0:
            return MessageToJson(resp)
        else:
            raise BoxdError(resp.message)

    def send_transaction(self, transaction):
        '''
        Send transaction to the chain, it will come into the memory pool

        :param _tx:
        :return:
        '''
        req = tx.SendTransactionReq(tx = transaction)
        resp = self.tx_stub.SendTransaction(req)
        if(resp.code == 0):
            return resp.hash
        else:
            raise BoxdError(resp.message)

    def get_raw_transaction(self, hash):
        '''
        et raw transaction info by transaction hash

        :param hash:
        :return:
        '''
        if not is_str(hash):
            raise ValidationError("Hash input error")

        #return self.tx_stub.GetRawTransaction(tx.GetRawTransactionRequest(hash = bytes.fromhex(hash)))
        raise NotImplementedError

    def get_fee_price(self):
        '''
        Get fee price on-chain

        :return:
        '''

        resp = self.tx_stub.GetFeePrice(tx.GetFeePriceRequest())
        if resp:
            return MessageToJson(resp)
        else:
            raise BoxdError("Request error")

    def make_unsigned_tx(self, _from, to, fee):
        '''
        Use rpc api to create unsigned transaction
        :param _from:
        :param to:
        :param fee:
        :return:
        '''
        if not is_valid_addr(_from):
            raise ValidationError("Not a valid addr of from")

        if not is_dict(to):
            raise ValidationError("Not a valid addr of to")

        if not is_number(fee):
            raise ValidationError("fee must be a number")

        if fee < 0 :
            raise ValidationError("fee must >= 0")

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

    def make_unsigned_split_addr_tx(self, _from, split_addr_info, fee):
        '''
        Use rpc api to create unsigned split address transaction

        :param _from:
        :param split_addr_info:
        :param fee:
        :return:
        '''
        if not is_valid_addr(_from):
            raise ValidationError("Not a valid addr of from")

        if not is_dict(split_addr_info):
            raise ValidationError("Split address info input error")

        if not is_number(fee):
            raise ValidationError("fee must be a number")

        if fee < 0 :
            raise ValidationError("fee must >= 0")

        req = tx.MakeSplitAddrTxReq()
        setattr(req, 'from', _from)
        setattr(req, 'fee', fee)
        addrs = []
        weights = []
        for k, v  in split_addr_info.items():
            addrs.append(k)
            weights.append(v)
        req.addrs.extend(addrs)
        req.weights.extend(weights)
        return self.tx_stub.MakeUnsignedSplitAddrTx(req)

    def make_unsigned_token_issue_tx(self, name, symbol, supply, decimal, issuer, owner, fee):
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
        if not is_number(fee):
            raise ValidationError("fee must be a number")

        if fee < 0 :
            raise ValidationError("fee must >= 0")

        token = tx.TokenTag(name = name, symbol = symbol, supply = supply, decimal = decimal)
        req = tx.MakeTokenIssueTxReq(issuer = issuer, owner = owner, tag = token, fee = fee)
        return self.tx_stub.MakeUnsignedTokenIssueTx(req)

    def make_unsigned_token_transfer_tx(self, _from, to, token_hash, token_index, fee):
        '''
        Use rpc api to create unsigned transaction to transfer a token

        :param _from:
        :param to:
        :param token_hash:
        :param token_index:
        :param fee:
        :return:
        '''
        if not is_valid_addr(_from):
            raise ValidationError("Not a valid addr of from")

        if not is_dict(to):
            raise ValidationError("Not a valid addr of to")

        if not is_number(fee):
            raise ValidationError("fee must be a number")

        if fee < 0 :
            raise ValidationError("fee must >= 0")


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
    def create_raw_transaction(self, _from, utxos, to, fee):
        '''
        Create unsigned transaction using utxos

        :param _from:
        :param utxos:
        :param to:
        :param fee:
        :return:
        '''
        if not is_valid_addr(_from):
            raise ValidationError("Not a valid addr of from")

        if not is_dict(to):
            raise ValidationError("Not a valid addr of to")

        if not is_number(fee):
            raise ValidationError("fee must be a number")

        if fee < 0 :
            raise ValidationError("fee must >= 0")


        _u_tx = block.Transaction()

        # init vin
        total_utxo = 0
        for utxo in utxos:
            total_utxo += utxo.tx_out.value
            vin = block.TxIn(prev_out_point = block.OutPoint(hash=utxo.out_point.hash, index = utxo.out_point.index), script_sig = utxo.tx_out.script_pub_key)
            _u_tx.vin.extend([vin])

        # init vout
        to_value = 0
        from boxd_client.protocol.core.script.op_code import Opcode
        for k, v in to.items():
            to_value += v

            pkh = get_pub_key_hash(k)
            if sys.version_info[0] >= 3:
                pkbb = [x for x in pkh]
            else:
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

            if sys.version_info[0] >= 3:
                pkbb = [x for x in pkh]
            else:
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

    def sign_transaction(self, unsigned_tx, priv_key_hex, rawMsgs = None):
        '''
        Sign the unsigned transaction using private key which is in hex format

        :param tx: unsigned transaction
        :param priv_key_hex:  private key in hex format
        :return:
        '''
        if priv_key_hex is None:
            raise ValidationError("Private key input err")

        for i in range(len(unsigned_tx.vin)):
            vin = unsigned_tx.vin[i]
            script_sig = vin.script_sig

            if rawMsgs:
                rawMsg = rawMsgs[i]
            else:
                rawMsg = calc_tx_hash_for_sig(script_sig, unsigned_tx, i)

            # sig hash
            sigHash = bin_double_sha256(rawMsg)

            # sign
            sig_bytes_hex = sign(priv_key_hex, bytes_to_hex(sigHash))

            if sys.version_info[0] >= 3:
                sbs = [item for item in sig_bytes_hex]
            else:
                sbs = [ord(item) for item in sig_bytes_hex]

            from boxd_client.protocol.core.script.op_code import Opcode
            oc = Opcode()
            oc.reset()
            oc.add_operand(sbs)
            pk = get_pub_key(priv_key_hex)
            if sys.version_info[0] >= 3:
                pkbs = [item for item in pk]
            else:
                pkbs = [ord(item) for item in pk]
            oc.add_operand(pkbs)
            script_sig_signed = oc.get_result()
            oc.reset()

            if sys.version_info[0] >= 3:
                vin.script_sig = hex_to_bytes(bytes_to_hex(bytes(script_sig_signed)))
            else:
                vin.script_sig = hex_to_bytes(bytes_to_hex(bytes(script_sig_signed)))
        return unsigned_tx



