#!/usr/bin/env python3

from __future__ import print_function
from __future__ import absolute_import

import grpc
import json
import os

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
from hash import bin_double_sha256
from signutils import get_pub_key_hash
from signutils import calc_tx_hash_for_sig
from signutils import sign, get_pub_key

from keystore import dumpprivkey as dump_priv_key
from keystore import dumpkeystore as dump_key_store
from keystore import get_addr
from keystore import get_pub_key as kgpk
from keystore import newaccount

from utils import is_list
from utils import is_str
from utils import is_number
from utils import is_addr_valid as utils_is_addr_valid

class BoxdClient(object):
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
        if not is_str(hash):
            raise ValueError("Hash input error")

        return self.control_stub.GetBlock(control.GetBlockRequest(block_hash = hash));

    def get_block_hash(self, height):
        '''
        Get block hash of the block by height

        :param height:
        :return:
        '''
        if not is_number(height):
            raise ValueError("Height input error")

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
        if not is_str(hash):
            raise ValueError("Hash input error")

        return self.control_stub.GetBlockHeader(control.GetBlockRequest(block_hash = hash))

    def set_debug_level(self, level):
        '''
        :param level:  debug|info|warning|error|fatal.
        :return:
        '''
        if level not in ["debug", "info", "warning", "error", "fatal"]:
            raise ValueError("Level input error, level can only be one of [debug|info|warning|error|fatal]")

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
        if not self.is_valid_addr(addr):
            raise ValueError("Not a valid addr")

        if not is_number(amount):
            raise ValueError("Amount must be a number")

        if  amount <= 0:
            raise ValueError("Amount should > 0")

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
        if not is_str(hash):
            raise ValueError("Hash param error")

        return self.web_stub.ViewTxDetail(web.ViewTxDetailReq(hash = hash, spread_split = spread_split))

    def view_block_detail(self, hash):
        '''
        Get block info by the given block hash

        :param hash:
        :return:
        '''
        if not is_str(hash):
            raise ValueError("Hash param error")

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
        if not is_list(addrs):
            raise ValueError("Addrs input is not a list")

        for addr in addrs:
            if not self.is_valid_addr(addr):
                raise ValueError("Not a valid addr")

        return self.tx_stub.GetBalance(tx.GetBalanceReq(addrs = addrs))

    def get_token_balance(self, addrs, token_hash, token_index):
        '''
        Get the token balance by the given address, tokenHash and tokenIndex

        :param addrs:
        :param token_hash:
        :param token_index:
        :return:
        '''
        if not is_list(addrs):
            raise ValueError("Addrs input is not a list")

        for addr in addrs:
            if not self.is_valid_addr(addr):
                raise ValueError("Not a valid addr")

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
        if not self.is_valid_addr(addr):
            raise ValueError("Not a valid addr")

        if not is_number(amount):
            raise ValueError("Amount must be a number")

        if  amount <= 0:
            raise ValueError("Amount should > 0")

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
        if not is_str(hash):
            raise ValueError("Hash param error")

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
        if not self.is_valid_addr(_from):
            raise ValueError("Not a valid addr of from")

        if not self.is_valid_addr(to):
            raise ValueError("Not a valid addr of to")

        if not is_number(fee):
            raise ValueError("fee must be a number")

        if fee < 0 :
            raise ValueError("fee must >= 0")

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
        if not self.is_valid_addr(_from):
            raise ValueError("Not a valid addr of from")

        if not is_number(fee):
            raise ValueError("fee must be a number")

        if fee < 0 :
            raise ValueError("fee must >= 0")

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
        if not self.is_valid_addr(_from):
            raise ValueError("Not a valid addr of from")

        if not self.is_valid_addr(to):
            raise ValueError("Not a valid addr of to")

        if not is_number(fee):
            raise ValueError("fee must be a number")

        if fee < 0 :
            raise ValueError("fee must >= 0")


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
        if not self.is_valid_addr(_from):
            raise ValueError("Not a valid addr of from")

        if not self.is_valid_addr(to):
            raise ValueError("Not a valid addr of to")

        if not is_number(fee):
            raise ValueError("fee must be a number")

        if fee < 0 :
            raise ValueError("fee must >= 0")


        _u_tx = block.Transaction()

        # init vin
        total_utxo = 0
        for utxo in utxos:
            total_utxo += utxo.tx_out.value
            vin = block.TxIn(prev_out_point = block.OutPoint(hash=utxo.out_point.hash, index = utxo.out_point.index), script_sig = utxo.tx_out.script_pub_key)
            _u_tx.vin.extend([vin])

        # init vout
        to_value = 0
        from op_code import Opcode
        for k, v in to.items():
            to_value += v

            pkh = get_pub_key_hash(k)
            #pkbb = [ord(x) for x in pkh]
            print (type(pkh))
            pkbb = [x for x in pkh]

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
            #pkbb = [ord(x) for x in pkh]
            pkbb = [x for x in pkh]

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
        if priv_key_hex is None:
            raise ValueError("Private key input err")

        for i in range(len(tx.vin)):
            vin = tx.vin[i]
            script_sig = vin.script_sig

            rawMsg = calc_tx_hash_for_sig(script_sig, tx, i)

            # sig hash
            sigHash = bin_double_sha256(rawMsg)

            # sign
            sig_bytes_hex = sign(priv_key_hex, bytes_to_hex(sigHash))

            #sbs = [ord(item) for item in sig_bytes_hex]
            sbs = [item for item in sig_bytes_hex]

            from op_code import Opcode
            oc = Opcode()
            oc.reset()
            oc.add_operand(sbs)
            pk = get_pub_key(priv_key_hex)
            #pkbs = [ord(item) for item in pk]
            pkbs = [item for item in pk]
            oc.add_operand(pkbs)
            script_sig_signed = oc.get_result()
            oc.reset()

            vin.script_sig = hex_to_bytes(bytes_to_hex(script_sig_signed))
        return tx


    def newaccount(self, password, path):
        '''
        Create new account

        :param password:
        :param path:
        :return:
        '''

        if path is None:
            raise  ValueError("KeyStore file path input err")

        if os.path.isdir(path):
            raise ValueError("Path can't be dir")

        if os.path.exists(path):
            raise ValueError("Path already exists")

        key_store_json = newaccount(password)
        with open(path, 'w') as outfile:
            json.dump(key_store_json, outfile)
        return True

    def dumpkeystore(self, priv_key, passphrase, path):
        '''
        Save keystore by private key and passphrase

        :param priv_key:
        :param passphrase:
        :param path:
        :return:
        '''
        if priv_key is None:
            raise ValueError("Private key input err")

        if passphrase is None:
            raise  ValueError("Passphrase input err")

        if path is None:
            raise  ValueError("KeyStore file path input err")

        if os.path.isdir(path):
            raise ValueError("Path can't be dir")

        if os.path.exists(path):
            raise ValueError("Path already exists")

        key_store_json = dump_key_store(passphrase, priv_key)
        with open(path, 'w') as outfile:
            json.dump(key_store_json, outfile)
        return True


    def privkey_to_pubkey(self, priv_key):
        '''
        Export public key from private key

        :param priv_key:
        :return:  pubkey array
        '''
        if priv_key is None:
            raise ValueError("Private key input err")

        return kgpk(priv_key)


    def privkey_to_addr(self, priv_key):
        '''
        Export boxd address from private key

        :param priv_key:
        :return:
        '''
        if priv_key is None:
            raise ValueError("Private key input err")

        return get_addr(kgpk(priv_key)).decode()

    def pubkey_to_addr(self, pub_key):
        '''
        Export boxd address from public key

        :param pub_key:
        :return:
        '''
        return get_addr(pub_key).decode()


    def dumpprivkey(self, path, passphrase):
        '''
        Export private key from keystore and passphrase

        :param path:
        :param passphrase:
        :return:
        '''
        if passphrase is None or passphrase == "":
            raise ValueError("Passphrase is empty")

        if path is None:
            raise  ValueError("KeyStore file path input err")

        if os.path.isdir(path):
            raise ValueError("Path can't be dir")

        if not os.path.exists(path):
            raise ValueError("Path doesn't exists")

        def load_keyfile(path_or_file_obj):
            try:
                with open(path_or_file_obj) as keyfile_file:
                    return json.load(keyfile_file)
            except:
                raise IOError("Keystore input error")

        keyfile_json = load_keyfile(path)
        return dump_priv_key(keyfile_json, passphrase)

    def is_valid_addr(self, addr):
        '''
        Check the addr is vaild or not

        :param addr:
        :return:
        '''
        if addr is None:
            raise ValueError("Address is empty")

        return utils_is_addr_valid(addr)