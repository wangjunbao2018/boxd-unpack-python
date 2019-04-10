#!/usr/bin/env python3

from __future__ import print_function

import sys

import grpc
# block
import proto.block_pb2 as block
import proto.block_pb2_grpc as block_rpc

# tx
import proto.transaction_pb2 as ptx
import proto.transaction_pb2_grpc as tx_rpc

#channel = grpc.insecure_channel('localhost:19111')
channel = grpc.insecure_channel('39.105.214.10:19161')
#channel = grpc.insecure_channel('39.97.169.1:19111')
stub = tx_rpc.TransactionCommandStub(channel)

def remove_0x_prefix(value):
    if is_0x_prefixed(value):
        return value[2:]
    return value

def is_0x_prefixed(value):
    return value.startswith("0x") or value.startswith("0X")

# Type ignored for `codecs.decode()` due to lack of mypy support for 'hex' encoding
# https://github.com/python/typeshed/issues/300
def hex_to_bytes(value):
    # return codecs.decode(remove_0x_prefix(value), "hex")  # type: ignore
    return bytes.fromhex(value)

def bytes_to_hex(value):
    # binary_hex = codecs.encode(value, "hex")  # type: ignore
    # return add_0x_prefix(binary_hex.decode("ascii"))
    return  ''.join( [ "%02X" % x for x in value ] ).strip()



addr = "b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m"

import base58
def getPkh(addr):
    if len(addr) != 35 or not addr.startswith("b1"):
        return None
    pkh = base58.b58decode_check(addr)
    if len(pkh) != 22:
        return None
    return pkh[2:]



def get_balance():
    addrs = list()
    addrs.append(addr)
    print(" req balance: ")
    response = stub.GetBalance(ptx.GetBalanceReq(addrs=addrs))
    print (" req balance end.")
    if response.code == 0:
        if len(response.balances) == 1:
            return response.balances[0]
    return 0


def send(tx):
    response = stub.SendTransaction(ptx.SendTransactionReq(tx = tx))
    if response.code == 0:
        return response.hash
    else:
        return response.message


def fetch_utxos():
    token_hash = None
    token_index = 0
    _addr = addr
    amount = 1000
    response = stub.FetchUtxos(ptx.FetchUtxosReq(addr = _addr, amount = amount, token_hash = token_hash, token_index = token_index))
    if response.code == 0:
        return response.utxos
    else:
        print("err")
        return None

def create_unsigned_tx(utxos):
    _u_tx = block.Transaction()

    fee = 100

    total_utxo = 0
    for utxo in utxos:
        total_utxo += utxo.tx_out.value
        vin = block.TxIn(prev_out_point = block.OutPoint(hash=utxo.out_point.hash, index = utxo.out_point.index), script_sig = utxo.tx_out.script_pub_key)
        _u_tx.vin.extend([vin])
    
    to = {}
    to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
    to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
    to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 300
    to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 400
    to_value = 0


    from op_code import Opcode
    for k, v in to.items():
        to_value += v
        pkh = getPkh(k)
        ar = []
        for item in pkh:
            ar.append(ord(item))

        oc = Opcode()
        oc.add_opcode(oc.OPDUP)
        oc.add_opcode(oc.OPHASH160)
        oc.add_operand(ar)
        oc.add_opcode(Opcode.OPEQUALVERIFY)
        oc.add_opcode(Opcode.OPCHECKSIG)
        script_pk = oc.get_result()
        oc.reset()
        print ("sig:" + bytes_to_hex(script_pk))
        script_pk_bytes = hex_to_bytes(bytes_to_hex(script_pk))
        #script_pk_bytes = bytes(script_pk)
        vout =  block.TxOut(value = v, script_pub_key = script_pk_bytes) 
        _u_tx.vout.extend([vout])
    if total_utxo - to_value - fee > 0:
        oc = Opcode()
        oc.add_opcode(oc.OPDUP)
        oc.add_opcode(oc.OPHASH160)
        pkh = getPkh(addr)
        ar = []
        for item in pkh:
            ar.append(ord(item))
        oc.add_operand(ar)
        oc.add_opcode(Opcode.OPEQUALVERIFY)
        oc.add_opcode(Opcode.OPCHECKSIG)
        script_pk = oc.get_result()
        oc.reset()
        script_pk_bytes = hex_to_bytes(bytes_to_hex(script_pk))
        vout =  block.TxOut(value = total_utxo - to_value - fee, script_pub_key = script_pk_bytes)
        _u_tx.vout.extend([vout])

    return _u_tx


def format_ret(t):
    ser = t.SerializeToString()
    #ar = []
    #for item in ser:
    #    ar.append(ord(item))
    #return ar
    return ser

def calc_tx_hash_for_sig(script_pub_key, tx, index):
    for i in range(len(tx.vin)):
        if i != index:
            tx.vin[index].script_sig = None
        else:
            tx.vin[index].script_sig = script_pub_key
    return   format_ret(tx)  


from op_code import Opcode
if __name__ == '__main__':
    print ("start..")
    
    # 1. check balance
    balance = get_balance()
    print (balance)
    if balance < 1000:
        sys.exit(0)


    # 2. Get utxos
    utxos = fetch_utxos()
    print (utxos)
    print ("\n\n")


    print ("--------------create----------------")
    # 2. create unsigned tx
    unsigned_tx = create_unsigned_tx(utxos)
    print(unsigned_tx)
    print (bytes_to_hex(unsigned_tx.SerializeToString()))


    # 3. sign
    print ("\n\n-------sign-------")
    for i in range(len(unsigned_tx.vin)):
        vin = unsigned_tx.vin[i]
        script_sig = vin.script_sig
        
        rawMsg = calc_tx_hash_for_sig(script_sig, unsigned_tx, i)
        #rawMsg = hex_to_bytes("123f0a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b54121976a914816666b318349468f8146e76e4e3751d937c14cb88ac1a1d0864121976a914708ad1a5ed3a8b4966587d59bbcbce6a93d25d6d88ac1a1e08c801121976a9147e2d5d890288663fe6c3447ce3dd265f4ea2f23988ac1a1e08ac02121976a9147ee4ec74695a42bf6e3bb88da2641ccb384f021d88ac1a1e089003121976a914c841d40ededa1aca576b815d08da5b3545abc84288ac1a2408e6f7d9ecb3aacf3a121976a914816666b318349468f8146e76e4e3751d937c14cb88ac")

        rrr = []
        for item in rawMsg:
            rrr.append(item)
        print ("raw msg: " + bytes_to_hex(rrr)) 
        # 123f0a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b54121976a914816666b318349468f8146e76e4e3751d937c14cb88ac1a1d0864121976a914708ad1a5ed3a8b4966587d59bbcbce6a93d25d6d88ac1a1e08c801121976a9147e2d5d890288663fe6c3447ce3dd265f4ea2f23988ac1a1e08ac02121976a9147ee4ec74695a42bf6e3bb88da2641ccb384f021d88ac1a1e089003121976a914c841d40ededa1aca576b815d08da5b3545abc84288ac1a2408e6f7d9ecb3aacf3a121976a914816666b318349468f8146e76e4e3751d937c14cb88ac
        # 123f0a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b54121976a914816666b318349468f8146e76e4e3751d937c14cb88ac1a1d0864121976a914708ad1a5ed3a8b4966587d59bbcbce6a93d25d6d88ac1a1e08c801121976a9147e2d5d890288663fe6c3447ce3dd265f4ea2f23988ac1a1e08ac02121976a9147ee4ec74695a42bf6e3bb88da2641ccb384f021d88ac1a1e089003121976a914c841d40ededa1aca576b815d08da5b3545abc84288ac1a2408e6f7d9ecb3aacf3a121976a914816666b318349468f8146e76e4e3751d937c14cb88ac

        # sig hash
        from hash import bin_double_sha256 
        #sigHash = bin_double_sha256(hex_to_bytes(rawMsgHex))
        sigHash = bin_double_sha256(rawMsg)
        print("\n\n sig Hash:" + bytes_to_hex(sigHash))
        # 46f7f67f515e7d053525459991c7a6b3e673950809af776324f46d91df9e600d
        # 46f7f67f515e7d053525459991c7a6b3e673950809af776324f46d91df9e600d

        print("\==============sign================")
        from signutils import sign, get_pub_key
        priv_hex_str = "29fbf01166fc31c941cadc1659a5f684f81c22c1113e5aa5b0af28b7dd453269"
        # sign
        sig_bytes_hex = sign(priv_hex_str, bytes_to_hex(sigHash))
        print ("sign:" + bytes_to_hex(sig_bytes_hex))
        # 30440220216fdf577fc913641453f5460a7cc5dfe36adb974134e64fd3db04d3aaaab49502200c4d7a280aa0b491ffee5323d1dd9aeeeaf8f2fb3917c156d6c91426ca3e2851
        # 30440220216fdf577fc913641453f5460a7cc5dfe36adb974134e64fd3db04d3aaaab49502200c4d7a280aa0b491ffee5323d1dd9aeeeaf8f2fb3917c156d6c91426ca3e2851

        print ("\n============last =============")
        # script sig
        sss = []
        for item in sig_bytes_hex:
            sss.append(ord(item))         

        from op_code import Opcode
        oc = Opcode()
        oc.reset()
        oc.add_operand(sss)
        pk = get_pub_key(priv_hex_str)      
        ppp = []
        for item in pk:
            ppp.append(ord(item))
        oc.add_operand(ppp)
        script_sig_signed = oc.get_result()
        oc.reset()
        print ("script sig:" + bytes_to_hex(script_sig_signed))
        vin.script_sig = hex_to_bytes(bytes_to_hex(script_sig_signed))

    print (unsigned_tx)
    ret = send(unsigned_tx) 
    print ("hash: " + ret)







