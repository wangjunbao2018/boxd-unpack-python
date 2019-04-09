#!/bin/python

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
print (channel)
#channel = grpc.insecure_channel('39.97.169.1:19111')
stub = tx_rpc.TransactionCommandStub(channel)


import binascii
def bytes_to_hex(b):
    return binascii.hexlify(bytearray(b))

def hex_to_bytes(v):
    return  v.decode("hex")






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


def get_unsigned_tx(to):
    to_addrs = []
    amounts = []
    for k, v in to.items():
        to_addrs.append(k)
        amounts.append(v)
    _addr = "b1fc1Vzz73WvBtzNQNbBSrxNCUC1Zrbnq4m"
    m = ptx.MakeTxReq()
    m.to.extend(to_addrs)
    m.amounts.extend(amounts)
    setattr(m, 'from', _addr)
    #setattr(m, 'to', to_addrs)
    #setattr(m, 'amounts', amounts)
    setattr(m, 'fee', 100)
    response = stub.MakeUnsignedTx(m)
    return response


from op_code import Opcode
if __name__ == '__main__':
    
    to = {}
    to["b1Tvej4G8Lma86pgYpWqv4fUFJcEyDdeGst"] = 100
    to["b1USvtdkLrXXtzTfz8R5tpicJYobDbwuqeT"] = 200
    to["b1dSx5FTXEpzB7hWZAydY5N4A5PtFJb57V1"] = 300
    to["b1Vc6vBWzjSp71c3c49hx3pENPL1TwU1Exy"] = 400
    
    mu_tx_resp = get_unsigned_tx(to)
    if mu_tx_resp is not None and mu_tx_resp.code == 0:
        tx = mu_tx_resp.tx
        #tx.vin[0].script_sig = hex_to_bytes("76a914816666b318349468f8146e76e4e3751d937c14cb88ac")
        print (len(mu_tx_resp.rawMsgs))

        print("\n\n================")
        rawMsgs = mu_tx_resp.rawMsgs
        rm = rawMsgs[0]
        print (bytes_to_hex(rm))
        print( bytes_to_hex(tx.SerializeToString()))



        for i in range(len(tx.vin)):
            vin = tx.vin[i]


            print("\n\n========================")
            #raw_msg_bytes = hex_to_bytes("123f0a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b54121976a914816666b318349468f8146e76e4e3751d937c14cb88ac1a1d0864121976a914708ad1a5ed3a8b4966587d59bbcbce6a93d25d6d88ac1a1e08c801121976a9147e2d5d890288663fe6c3447ce3dd265f4ea2f23988ac1a1e08ac02121976a9147ee4ec74695a42bf6e3bb88da2641ccb384f021d88ac1a1e089003121976a914c841d40ededa1aca576b815d08da5b3545abc84288ac1a2408e6f7d9ecb3aacf3a121976a914816666b318349468f8146e76e4e3751d937c14cb88ac")
            raw_msg_bytes = rawMsgs[i]
            print ("raw_msg:  " + bytes_to_hex(raw_msg_bytes))


            priv_hex_str = "29fbf01166fc31c941cadc1659a5f684f81c22c1113e5aa5b0af28b7dd453269"
            from hash import bin_double_sha256
            sig_hash_bytes = bin_double_sha256(raw_msg_bytes)
            #sig_hash_bytes = bin_double_sha256(a_raw_msg_hex.decode("hex"))
            print ("sig hash:" + bytes_to_hex(sig_hash_bytes))
            # 46f7f67f515e7d053525459991c7a6b3e673950809af776324f46d91df9e600d
            # 46f7f67f515e7d053525459991c7a6b3e673950809af776324f46d91df9e600d


            from pc import sign, get_pub_key
            priv_hex_str = "29fbf01166fc31c941cadc1659a5f684f81c22c1113e5aa5b0af28b7dd453269"
            sig_bytes = sign(priv_hex_str, bytes_to_hex(sig_hash_bytes))
            print("sig:  " + bytes_to_hex(sig_bytes))
            sigbs = []
            for item in sig_bytes:
                sigbs.append(ord(item))
            # 30440220216fdf577fc913641453f5460a7cc5dfe36adb974134e64fd3db04d3aaaab49502200c4d7a280aa0b491ffee5323d1dd9aeeeaf8f2fb3917c156d6c91426ca3e2851
            # 30440220216fdf577fc913641453f5460a7cc5dfe36adb974134e64fd3db04d3aaaab49502200c4d7a280aa0b491ffee5323d1dd9aeeeaf8f2fb3917c156d6c91426ca3e2851


            pk_bytes = get_pub_key(priv_hex_str)
            print ("pk_bytes:  " + bytes_to_hex(pk_bytes))
            pkbs = []
            for item in pk_bytes:
                pkbs.append(ord(item))
            print ("pbbs:  " + bytes_to_hex(pkbs))


            from op_code import Opcode
            oc = Opcode()
            oc.add_operand(sigbs)
            oc.add_operand(pkbs)
            addrScripts = oc.get_result()
            oc.reset()
            print ("script_sig:   "  + bytes_to_hex(addrScripts))
            # 4630440220216fdf577fc913641453f5460a7cc5dfe36adb974134e64fd3db04d3aaaab49502200c4d7a280aa0b491ffee5323d1dd9aeeeaf8f2fb3917c156d6c91426ca3e28512103ac5906f34b6f12150d49942dcd3df4b30716cb78abc9e3f6e488e2c1f28ab8bd
            # 4630440220216fdf577fc913641453f5460a7cc5dfe36adb974134e64fd3db04d3aaaab49502200c4d7a280aa0b491ffee5323d1dd9aeeeaf8f2fb3917c156d6c91426ca3e28512103ac5906f34b6f12150d49942dcd3df4b30716cb78abc9e3f6e488e2c1f28ab8bd


            #vin.script_sig = #bytes(addrScripts)
            vin.script_sig = hex_to_bytes(bytes_to_hex(addrScripts))
            #vin.script_sig = addrScripts


        print (tx)
        ret = send(tx)
        print (ret)
        print ("\n\n---------------------------------------------")
        print ( bytes_to_hex(tx.SerializeToString()))




# //1224 0a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b54
#
# 1a1e08c8011219 76a91407056d0500e1c102bdb382c1339ed6f75db5ccc788ac
# 1a1d08641219 76a914014b73fa24ba03acb300c64ed12c0c4ebc06c25288ac1a1e08ac
# 021219 76a91469bf8ba2e9462d830a021a4748abc8c2afaac90288ac
# 1a1e0890031219 76a91413b9aa477777c51603a2d5efb620d49faed1bd5c88ac
# 1a2408b4f7d9ecb3aacf3a1219 76a914816666b318349468f8146e76e4e3751d937c14cb88ac
#
#
#
#
# //123f 0a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b54
# 1219 76a914816666b318349468f8146e76e4e3751d937c14cb88ac
#
# 1a1e08c8011219 76a91407056d0500e1c102bdb382c1339ed6f75db5ccc788ac
# 1a1d08641219 76a914014b73fa24ba03acb300c64ed12c0c4ebc06c25288ac1a1e08ac
# 021219 76a91469bf8ba2e9462d830a021a4748abc8c2afaac90288ac
# 1a1e0890031219 76a91413b9aa477777c51603a2d5efb620d49faed1bd5c88ac
# 1a2408b4f7d9ecb3aacf3a1219 76a914816666b318349468f8146e76e4e3751d937c14cb88ac


#1286040a220a20206029513377e45fed5cf8486b76664864a8138d1cc5248c84202eab2c803b5412df035b37312c2034382c2036392c20322c2033332c20302c203233372c203231372c203130312c203136312c203137392c2035312c2031332c203233312c2038312c203233352c2033382c203134372c203136392c203139352c203130352c2035342c203133302c2038362c203235332c20372c203231382c203134332c203234312c203132362c203131382c203136322c203231372c2039372c203132352c203233302c20302c203130342c20322c2033322c2034372c203230352c2035342c203231392c203232322c203230322c20322c2031372c2034382c203133332c203234342c203230312c203230362c203134372c203137322c2031302c203233332c203231322c203135392c203233392c20362c203132352c2033322c203139392c203233352c203235302c203234302c203137382c203133362c2031392c20352c203231342c2033332c20332c203137322c2038392c20362c203234332c2037352c203131312c2031382c2032312c2031332c2037332c203134382c2034352c203230352c2036312c203234342c203137392c20372c2032322c203230332c203132302c203137312c203230312c203232372c203234362c203232382c203133362c203232362c203139332c203234322c203133382c203138342c203138395d

# 1a1e08c8011219 76a91407056d0500e1c102bdb382c1339ed6f75db5ccc788ac
# 1a1d08641219 76a914014b73fa24ba03acb300c64ed12c0c4ebc06c25288ac1a1e08ac
# 021219 76a91469bf8ba2e9462d830a021a4748abc8c2afaac90288ac
# 1a1e0890031219 76a91413b9aa477777c51603a2d5efb620d49faed1bd5c88ac
# 1a2408b4f7d9ecb3aacf3a1219 76a914816666b318349468f8146e76e4e3751d937c14cb88ac