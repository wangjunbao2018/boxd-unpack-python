# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import faucet_pb2 as faucet__pb2


class FaucetStub(object):
  """import "google/api/annotations.proto";

  """

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.Claim = channel.unary_unary(
        '/rpcpb.Faucet/Claim',
        request_serializer=faucet__pb2.ClaimReq.SerializeToString,
        response_deserializer=faucet__pb2.ClaimResp.FromString,
        )


class FaucetServicer(object):
  """import "google/api/annotations.proto";

  """

  def Claim(self, request, context):
    """rpc Claim(ClaimReq) returns (ClaimResp) {
    option (google.api.http) = {
    post: "/v1/faucet/claim"
    body: "*"
    };
    }
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_FaucetServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'Claim': grpc.unary_unary_rpc_method_handler(
          servicer.Claim,
          request_deserializer=faucet__pb2.ClaimReq.FromString,
          response_serializer=faucet__pb2.ClaimResp.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'rpcpb.Faucet', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))
