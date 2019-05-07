#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import

import threading
import logging

from boxd_client.protocol.generated import web_pb2 as web
from google.protobuf.json_format import MessageToJson


class BoxdDaemon(threading.Thread):

    def __init__(self, box_client):
        '''
        Boxd daemon class to listen and read new blocks

        :param box_client:
        :param handler:  a function used to handle new blocks, which should accept a block \n

                         e.g. \n\n

                         <code>
                         def block_handler(block):
                            print (block.SerializeToString())
                         </>

        '''
        self._handler = []
        self._web_stub = box_client.web_stub
        threading.Thread.__init__(self)


    def set_block_listener(self, handler):
        self._handler.append(handler)

    def run(self):
        self.listen_and_read_new_block(handlers = self._handler)


    def listen_and_read_new_block(self, handlers):
        '''
        Do listen and read new blocks

        :param handler:  a function used to handle new blocks, which should accept a block \n

                         e.g. \n\n
                         <code>
                         def block_handler(block):
                            print (block.SerializeToString())
                         </>
        :return:
        '''
        blocks = self._web_stub.ListenAndReadNewBlock(web.ListenBlocksReq())
        try:
            for block in blocks:
                j = MessageToJson(block)
                for handler in handlers:
                    handler(j)
        except:
            logging.error("Read new block err")
            pass