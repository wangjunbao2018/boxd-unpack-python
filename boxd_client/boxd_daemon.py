#!/usr/bin/env python3

from __future__ import print_function
from __future__ import absolute_import

import threading
import logging

from .proto import web_pb2 as web

class BoxdDaemon(threading.Thread):

    def __init__(self, box_client, handler):
        '''
        Boxd daemon class to listen and read new blocks

        :param box_client:
        :param handler:
        '''
        self._web_stub = box_client.web_stub
        self._handler = handler
        threading.Thread.__init__(self)

    def run(self):
        self.listen_and_read_new_block(handler=self._handler)


    def listen_and_read_new_block(self, handler):
        blocks = self._web_stub.ListenAndReadNewBlock(web.ListenBlocksReq())
        try:
            for block in blocks:
                handler(block)
        except:
            logging.error("Read new block err")
            pass