#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import


from boxd_client.protocol.rpc.boxd_client import BoxdClient
from boxd_client.protocol.rpc.boxd_daemon import BoxdDaemon

def block_handler(block):
    print (block)
    print ("\n\n==================================")

boxd_client = BoxdClient("39.105.214.10", 19161)
boxd_daemon = BoxdDaemon(boxd_client)

boxd_daemon.set_block_listener(block_handler)
boxd_daemon.start()