#!/usr/bin/env python

from __future__ import print_function
from __future__ import absolute_import

from boxd_client.boxd_client import BoxdClient
from boxd_client.boxd_daemon import BoxdDaemon

def block_handler(block):
    #print (block)
    print (block.SerializeToString())

boxd_client = BoxdClient("39.105.214.10", 19161)
boxd_daemon = BoxdDaemon(boxd_client, block_handler)
boxd_daemon.start()