from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import struct
import logging

import inspect

    
file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(file_path, '../../'))

from shadowsocks import eventloop, shell, common, lru_cache, version
from shadowsocks import asyncdns

logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')


dns_resolver = asyncdns.DNSResolver()
loop = eventloop.EventLoop()
dns_resolver.add_to_loop(loop)

global counter
counter = 0

def make_callback():
    global counter
 
    def callback(result, error):
        global counter
        # TODO: what can we assert?
        print(result, error)
        counter += 1
        if counter == 9:
            dns_resolver.close()
            loop.stop()
            
    a_callback = callback
    return a_callback
 
assert(make_callback() != make_callback())
 
loop.run()
print('hello world')
dns_resolver.resolve(b'www.jxqx.net', make_callback())
