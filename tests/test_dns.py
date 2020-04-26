from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import struct
import logging

import inspect

import socket


file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(file_path, '../../'))

print(sys.path)
#sys.exit()

from shadowsocks import eventloop, shell, common, lru_cache, version
from shadowsocks import asyncdns


logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')


def make_callback(sock,addr):
    def callback(result, error):
        sock.sendto(result[1],addr)
        
    a_callback = callback
    return a_callback


class InputDNS(object):
    def __init__(self, dns_resolver):
        self._loop = None
        self._dns_resolver = dns_resolver
        
    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
   
        address = ('0.0.0.0',1985)
        self._sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self._sock.bind(address)
        
        loop.add(self._sock, eventloop.POLL_IN, self)
        
            
    def handle_event(self, sock, fd, event):
        logging.debug('handle_event')
        if sock != self._sock:
            return
        if event & eventloop.POLL_ERR:
            logging.error('dns socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            address = ('0.0.0.0',1985)
            self._sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            self._sock.bind(address)
        
            loop.add(self._sock, eventloop.POLL_IN, self)
            
        elif event & eventloop.POLL_IN:
            data, addr = self._sock.recvfrom(1024)
            logging.debug('received addr:%s' %(addr,))
            logging.debug('received data:%s' %data)
            
            self._dns_resolver.resolve(data, make_callback(self._sock,addr))
        
        else:
            loop.stop()
            

dns_resolver = asyncdns.DNSResolver()
loop = eventloop.EventLoop()
dns_resolver.add_to_loop(loop)

indns = InputDNS(dns_resolver)
indns.add_to_loop(loop)

loop.run()


