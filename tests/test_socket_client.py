#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket

address = ('127.0.0.1',2000)
s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

while True:
    msg = raw_input("dns> ")
    if not msg:
        break
    s.sendto(msg,address)
    
    data, addr = s.recvfrom(1024)
    print 'ip> %s' %data
    
s.close()