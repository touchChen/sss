from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import logging
import signal

import inspect

    
file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(file_path, '../../'))

from shadowsocks import common,obfs
from shadowsocks.obfsplugin import auth_data


logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')



_obfs = auth_data.create_auth_data('auth_data')

server_info = _obfs.init_server_info()
 
 
NETWORK_MTU = 1500
TCP_MSS = NETWORK_MTU - 40
 
server_info.users = {}
server_info.protocol_param = b''
server_info.obfs_param = ''
server_info.iv = b''
server_info.recv_iv = b''
server_info.key = b''
server_info.tcp_mss = TCP_MSS
server_info.buffer_size = 1024

_obfs.set_server_info(server_info)
 
 
_ens = []
_en1 = _obfs.client_pre_encrypt("5454451111hello world, ")
_ens.append(_en1)
 
_en2 = _obfs.client_pre_encrypt("  is home,")
_en3 = _obfs.client_pre_encrypt("  worrrr.")
 
_ens.append(_en2)
_ens.append(_en3)
 
_en = b''.join(_ens)
 
_de = _obfs.server_post_decrypt(_en)


 
print(_de)
 
sys.exit()



