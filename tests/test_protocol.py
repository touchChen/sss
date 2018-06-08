from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import logging
import signal
import inspect

file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(file_path, '../../'))

from shadowsocks import common
from shadowsocks.protocolplugin import auth_data



logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

 
NETWORK_MTU = 1500
TCP_MSS = NETWORK_MTU - 40
 

server_info = {}
server_info['protocol_param'] = b''
server_info['iv'] = server_info['recv_iv'] = b'2'

server_info['key'] = b'19999'
server_info['tcp_mss'] = TCP_MSS
server_info['buffer_size'] = 1024


_obfs = auth_data.create_auth_aes128_md5(server_info)
_obfs2 = auth_data.create_auth_aes128_md5(server_info)

 
 
_ens = []
_en1 = _obfs.client_pre_encrypt("66666")
_en2 = _obfs.client_pre_encrypt("  is home,")
_en3 = _obfs.client_pre_encrypt("  worrrr.")

_ens.append(_en1)
_ens.append(_en2)
_ens.append(_en3)
  
_en = b''.join(_ens)
_de = _obfs2.server_post_decrypt(_en)

print(_de)
 
_en5 = _obfs.client_pre_encrypt(" 999 ")
_de3 = _obfs2.server_post_decrypt(_en5)
 
 

print(_de3)
 
print()
 
 
c_en = _obfs.server_pre_encrypt("server_encrypt")
c_de = _obfs2.client_post_decrypt(c_en)
  
print(c_de)
