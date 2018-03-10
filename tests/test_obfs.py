from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import logging
import signal

import inspect
from sympy.logic.algorithms.dpll2 import Level

    
file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(file_path, '../../'))

from shadowsocks import encrypt, obfs, eventloop, shell, common, lru_cache, version
from shadowsocks.common import pre_parse_header, parse_header

logging.basicConfig(level=logging.DEBUG)

_obfs = obfs.obfs("auth_aes128_md5")
#print(_obfs.obfs.max_time_dif)


_data = _obfs.init_data()

server_info = obfs.server_info(_data)


NETWORK_MTU = 1500
TCP_MSS = NETWORK_MTU - 40

# server_info.host = config['server']
# server_info.port = server._listen_port
server_info.users = {}
# server_info.update_user_func = self._update_user
# server_info.client = self._client_address[0]
# server_info.client_port = self._client_address[1]

server_info.protocol_param = b''


server_info.obfs_param = ''
server_info.iv = b''
server_info.recv_iv = b''
# server_info.key_str = common.to_bytes(config['password'])
server_info.key = b''
# server_info.head_len = 30
server_info.tcp_mss = TCP_MSS
server_info.buffer_size = 1024
# server_info.overhead = self._overhead
_obfs.set_server_info(server_info)



_en = _obfs.client_pre_encrypt("012345678")
_de = _obfs.server_post_decrypt(_en)


print(_en)
print(_de)

sys.exit()