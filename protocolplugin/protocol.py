#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import shadowsocks  
from shadowsocks import encrypt, obfs, eventloop, shell, common, lru_cache
from shadowsocks.common import pre_parse_header, parse_header
    
def create_protocal(config):
    protocol = None
    
    if config['protocol'] != 'confusion':
        protocol = obfs.obfs(config['protocol']).get_obfs()
        
        protocol_data = protocol.init_data()
        
        server_info = obfs.server_info(protocol_data)
        
        server_info.host = config['server']
        server_info.port = server._listen_port
        server_info.users = server.server_users
        server_info.update_user_func = self._update_user
        server_info.client = self._client_address[0]
        server_info.client_port = self._client_address[1]
        server_info.protocol_param = config['protocol_param']
        server_info.obfs_param = ''
        server_info.iv = self._encryptor.cipher_iv
        server_info.recv_iv = b''
        server_info.key_str = common.to_bytes(config['password'])
        server_info.key = self._encryptor.cipher_key
        server_info.head_len = 30
        server_info.tcp_mss = self._tcp_mss
        server_info.buffer_size = self._recv_buffer_size
        server_info.overhead = self._overhead
        self.protocol.set_server_info(server_info)
    else:
        protocol_info = {}
        protocol_info['protocol_param'] = b''
        protocol_info['iv'] = protocol_info['recv_iv'] = b'2'

        protocol_info['key'] = b'19999'
        protocol_info['tcp_mss'] = TCP_MSS
        protocol_info['buffer_size'] = 1024

        from shadowsocks.protocolplugin import auth_data
        protocol = auth_data.create_auth_data(protocol_info)
        
        
        