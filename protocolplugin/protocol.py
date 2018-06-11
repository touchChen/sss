#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

from shadowsocks.protocolplugin import auth_data


NETWORK_MTU = 1500
TCP_MSS = NETWORK_MTU - 40

class Protocol(object):
    def __init__(self,protocol_name):
        self.protocol_name = protocol_name
    
    def get_protocol(self,protocol_info):
        self.protocol = None
        if self.protocol_name in self.mu_protocol():
            protocol_info['iv'] = protocol_info['recv_iv'] = b'it is using...'
            #protocol_info['recv_iv'] = b''
           
            m = auth_data.protocol_map.get(self.protocol_name)
            self.protocol = m[0](protocol_info)
            
            return self.protocol
        else:
            raise Exception('protocol plugin [%s] not supported' % self.protocol_name)
          
    def mu_protocol(self):
        return ["auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "confusion"]
    
        
    
        
        
        