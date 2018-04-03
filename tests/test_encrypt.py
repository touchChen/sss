from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import struct
import logging

import inspect
from grp import struct_group

    
file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(file_path, '../../'))

from shadowsocks import encrypt, obfs, eventloop, shell, common, lru_cache, version
from shadowsocks.common import pre_parse_header, parse_header

logging.basicConfig(level=logging.DEBUG)


u16 = b'1234567890abcdef1234567890'
print(u16)



encryptor = encrypt.Encryptor('hello this is key', 'aes-128-cbc', b'\x00' * 16)

en_u16 = encryptor.encrypt(u16)
print(en_u16)

_u16 = en_u16[:16]
print(struct.unpack('16b',_u16))
print(struct.unpack('16b',en_u16[16:]))

#de_u16 = encryptor.decrypt(b'\x00' * 16 + en_u16[16:] + b'\x00')
de_u16 = encryptor.decrypt(en_u16 + b'\x00') 
 

print(de_u16)
