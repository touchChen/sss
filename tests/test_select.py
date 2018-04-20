#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import signal
import select
import time
import argparse
from subprocess import Popen, PIPE

python = ['python']

client_args = python + ['../local.py', '-v']
server_args = python + ['../server.py', '-v']


p1 = Popen(server_args, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
time.sleep(2)
p2 = Popen(client_args, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)


stage = 1

try:
   
    fdset = [p1.stdout, p1.stderr,p2.stdout, p2.stderr]
    while True:
        r, w, e = select.select(fdset, [], fdset)
        if e:
            break

        for fd in r:
            line = fd.readline()
            if not line:
                print('line is empty!')
                break
            if bytes != str:
                line = str(line, 'utf8')
            sys.stderr.write(line)

finally:
    for p in [p1,p2]:
        try:
            os.kill(p.pid, signal.SIGINT)
            os.waitpid(p.pid, 0)
        except OSError:
            pass
