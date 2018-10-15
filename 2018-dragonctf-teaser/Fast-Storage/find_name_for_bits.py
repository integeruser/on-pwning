#!/usr/bin/env python3
import z3


def hash1(name):
    h = z3.BitVecVal(4919, 32)
    for i in range(len(name)):
        h = h * name[i] + 1
    return h


def hash2(name):
    h = z3.BitVecVal(0, 16)
    assert len(name) % 2 == 0  # for simplicity
    for i in range(0, len(name), 2):
        a = z3.BitVecVal(0, 16)
        a |= z3.Extract(15, 0, name[i])
        a |= z3.Extract(15, 0, name[i + 1]) << 8
        h ^= a
    a = z3.LShR(h, 10)
    b = z3.ZeroExt(8, z3.Extract(7, 0, h ^ z3.LShR(h, 5)))
    h = (a ^ b) & 0x1f
    return h


def hash3(name):
    h = z3.BitVecVal(0, 32)
    for i in range(len(name)):
        for j in range(8):
            h = z3.If(z3.LShR(name[i], j) & 1 == 1, (h + 1) & 0xff, h)
        h &= 0x1f
    return h


def find_name_for_bit_at_index(index, bit):
    solver = z3.Solver()

    NAME_LENGTH = 12  # arbitrary
    name = [z3.BitVec("c%d" % i, 32) for i in range(NAME_LENGTH)]
    for i in range(len(name)):
        solver.add(z3.And(name[i] > 0, name[i] <= 0xff))

    h1 = hash1(name)
    solver.add(h1 == index)

    h2 = hash2(name)
    solver.add(h2 == bit)

    h3 = hash3(name)
    solver.add(z3.Extract(15, 0, h3) == h2)  # for simplicity

    if solver.check() == z3.sat:
        return "".join(chr(solver.model()[c].as_long()) for c in name).encode("latin-1")


INT_MIN = 0x80000000
index = INT_MIN
bit = 0  # whatever
print(index, bit, find_name_for_bit_at_index(index, bit))
# 2147483648 0 b'\xb5\xcc\x8c\x05\x04S\x10P$\xca"\t'

index = 60
for bit in range(12, 32):
    print(index, bit, find_name_for_bit_at_index(index, bit))
# 60 12 b'K\x131\tz{\xf2(B\x01-\x7f'
# 60 13 b'.\xd6;wI\xe6\xe1\x10\xc0\xe4\x06\xa5'
# 60 14 b'^\xe0\xc0\xd0 \xc8\xd4\xca\xbf\x0e\xfc\xc7'
# 60 15 b'\x8dg\xcd_\xa0T\xe4P\xa7\x10\xd2\xf9'
# 60 16 b'r\xfd\xdb\xd4\xe0\xe5\xe8\xc9\xa0a\x03\x8d'
# 60 17 b'\xbeO\xf2\xdf\xa48\xf32\xe04\xc8\x03'
# 60 18 b'\x16\xfd\xbe\xb4\x18y\x07\x1c\xfc\xd0,\xc7'
# 60 19 b'\xf6\xec\xf6\xe0\xa8\x80\xc4\xd0\xe9\xba\xce\xed'
# 60 20 b'\xf9\xf6\xdf\x7f-\x18\xf1\x98X\xa0z\x81'
# 60 21 b'\x01\x08\xc0\x01G\x08\x10\xc0\xa0\x01\x08\x8b'
# 60 22 b'~\xee\x97\xf3\xa6z`\xe1\xbb\xa0*\xf1'
# 60 23 b'\x10\x80\x01\x87\t\x9a\x10\x80\x90\x81\x14\x03'
# 60 24 b'\x0c\x08\xc5\x10\x08( \x89CDB\x81'
# 60 25 b'A\x16\xa3"\x04\x84\x80\x01\x16\x84\x06\x05'
# 60 26 b'\x88$\x98\xb0\xc1\nI\x02\x01\x82\x08\x83'
# 60 27 b'@\x04\x030\x05\x80\x18\xaca\xa0\xaa1'
# 60 28 b'\x02\x84\x90\x10\x98\x05\x90\x84\x14\xe0\xc6-'
# 60 29 b'\x8f \x02\x84\x81\xa4\x08"\xe2\x88\x1aQ'
# 60 30 b'\xa4\x12\xac0\x03\x80\xca\x02\r\x84`\x1b'
# 60 31 b'@$ (\xa9(\x80(\xd4,\xb4\x1f'

index = 61
for bit in range(0, 16):
    print(index, bit, find_name_for_bit_at_index(index, bit))
# 61 0 b'\xb0\x9a\xb6\xca \xd1 \x01I\xa0B\x14'
# 61 1 b'\x0b\x820L\x10 3\xa6\x81\xe0;\x91'
# 61 2 b'\x01H\x01$A\xa0G\xc4\xf4\xf8\x90|'
# 61 3 b'\xfe\xdf\xae\x92\x02\x01\x02\x02\x04\x80\xbb\x01'
# 61 4 b"'\x82'\x02\xe2\x83BW\xa4\xa0\x8d\x12"
# 61 5 b'\x9e\x9a\x1f\xa0\x10\xc1\x90\x80\x06\x0e\x8f\xb2'
# 61 6 b'a\x02a\x9cw"1\xc4\x90\xd1\xb2\x8c'
# 61 7 b'\xd1XAT\xd9 \x80(}<\x91v'
# 61 8 b'\xe2\x95\xd7\xfa\xc0\xaex\t\x08\x02Q\x03'
# 61 9 b'\x19\xec\xf2\xc4b\xa6\x027\xbc\x08\x88\\'
# 61 10 b'\xbf`\xeaf\x9c\xd8\x08i\x80\x88S\x1d'
# 61 11 b'\xf66\xdbb\xb1\x80\x10)\xb3\x88Y.'
# 61 12 b'<`Qv\x03\xa5\xef\x9a\x89\xa00\xfc'
# 61 13 b'\xeeP\x8c\x84\xa8\xf9\x98y\x92\xc0\xf3\x8b'
# 61 14 b'P\x98&\xd7\x11\x13\x06\xfd\xa0\x88\xeb\xff'
# 61 15 b'\xe0\x17\xd4\x98\x9f$\x9a\xe81\xb8\xf1>'

index = 60
bit = 5
print(index, bit, find_name_for_bit_at_index(index, bit))
# 60 5 b'\x80Fl\x97\x9c\xd89\x80(Xr\t'

index = 60
bit = 6
print(index, bit, find_name_for_bit_at_index(index, bit))
# 60 6 b'\x1b\x06\x8fM\x10\x0f\xc1\x8d\x12\x80\x1c7'
