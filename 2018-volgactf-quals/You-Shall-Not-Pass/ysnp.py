#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import z3

chars = [z3.Int('c%d' % i) for i in range(50)]

solver = z3.Solver()
for c in chars:
    solver.add(z3.And(c >= 0x0, c <= 0xff))

solver.add(chars[0] == ord('V'))
solver.add(chars[1] == ord('o'))
solver.add(chars[2] == ord('l'))
solver.add(chars[3] == ord('g'))
solver.add(chars[4] == ord('a'))
solver.add(chars[5] == ord('C'))
solver.add(chars[6] == ord('T'))
solver.add(chars[7] == ord('F'))
solver.add(chars[8] == ord('{'))

# a
v5 = chars[30]
solver.add(13 * chars[29] + chars[36] * 132 * chars[0] + 13 * chars[19] + 3 * chars[1] - v5 * 14 * chars[30] +
           chars[34] * 60 * chars[3] - 14 * chars[26] - 8 * chars[28] - chars[28] + 3 * chars[19] + 10 * chars[7] -
           chars[4] + v5 + 8 * chars[42] == 1311351)

# b
solver.add(-11 * chars[43] + chars[20] * 20 * chars[44] + chars[35] * 60 * chars[5] -
           chars[40] * chars[3] * 1008 * chars[1] + 8 * chars[44] - 10 * chars[28] - 7 * chars[35] - 2 * chars[27] -
           4 * chars[17] - chars[17] - 8 * chars[26] - chars[18] - 8 * chars[9] == -1324642844)

# c
solver.add(11 * chars[6] + chars[25] + 7 * (chars[32] + chars[26]) + chars[36] * 180 * chars[33] +
           chars[35] * 99 * chars[9] - 12 * chars[42] - chars[22] * 32 * chars[27] + 10 * chars[15] + 15 * chars[8] +
           8 * chars[4] - 10 * chars[33] + 14 * chars[8] == 910067)

# d
solver.add(15 * chars[0] + 13 * chars[13] + -13 * chars[3] + 3 * chars[15] + 3 * chars[34] + 6 * chars[39] -
           chars[32] * 60 * chars[38] + 15 * chars[33] + chars[6] * 60 * chars[32] - 4 * chars[30] - chars[30] -
           8 * chars[36] - chars[36] - chars[11] + 8 * chars[35] + 7 * chars[0] == -119712)

# e
solver.add(9 * chars[5] + chars[8] + chars[0] + 10 * chars[3] - chars[13] * 84 * chars[2] + chars[27] * 16 * chars[28] +
           12 * chars[28] + 2 * chars[11] - 14 * chars[40] - 12 * chars[32] + 15 * chars[10] - 4 * chars[23] -
           chars[23] - 3 * chars[11] - 5 * chars[5] == -914171)

# f
v5 = chars[33]
solver.add(11 * chars[31] + 13 * chars[18] + chars[18] * 84 * chars[26] - 12 * chars[7] + 14 * chars[42] +
           6 * chars[23] - chars[20] * v5 * 1260 * chars[24] - chars[44] * 98 * chars[17] +
           chars[41] * 270 * chars[43] * v5 + 10 * chars[8] == -701812476)

# g
v5 = chars[36]
v6 = chars[32]
solver.add(-11 * chars[23] + 9 * v5 + -7 * chars[36] + chars[38] * 78 * chars[0] - 8 * chars[40] - chars[40] -
           chars[42] * 10 * chars[34] - 7 * chars[36] + v5 + chars[13] * chars[14] * 560 * chars[34] - v6 + 11 * v6 +
           15 * chars[35] == 805471623)

# h
v6 = chars[112 / 8]
solver.add(chars[44] * 55 * chars[15] + chars[17] * 48 * chars[36] + 2 *
           (chars[19] + 6 * chars[2]) - v6 * 14 * chars[38] + 11 * chars[2] - 12 * chars[6] * v6 + 8 * chars[11] -
           chars[11] + chars[23] * 13 * chars[18] - 10 * chars[4] + 3 * chars[21] == 986086)

# i
v5 = chars[20]
solver.add(13 * v5 + 7 * chars[2] - 14 * chars[42] - 4 * chars[24] + 8 * chars[37] + chars[19] * 78 * chars[36] -
           63 * chars[24] * chars[42] - chars[18] - 2 * v5 - 4 * chars[31] + 4 * chars[15] + 10 * chars[38] + 7 * v5 -
           4 * chars[26] == -471203)

# j
solver.add(chars[43] + chars[27] + 3 * chars[29] + -9 * chars[20] + 4 * chars[15] - chars[25] - chars[41] +
           15 * chars[12] - 6 * chars[13] + 4 * chars[9] - chars[4] * 24 * chars[28] + 130 * chars[4] * chars[41] +
           14 * chars[3] + 8 * chars[0] - chars[0] == 584152)

# k
solver.add(11 * chars[18] - 8 * chars[22] + 4 * chars[17] - 9 * chars[29] + 8 * chars[14] - 8 * chars[1] -
           12 * chars[38] + 2 * chars[26] - 11 * chars[14] + 6 * chars[3] + chars[39] * 3 * chars[35] - 10 * chars[16] +
           22 * chars[21] * chars[29] + 14 * chars[42] == 302239)

# l
solver.add(15 * chars[35] + -13 * chars[14] + -7 * chars[41] + -7 * chars[38] + 9 * chars[3] +
           chars[39] * chars[9] * 360 * chars[16] + 6 * chars[24] - chars[30] + 135 * chars[2] * chars[16] -
           9 * chars[9] + 4 * chars[30] - chars[23] * 112 * chars[10] == 118806054)

# m
solver.add(13 * chars[1] + -3 * chars[25] + chars[28] * 150 * chars[27] + -13 * chars[43] + chars[38] * 12 * chars[0] -
           4 * chars[29] - chars[10] - 2 * chars[42] + 4 * chars[26] - 8 * chars[33] - 10 * chars[12] +
           chars[39] * 18 * chars[24] + 13 * chars[20] == 1675940)

# n
solver.add(chars[18] + 5 * chars[37] + 15 * chars[43] + chars[16] + 11 * chars[13] + chars[6] * 15 * chars[23] -
           6 * chars[20] - chars[8] * 10 * chars[23] + 135 * chars[20] * chars[6] + 10 * chars[19] - 6 * chars[18] +
           14 * chars[2] - 12 * chars[33] == 1333282)

# o
v5 = chars[20]
solver.add(9 * chars[0] + 9 * chars[1] + chars[6] * 156 * chars[24] - 4 * chars[32] - chars[32] + 2 * chars[39] +
           15 * chars[9] + 10 * chars[24] - 4 * chars[19] + 8 * v5 + 4 * v5 - 8 * chars[23] - chars[23] +
           13 * chars[40] - 7 * chars[29] - 3 * chars[36] - 12 * chars[0] == 1457854)

# p
solver.add(13 * chars[5] + 13 * chars[36] + 7 * chars[9] - 15 * chars[30] - 12 * chars[43] + 11 * chars[40] -
           12 * chars[18] + 12 * chars[12] - 11 * chars[18] - chars[4] * 104 * chars[0] - chars[20] * 132 * chars[1] -
           8 * chars[6] + 8 * chars[19] - chars[19] + 5 * chars[14] == -2582478)

# q
v6 = chars[29]
solver.add(9 * chars[40] + 11 * chars[18] + 3 * chars[21] + -13 * chars[1] + chars[31] + chars[30] - 4 * v6 +
           8 * chars[4] - chars[4] - chars[36] * 210 * v6 - 14 * chars[37] - 6 * chars[44] * chars[21] - 2 * chars[39] +
           8 * v6 + 4 * chars[35] == -1562727)

# r
v7 = chars[96 / 8]
v8 = chars[0]
solver.add(
    3 * chars[31] + 6 * chars[19] - chars[7] * 130 * chars[36] + 12 * chars[40] - v7 * 42 * chars[31] + 4 * chars[2] +
    10 * v8 + chars[10] * 99 * chars[28] - chars[34] * 40 * chars[24] - 8 * chars[5] + v7 + 7 * v8 == -1038889)

# s
v6 = chars[1]
solver.add(chars[23] + 5 * chars[41] + 9 * chars[3] + v6 * 15 * chars[41] + 5 * chars[22] - 15 * chars[25] -
           chars[31] * 24 * chars[22] - 4 * chars[12] - chars[16] * 36 * chars[44] - 10 * chars[4] + 9 * chars[8] -
           45 * chars[34] * v6 == -923909)

# t
solver.add(15 * chars[5] + chars[33] * 130 * chars[40] + chars[4] + 2 * chars[10] - chars[35] * 132 * chars[16] +
           chars[14] * 75 * chars[23] - 2 * chars[24] - 6 * chars[32] - 2 * chars[26] + 4 * chars[40] - 11 * chars[15] +
           4 * chars[19] - 8 * chars[5] == 856586)

# u
solver.add(5 * chars[31] + -15 * chars[39] + chars[19] * 90 * chars[18] + chars[27] * 16 * chars[16] -
           chars[44] * chars[41] * 70 * chars[28] + 2 * chars[8] + chars[42] * 35 * chars[38] + 10 * chars[7] +
           2 * chars[12] + 8 * chars[29] + 4 * chars[20] == -53357640)

# v
v5 = chars[21]
solver.add(5 * chars[23] + chars[1] + 4 * (
    2 * chars[29] - chars[18] - v5) + chars[28] * 39 * chars[12] - chars[36] * chars[22] * 30 * v5 + 8 * chars[26] -
           chars[26] + chars[18] + 12 * chars[0] - 10 * chars[17] - 12 * chars[27] * chars[17] == -20510795)

# w
solver.add(3 * chars[41] + 5 * chars[6] + 8 * chars[10] + 10 * chars[8] - chars[41] * 28 * chars[9] - 10 * chars[30] +
           10 * chars[21] + 10 * chars[19] - chars[24] + 5 * chars[8] - 10 * chars[22] - 3 * chars[23] + 4 * chars[32] +
           9 * chars[30] + 11 * chars[28] == -117294)

# x
v6 = chars[13]
solver.add(9 * chars[43] + 15 * chars[29] + chars[1] * 120 * chars[44] + 12 * v6 + 12 * chars[15] + 14 * chars[32] +
           10 * chars[25] + 13 * chars[37] - 4 * chars[22] - chars[22] + 8 * chars[26] - chars[26] - 4 * chars[36] -
           chars[36] - v6 + 7 * v6 - chars[40] * 36 * chars[38] == 1256993)

# y
solver.add(9 * chars[25] + 5 * chars[8] + chars[37] * 28 * chars[23] + 6 * chars[13] - 6 * chars[17] - 3 * chars[26] -
           2 * chars[36] - 6 * chars[4] - 10 * chars[29] - 8 * chars[3] + chars[24] * 99 * chars[9] + 4 * chars[19] +
           chars[11] * 84 * chars[12] == 1373634)

# z
v6 = chars[16]
solver.add(-3 * chars[17] + 9 * chars[24] + 4 * chars[37] + 9 * chars[34] - 4 * chars[34] + 8 * chars[15] +
           chars[7] * 40 * chars[42] + 10 * chars[15] - chars[11] * chars[27] * 360 * v6 + 12 * chars[5] -
           15 * chars[10] * v6 + 13 * chars[1] == -62537013)

# z1
solver.add(-5 * chars[23] + 15 * chars[26] + 8 * chars[25] + 15 * chars[23] - chars[1] * 90 * chars[6] - 6 * chars[32] -
           4 * chars[8] - 13 * chars[32] + chars[26] - chars[14] * 70 * chars[23] - 4 * chars[9] - 8 * chars[19] -
           chars[12] * 78 * chars[33] == -1952483)

# z2
v5 = chars[1]
v6 = chars[38]
solver.add(9 * chars[22] + -7 * chars[27] + 8 * v5 + 4 *
           (3 * chars[9] - 3 * chars[31]) - 6 * chars[10] + 2 * v6 + 8 * chars[41] - chars[41] - 4 * chars[13] -
           chars[13] - 2 * chars[8] - chars[10] * 60 * chars[16] + v5 * 60 * v6 - chars[28] * 7 * v5 == 447630)

# z3
solver.add(13 * chars[7] + -7 * chars[13] + 9 * chars[27] + -2 * chars[35] + 12 * chars[34] - 3 * chars[14] +
           63 * chars[44] * chars[27] - 7 * chars[20] + chars[37] * 70 * chars[42] - chars[32] * 156 * chars[19] -
           2 * chars[12] - 12 * chars[10] == 656269)

# z4
solver.add(11 * chars[9] + chars[1] * 56 * chars[2] - 4 * chars[6] - chars[6] - chars[20] * 77 * chars[14] -
           12 * chars[34] - 11 * chars[38] - 8 * chars[5] - 15 * chars[26] + chars[11] * chars[41] * 72 * chars[29] -
           chars[18] * chars[35] * 528 * chars[32] == -716423735)

# z5
v5 = chars[37]
solver.add(-3 * chars[13] + -13 * chars[38] + 15 * chars[26] + 11 * chars[13] + chars[23] * 110 * chars[8] + 2 *
           (-3 * chars[25] + 5 * chars[27]) + v5 * chars[9] * 550 * chars[34] - 4 * chars[7] - chars[7] -
           chars[31] * 135 * v5 + 12 * chars[11] - 9 * chars[8] == 498719083)

# z6
v5 = chars[26]
solver.add(
    -7 * chars[20] + -3 * chars[43] + chars[29] - 7 * chars[35] + 11 * chars[34] - chars[39] * v5 * 18 * chars[37] -
    4 * chars[0] + 2 * chars[8] - 8 * chars[27] + 8 * chars[15] - chars[15] - v5 * 8 * chars[33] - 13 * v5 == -19729480)

# z7
v5 = chars[17]
solver.add(chars[10] * chars[0] * 182 * chars[24] + chars[32] * 2 * chars[30] - 4 * chars[39] - chars[39] +
           10 * chars[32] + 8 * v5 - 8 * chars[30] + 4 * chars[34] - 12 * chars[29] - chars[12] * 55 * chars[41] +
           chars[8] * chars[4] * 1144 * v5 == 1381453791)

# z8
solver.add(9 * chars[3] + -5 * chars[34] + 6 * chars[44] - 11 * chars[21] - 14 * chars[4] - 8 * chars[5] +
           chars[39] * 1344 * chars[4] * chars[21] + 5 * chars[40] + 15 * chars[1] - chars[27] * 15 * chars[26] -
           10 * chars[13] + 11 * chars[16] + 8 * chars[17] - chars[17] == 1411741755)

# z9
v5 = chars[11]
solver.add(13 * chars[33] + chars[20] + 4 * (chars[6] - chars[20]) + 8 * chars[44] - chars[44] -
           chars[13] * 90 * chars[36] + 6 * chars[20] - 4 * chars[37] - chars[37] + v5 * chars[32] * 20 * chars[7] -
           4 * chars[9] - chars[9] + 2 * chars[29] - 10 * chars[0] + chars[23] * 156 * v5 == 5981100)

# z10
v5 = chars[14]
solver.add(-7 * chars[19] + 7 * v5 + 13 * chars[6] + chars[42] + chars[23] * 4 * chars[17] - 2 * chars[40] -
           13 * chars[17] + 9 * v5 + 14 * chars[1] - chars[5] * 39 * chars[13] + 6 * chars[32] + 4 * chars[29] -
           chars[37] + 14 * chars[24] == -262868)

# z11
v5 = chars[1]
solver.add(chars[10] + chars[9] * 10 * chars[14] + 8 * chars[44] - 3 * chars[13] - chars[7] * 90 * chars[26] -
           6 * chars[27] + 11 * v5 + 6 * chars[27] + 2 * chars[24] + chars[27] - chars[29] - 8 * chars[33] - chars[33] +
           6 * v5 - 13 * chars[11] == -563008)

# z12
v5 = chars[40]
solver.add(-7 * chars[24] + -11 * chars[27] + -11 * chars[9] + chars[12] + chars[38] * 70 * chars[30] - 10 * chars[29] -
           2 * v5 - 6 * chars[28] - chars[43] * 8 * chars[6] + 10 * chars[25] - 2 * chars[12] - chars[3] * chars[43] *
           ((v5 * 2**8) - 32 * chars[40]) == -267345737)  # (v5 << 8) - 32 * chars[40]) == -267345737)

# z13
v6 = chars[232 / 8]
solver.add(-11 * chars[6] + 13 * v6 + 13 * chars[28] + v6 + -7 * chars[20] + 5 * chars[16] + 15 * chars[10] +
           4 * chars[41] + 2 * chars[17] - 15 * chars[18] - 10 * chars[30] - 6 * chars[24] + 13 * chars[0] -
           48 * chars[43] * chars[18] - 2 * chars[7] == -586617)

# z14
v6 = chars[12]
solver.add(2 * v6 + chars[3] * 225 * chars[0] - 12 * chars[36] - 7 * chars[3] - chars[43] * 12 * chars[7] -
           12 * chars[43] - chars[0] - chars[4] * 18 * chars[29] - chars[11] * chars[21] * 75 * chars[2] + 12 * v6 +
           15 * chars[25] == -31526095)

assert solver.check() == z3.sat
model = solver.model()
print ''.join([chr(model[c].as_long()) for c in chars])

# $ ./ysnp.py
# VolgaCTF{D1$guis3_y0ur_code_and_y0u_@re_s@fe}
