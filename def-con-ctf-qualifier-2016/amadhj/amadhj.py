#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import struct

import z3


def s264(s):
    return struct.unpack('<Q', s)[0]


def to8(i):
    return i & 0xff


def to16(i):
    return i & 0xffff


def to32(i):
    return i & 0xffffffff


################################################################################


def f_a(a1, a2):
    return a1 ^ a2


def f_b(a1, a2, a3):
    return (to8(z3.LShR(a1, 8 * a2)) << 8 * a3) | (
        to8(z3.LShR(a1, 8 * a3)) << 8 * a2) | ~(255 << 8 * a2) & ~(255 << 8 * a3) & a1


def f_c(a1, a2):
    return (a1 << (a2 & 0x3F)) | (z3.LShR(a1, (64 - (a2 & 0x3F))))


def f_d(a1, a2):
    return (a1 << (64 - (a2 & 0x3F))) | z3.LShR(a1, (a2 & 0x3F))


def f_e(a1):
    return (a1 << 56) ^ a1 & 0xFF00000000000000 | z3.LShR((to16(a1) & 0xFF00), 8) ^ to8(a1) | z3.LShR(
        (a1 & 0xFF0000), 8) ^ to16(a1) & 0xFF00 | z3.LShR((to32(a1) & 0xFF000000), 8) ^ a1 & 0xFF0000 | z3.LShR(
            (a1 & 0xFF00000000), 8) ^ to32(a1) & 0xFF000000 | z3.LShR(
                (a1 & 0xFF0000000000), 8) ^ a1 & 0xFF00000000 | z3.LShR(
                    (a1 & 0xFF000000000000), 8) ^ a1 & 0xFF0000000000 | z3.LShR(
                        (a1 & 0xFF00000000000000), 8) ^ a1 & 0xFF000000000000


def f_f(a1):
    return z3.LShR((a1 & 0xFF00000000000000), 8) | z3.LShR((a1 & 0xFF000000000000), 40) | z3.LShR(
        (a1 & 0xFF0000000000), 40) | z3.LShR((a1 & 0xFF00000000), 16) | ((to32(a1) & 0xFF000000) << 16) | (
            (a1 & 0xFF0000) << 40) | ((to16(a1) & 0xFF00) << 24) | (to16(a1) << 24)


def check1(i):
    v1 = f_a(i, 3861390726976975706)
    v2 = f_b(v1, 2, 0)
    v3 = f_a(v2, 0x89FDAF6604952DF1)
    v4 = f_a(v3, 0xE9F30F0CE704876A)
    v5 = f_b(v4, 2, 3)
    v6 = f_a(v5, 0xBDC5026D3C0B56E6)
    v7 = f_c(v6, 16)
    v8 = f_c(v7, 35)
    v9 = f_d(v8, 19)
    v10 = f_e(v9)
    v11 = f_c(v10, 36)
    v12 = f_d(v11, 40)
    v13 = f_b(v12, 1, 0)
    v14 = f_a(v13, 6765015749217278743)
    v15 = f_f(v14)
    v16 = f_f(v15)
    v17 = f_b(v16, 2, 1)
    v18 = f_a(v17, 7686949068708848117)
    v19 = f_b(v18, 3, 0)
    v20 = f_f(v19)
    v21 = f_a(v20, 6401935715922169987)
    v22 = f_d(v21, 22)
    v23 = f_e(v22)
    v24 = f_a(v23, 5166993816397978483)
    v25 = f_e(v24)
    v26 = f_e(v25)
    v27 = f_b(v26, 6, 5)
    v28 = f_c(v27, 59)
    v29 = f_b(v28, 5, 2)
    v30 = f_b(v29, 2, 3)
    v31 = f_c(v30, 12)
    v32 = f_a(v31, 0xAD25307F8E364B17)
    v33 = f_a(v32, 5234710379464860866)
    v34 = f_c(v33, 6)
    v35 = f_b(v34, 6, 5)
    v36 = f_d(v35, 11)
    v37 = f_f(v36)
    v38 = f_a(v37, 0x869365DB4C9F3CB6)
    v39 = f_f(v38)
    v40 = f_d(v39, 2)
    v41 = f_a(v40, 4649309708712362587)
    v42 = f_c(v41, 35)
    v43 = f_c(v42, 9)
    v44 = f_e(v43)
    v45 = f_c(v44, 7)
    v46 = f_c(v45, 38)
    v47 = f_e(v46)
    v48 = f_a(v47, 0xDEF2D72447EF4E1B)
    v49 = f_f(v48)
    v50 = f_f(v49)
    v51 = f_b(v50, 2, 7)
    v52 = f_d(v51, 51)
    v53 = f_f(v52)
    v54 = f_d(v53, 19)
    v55 = f_a(v54, 0x95DE49591A44EE21)
    v56 = f_e(v55)
    v57 = f_f(v56)
    return f_d(v57, 16)


def check2(i):
    v1 = f_c(i, 22)
    v2 = f_f(v1)
    v3 = f_b(v2, 4, 1)
    v4 = f_f(v3)
    v5 = f_e(v4)
    v6 = f_c(v5, 35)
    v7 = f_b(v6, 2, 6)
    v8 = f_a(v7, 0x80A9EA4F90944FEA)
    v9 = f_c(v8, 3)
    v10 = f_b(v9, 0, 1)
    v11 = f_b(v10, 1, 2)
    v12 = f_f(v11)
    v13 = f_e(v12)
    v14 = f_b(v13, 5, 1)
    v15 = f_d(v14, 24)
    v16 = f_c(v15, 39)
    v17 = f_b(v16, 2, 4)
    v18 = f_a(v17, 7462025471038891063)
    v19 = f_b(v18, 4, 3)
    v20 = f_b(v19, 0, 7)
    v21 = f_c(v20, 62)
    v22 = f_f(v21)
    v23 = f_b(v22, 7, 6)
    v24 = f_b(v23, 2, 6)
    v25 = f_f(v24)
    v26 = f_e(v25)
    v27 = f_b(v26, 5, 2)
    v28 = f_e(v27)
    v29 = f_b(v28, 1, 7)
    v30 = f_a(v29, 4749710960471120103)
    v31 = f_f(v30)
    v32 = f_e(v31)
    v33 = f_b(v32, 1, 4)
    v34 = f_c(v33, 10)
    v35 = f_f(v34)
    v36 = f_f(v35)
    v37 = f_d(v36, 24)
    v38 = f_b(v37, 0, 4)
    v39 = f_d(v38, 61)
    v40 = f_b(v39, 3, 4)
    v41 = f_d(v40, 35)
    v42 = f_c(v41, 55)
    v43 = f_c(v42, 34)
    v44 = f_e(v43)
    v45 = f_e(v44)
    v46 = f_d(v45, 23)
    v47 = f_c(v46, 59)
    v48 = f_d(v47, 20)
    v49 = f_c(v48, 28)
    v50 = f_a(v49, 0xC26499379C0927CD)
    v51 = f_e(v50)
    return f_d(v51, 13)


def check3(i):
    v1 = f_c(i, 18)
    v2 = f_c(v1, 29)
    v3 = f_b(v2, 5, 3)
    v4 = f_b(v3, 0, 7)
    v5 = f_c(v4, 18)
    v6 = f_a(v5, 0xC9AB604BB92038AD)
    v7 = f_d(v6, 33)
    v8 = f_b(v7, 0, 4)
    v9 = f_e(v8)
    v10 = f_b(v9, 6, 2)
    v11 = f_d(v10, 13)
    v12 = f_d(v11, 20)
    v13 = f_a(v12, 6368261268581873766)
    v14 = f_e(v13)
    v15 = f_f(v14)
    v16 = f_d(v15, 46)
    v17 = f_b(v16, 2, 3)
    v18 = f_d(v17, 44)
    v19 = f_d(v18, 3)
    v20 = f_b(v19, 4, 3)
    v21 = f_e(v20)
    v22 = f_b(v21, 7, 6)
    v23 = f_d(v22, 59)
    v24 = f_d(v23, 38)
    v25 = f_f(v24)
    v26 = f_b(v25, 1, 5)
    v27 = f_f(v26)
    v28 = f_c(v27, 27)
    v29 = f_a(v28, 0xBED577A97EB7966F)
    v30 = f_d(v29, 14)
    v31 = f_c(v30, 7)
    v32 = f_c(v31, 18)
    v33 = f_c(v32, 57)
    v34 = f_a(v33, 0xB44427BE7889C31B)
    v35 = f_a(v34, 929788566303591270)
    v36 = f_a(v35, 0x94B1608ADB7F7221)
    v37 = f_a(v36, 0x85BEF139817EBC4A)
    v38 = f_b(v37, 5, 1)
    v39 = f_c(v38, 20)
    v40 = f_c(v39, 24)
    v41 = f_d(v40, 46)
    v42 = f_d(v41, 13)
    v43 = f_a(v42, 0xC95E5C35034B9775)
    v44 = f_c(v43, 7)
    v45 = f_a(v44, 641209893495219690)
    v46 = f_a(v45, 6473287570272602621)
    v47 = f_e(v46)
    v48 = f_b(v47, 4, 7)
    v49 = f_e(v48)
    v50 = f_d(v49, 22)
    v51 = f_d(v50, 50)
    return f_e(v51)


def check4(i):
    v1 = f_b(i, 1, 7)
    v2 = f_c(v1, 6)
    v3 = f_b(v2, 2, 5)
    v4 = f_d(v3, 57)
    v5 = f_a(v4, 902179681853661902)
    v6 = f_b(v5, 5, 1)
    v7 = f_c(v6, 1)
    v8 = f_e(v7)
    v9 = f_a(v8, 6764338754798371998)
    v10 = f_e(v9)
    v11 = f_c(v10, 6)
    v12 = f_e(v11)
    v13 = f_c(v12, 33)
    v14 = f_d(v13, 25)
    v15 = f_e(v14)
    v16 = f_a(v15, 762415417889401952)
    v17 = f_b(v16, 6, 2)
    v18 = f_e(v17)
    v19 = f_a(v18, -3724318961155856981)
    v20 = f_a(v19, -8646321147571282756)
    v21 = f_e(v20)
    v22 = f_a(v21, -8802313616937474543)
    v23 = f_d(v22, 8)
    v24 = f_d(v23, 43)
    v25 = f_a(v24, 7150187182015826299)
    v26 = f_b(v25, 3, 1)
    v27 = f_b(v26, 5, 7)
    v28 = f_f(v27)
    v29 = f_e(v28)
    v30 = f_d(v29, 59)
    v31 = f_d(v30, 10)
    v32 = f_e(v31)
    v33 = f_b(v32, 2, 1)
    v34 = f_b(v33, 7, 2)
    v35 = f_e(v34)
    v36 = f_a(v35, 7246290916701591349)
    v37 = f_a(v36, -243320396905423181)
    v38 = f_a(v37, -43605043069428557)
    v39 = f_b(v38, 2, 4)
    v40 = f_b(v39, 5, 4)
    v41 = f_d(v40, 11)
    v42 = f_e(v41)
    v43 = f_c(v42, 39)
    v44 = f_f(v43)
    v45 = f_e(v44)
    v46 = f_a(v45, -4064264580452746468)
    v47 = f_f(v46)
    v48 = f_e(v47)
    v49 = f_c(v48, 35)
    v50 = f_b(v49, 3, 5)
    v51 = f_e(v50)
    v52 = f_f(v51)
    return f_e(v52)


s = z3.Solver()

i1 = z3.BitVec('i1', 64)
i2 = z3.BitVec('i2', 64)
i3 = z3.BitVec('i3', 64)
i4 = z3.BitVec('i4', 64)

for v in [i1, i2, i3, i4]:
    for i in range(8):
        mask = 0xff << (i * 8)
        s.add(z3.Or(v & mask == (32 << (i * 8)), v & mask > (0x40 << (i * 8))))
        s.add(v & mask <= (0x7a << (i * 8)))
        s.add(v & mask != (91 << (i * 8)))
        s.add(v & mask != (92 << (i * 8)))
        s.add(v & mask != (93 << (i * 8)))
        s.add(v & mask != (94 << (i * 8)))
        s.add(v & mask != (96 << (i * 8)))

r1 = check1(i1)
r2 = check2(i2)
r3 = check3(i3)
r4 = check4(i4)
s.add(r1 ^ r2 ^ r3 ^ r4 == 0xB101124831C0110A)

assert s.check() == z3.sat
model = s.model()

print repr(''.join(struct.pack('<Q', model[v].as_long()) for v in [i1, i2, i3, i4]))
# '  V YYVZj iyVFvxPDalGHWT aLw  YT'

# $ nc amadhj_b76a229964d83e06b7978d0237d4d2b0.quals.shallweplayaga.me 4567
#   V YYVZj iyVFvxPDalGHWT aLw  YT
# The flag is: Da robats took err jerbs.
