#!/usr/bin/env python3
import z3


def hash1(name):
    h = z3.BitVecVal(4919, 32)
    for i in range(len(name)):
        h = h * name[i] + 1
    return h


solver = z3.Solver()

NAME_LENGTH = 4  # arbitrary
name = [z3.BitVec("c%d" % i, 32) for i in range(NAME_LENGTH)]
for i in range(len(name)):
    solver.add(z3.And(name[i] > 0, name[i] <= 0xff))
# # mov     rdi, rax        ; name
# # call    compute1
# # mov     [rbp+index], eax
h1 = hash1(name)
index = h1

# mov     eax, [rbp+index]
eax = index
# sar     eax, 1Fh
eax >>= 0x1f
# mov     ecx, eax
ecx = eax
# xor     ecx, [rbp+index]
ecx ^= index
# sub     ecx, eax
ecx -= eax
# mov     edx, 2216757315
edx = z3.BitVecVal(2216757315, 32)
# mov     eax, ecx
eax = ecx
# imul    edx
imul = z3.SignExt(64 - eax.size(), eax) * z3.SignExt(64 - edx.size(), edx)
eax = z3.Extract(31, 0, imul)
edx = z3.Extract(63, 32, imul)
# lea     eax, [rdx+rcx]
eax = edx + ecx
# sar     eax, 5
eax >>= 5
# mov     edx, eax
edx = eax
# mov     eax, ecx
eax = ecx
# sar     eax, 1Fh
eax >>= 0x1f
# sub     edx, eax
edx -= eax
# mov     eax, edx
eax = edx
# mov     [rbp+index], eax
index = eax
# mov     eax, [rbp+index]
eax = index
# imul    eax, 62
imul = z3.SignExt(64 - eax.size(), eax) * z3.BitVecVal(62, 64)
eax = z3.Extract(31, 0, imul)
edx = z3.Extract(63, 32, imul)
# sub     ecx, eax
ecx -= eax
# mov     eax, ecx
eax = ecx
# mov     [rbp+index], eax
index = eax

# solver.add(z3.LShR(index, 31) == 1)
solver.add(index <= z3.BitVecVal(-1, 32))

print(solver.check(), solver.model())
print("name:", repr("".join(chr(solver.model()[c].as_long()) for c in name)))
print("h1: %#x" % solver.model().evaluate(h1).as_long())
# sat [c1 = 97, c3 = 145, c0 = 219, c2 = 18]
# name: 'Ûa\x12\x91'
# h1: 0x80000000
