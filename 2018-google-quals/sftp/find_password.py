#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import z3

for PASSWORD_LENGTH in range(1, 16):
    solver = z3.Solver()

    password = [z3.BitVec('c{}'.format(i), 64) for i in range(PASSWORD_LENGTH)]
    for i in range(PASSWORD_LENGTH):
        # costraints not really needed, just for finding a password composed of letters
        solver.add(
            z3.Or(
                z3.And(password[i] >= ord('a'), password[i] <= ord('z')),
                z3.And(password[i] >= ord('A'), password[i] <= ord('Z'))))

    checksum = z3.BitVecVal(0x5417, 64)
    rax = 0x0
    for i in range(PASSWORD_LENGTH):
        rax = rax & 0xffffffffffff0000 | password[i]
        rax = rax ^ checksum
        checksum = 2 * rax
    solver.add(checksum & 0xffff == 0x8DFA)

    if solver.check() == z3.sat:
        print 'A valid password is:', ''.join(chr(solver.model()[c].as_long()) for c in password)
        break
# A valid password is: AHIPY
