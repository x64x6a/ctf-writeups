"""
L1n34R_4L93bR4_i5_FuN@flare-on.com
"""
import sys
from z3 import *



def calc_b(x):
    b = [0]*16
    b[0] = x[2] ^ x[3] ^ x[4] ^ x[8] ^ x[11] ^ x[14]
    b[1] = x[0] ^ x[1] ^ x[8] ^ x[11] ^ x[13] ^ x[14]
    b[2] = x[0] ^ x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[9] ^ x[10] ^ x[13] ^ x[14] ^ x[15]
    b[3] = x[5] ^ x[6] ^ x[8] ^ x[9] ^ x[10] ^ x[12] ^ x[15]
    b[4] = x[1] ^ x[6] ^ x[7] ^ x[8] ^ x[12] ^ x[13] ^ x[14] ^ x[15]
    b[5] = x[0] ^ x[4] ^ x[7] ^ x[8] ^ x[9] ^ x[10] ^ x[12] ^ x[13] ^ x[14] ^ x[15]
    b[6] = x[1] ^ x[3] ^ x[7] ^ x[9] ^ x[10] ^ x[11] ^ x[12] ^ x[13] ^ x[15]
    b[7] = x[0] ^ x[1] ^ x[2] ^ x[3] ^ x[4] ^ x[8] ^ x[10] ^ x[11] ^ x[14]
    b[8] = x[1] ^ x[2] ^ x[3] ^ x[5] ^ x[9] ^ x[10] ^ x[11] ^ x[12]
    b[9] = x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[11] ^ x[12] ^ x[15]
    b[10] = x[0] ^ x[3] ^ x[4] ^ x[7] ^ x[8] ^ x[10] ^ x[11] ^ x[12] ^ x[13] ^ x[14] ^ x[15]
    b[11] = x[0] ^ x[2] ^ x[4] ^ x[6] ^ x[13]
    b[12] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[10] ^ x[12] ^ x[15]
    b[13] = x[2] ^ x[3] ^ x[4] ^ x[5] ^ x[6] ^ x[7] ^ x[11] ^ x[12] ^ x[13] ^ x[14]
    b[14] = x[1] ^ x[2] ^ x[3] ^ x[5] ^ x[7] ^ x[11] ^ x[13] ^ x[14] ^ x[15]
    b[15] = x[1] ^ x[3] ^ x[5] ^ x[9] ^ x[10] ^ x[11] ^ x[13] ^ x[15]
    return b


h = [115, 29, 32, 68, 106, 108, 89, 76, 21, 71, 78, 51, 75, 1, 55, 102]

x0 = BitVec("x0", 8)
x1 = BitVec("x1", 8)
x2 = BitVec("x2", 8)
x3 = BitVec("x3", 8)
x4 = BitVec("x4", 8)
x5 = BitVec("x5", 8)
x6 = BitVec("x6", 8)
x7 = BitVec("x7", 8)
x8 = BitVec("x8", 8)
x9 = BitVec("x9", 8)
x10 = BitVec("x10", 8)
x11 = BitVec("x11", 8)
x12 = BitVec("x12", 8)
x13 = BitVec("x13", 8)
x14 = BitVec("x14", 8)
x15 = BitVec("x15", 8)


s = Solver()

# restrict to printable characters
s.add(And(x0 >= 0x20, x0 <= 0x7E))
s.add(And(x1 >= 0x20, x1 <= 0x7E))
s.add(And(x2 >= 0x20, x2 <= 0x7E))
s.add(And(x3 >= 0x20, x3 <= 0x7E))
s.add(And(x4 >= 0x20, x4 <= 0x7E))
s.add(And(x5 >= 0x20, x5 <= 0x7E))
s.add(And(x6 >= 0x20, x6 <= 0x7E))
s.add(And(x7 >= 0x20, x7 <= 0x7E))
s.add(And(x8 >= 0x20, x8 <= 0x7E))
s.add(And(x9 >= 0x20, x9 <= 0x7E))
s.add(And(x10 >= 0x20, x10 <= 0x7E))
s.add(And(x11 >= 0x20, x11 <= 0x7E))
s.add(And(x12 >= 0x20, x12 <= 0x7E))
s.add(And(x13 >= 0x20, x13 <= 0x7E))
s.add(And(x14 >= 0x20, x14 <= 0x7E))
s.add(And(x15 >= 0x20, x15 <= 0x7E))

# calculate missile trajectory
s.add(h[0] == x2 ^ x3 ^ x4 ^ x8 ^ x11 ^ x14)
s.add(h[1] == x0 ^ x1 ^ x8 ^ x11 ^ x13 ^ x14)
s.add(h[2] == x0 ^ x1 ^ x2 ^ x4 ^ x5 ^ x8 ^ x9 ^ x10 ^ x13 ^ x14 ^ x15)
s.add(h[3] == x5 ^ x6 ^ x8 ^ x9 ^ x10 ^ x12 ^ x15)
s.add(h[4] == x1 ^ x6 ^ x7 ^ x8 ^ x12 ^ x13 ^ x14 ^ x15)
s.add(h[5] == x0 ^ x4 ^ x7 ^ x8 ^ x9 ^ x10 ^ x12 ^ x13 ^ x14 ^ x15)
s.add(h[6] == x1 ^ x3 ^ x7 ^ x9 ^ x10 ^ x11 ^ x12 ^ x13 ^ x15)
s.add(h[7] == x0 ^ x1 ^ x2 ^ x3 ^ x4 ^ x8 ^ x10 ^ x11 ^ x14)
s.add(h[8] == x1 ^ x2 ^ x3 ^ x5 ^ x9 ^ x10 ^ x11 ^ x12)
s.add(h[9] == x6 ^ x7 ^ x8 ^ x10 ^ x11 ^ x12 ^ x15)
s.add(h[10] == x0 ^ x3 ^ x4 ^ x7 ^ x8 ^ x10 ^ x11 ^ x12 ^ x13 ^ x14 ^ x15)
s.add(h[11] == x0 ^ x2 ^ x4 ^ x6 ^ x13)
s.add(h[12] == x0 ^ x3 ^ x6 ^ x7 ^ x10 ^ x12 ^ x15)
s.add(h[13] == x2 ^ x3 ^ x4 ^ x5 ^ x6 ^ x7 ^ x11 ^ x12 ^ x13 ^ x14)
s.add(h[14] == x1 ^ x2 ^ x3 ^ x5 ^ x7 ^ x11 ^ x13 ^ x14 ^ x15)
s.add(h[15] == x1 ^ x3 ^ x5 ^ x9 ^ x10 ^ x11 ^ x13 ^ x15)

s.check()
model = s.model()

x = 16*[None]
for d in model.decls():
    i = int(d.name()[1:])
    val = model[d]
    x[i] = val.as_long()

launch_code = "".join(map(chr, x))
print("launch_code="+launch_code)
#launch_code=5C0G7TY2LWI2YXMB

"""
- extracted some source code from memory.. saved as wopr.py
- edited the `wrong()` function to load `wopr` into memory manually to get the write values
- calculate list x to get the launch_code ("5C0G7TY2LWI2YXMB")
- run game manually and enter this for flag
"""