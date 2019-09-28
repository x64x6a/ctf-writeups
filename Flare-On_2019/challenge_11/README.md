I feel like I spent way too long on this problem.  My notes here are probably not too helpful.  I might clarify this later.


I re-wrote a majority of the interpreter in `solve.py`, but used `test.py` to actually invert the logic.

I ended up stopping partway through since I could manually guess characters of the key as I had to pick between two characters.  I would pick a character and determine which key resulted in the better result and then move on.

Some of my notes:
```
Using the printed list to brute force w/ attempt() func below

0x0 c   c
0x1 HN  H
0x2 CI  C
0x3 sy  y
0x4 lr  r
0x5 AG  A
0x6 HN  H
0x7 SY  S
0x8 X   X
0x9 gm  m
0xa EK  E
0xb KQ  K
0xc jp  p
0xd sy  y
0xe kq  q
0xf io  o
0x10 CI C
0x11 BH B
0x12 sy y
0x13 GM G
0x14 GM G
0x15 ou u
0x16 bh h
0x17 FL F
0x18 sy y
0x19 CI C
0x1a gm m
0x1b sy y
0x1c 8  8
0x1d 6  6
0x1e EK E
0x1f e  e

solution:  "cHCyrAHSXmEKpyqoCByGGuhFyCmy86Ee"
run with these args
```
