"""
NARPAS-SWORD@FLARE-ON.COM
"""



"""
Used Mesen emulator and debugger..


adds +5 to the length for every apple
adds +1 to nummber of apples


0x0B -> length
0x13 -> length?

0x25 -> number of apples
0x27 -> ??? (might need to be 4?)
0x28 -> ??? (x2 each time?)


stores 0xf0 into [0x26] when apples is 0x33 and [0x27] is 0x4

prints the flag when I had [0x25] set to 0x32 and [0x27] set to 0x4.  The next apple ate would print the flag due to [0x26] being set to 0xF0.
NARPAS-SWORD@FLARE-ON.COM
"""