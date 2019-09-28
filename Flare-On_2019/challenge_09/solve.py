"""
I_mUsT_h4vE_leFt_it_iN_mY_OthEr_p4nTs?!@flare-on.com
"""

# red herring solve:
"""
key = map(ord, "ABCDEF01234")

key[0] = ((2 - 0xFFFFFF0A) & 0xFFFFFFFF) / 3
key[1] = 0x31 ^ 0x5e
key[2] = 0x54
#key[3] = 0x31
#key[4] = 0x70
key[3] = ord("3")
key[4] = ord("r")
assert key[4] ^ key[3] == 0x41
key[5] = ord('H')
key[6] = 0x65
key[7] = ~0xAD & 0xFF
key[8] = (0x3 + 0x520800) / 0xc800
key[9] = 0x6e
key[10] = 0x47

print map(hex, key)
print `"".join(map(chr, key))`

def decrypt(key, data):
    flag = ""
    for i in range(len(data)):
        c = data[i] ^ key[i % len(key)]
        flag += chr(c)
    return flag

# RED HERING
data = [28, 92, 34, 0, 0, 23, 2, 98, 7, 0, 6, 13, 8, 117, 69, 23, 23, 60, 61, 28, 49, 50, 2, 47, 18, 114, 57, 13, 35, 30, 40, 41, 105, 49, 0, 57]

flag = decrypt(key, data)
print `flag`
"""
"""
RED HERING:

'RoT3rHeRinG'
'N3v3r_g0nnA_g!ve_You_uP@FAKEFLAG.com'

+---------------------------------------------------+
|                                                   |
|                     ReLoaDerd                     |
|                                                   |
+---------------------------------------------------+


Enter key: RoT3rHeRinG
Here is your prize:

        N3v3r_g0nnA_g!ve_You_uP@FAKEFLAG.com

"""


def decrypt(key, data):
    flag = ""
    for i in range(len(data)):
        c = data[i] ^ key[i % len(key)]
        flag += chr(c)
    return flag

# encrypted flag after xor loop
data = [122, 23, 8, 52, 23, 49, 59, 37, 91, 24, 46, 58, 21, 86, 14, 17, 62, 13, 17, 59, 36, 33, 49, 6, 60, 38, 124, 60, 13, 36, 22, 58, 20, 121, 1, 58, 24, 90, 88, 115, 46, 9, 0, 22, 0, 73, 34, 1, 64, 8, 10, 20]
test = map(ord,"@flare-on.com")

key = map(ord,decrypt(test, data[-len(test):]))
flag = decrypt(key, data)
print flag


"""

need debugging flag off in TEB

some cpu id needs to be 12345678


  i = 0;
  do
  {
    j = 0;
    do
    {
      if ( !(i % 3) || !(i % 7) )
        *(&ENC_FLAG + j) ^= i;
      ++j;
    }
    while ( j < 0x34 );
    ++i;
  }
  while ( i < 0x539 );

after this loop^
    ENC_FLAG = [122, 23, 8, 52, 23, 49, 59, 37, 91, 24, 46, 58, 21, 86, 14, 17, 62, 13, 17, 59, 36, 33, 49, 6, 60, 38, 124, 60, 13, 36, 22, 58, 20, 121, 1, 58, 24, 90, 88, 115, 46, 9, 0, 22, 0, 73, 34, 1, 64, 8, 10, 20]

calculate key and decrypt
"""