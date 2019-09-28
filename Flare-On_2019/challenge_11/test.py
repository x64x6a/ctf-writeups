import struct
import string



DEBUG = False

def p16(s):
    return struct.pack("H", s)
def u16(n):
    return struct.unpack("H", n)[0]
def p32(s):
    return struct.pack("I", s)
def u32(n):
    return struct.unpack("I", n)[0]
def p64(s):
    return struct.pack("Q", s)
def u64(n):
    return struct.unpack("Q", n)[0]
def u256(s):
    res = 0
    for i in range(4):
        res += u64(s[i*8:(i*8)+8]) << (64*i)
    return res

def vpshufb(ymmword, ymm0):
    res = [None]*32
    for i in range(16):
        if ord(ymmword[i]) & 0x80:
            res[i] = "\x00"
        else:
            index = ord(ymmword[i]) & 0xf
            res[i] = ymm0[index]

        if ord(ymmword[16:][i]) & 0x80:
            res[16 + i] = "\x00"
        else:
            index = ord(ymmword[16:][i]) & 0xf
            res[16 + i] = ymm0[16:][index]
    res = ''.join(res)
    return res

def vpmaddubsw(ymmword, ymm0):
    res = ""
    for i in range(16):
        ymmword_0 = ord(ymmword[i*2])
        ymmword_1 = ord(ymmword[i*2 + 1])
        ymm0_0 = ord(ymm0[i*2])
        ymm0_1 = ord(ymm0[i*2 + 1])
        #print "   ",hex(ymmword_0),hex(ymmword_1)
        #print "   ",hex(ymm0_0),hex(ymm0_1)
        #print "     ==> ",hex(((ymmword_1 * ymm0_1) + (ymmword_0 * ymm0_0)) & 0xFFFF)
        res += p16(((ymmword_1 * ymm0_1) + (ymmword_0 * ymm0_0)) & 0xFFFF)
    return res

def vpmaddwd(ymmword, ymm0):
    res = ""
    for i in range(8):
        ymmword_0 = u16(ymmword[i*4:i*4 + 2])
        ymmword_1 = u16(ymmword[i*4 + 2:i*4 + 4])
        ymm0_0 = u16(ymm0[i*4:i*4 + 2])
        ymm0_1 = u16(ymm0[i*4 + 2:i*4 + 4])
        res += p32(((ymmword_1 * ymm0_1) + (ymmword_0 * ymm0_0)) & 0xFFFFFFFF)
    return res

def vpermd(ymmword, ymm0):
    res = ""
    ymmword = u256(ymmword)
    for i in range(8):
        ymm0_0 = (ord(ymm0[i*4]) & 0x7) * 32
        res += p32((ymmword >> ymm0_0) & 0xFFFFFFFF)
    return res


def inverse_vpermd(ymmword, ymm0):
    res = ""
    ymmword = u256(ymmword)
    for i in range(8):
        ymm0_0 = (ord(ymm0[i*4]) & 0x7) * 32
        res += p32((ymmword >> ymm0_0) & 0xFFFFFFFF)
        #res += p32((ymmword >> ymm0_0) & 0xFFFFFFFF)
    return res


def encrypt(s):
    # initial
    arg2_0 = s
    if DEBUG:
        print "arg2_0=", arg2_0.encode("hex")

    # vpsrld
    arg2_1 = ''.join([chr(ord(c) >> 4) for c in arg2_0])
    if DEBUG:
        print "arg2_1=", arg2_1.encode("hex")

    # vpand
    arg2_2 = ''.join([chr(ord(c) & 0x2f) for c in arg2_1])
    if DEBUG:
        print "arg2_2=", arg2_2.encode("hex")

    # vpcmpeqb ? todo
    var_900 = '2f'*32 == arg2_0.encode("hex")
    # vpcmpeqb ? todo
    #var_900 = '2f'*32 == arg2_0.encode("hex")
    var_900 = ["\xff" if c=="\x2f" else "\x00" for c in arg2_0]

    #vpaddb
    #arg2_3 = ''.join([chr(ord(c) + 0x00) for c in arg2_2])
    arg2_3 = ''.join([chr((ord(c) + ord(v))&0xff) for c,v in zip(arg2_2, var_900)])
    if DEBUG:
        print "arg2_3=", arg2_3.encode("hex")

    #vpshufb
    ymm0 = "00101304bfbfb9b9000000000000000000101304bfbfb9b90000000000000000".decode("hex")
    arg2_4 = vpshufb(arg2_3, ymm0)
    if DEBUG:
        print "arg2_4=", arg2_4.encode("hex")
        print "shuff2=", vpshufb(arg2_4, ymm0).encode("hex")

    #vpaddb
    arg2_5 = ''.join([chr((ord(x) + ord(y)) & 0xFF) for x,y in zip(arg2_0, arg2_4)])
    if DEBUG:
        print "arg2_5=", arg2_5.encode("hex")

    #vpmaddubsw
    ymm0 = "4001400140014001400140014001400140014001400140014001400140014001".decode("hex")
    arg2_6 = vpmaddubsw(arg2_5, ymm0)
    if DEBUG:
        print "arg2_6=", arg2_6.encode("hex")

    #vpmaddwd
    ymm0 = "0010010000100100001001000010010000100100001001000010010000100100".decode("hex")
    arg2_7 = vpmaddwd(arg2_6, ymm0)
    if DEBUG:
        print "arg2_7=", arg2_7.encode("hex")

    #vpshufb
    ymm0 = "0201000605040a09080e0d0cffffffff0201000605040a09080e0d0cffffffff".decode("hex")
    arg2_8 = vpshufb(ymm0, arg2_7)
    if DEBUG:
        print "arg2_8=", arg2_8.encode("hex")

    #vpermd
    ymm0 = "000000000100000002000000040000000500000006000000ffffffffffffffff".decode("hex")
    arg2_9 = vpermd(arg2_8, ymm0)
    if DEBUG:
        print "arg2_9=", arg2_9.encode("hex")

    return arg2_9


def decrypt(b):
    s9 = b
    print "s9    =", s9.encode("hex")
    print "       ","d35db7e39ebbf3d00108310518720928b30d38f4114935150000000000000000"
    print "       ","d35db7e39ebbf3d00108310518720928b30d38f4114935150000000000000000"==s9.encode("hex")


    #inverse vpermd
    # doing it manually since ymm0 is static
    s8 = s9[:12] + s9[24:28] + s9[12:24] + s9[28:32]
    print "s8    =", s8.encode("hex")
    print "       ","d35db7e39ebbf3d0010831050000000018720928b30d38f41149351500000000"
    print "       ","d35db7e39ebbf3d0010831050000000018720928b30d38f41149351500000000"==s8.encode("hex")


    #inverse vpshufb
    ymm0 = "0201000605040a09080e0d0c03070b0f0201000605040a09080e0d0c03070b0f".decode("hex")

    res_0 = ["\xff"]*16
    res_1 = ["\xff"]*16
    for i in range(16):
        res_0[ord(ymm0[i])] = s8[i]
    for i in range(16):
        res_1[ord(ymm0[16:][i])] = s8[16:][i]

    s7 = ''.join(res_0) + ''.join(res_1)
    print "s7    =", s7.encode("hex")
    print "       ","b75dd300bb9ee30001d0f30005310800097218000db3280011f4380015354900"
    print "       ","b75dd300bb9ee30001d0f30005310800097218000db3280011f4380015354900"==s7.encode("hex")


    #inverse vpmaddwd
    res = ""
    for i in range(8):
        s = u32(s7[i*4:i*4 + 4])
        n_0 = s >> 0xc
        n_1 = s & 0xFFF
        res += p16(n_0) + p16(n_1)

    s6 = res
    print "s6    =", s6.encode("hex")
    print "       ","350db70d390ebb0e3d0f010083000501870109028b020d038f03110493041505"
    print "       ","350db70d390ebb0e3d0f010083000501870109028b020d038f03110493041505"==s6.encode("hex")


    #inverse vpmaddubsw
    res = ""
    for i in range(16):
        s = u16(s6[i*2:i*2 + 2])
        n_0 = s / 0x40
        n_1 = s % 0x40
        res += chr(n_0) + chr(n_1)
    s5 = res
    print "s5    =", s5.encode("hex")
    print "       ","3435363738393a3b3c3d000102030405060708090a0b0c0d0e0f101112131415"
    print "       ","3435363738393a3b3c3d000102030405060708090a0b0c0d0e0f101112131415"==s5.encode("hex")


    def semi_encrypt_byte(b):
        a0 = b & 0xFF
        a1 = a0 >> 4
        a2 = a1 & 0x2F
        
        v900 = 0xff if a0 == 0x2f else 0x00

        a3 = a2 + v900

        #vpshufb
        ymm0 = "00101304bfbfb9b9000000000000000000101304bfbfb9b90000000000000000".decode("hex")
        arg2_4 = vpshufb(arg2_3, ymm0)
        if DEBUG:
            print "arg2_4=", arg2_4.encode("hex")
            print "shuff2=", vpshufb(arg2_4, ymm0).encode("hex")



    #inverse vpaddb
    alphabet = string.digits + string.uppercase + string.lowercase
    s4_alphabet = "\x04\xbf\xbf\xb9"
    shuffle_key = "00101304bfbfb9b9000000000000000000101304bfbfb9b90000000000000000".decode("hex")
    for i,c in enumerate(s5):
        potential_chars = ""
        for attempt in s4_alphabet:
            r = chr((ord(c) - ord(attempt)) & 0xFF)
            if r in alphabet and r not in potential_chars:
                potential_chars += r
        print hex(i),potential_chars
    """
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
    """

    exit()

    s4 = s5
    print "s4    =", s4.encode("hex")
    print "       ","04040404040404040404bfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbf"
    print "       ","04040404040404040404bfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbf"==s4.encode("hex")

    ##vpaddb
    #arg2_5 = ''.join([chr((ord(x) + ord(y)) & 0xFF) for x,y in zip(arg2_0, arg2_4)])
    #if DEBUG:
    #    print "arg2_5=", arg2_5.encode("hex")

    ##vpshufb
    #ymm0 = "00101304bfbfb9b9000000000000000000101304bfbfb9b90000000000000000".decode("hex")
    #arg2_4 = vpshufb(arg2_3, ymm0)
    #if DEBUG:
    #    print "arg2_4=", arg2_4.encode("hex")


def attempt(s):
    b = encrypt(s)
    encoded = b.encode("hex").upper()
    print `encoded`
    print `"7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"`
"""
exit()
for i,c in enumerate(string.printable):
    print "="*20
    s = "cHA\xffpzGCU2zzzzzzzzzzzzzzzzz\xff" + c + "qEe"
    b = encrypt(s)
    print hex(i),`c`
    encoded = b.encode("hex").upper()
    print `encoded`
    print `"7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"`
"""
def test():
    global DEBUG
    DEBUG = True
    s = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    s = "0123456789ABCDEFGHijklmnopqrstuv"
    s = "\x30\x40\x50\x60\x7056789ABCDEFGHijklmnopqrstuv"
    b = encrypt(s)

    """
    "020100"
    "0605040a09080e0d0cffffffff0201000605040a09080e0d0cffffffff"

    s = "cHA"
    s += " qA00000000000000000000000000"
    b = encrypt(s)

    encoded = b.encode("hex").upper()
    print ' === '
    print "b = ",`encoded`
    print "    ",`"7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"`

    exit()
    """
    print ' === '
    print "b = ",`b.encode("hex").upper()`
    print "    ",`"7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"`
    #assert b.encode("hex").upper() == "D35DB7E39EBBF3D00108310518720928B30D38F4114935150000000000000000"
    #print 'b == "D35DB7E39EBBF3D00108310518720928B30D38F4114935150000000000000000"'
    print ' === '

    b = "7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000".decode("hex")
    print decrypt(b)

b = "7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"
#print decrypt(b)

test()
