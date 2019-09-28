"""
AVX2_VM_M4K3S_BASE64_C0MPL1C4T3D@flare-on.com
"""
import struct
import sys


func_to_args = {
    0x00: [],
    0x11: [1, 32],
    0x15: [1, 1, 1],
}
def print_vv_elements():
    index = 0
    while index < len(MEMORY):
        func_id = ord(MEMORY[index])
        if func_id not in func_to_args:
            print hex(func_id),
            print "Quiting..."
            return
        index += 1

        print hex(func_id),
        for arg_length in func_to_args[func_id]:
            if arg_length == 1:
                print hex(ord(MEMORY[index])),
                index += 1
            else:
                print `MEMORY[index:index + arg_length]`,
                index += arg_length
        print


def p8(s):
    return struct.pack("B", s)
def u8(n):
    return struct.unpack("B", n)[0]
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

TAINTED_MEMORY = [0x25, 0x820, 0x8e0, 0x840, 0x900]
PRINT = False
def read_memory(offset, length=1):
    global MEMORY
    global PRINT
    if offset in TAINTED_MEMORY:
        PRINT = True
    data = "".join(MEMORY[offset: offset + length])
    if PRINT and p_flag:
        print "==================================================== READ  MEMORY[{}] {} ->".format(hex(offset), hex(length)), data.encode("hex"), `data[:10]`
    elif p_flag:
        print "read->",hex(length), data.encode("hex"), `data[:10]`
    return data

def write_memory(offset, s):
    global MEMORY
    global PRINT
    for i in range(len(s)):
        MEMORY[offset + i] = s[i]
    if PRINT and p_flag:
        print "            WRITE MEMORY[{}] <-".format(hex(offset)), s.encode("hex"), `s[:10]`
    if offset not in TAINTED_MEMORY:
        PRINT = False
    return


def fun_(a, b, c):
    """
    """
    a,b,c = map(ord, (a, b, c))
    return


def fun_00():
    return

def fun_01(a, b, c):
    """
    vpmaddubsw ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    res = ""
    for i in range(16):
        ymmword_0 = u8(read_memory(0x800 + (c*0x20) + (i*2), 1))
        ymm0_0 = u8(read_memory(0x800 + (b*0x20) + (i*2), 1))
        ymmword_1 = u8(read_memory(0x800 + (c*0x20) + (i*2) + 1, 1))
        ymm0_1 = u8(read_memory(0x800 + (b*0x20) + (i*2) + 1, 1))

        res += p16(((ymmword_1 * ymm0_1) + (ymmword_0 * ymm0_0)) & 0xFFFF)
    write_memory(0x800 + (a*0x20), res)
    return

def fun_02(a, b, c):
    """
    vpmaddwd ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    res = ""
    for i in range(8):
        ymmword_0 = u16(read_memory(0x800 + (c*0x20) + (i*4), 2))
        ymm0_0 = u16(read_memory(0x800 + (b*0x20) + (i*4), 2))
        ymmword_1 = u16(read_memory(0x800 + (c*0x20) + (i*4) + 2, 2))
        ymm0_1 = u16(read_memory(0x800 + (b*0x20) + (i*4) + 2, 2))

        res += p32(((ymmword_1 * ymm0_1) + (ymmword_0 * ymm0_0)) & 0xFFFFFFFF)
    write_memory(0x800 + (a*0x20), res)
    return

def fun_03(a, b, c):
    """
    vmovdqu ymm0, ymmword ptr [rdx+rcx+800h]
    vpxor   ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    ymmword = read_memory(0x800 + (c*0x20), 32)
    ymm0 = read_memory(0x800 + (b*0x20), 32)
    res = ""
    for i,j in zip(ymm0, ymmword):
        res += chr(ord(i) ^ ord(j))
    write_memory(0x800 + (a*0x20), res)
    #print "        ","ymmword:",`ymmword`
    #print "        ","ymm0:",`ymm0`
    #print "        ","res:",`res`
    return

def fun_04(a, b, c):
    """
    vmovdqu ymm0, ymmword ptr [rdx+rcx+800h]
    vpor   ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    ymmword = read_memory(0x800 + (c*0x20), 32)
    ymm0 = read_memory(0x800 + (b*0x20), 32)
    res = ""
    for i,j in zip(ymm0, ymmword):
        res += chr(ord(i) | ord(j))
    write_memory(0x800 + (a*0x20), res)
    return

def fun_05(a, b, c):
    """
    """
    a,b,c = map(ord, (a, b, c))

    ymmword = read_memory(0x800 + (c*0x20), 32)
    ymm0 = read_memory(0x800 + (b*0x20), 32)
    res = ""
    for i,j in zip(ymm0, ymmword):
        res += chr(ord(i) & ord(j))
    write_memory(0x800 + (a*0x20), res)
    return

def fun_07(a, b, c):
    """
    vpaddb  ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    ymmword = read_memory(0x800 + (c*0x20), 32)
    ymm0 = read_memory(0x800 + (b*0x20), 32)
    res = ""
    for i,j in zip(ymm0, ymmword):
        res += chr((ord(i) + ord(j)) & 0xFF)
    write_memory(0x800 + (a*0x20), res)
    return

def fun_0b(a, b, c):
    """
    vpaddd  ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    res = ""
    word_out = ""
    for i in range(8):
        ymmword = u32(read_memory(0x800 + (c*0x20) + (i*4), 4))
        ymm0 = u32(read_memory(0x800 + (b*0x20) + (i*4), 4))
        res = p32((ymmword + ymm0) & 0xFFFFFFFF)
        word_out += res.encode("hex")
        #typo write_memory(0x800 + (c*0x20), res)
        write_memory(0x800 + (a*0x20) + (i*4), res)
    return

def fun_11(a, b):
    """
    loads 32byte string
    """
    a = ord(a)
    write_memory(0x800 + (a*0x20), b)
    return

def fun_12(a, b, c):
    """
    vpsrld  ymm0, ymm1, xmm0

    ymm0 <- ymm1 >> xmm0
    """
    a = ord(a)
    b = ord(b)
    c = ord(c)

    #ymm1 = read_memory(0x800 + b*0x20, 32)
    xmm0 = c
    for i in range(8):
        ymm1_dword = u32(read_memory((0x800 + b*0x20) + (i*4), 4))
        #ymm1_dword = u32(ymm1[i*4:(i*4) + 4])
        res = p32(ymm1_dword >> xmm0)
        write_memory((0x800 + (a*0x20)) + (i*4), res)
    return

def fun_13(a, b, c):
    """
    vmovdqu ymm1, ymmword ptr [rax+rcx+800h]
    vpslld  ymm0, ymm1, xmm0
    """
    a,b,c = map(ord, (a, b, c))

    xmm0 = c
    for i in range(8):
        ymm1_dword = u32(read_memory((0x800 + b*0x20) + (i*4), 4))
        res = p32((ymm1_dword << xmm0) & 0xFFFFFFFF)
        write_memory((0x800 + (a*0x20)) + (i*4), res)
    return

def fun_14(a, b, c):
    """
    vpshufb ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    ymmword = read_memory(0x800 +(c*0x20), 32)
    ymm0 = read_memory(0x800 + (b*0x20), 32)
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
    write_memory(0x800 + (a*0x20), res)
    return

def fun_15(a, b, c):
    """
    basically just performs vpermd instruction
    """
    a,b,c = map(ord, (a, b, c))

    ymmword = u256(read_memory(0x800 + (b*0x20), 32))
    res = ""
    for i in range(8):
        ymm0 = (u8(read_memory(0x800 + (c*0x20) + (i*4), 1)) & 0x7) * 32
        res += p32((ymmword >> ymm0) & 0xFFFFFFFF)
    write_memory(0x800 + (a*0x20), res)
    return

def fun_16(a, b, c):
    """
    vmovdqu ymm0, ymmword ptr [rdx+rcx+800h]
    vpcmpeqb ymm0, ymm0, ymmword ptr [r8+rax+800h]
    """
    a,b,c = map(ord, (a, b, c))

    ymmword = read_memory(0x800 + (c*0x20), 32)
    ymm0 = read_memory(0x800 + (b*0x20), 32)
    if ymmword == ymm0:
        res = '\xff'*32
    else:
        res = '\x00'*32
    write_memory(0x800 + (a*0x20), res)
    return

def func_default(dummmy=1):
    return

id_to_func = {
    0x00: (fun_00, []),
    0x01: (fun_01, [1, 1, 1]),  # vpmaddubsw
    0x02: (fun_02, [1, 1, 1]),  # vpmaddwd
    0x03: (fun_03, [1, 1, 1]),  # vpxor
    0x04: (fun_04, [1, 1, 1]),  # vpor
    0x05: (fun_05, [1, 1, 1]),  # vpand
    0x07: (fun_07, [1, 1, 1]),  # vpaddb
    0x0b: (fun_0b, [1, 1, 1]),  # vpaddd
    0x11: (fun_11, [1, 32]),
    0x12: (fun_12, [1, 1, 1]),  # vpsrld
    0x13: (fun_13, [1, 1, 1]),  # vpslld
    0x14: (fun_14, [1, 1, 1]),  # vpshufb
    0x15: (fun_15, [1, 1, 1]),  # vpermd
    0x16: (fun_16, [1, 1, 1]),  # vpcmpeqb 

    0x06: (func_default, [3]),  # vpxor
    0x08: (func_default, [3]),  # vpsubb
    0x09: (func_default, [3]),  # vpaddw
    0x0a: (func_default, [3]),  # vpsubw
    0x0c: (func_default, [3]),  # vpsubd
    0x0d: (func_default, [3]),  # vpaddq
    0x0e: (func_default, [3]),  # vpsubq
    0x0f: (func_default, [3]),  # vpmuldq
    0x10: (func_default, [2]),  # vmovdqu

    
    0x17: (func_default, []),  #    nothing, inc index
}

id_to_comment = {
    0x00: "init",
    0x01: "vpmaddubsw",
    0x02: "vpmaddwd",
    0x03: "vpxor",
    0x04: "vpor",
    0x05: "vpand",
    0x07: "vpaddb",
    0x0b: "vpaddd",
    0x11: "store",
    0x12: "vpsrld",
    0x13: "vpslld",
    0x14: "vpshufb",
    0x15: "vpermd",
    0x16: "vpcmpeqb ",

    0x06: "vpxor",
    0x08: "vpsubb",
    0x09: "vpaddw",
    0x0a: "vpsubw",
    0x0c: "vpsubd",
    0x0d: "vpaddq",
    0x0e: "vpsubq",
    0x0f: "vpmuldq",
    0x10: "vmovdqu",

    0x17: "   nothing, inc index",
}

def run(flare_2019, flag, print_start=0):
    global p_flag
    # load args

    flare_2019 = flare_2019 + "\x00"*(0x20-len(flare_2019))
    write_memory(3, flare_2019[:0x20])
    write_memory(3+0x20+2, flag[:0x20])

    index = 0
    # vpcmpeqb

    p_flag = False
    cmd_n = 0
    while index < len(MEMORY):
        if print_start == cmd_n:
            p_flag = True
        func_id = read_memory(index)
        index += 1
        if func_id == "\xff":
            #print "Finished"
            break
        if ord(func_id) not in id_to_func:
            print "Function id:",hex(ord(func_id))
            print "Data:", `read_memory(index, 32)`
            print "Quiting..."
            #raw_input("> ")
            return

        func, arg_lengths = id_to_func[ord(func_id)]
        args = ()
        for arg_length in arg_lengths:
            arg = "".join(read_memory(index, arg_length))
            index += arg_length
            args += (arg,)
        #print hex(ord(func_id)),args, id_to_comment[ord(func_id)]
        printable_args = ()
        for arg in args:
            if len(arg) == 1:
                printable_args += (hex(ord(arg)),)
            else:
                printable_args += (arg.encode("hex"),)
        if p_flag:
            print hex(cmd_n),id_to_comment[ord(func_id)], printable_args
        func(*args)
        cmd_n += 1
        #print "   ",read_memory(0x800 + (0x20*0x14), 32).encode("hex").upper()
        #print "   ","7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"

    # vpcmpeqb
    res0 = read_memory(0x800 + (0x20*2), 32)
    res1 = read_memory(0x800 + (0x20*0x14), 32)
    return res0, res1



#arr = extract_numbers(0x000006D5E4FE6A0)

# whole arr
arr = [[17, 0, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86], [17, 1, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90], [17, 3, 21, 17, 17, 17, 17, 17, 17, 17, 17, 17, 19, 26, 27, 27, 27, 26, 21, 17, 17, 17, 17, 17, 17, 17, 17, 17, 19, 26, 27, 27, 27, 26], [17, 4, 16, 16, 1, 2, 4, 8, 4, 8, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 1, 2, 4, 8, 4, 8, 16, 16, 16, 16, 16, 16, 16, 16], [17, 5, 0, 16, 19, 4, 191, 191, 185, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 19, 4, 191, 191, 185, 185, 0, 0, 0, 0, 0, 0, 0, 0], [17, 6, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47], [17, 10, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1], [17, 11, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0], [17, 12, 2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 255, 255, 255, 255, 2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 255, 255, 255, 255], [17, 13, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255], [17, 16, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], [17, 17, 25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114, 243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106], [17, 18, 213, 94, 28, 171, 164, 130, 63, 146, 241, 17, 241, 89, 91, 194, 86, 57, 165, 219, 181, 233, 207, 251, 192, 181, 145, 68, 55, 113, 152, 47, 138, 66], [17, 19, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0], [17, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [17, 21, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0], [17, 22, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0], [17, 23, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0], [17, 24, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0], [17, 25, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0], [17, 26, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0], [17, 27, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0], [21, 20, 0, 20, 21, 21, 0, 21, 21, 22, 0, 22, 21, 23, 0, 23, 21, 24, 0, 24, 21, 25, 0, 25, 21, 26, 0, 26, 21, 27, 0, 27, 18, 7], [1, 4, 3, 28, 20, 21, 3, 28, 28, 22, 3, 28, 28, 23, 3, 28, 28, 24, 3, 28, 28, 25, 3, 28, 28, 26, 3, 28, 28, 27, 5, 7, 7, 6], [19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 22, 8, 1, 6, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 22, 8], [1, 6, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 3, 29, 20, 16, 5, 30, 20, 18, 3, 29, 29, 30, 11, 15, 29, 15], [11, 20, 15, 0, 7, 7, 8, 7, 3, 29, 20, 28, 21, 17, 29, 19, 20, 7, 5, 7, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29], [17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 7, 2, 1, 7], [3, 29, 21, 16, 5, 30, 21, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 21, 15, 0, 3, 29, 21, 28, 21, 17, 29, 19, 3, 20, 20, 21, 19, 29], [17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6], [4, 29, 29, 30, 3, 15, 15, 29, 1, 7, 2, 10, 3, 29, 22, 16, 5, 30, 22, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 22, 15, 0, 3, 29], [22, 28, 21, 17, 29, 19, 3, 20, 20, 22, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30], [3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 2, 2, 7, 11, 3, 29, 23, 16, 5, 30, 23, 18, 3, 29], [29, 30, 11, 15, 29, 15, 11, 23, 15, 0, 3, 29, 23, 28, 21, 17, 29, 19, 3, 20, 20, 23, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30], [19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 3, 29], [24, 16, 5, 30, 24, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 24, 15, 0, 3, 29, 24, 28, 21, 17, 29, 19, 3, 20, 20, 24, 19, 29, 17, 7], [18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29], [29, 30, 3, 15, 15, 29, 3, 29, 25, 16, 5, 30, 25, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 25, 15, 0, 3, 29, 25, 28, 21, 17, 29, 19], [3, 20, 20, 25, 20, 2, 2, 12, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15], [15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 3, 29, 26, 16, 5, 30, 26, 18, 3, 29, 29, 30, 11, 15, 29, 15], [11, 26, 15, 0, 3, 29, 26, 28, 21, 17, 29, 19, 3, 20, 20, 26, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30], [17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 21, 2, 2, 13, 3, 29, 27, 16], [5, 30, 27, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 27, 15, 0, 3, 29, 27, 28, 21, 17, 29, 19, 3, 20, 20, 27, 17, 19, 255, 255, 255, 255]]

# arr with first 2 arg cut off
#arr = [[21, 17, 17, 17, 17, 17, 17, 17, 17, 17, 19, 26, 27, 27, 27, 26, 21, 17, 17, 17, 17, 17, 17, 17, 17, 17, 19, 26, 27, 27, 27, 26], [16, 16, 1, 2, 4, 8, 4, 8, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 1, 2, 4, 8, 4, 8, 16, 16, 16, 16, 16, 16, 16, 16], [0, 16, 19, 4, 191, 191, 185, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 19, 4, 191, 191, 185, 185, 0, 0, 0, 0, 0, 0, 0, 0], [47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47], [64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1], [0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 16, 1, 0], [2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 255, 255, 255, 255, 2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 255, 255, 255, 255], [0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255], [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], [25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114, 243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106], [213, 94, 28, 171, 164, 130, 63, 146, 241, 17, 241, 89, 91, 194, 86, 57, 165, 219, 181, 233, 207, 251, 192, 181, 145, 68, 55, 113, 152, 47, 138, 66], [4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0], [2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0], [3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0], [4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0], [5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0], [6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0, 6, 0, 0, 0], [7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0], [0, 20, 21, 21, 0, 21, 21, 22, 0, 22, 21, 23, 0, 23, 21, 24, 0, 24, 21, 25, 0, 25, 21, 26, 0, 26, 21, 27, 0, 27, 18, 7], [3, 28, 20, 21, 3, 28, 28, 22, 3, 28, 28, 23, 3, 28, 28, 24, 3, 28, 28, 25, 3, 28, 28, 26, 3, 28, 28, 27, 5, 7, 7, 6], [17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 22, 8, 1, 6, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 22, 8], [19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 3, 29, 20, 16, 5, 30, 20, 18, 3, 29, 29, 30, 11, 15, 29, 15], [15, 0, 7, 7, 8, 7, 3, 29, 20, 28, 21, 17, 29, 19, 20, 7, 5, 7, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29], [18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 7, 2, 1, 7], [21, 16, 5, 30, 21, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 21, 15, 0, 3, 29, 21, 28, 21, 17, 29, 19, 3, 20, 20, 21, 19, 29], [18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6], [29, 30, 3, 15, 15, 29, 1, 7, 2, 10, 3, 29, 22, 16, 5, 30, 22, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 22, 15, 0, 3, 29], [21, 17, 29, 19, 3, 20, 20, 22, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30], [15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 2, 2, 7, 11, 3, 29, 23, 16, 5, 30, 23, 18, 3, 29], [11, 15, 29, 15, 11, 23, 15, 0, 3, 29, 23, 28, 21, 17, 29, 19, 3, 20, 20, 23, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30], [17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 3, 29], [5, 30, 24, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 24, 15, 0, 3, 29, 24, 28, 21, 17, 29, 19, 3, 20, 20, 24, 19, 29, 17, 7], [17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29], [3, 15, 15, 29, 3, 29, 25, 16, 5, 30, 25, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 25, 15, 0, 3, 29, 25, 28, 21, 17, 29, 19], [20, 25, 20, 2, 2, 12, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30, 17, 11, 4, 29, 29, 30, 3, 15], [19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 3, 29, 26, 16, 5, 30, 26, 18, 3, 29, 29, 30, 11, 15, 29, 15], [15, 0, 3, 29, 26, 28, 21, 17, 29, 19, 3, 20, 20, 26, 19, 29, 17, 7, 18, 30, 17, 25, 4, 15, 29, 30, 19, 29, 17, 21, 18, 30], [4, 29, 29, 30, 3, 15, 15, 29, 19, 29, 17, 26, 18, 30, 17, 6, 4, 29, 29, 30, 3, 15, 15, 29, 21, 2, 2, 13, 3, 29, 27, 16], [27, 18, 3, 29, 29, 30, 11, 15, 29, 15, 11, 27, 15, 0, 3, 29, 27, 28, 21, 17, 29, 19, 3, 20, 20, 27, 17, 19, 255, 255, 255, 255]]


MEMORY = '\x00\x11\x000123456789ABCDEFGHIJKLMNOPQRSTUV\x11\x01ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\x11\x03\x15\x11\x11\x11\x11\x11\x11\x11\x11\x11\x13\x1a\x1b\x1b\x1b\x1a\x15\x11\x11\x11\x11\x11\x11\x11\x11\x11\x13\x1a\x1b\x1b\x1b\x1a\x11\x04\x10\x10\x01\x02\x04\x08\x04\x08\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x01\x02\x04\x08\x04\x08\x10\x10\x10\x10\x10\x10\x10\x10\x11\x05\x00\x10\x13\x04\xbf\xbf\xb9\xb9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x13\x04\xbf\xbf\xb9\xb9\x00\x00\x00\x00\x00\x00\x00\x00\x11\x06////////////////////////////////\x11\n@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01@\x01\x11\x0b\x00\x10\x01\x00\x00\x10\x01\x00\x00\x10\x01\x00\x00\x10\x01\x00\x00\x10\x01\x00\x00\x10\x01\x00\x00\x10\x01\x00\x00\x10\x01\x00\x11\x0c\x02\x01\x00\x06\x05\x04\n\t\x08\x0e\r\x0c\xff\xff\xff\xff\x02\x01\x00\x06\x05\x04\n\t\x08\x0e\r\x0c\xff\xff\xff\xff\x11\r\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x06\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x11\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x11\x11\x19\xcd\xe0[\xab\xd9\x83\x1f\x8ch\x05\x9b\x7fR\x0eQ:\xf5O\xa5r\xf3n<\x85\xaeg\xbbg\xe6\tj\x11\x12\xd5^\x1c\xab\xa4\x82?\x92\xf1\x11\xf1Y[\xc2V9\xa5\xdb\xb5\xe9\xcf\xfb\xc0\xb5\x91D7q\x98/\x8aB\x11\x13\x04\x00\x00\x00\x05\x00\x00\x00\x06\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x11\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x15\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x11\x16\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x11\x17\x03\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x11\x18\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x11\x19\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x11\x1a\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x11\x1b\x07\x00\x00\x00\x07\x00\x00\x00\x07\x00\x00\x00\x07\x00\x00\x00\x07\x00\x00\x00\x07\x00\x00\x00\x07\x00\x00\x00\x07\x00\x00\x00\x15\x14\x00\x14\x15\x15\x00\x15\x15\x16\x00\x16\x15\x17\x00\x17\x15\x18\x00\x18\x15\x19\x00\x19\x15\x1a\x00\x1a\x15\x1b\x00\x1b\x12\x07\x01\x04\x03\x1c\x14\x15\x03\x1c\x1c\x16\x03\x1c\x1c\x17\x03\x1c\x1c\x18\x03\x1c\x1c\x19\x03\x1c\x1c\x1a\x03\x1c\x1c\x1b\x05\x07\x07\x06\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x16\x08\x01\x06\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x16\x08\x01\x06\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x03\x1d\x14\x10\x05\x1e\x14\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x14\x0f\x00\x07\x07\x08\x07\x03\x1d\x14\x1c\x15\x11\x1d\x13\x14\x07\x05\x07\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x07\x02\x01\x07\x03\x1d\x15\x10\x05\x1e\x15\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x15\x0f\x00\x03\x1d\x15\x1c\x15\x11\x1d\x13\x03\x14\x14\x15\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x01\x07\x02\n\x03\x1d\x16\x10\x05\x1e\x16\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x16\x0f\x00\x03\x1d\x16\x1c\x15\x11\x1d\x13\x03\x14\x14\x16\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x02\x02\x07\x0b\x03\x1d\x17\x10\x05\x1e\x17\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x17\x0f\x00\x03\x1d\x17\x1c\x15\x11\x1d\x13\x03\x14\x14\x17\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x03\x1d\x18\x10\x05\x1e\x18\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x18\x0f\x00\x03\x1d\x18\x1c\x15\x11\x1d\x13\x03\x14\x14\x18\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x03\x1d\x19\x10\x05\x1e\x19\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x19\x0f\x00\x03\x1d\x19\x1c\x15\x11\x1d\x13\x03\x14\x14\x19\x14\x02\x02\x0c\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x03\x1d\x1a\x10\x05\x1e\x1a\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x1a\x0f\x00\x03\x1d\x1a\x1c\x15\x11\x1d\x13\x03\x14\x14\x1a\x13\x1d\x11\x07\x12\x1e\x11\x19\x04\x0f\x1d\x1e\x13\x1d\x11\x15\x12\x1e\x11\x0b\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x13\x1d\x11\x1a\x12\x1e\x11\x06\x04\x1d\x1d\x1e\x03\x0f\x0f\x1d\x15\x02\x02\r\x03\x1d\x1b\x10\x05\x1e\x1b\x12\x03\x1d\x1d\x1e\x0b\x0f\x1d\x0f\x0b\x1b\x0f\x00\x03\x1d\x1b\x1c\x15\x11\x1d\x13\x03\x14\x14\x1b\x11\x13\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x05\x14\x14\x13\x11\x1f"\x1e\x1bK-\x17\x05\x0c\x15Y\x0ex#&3.\x10\x07Os\x186X\x0b)\x0f\\:\x0cbv!\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xb0\x17\xc8\xba\xf7\x7f\x00\x00\x00#\xc8\xba\xf7\x7f\x00\x00\xe0!\xc8\xba\xf7\x7f\x00\x0000\xc8\xba\xf7\x7f\x00\x00@\'\xc8\xba\xf7\x7f\x00\x00\xd0\x1d\xc8\xba\xf7\x7f\x00\x000&\xc8\xba\xf7\x7f\x00\x00\xb0\x1c\xc8\xba\xf7\x7f\x00\x00\x10/\xc8\xba\xf7\x7f\x00\x00P\x19\xc8\xba\xf7\x7f\x00\x00\xb0+\xc8\xba\xf7\x7f\x00\x00p\x1a\xc8\xba\xf7\x7f\x00\x00\xd0,\xc8\xba\xf7\x7f\x00\x00\x90\x1b\xc8\xba\xf7\x7f\x00\x00\xf0-\xc8\xba\xf7\x7f\x00\x00\xe0$\xc8\xba\xf7\x7f\x00\x00 $\xc8\xba\xf7\x7f\x00\x00\x10 \xc8\xba\xf7\x7f\x00\x00\x80)\xc8\xba\xf7\x7f\x00\x00\xd0 \xc8\xba\xf7\x7f\x00\x00\x90*\xc8\xba\xf7\x7f\x00\x00`(\xc8\xba\xf7\x7f\x00\x00\xf0\x1e\xc8\xba\xf7\x7f\x00\x00\x00&\xc8\xba\xf7\x7f\x00\x00\x00'
MEMORY = list(MEMORY)

#print_vv_elements()


def test():
    if len(sys.argv) > 1:
        print_start = int(sys.argv[1], 16)
    else:
        print_start = 0
    #a,b = run("FLARE2019", "00000000000000000000000000000000", print_start=print_start)
    #assert a.encode("hex").upper() == "D34D34D34D34D34D34D34D34D34D34D34D34D34D34D34D340000000000000000"
    #print 'a.encode("hex").upper() == "D34D34D34D34D34D34D34D34D34D34D34D34D34D34D34D340000000000000000"'

    a,b = run("FLARE2019", "0123456789ABCDEFGHIJKLMNOPQRSTUV", print_start=print_start)
    assert a.encode("hex").upper() == "D35DB7E39EBBF3D00108310518720928B30D38F4114935150000000000000000"
    print 'a.encode("hex").upper() == "D35DB7E39EBBF3D00108310518720928B30D38F4114935150000000000000000"'

    assert b.encode("hex").upper() == "7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"
    print 'b.encode("hex").upper() == "7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"'

#test()

import string
import itertools
arg1 = "FLARE2019"

alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!+-_"

b= "7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"
#print "    b=",b
"""
prefix = ""
find = "7070"

for attempt in itertools.product(alphabet, repeat=3):
    arg2 = prefix + "".join(attempt)
    arg2 += "0"*(32-len(arg2))

    a,b = run(arg1, arg2)
    a_hex = a.encode("hex").upper()
    b_hex = b.encode("hex").upper()
    if a_hex.startswith(find):
        print `arg2`
        print "    a=",a_hex
# this found "cHA"
"""


prefix = "cHA"
find = "7070B"
alphabet = string.printable
for attempt in itertools.product(alphabet, repeat=3):
    arg2 = prefix + "".join(attempt)
    arg2 += "0"*(32-len(arg2))

    a,b = run(arg1, arg2, print_start=-1)
    a_hex = a.encode("hex").upper()
    b_hex = b.encode("hex").upper()
    if a_hex.startswith(find):
        print `arg2`
        print "    a=",a_hex
# this found "cHA"
exit()


test()


def find_arg():
    b = "7070B2AC01D25E610AA72AA8081C861AE845C829B2F3A11E0000000000000000"
    prefix = ""
    while len(prefix) != 32:
        prefix = find_arg_next_3(prefix)

"""
for c in string.printable:
    #arg2 = "00000000000000000000000000000000"
    arg2 = "c" + c+"Z00000000000000000000000000000"
    arg2 = "c" + c+"ZMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
    a,b = run(arg1, arg2)
    a_hex = a.encode("hex").upper()
    b_hex = b.encode("hex").upper()

    if a_hex.startswith(find):
        print `arg2`
        print "    a=",a_hex
        #print "b=",b_hex
"""
