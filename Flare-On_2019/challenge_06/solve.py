"""
d0nT_tRu$t_vEr1fy@flare-on.com
"""
import PIL.Image as Image


def program_init():
    global a
    global c
    global f
    a = b
    c = d

    # how is one this done?
    f = g


def a(b, r):
    return (b + r ^ r) & 255

def b(b, r):
    for i in range(r):
        b2 = ((b & 128) / 128) & 0xff
        b = ((b * 2) & 0xff) + b2
    return b & 0xff

def c(b, r):
    b2 = 1
    for i in range(8):
        flag = (b & 1) == 1
        if flag:
            b2 = (b2 * 2 + 1) & 255
        else:
            b2 = (b2 - 1) & 255
    return b2

def d(b, r):
    for i in range(r):
        b2 = ((b & 1) * 128) & 0xff
        b = ((b / 2) & 0xff) + b2
    return b & 0xff

def e(b, k):
    for i in range(8):
        flag = ((b >> i) & 1) == ((k >> i) & 1)
        if flag:
            b = (b & ((~(1 << i)) & 0xFFFFFFFF)) & 255
        else:
            b = (b | (1 << i)) & 255
    return b

def f(idx):
    arr = [121,255,214,60,106,216,149,89,96,29,81,123,182,24,167,252,88,212,43,85,181,86,108,213,50,78,247,83,193,35,135,217,0,64,45,236,134,102,76,74,153,34,39,10,192,202,71,183,185,175,84,118,9,158,66,128,116,117,4,13,46,227,132,240,122,11,18,186,30,157,1,154,144,124,152,187,32,87,141,103,189,12,53,222,206,91,20,174,49,223,155,250,95,31,98,151,179,101,47,17,207,142,199,3,205,163,146,48,165,225,62,33,119,52,241,228,162,90,140,232,129,114,75,82,190,65,2,21,14,111,115,36,107,67,126,80,110,23,44,226,56,7,172,221,239,161,61,93,94,99,171,97,38,40,28,166,209,229,136,130,164,194,243,220,25,169,105,238,245,215,195,203,170,16,109,176,27,184,148,131,210,231,125,177,26,246,127,198,254,6,69,237,197,54,59,137,79,178,139,235,249,230,233,204,196,113,120,173,224,55,92,211,112,219,208,77,191,242,133,244,168,188,138,251,70,150,145,248,180,218,42,15,159,104,22,37,72,63,234,147,200,253,100,19,73,5,57,201,51,156,41,143,68,8,160,58]
    num = 0
    num2 = 0
    num3 = 0
    result = 0
    for i in range(idx):
        num = (num + 1) & 0xff
        num2 = (num2 + arr[num]) & 0xff
        num3 = arr[num]
        arr[num] = arr[num2]
        arr[num2] = num3
        result = arr[(arr[num] + arr[num2]) & 0xff]
    return result

def g(idx):
    # oddly, the constants for calculating b and k were not correct.. not sure were they were modified
    #b = ((idx + 1) * (-306674912 & 0xFFFFFFFF)) & 0xFF
    #k = ((idx + 2) * 1669101435) & 0xFF

    # patched constants
    b = ((idx + 1) * 0xc5) & 0xFF
    k = ((idx + 2) * 0x7d) & 0xFF
    return e(b, k)

def h(data):
    arr = []
    num = 0
    # assuming swaps done in init..
    for i in range(len(data)):
        # not sure where f was swapped with g, but its done in program_init() in here
        num2 = f(num)
        num += 1

        num3 = ord(data[i])
        num3 = e(num3, num2)
        num3 = a(num3, 7)

        num4 = f(num)
        num += 1

        num3 = e(num3, num4)
        num3 = c(num3, 3)

        arr.append(num3)
    return arr

def reverse_h(arr):
    num = 0
    data = []
    # not assuming init swapped variables..
    for i in range(len(arr)):
        num2 = g(num)
        num += 1
        num4 = g(num)
        num += 1

        num3 = arr[i]
        # inverse for d is b
        num3 = b(num3, 3)
        # inverse for e is e
        num3 = e(num3, num4)
        # inverse for b is d
        num3 = d(num3, 7)
        # inverse for e is e
        num3 = e(num3, num2)

        data.append(num3)

    return data

def reverse_i(img, data_length):
    data = ""
    pixels = img.load()
    width, height = img.size
    for w in range(width):
        for h in range(height):
            r,g,b = pixels[w,h]
            orig_r = (r & 0xf8)
            orig_g = (g & 0xf8)
            orig_b = (b & 0xfc)

            d1 = r & 0x07
            d2 = (g & 0x07) << 0x03
            d3 = (b & 0x03) << 0x06
            d = d1 | d2 | d3
            data += chr(d)

            if len(data) == data_length:
                break
        if len(data) == data_length:
            break
    return data


def test_i(arr, data):
    for i in range(len(arr)):
        if i >= len(data):
            break
        r,g,b = arr[i]

        c = ord(data[i])
        r = (r & 0xf8) | (c & 0x07)
        g = (g & 0xf8) | (c >> 0x03 & 0x07)
        b = (b & 0xfc) | (c >> 0x06 & 0x03)

        arr[i] = r,g,b
    return arr

def test_reverse_i(arr, data_length):
    data = ""
    for row in arr:
        r,g,b = row

        d1 = r & 0x07
        d2 = (g & 0x07) << 0x03
        d3 = (b & 0x03) << 0x06
        d = d1 | d2 | d3
        data += chr(d)
        if len(data) == data_length:
            break
    return data

def test():
    data = "THISISATESTKEY"
    img = [(255,255,255)]*1000
    enc_img = test_i(img, data)
    extracted_data = test_reverse_i(enc_img, len(data))
    assert data == extracted_data

    data = "AAAABBBBCCCCDDDD"
    enc_data = h(data)
    # "AAAABBBBCCCCDDDD" -> [0x58,0x03,0xD9,0x05,0x69,0x32,0xEB,0x32,0x7A,0x25,0xF7,0x2D,0x19,0x46,0x9D,0x44]
    assert enc_data == [0x58,0x03,0xD9,0x05,0x69,0x32,0xEB,0x32,0x7A,0x25,0xF7,0x2D,0x19,0x46,0x9D,0x44]
    dec_data = reverse_h(enc_data)
    dec_data = "".join(map(chr, dec_data))
    assert dec_data == data


program_init()
test()

img = Image.open("image.bmp")
width,height = img.size
enc_flag = reverse_i(img, width*height)
enc_flag = map(ord,enc_flag)
flag = reverse_h(enc_flag)
flag = ''.join(map(chr, flag))

with open("flag.bmp","wb") as fl:
    fl.write(flag)

img = Image.open("flag.bmp")
width,height = img.size
enc_flag = reverse_i(img, width*height)
enc_flag = map(ord,enc_flag)
flag = reverse_h(enc_flag)
flag = ''.join(map(chr, flag))

with open("flag2.bmp","wb") as fl:
    fl.write(flag)


"""
j(103) -> 0x00
j(231) -> 0x01
j(27)  -> 0xf8
j(228) -> 0x07
j(230) -> 0x03
j(25)  -> 0xfc
j(100) -> 0x06
j(231) -> 0x01



a = b
c = d

???
f = g


wrote decrypt functions.. decrypt twice

d0nT_tRu$t_vEr1fy@flare-on.com
"""