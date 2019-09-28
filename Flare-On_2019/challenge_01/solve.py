"""
Kitteh_save_galixy@flare-on.com
"""
# -*- coding: utf-8 -
import base64

#stage 1 - RAINBOW
stage1_code = "RAINBOW"
print stage1_code


#stage 2 - Bagel_Cannon
data = ['\x03','"','"','"','%','\x14','\x0E','.','?','=',':','9']
stage2_code = ""
for i,c in enumerate(data):
    stage2_code += chr(ord(c) ^ (65 + i *2))
print stage2_code


#stage 3 - Defeat_them_with_love
# looks to be rc4
def CatFact(s, i ,j):
    b = s[i]
    s[i] = s[j]
    s[j] = b

def InvertCosmicConstants(cat):
    array = range(256)
    num = 0
    for j in range(256):
        num = (num + cat[j % len(cat)] + array[j]) & 0xff
        CatFact(array, j , num)
    return array

def AssignFelineDesignation(cat, data):
    s = InvertCosmicConstants(cat)
    out = []
    i = 0
    j = 0
    for b in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        CatFact(s, i, j)
        res = b ^ s[(s[i] + s[j]) & 0xff]
        out.append(res)
    return "".join(map(chr,out))

data = [95,193,50,12,127,228,98,6,215,46,200,106,251,121,186,119,109,73,35,14,20]
catGenetics = map(ord, base64.b64encode(stage2_code))
stage3_code = AssignFelineDesignation(catGenetics, data)
print stage3_code

"""
Codes:
RAINBOW
Bagel_Cannon
Defeat_them_with_love

Flag:
Kitteh_save_galixy@flare-on.com
"""