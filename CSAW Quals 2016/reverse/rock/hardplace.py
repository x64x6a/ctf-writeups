
flag = list('FLAG23456912365453475897834567')
for i,c in enumerate(flag):
  flag[i] = chr(((ord(c) - 0x09) & 0xff) ^ 0x10)

for i,c in enumerate(flag):
  flag[i] = chr(((ord(c) - 0x14) & 0xff) ^ 0x50)

flag = ''.join(flag)

print flag

