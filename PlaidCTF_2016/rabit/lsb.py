from hashlib import sha1
import itertools
import string
import socket
import re

def encrypt(m, N):
    return pow(m, 2, N)

def find_proof(proof,length=15,H=sha1):
    l = length-len(start)
    for i in itertools.product(string.lowercase+string.uppercase, repeat=l):
        proof = start + "".join(i)
        if H(proof).digest()[-3:] == "\xff\xff\xff":
            return proof

reg_proof = re.compile(r'Give me a string starting with (\S*), ')
reg_N = re.compile(r'Welcome to the LSB oracle! N = (\d+)')
reg_encflag = re.compile(r'Encrypted Flag: (\d+)')
reg_lsb = re.compile(r'lsb is (\d+)')

#s = socket.create_connection(('localhost',7763)); PROOF=False
s = socket.create_connection(('rabit.pwning.xxx',7763)); PROOF=True


if PROOF:
    print s.recv(4096)
    r = s.recv(4096)
    print r
    start = reg_proof.findall(r)[0]
    print 'Finding proof...'
    proof = find_proof(start)
    s.send(proof)
    print 'Found',proof
    print 

r = s.recv(4096)
N = int(reg_N.findall(r)[0])

r = s.recv(4096)
ct = int(reg_encflag.findall(r)[0])

length = 1024
upper = N
lower = 0
for i in xrange(length):
    print 'Round',i
    while 'ciphertext' not in r:
        r = s.recv(4096)

    power = pow(2,(i+1),N)
    _ct = (encrypt(power,N)*ct)%N
    s.send(str(_ct)+'\n')
    r = s.recv(4096)
    b = reg_lsb.findall(r)[0]

    # even
    if b == '0':
        upper = (upper + lower)/2
    # odd
    else: 
        lower = (upper + lower)/2
    if upper < lower:
        break

print '\nFlag:'
print hex(int(upper))[2:].strip('L').decode('hex')
print
print hex(int(lower))[2:].strip('L').decode('hex')

"""
Flag:
PCTF{LSB_is_4ll_y0u_ne3d}

PCTF{LSB_is_4ll_y0u_ne3d}
"""

