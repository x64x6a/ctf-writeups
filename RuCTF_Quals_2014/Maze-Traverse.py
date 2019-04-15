'''
This program traverse the Maze challenge from RuCTF Quals 2014 
'''
import socket
import sys
import multiprocessing

passwords = {}  # dictionary containing port's passwords		{PORT:PASSWORD}
current = []   # contains all ports that have been found, but not yet accessed


# direction distances to port from current port
paths = {'up':-256,'left':-1,'down':256,'right':1, 'rigth':1}

# just to fix their rigth mispelling,..
words = {'up':'up','left':'left','down':'down','right':'right', 'rigth':'right'} 

# UDP socket stuff
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

# returns with the specified way, port, and password
# I was too foolish to use regex..
def handle(s, currentPort):
	try:
		way = ''
		pos = s.find('go ')
		pos1 = s.find('(')
		
		if pos1 == -1:
			way = s[pos+3:]
			way = way[:way.find(' ')]
			
			port = paths[way] + currentPort
		else:
			way = s[pos+3:pos1]
			pos2 = s.find(')')
			port = int(s[pos1+1:pos2])
		
		pos3 = s.find('password: ')
		password = s[pos3 + len('password: '):]
		
		#print "Returning ",way,port,password
		return words[way],port,password
	# catch errors, return 0 instead
	except:
		print "Error with:\n " + s 
		print "="*20
		return 0

# connects to given port with the password in the dictionary
def check(port):
	print "Port " + str(port) + "..."
	
	sock.sendto( passwords[port], (IP, port))
	
	r = sock.recv(1024)
	
	
	# print key and throw exit
	if 'RUCTF_' in r:
		print r
		print "Found!"
		exit()
	
	
	r = r.split('\n')
	greeting = r[0]
	rest = r[1:]
	
	for line in rest:
		tup = handle(line, port)
		
		if tup:
			w,_port,_password = tup
			
			# check if found port was already accessed
			if _port not in passwords:
				passwords[_port] = _password
				current.append(_port)   # push found port



def main():
	global IP
	global passwords
	
	
	IP = "194.226.244.125"
	PORT = 1024
	
	password = '3k8bbz032mrap75c8iz8tmi7f4ou00'
	
	passwords[PORT] = password
	
	current.append(PORT)
	
	# for every item in the global current
	while current != []:
		p = current.pop()
		while 1:
			try:
				check(p)
				break
			# to catch UDP timeout errors... also catches exit()
			except:
				print "Error... Retrying..."
		


if __name__ == '__main__':
	main()


