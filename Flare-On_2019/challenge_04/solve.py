"""
LooksLikeYouLockedUpTheLookupZ@flare-on.com
"""
import re


# parse tcpdump output
with open("dns.txt", "rb") as f:
    dns_pcap = f.read()

re_query = re.compile(r".+192.168.122.1.(\d+) > 192.168.122.29.domain: \d+\+ \[.+\] \S+ (.+) \(\d+\)")
re_reply = re.compile(r".+ 192.168.122.29.domain > 192.168.122.1.(\d+): \d+\* .+ A (\S+) \(\d+\)")

dns_pcap = dns_pcap.rstrip("\n").split("\n")
ips = []
i = 0
moves = []
while i < len(dns_pcap):
    line = dns_pcap[i]
    query = re_query.findall(line)[0]
    host = query[1]

    line = dns_pcap[i + 1]
    reply = re_reply.findall(line)[0]
    ip = reply[1]

    moves.append((host, ip))
    i += 2


# print all moves unparsed
ip_to_host = {}
host_to_ip = {}
for move in moves:
    host = move[0][:-1]
    ip = move[1]
    ip_to_host[ip] = host
    host_to_ip[host] = ip
    #print "{:15}        {}".format(ip, host)
#print '---'*10


# parse and print move numbers

# get move numbers
ordered = {}
for move in moves:
    ip = map(int, move[1].split('.'))
    move_id = ip[2] & 0xf
    if move_id not in ordered:
        ordered[move_id] = [ip]
    else:
        ordered[move_id].append(ip)
# print moves by move number
for i in range(16):
    for ip in ordered[i]:
        ip = ".".join(map(str,ip))
        host = ip_to_host[ip]
        #print "   ","{:15}        {}".format(ip, host)


########################################################################################

# calculate flag
enc_flag = [121, 90, 184, 188, 236, 211, 223, 221, 153, 165, 182, 172, 21, 54, 133, 141, 9, 8, 119, 82, 77, 113, 84, 125, 167, 167, 8, 22, 253, 215]
flag = [76, 111, 111, 107, 115, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 102, 108, 97, 114, 101, 45, 111, 110, 46, 99, 111, 109]

solution_ips = r"""127.53.176.56
127.215.177.38
127.159.162.42
127.182.147.24
127.252.212.90
127.217.37.102
127.89.38.84
127.230.231.104
127.108.24.10
127.34.217.88
127.25.74.92
127.49.59.14
127.200.76.108
127.99.253.122
127.141.14.174""".split("\n")

for line in solution_ips:
    ip = map(int,line.split("."))
    move_id = ip[2] & 0xf
    flag[move_id * 2] = enc_flag[move_id * 2] ^ ip[1]
    flag[move_id * 2 + 1] = enc_flag[move_id * 2 + 1] ^ ip[1]
flag = "".join(map(chr, flag))
print flag

"""
127.53.176.56          pawn-d2-d4.game-of-thrones.flare-on.com
127.215.177.38         pawn-c2-c4.game-of-thrones.flare-on.com
127.159.162.42         knight-b1-c3.game-of-thrones.flare-on.com

127.150.96.223         rook-c3-c6.game-of-thrones.flare-on.com
127.252.212.90         knight-g1-f3.game-of-thrones.flare-on.com
127.118.118.207        knight-c7-d5.game-of-thrones.flare-on.com
127.89.38.84           bishop-f1-e2.game-of-thrones.flare-on.com
127.109.155.97         rook-a1-g1.game-of-thrones.flare-on.com
127.217.37.102         bishop-c1-f4.game-of-thrones.flare-on.com
127.49.59.14           bishop-c6-a8.game-of-thrones.flare-on.com
127.182.147.24         pawn-e2-e4.game-of-thrones.flare-on.com
127.0.143.11           king-g1-h1.game-of-thrones.flare-on.com
127.227.42.139         knight-g1-h3.game-of-thrones.flare-on.com
127.101.64.243         king-e5-f5.game-of-thrones.flare-on.com
127.201.85.103         queen-d1-f3.game-of-thrones.flare-on.com
127.200.76.108         pawn-e5-e6.game-of-thrones.flare-on.com
127.50.67.23           king-c4-b3.game-of-thrones.flare-on.com
127.157.96.119         king-c1-b1.game-of-thrones.flare-on.com
127.99.253.122         queen-d1-h5.game-of-thrones.flare-on.com
127.25.74.92           bishop-f3-c6.game-of-thrones.flare-on.com
127.168.171.31         knight-d2-c4.game-of-thrones.flare-on.com
127.148.37.223         pawn-c6-c7.game-of-thrones.flare-on.com
127.108.24.10          bishop-f4-g3.game-of-thrones.flare-on.com
127.37.251.13          rook-d3-e3.game-of-thrones.flare-on.com
127.34.217.88          pawn-e4-e5.game-of-thrones.flare-on.com
127.57.238.51          queen-a8-g2.game-of-thrones.flare-on.com
127.196.103.147        queen-a3-b4.game-of-thrones.flare-on.com
127.141.14.174         queen-h5-f7.game-of-thrones.flare-on.com
127.238.7.163          pawn-h4-h5.game-of-thrones.flare-on.com
127.230.231.104        bishop-e2-f3.game-of-thrones.flare-on.com
127.55.220.79          pawn-g2-g3.game-of-thrones.flare-on.com
127.184.171.45         knight-h8-g6.game-of-thrones.flare-on.com
127.196.146.199        bishop-b3-f7.game-of-thrones.flare-on.com
127.191.78.251         queen-d1-d6.game-of-thrones.flare-on.com
127.184.48.79          bishop-f1-d3.game-of-thrones.flare-on.com
127.127.29.123         rook-b4-h4.game-of-thrones.flare-on.com
127.191.34.35          bishop-c1-a3.game-of-thrones.flare-on.com
127.5.22.189           bishop-e8-b5.game-of-thrones.flare-on.com
127.233.141.55         rook-f2-f3.game-of-thrones.flare-on.com
127.55.250.81          pawn-a2-a4.game-of-thrones.flare-on.com


testing possible moves by hand... assuming we need 16 of these moves as there are multiple move numbers in the ip addresses
===========================================================================
0
    127.150.96.223         
    127.101.64.243         
    127.157.96.119         
    127.184.48.79          
    127.53.176.56          pawn-d2-d4.game-of-thrones.flare-on.com
1
    127.215.177.38         pawn-c2-c4.game-of-thrones.flare-on.com
2
    127.196.146.199        
    127.159.162.42         knight-b1-c3.game-of-thrones.flare-on.com
    127.191.34.35          
3
    127.182.147.24         pawn-e2-e4.game-of-thrones.flare-on.com
    127.50.67.23           
4
    127.252.212.90         knight-g1-f3.game-of-thrones.flare-on.com
5
    127.217.37.102         bishop-c1-f4.game-of-thrones.flare-on.com
    127.201.85.103         
    127.148.37.223         
6
    127.118.118.207        
    127.89.38.84           bishop-f1-e2.game-of-thrones.flare-on.com
    127.5.22.189           
7
    127.196.103.147        
    127.238.7.163          
    127.230.231.104        bishop-e2-f3.game-of-thrones.flare-on.com
8
    127.108.24.10          bishop-f4-g3.game-of-thrones.flare-on.com
9
    127.34.217.88          pawn-e4-e5.game-of-thrones.flare-on.com
10
    127.227.42.139         
    127.25.74.92           bishop-f3-c6.game-of-thrones.flare-on.com
    127.55.250.81          
11
    127.109.155.97         
    127.49.59.14           bishop-c6-a8.game-of-thrones.flare-on.com
    127.168.171.31         
    127.37.251.13          
    127.184.171.45         
12
    127.200.76.108         pawn-e5-e6.game-of-thrones.flare-on.com
    127.55.220.79          
13
    127.99.253.122         queen-d1-h5.game-of-thrones.flare-on.com
    127.127.29.123         
    127.233.141.55         
14
    127.57.238.51          
    127.141.14.174         queen-h5-f7.game-of-thrones.flare-on.com
    127.191.78.251         
15
    127.0.143.11           
==============================================================================

move solution:
127.53.176.56          pawn-d2-d4.game-of-thrones.flare-on.com
127.215.177.38         pawn-c2-c4.game-of-thrones.flare-on.com
127.159.162.42         knight-b1-c3.game-of-thrones.flare-on.com
127.182.147.24         pawn-e2-e4.game-of-thrones.flare-on.com
127.252.212.90         knight-g1-f3.game-of-thrones.flare-on.com
127.217.37.102         bishop-c1-f4.game-of-thrones.flare-on.com
127.89.38.84           bishop-f1-e2.game-of-thrones.flare-on.com
127.230.231.104        bishop-e2-f3.game-of-thrones.flare-on.com
127.108.24.10          bishop-f4-g3.game-of-thrones.flare-on.com
127.34.217.88          pawn-e4-e5.game-of-thrones.flare-on.com
127.25.74.92           bishop-f3-c6.game-of-thrones.flare-on.com
127.49.59.14           bishop-c6-a8.game-of-thrones.flare-on.com
127.200.76.108         pawn-e5-e6.game-of-thrones.flare-on.com
127.99.253.122         queen-d1-h5.game-of-thrones.flare-on.com
127.141.14.174         queen-h5-f7.game-of-thrones.flare-on.com

"""

