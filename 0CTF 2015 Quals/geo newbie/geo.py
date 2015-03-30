import socket
import requests
import json
import re

# import all my dictionaries
from alpha2 import rev_alpha2,r40,fixes

DEBUG = False

def Find(pat, text):
	match = re.search(pat, text)
	if match: return match.group()
	else: return False


googlemaps = 'https://maps.googleapis.com/maps/api/geocode/json'
wikipedia  = 'http://en.wikipedia.org/w/api.php'
data = {}

HOST = '202.112.26.111'
PORT = 29995

s = socket.create_connection((HOST, PORT))
r = s.recv(4096)



counter = 0
while 1:
	r = s.recv(4096)
	print `r`
	
	if not r:
		break
	found = Find(r'.+:',r)
	
	if not found: # check for '\n' and similar
		continue
	
	# Level 0 dictionary
	if counter < 20 and found[:-1] in rev_alpha2:
		alpha2 = rev_alpha2[found[:-1]]
	# Level 1 dictionary
	elif counter < 70 and found[:-1] in r40:
		alpha2 = r40[found[:-1]]
	# Level 0 and Level 1 google maps api check
	elif counter < 70:
		# just remove anything after a '(' because they seemed to not work with google api
		f = found.find('(')
		if f != -1:
			found = found[:f]
		f = found.find(',')
		if f != -1:
			found = found[:f]
		
		# specify that it is a country if in Level 0
		if counter < 20:
			data['address'] = 'country '+found[:-1]
		else:
			data['address'] = found[:-1]
		
		# perform google maps geocode api request
		resp = requests.get(googlemaps, params=data)
		respdata = json.loads(resp.text)
		alpha2 = ''
		
		# iterate through the response to find a 2 character code
		# ..alpha codes are *usually* at the end
		for d in respdata['results'][0]['address_components'][::-1]:
			alpha2 = d['short_name']
			if len(alpha2) == 2:
				break
	print 'Sending:',alpha2
	s.send(alpha2 + '\n')
	
	counter += 1
	if counter == 70: # break on Level 2
		break



r = s.recv(4096)
r = s.recv(4096)
print `r`
if r == '\n':
	r = s.recv(4096)
	print `r`
found = Find(r'.+:',r)
while 1:
	if not found:
		continue
	print found
	found = Find("Which countries does .+",found)[21:]
	
	# RIVER
	if ' run across' in found:
		found = found[:-13]
	# MOUNTAINS
	elif ' span' in found:
		found = found[:-7]
	found = '_'.join(found.split(' '))
	
	if DEBUG: print "found:",found
	# use fixes dictionary
	if found in fixes:
		found = fixes[found]
	
	# wikipedia api get params
	data = {
		'rawcontinue':'',
		'format':'json',
		'action':'query',
		'titles':found,
		'prop':'revisions',
		'rvprop':'content'
	}
	
	# send request to wikipedia for page
	resp = requests.get(wikipedia, params=data)
	respdata = resp.text
	if DEBUG: print "Went to:",resp.url
	
	# find all countries listed for the mountain range or river
	countries = re.findall(r'country\d?\W*=\W*(\w+[ \w+]*)',respdata)
	if DEBUG: print countries
	
	
	# if didn't find 'Rhine_River'.. look for 'Rhine' instead
	if not countries:
		#print "no countries found...?"
		
		found = '_'.join(found.split('_')[:-1])
		data['titles'] = found
		resp = requests.get(wikipedia, params=data)
		respdata = resp.text
		if DEBUG: print "Went to:",resp.url
		countries = re.findall(r'country\d?\W*=\W*(\w+)',respdata)
		
		if DEBUG: print countries
		
		# it broke!
		if not countries:
			print "no countries found..."
			break
	
	for country in countries:
		# replace [[country]] brackets.. incase they passed regex??
		country = country.replace('[','').replace(']','')
		
		if DEBUG: print "getting country: ",country
		if country in rev_alpha2:
			alpha2 = rev_alpha2[country]
		else:
			data = {}
			data['address'] = 'country '+country
			
			resp = requests.get(googlemaps, params=data)
			data = json.loads(resp.text)
			alpha2 = ''
			
			for d in data['results'][0]['address_components'][::-1]:
				alpha2 = d['short_name']
				if len(alpha2) == 2:
					break
		print 'Sending:',alpha2
		s.send(alpha2 + '\n')
		
		r = s.recv(4096)
		print `r`
		while r == ' ' or r == '\n':
			r = s.recv(4096)
			print `r`
		if 'Next:' not in r:
			break
	
	if not r:
		break
	found = Find(r'.+:',r)
	
	counter += 1




