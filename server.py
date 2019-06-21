#!/usr/bin/env python
# Python Network Programming Cookbook, Second Edition -- Chapter - 1
# This program is optimized for Python 2.7.12 and Python 3.5.2.
# It may run on any other version with/without modifications.

# unicodefy = lambda x : u'\x00' if x == '\x00' else eval("u'{}'".format(x))
# unbytefy = lambda x : unicodefy(x).encode('unicode_escape')[2:]
# getChar = lambda x : 
unbytefy = lambda x : x.encode('hex')
bytefy   = lambda x : "\\x{}".format(x).decode('unicode_escape')
toBytes  = lambda x : ''.join([bytefy(x[i:i+2]) if x[i:i+2] != '{}' 
							else '{}' for i in range(0,len(x),2)])

import socket
import sys
import argparse
import optionsProcessor
import info
#from consts import *

host = '255.255.255.255'
data_payload = 2048
DHCP_SERVER_PORT = 67
cookie = '63825363'

def write(mType):
	fields = []
	fields.append(hex(0)+hex(2)) # OP
	fields.append(hex(0)+hex(1)) # htype
	fields.append(hex(0)+hex(6)) # hlen
	fields.append(hex(0)+hex(0)) # hops
	fields.append('{}') # XID
	fields.append('0'*4) # secs
	fields.append('0'*4) # flags
	fields.append('0'*8) # CIADDR
	fields.append('{}') # YIADDR
	fields.append(optionsProcessor.SERVER_HEX) # SIADDR
	fields.append('0'*8) # GIADDR
	fields.append('{}') # CHADDR
	fields.append(cookie) # MAGIC COOKIE
	fields.append(optionsProcessor.write(mType)) # OPTIONS
	message = ''.join(fields)+'ff'
	asbytes = toBytes(message)
	return asbytes

TEMPLATE_OFFER = write(optionsProcessor.DHCP_OFFER)
TEMPLATE_ACK   = write(optionsProcessor.DHCP_ACK)

def fill(mType, XID, YIADDR, CHADDR):
	xid   = toBytes(XID)
	yaddr = toBytes(YIADDR)
	addr  = toBytes(pad(CHADDR))

	if mType == 'offer':
		return TEMPLATE_OFFER.format(xid,yaddr,addr)
	return TEMPLATE_ACK.format(xid,yaddr,addr)

def pad(chaddr):
	size = 2*4*4+192
	return chaddr + '0'*(size-len(chaddr))

def clear_stuffing(byteStr):
	for i in range(len(byteStr),0,-2):
		i -= 1
		if byteStr[i] != '0':
			break
	return byteStr[:i+2]

def getOpts(packet):
	values = []
	while packet[0] != 'ff':
		values.append(getVariable(packet))
	return values

def get(byteList, nbytes):
	value = []
	for i in range(nbytes):
		value += byteList[0]
		del byteList[0]
	return '0x'+''.join(value)

def getVariable(byteList):
	head = int(get(byteList,1),16)
	nbytes = int(get(byteList,1),16)
	tail = get(byteList,nbytes)
	return head,tail

def getFields(packet):
	packet = [unbytefy(b) for b in packet]
		
	assert all([len(x)==2 for x in packet])

	fields = {}
	fields['op']     = get(packet, 1)
	fields['htype']  = get(packet, 1)
	fields['hlen']   = get(packet, 1)
	fields['hops']   = get(packet, 1)
	fields['xid']    = get(packet, 4)
	fields['secs']   = get(packet, 2)
	fields['flags']  = get(packet, 2)
	fields['ciaddr'] = get(packet, 4)
	fields['yiaddr'] = get(packet, 4)
	fields['siaddr'] = get(packet, 4)
	fields['giaddr'] = get(packet, 4)
	fields['chaddr'] = clear_stuffing(get(packet, 4*4+192))
	fields['cookie'] = get(packet, 4)
	fields['opts']   = getOpts(packet) # opts[0] -> Discover, Offer, Request, Ack, Nak
	return fields

def echo_server(port):
	import json
	""" A simple echo server """
	# Create a UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	# 25 here corresponds to SO_BINDTODEVICE, which is not exposed by Python (presumably for portability reasons).
	sock.setsockopt(socket.SOL_SOCKET, 25, info.myInfo()[0])

	# Bind the socket to the port
	server_address = (host, port)
	print ("Starting up echo server on %s port %s" % server_address)

	sock.bind(server_address)

	while True:
		print ("Waiting to receive message from client")
		data, address = sock.recvfrom(data_payload)
	
		print ("received %s bytes from %s" % (len(data), address))
		# print ("Data: %s" %data)
	
		if data:
			print (json.dumps(getFields(data), indent=4))
			# fields = packet[0:480]
			# options = packet[480:]


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Socket Server Example')
	# parser.add_argument('--port', action="store", dest="port", type=int, required=True)
	given_args = parser.parse_args() 
	# port = given_args.port
	echo_server(DHCP_SERVER_PORT)
