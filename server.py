import socket
import info
from utils import *
from optionsProcessor import SERVER_HEX, addrToHex
import argparse

def getFields(packet):
	# packet = [unbytefy(b) for b in packet]
		
	def pick(packet, strt, nbytes):
		tmp = packet[strt:strt+nbytes]
		tmp = [unbytefy(b) for b in tmp]
		return get(tmp,nbytes)

	def pickOpt(packet, strt):
		tmp = []
		for b in packet[strt:]:
			tmp.append(unbytefy(b))
			if b == '\xff':
				break
		return tmp

	# assert all([len(x)==2 for x in packet])

	fields = {}
	# fields['op']     = get(packet, 1)
	# fields['htype']  = get(packet, 1)
	# fields['hlen']   = get(packet, 1)
	# fields['hops']   = get(packet, 1)
	# fields['xid']    = get(packet, 4)
	# fields['secs']   = get(packet, 2)
	# fields['flags']  = get(packet, 2)
	# fields['ciaddr'] = get(packet, 4)
	# fields['yiaddr'] = get(packet, 4)
	# fields['siaddr'] = get(packet, 4)
	# fields['giaddr'] = get(packet, 4)
	# fields['chaddr'] = clear_stuffing(get(packet, 4*4+192))
	# fields['cookie'] = get(packet, 4)
	# fields['opts']   = getOpts(packet) # opts[0] -> Discover, Offer, Request, Ack, Nak

	fields['xid']    = pick(packet, 4, 4)
	fields['siaddr'] = pick(packet,20, 4)
	fields['chaddr'] = pick(packet,28, 4*4)
	return fields

def echo_server(port,address):
	import json
	""" A simple echo server """
	# Create a UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	# 25 here corresponds to SO_BINDTODEVICE, which is not exposed by Python (presumably for portability reasons).
	sock.setsockopt(socket.SOL_SOCKET, 25, info.myInfo()[0])

	# Bind the socket to the port
	# server_address = (host, port)
	server_address = ('', port)
	# print ("Starting up echo server on %s port %s" % server_address)

	sock.bind(server_address)
	print address
	haddress = addrToHex(address)

	while True:
		data, _ = sock.recvfrom(data_payload)
		print ("received %s bytes from %s" % (len(data), '255.255.255.255'))
	
		if data:
			fields = getFields(data)

			response = 'ack'
			target	 = address
			if fields['siaddr'] == '00000000':
				response = 'offer'
				target	 = '255.255.255.255'
			
			sock.sendto(fill(response, fields['xid'], haddress, fields['chaddr']), (target,68))
			print 'sent', response

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Socket Server Example')
	parser.add_argument('--address', action="store", dest="address", type=str, required=False, default='10.32.143.244')
	args = parser.parse_args() 
	# port = given_args.port
	echo_server(DHCP_SERVER_PORT, args.address)
