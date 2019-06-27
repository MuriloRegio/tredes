import socket
import info
from utils import *
from optionsProcessor import SERVER_HEX

def getFields(packet):
	# packet = [unbytefy(b) for b in packet]
		
	def pick(packet, strt, nbytes):
		tmp = packet[strt:strt+nbytes]
		tmp = [unbytefy(b) for b in tmp]
		return get(tmp,nbytes)
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
	opts = 4*4+192 + 28 + 4
	pack_opts = pick(packet,opts,len(packet))

	fields['xid']    = pick(packet, 4, 4)
	fields['siaddr'] = pick(packet,20, 4)
	fields['chaddr'] = pick(packet,28, 4*4)
	fields['opts']   = getOpts(packet, focus = '50')
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
	# server_address = (host, port)
	server_address = ('', port)
	# print ("Starting up echo server on %s port %s" % server_address)

	sock.bind(server_address)

	while True:
		data, address = sock.recvfrom(data_payload)
		print ("received %s bytes from %s" % (len(data), address))
	
		if data:
			fields = getFields(data)

			response = 'ack'
			if fields['siaddr'] == '00000000':
				response = 'offer'
			
			sock.sendto(fill(response, fields['xid'], fields['opts'], fields['chaddr']), (toAddr(fields['opts']),68))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Socket Server Example')
	# parser.add_argument('--port', action="store", dest="port", type=int, required=True)
	given_args = parser.parse_args() 
	# port = given_args.port
	echo_server(DHCP_SERVER_PORT)
