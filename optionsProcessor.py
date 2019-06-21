import info

toInt     = lambda x : int(x,16)
toAddr    = lambda x : '.'.join([str(toInt(x[i:i+2])) for i in range(0,len(x),2)])
addrToHex = lambda a : ''.join([
		k if len(k) == 2 else '0'+k
		[hex(int(x)) for x in a.split('.')]
	])


mask   = info.myInfo(True)
server = info.myInfo()[-1]

MASK_HEX   = addrToHex(mask)
SERVER_HEX = addrToHex(server)


DHCP_DISCOVER = 1
DHCP_OFFER    = 2
DHCP_REQUEST  = 3
DHCP_ACK      = 5
DHCP_NAK      = 6

lease = "015180" # Hex for 1 day worth of seconds

def read(options):
	def get(opt):
		head, tail = opt[0]
		del opt[0]
		return head,tail[2:]

	keys = { 53:('type',toInt), 
			 50:('addr',toAddr), 
			 55:('pars', lambda x : x),
			 54:('server',toAddr)
			}
	fields = {}

	while len(options)>0:
		head,tail = get(options)

		if head in keys:
			key, f = keys[head]
			fields[key] = f(tail)

	return fields


def write(mType):
	t = hex(53)+hex(0)+hex(1)+hex(mType)
	m =  hex(0)+hex(1)+hex(4)+MASK_HEX
	r =  hex(0)+hex(3)+hex(0)+hex(4)+SERVER_HEX
	l = hex(51)+hex(0)+hex(2)+lease
	s = hex(54)+hex(0)+hex(4)+SERVER_HEX

	d = hex(0)+hex(6)+hex(len(4*DNS_SERVERS))
	for srvr in DNS_SERVERS:
		for nmbr in srvr.split('.'):
			d+= hex(int(nmbr))

	return ''.join([t,m,r,l,s,d])