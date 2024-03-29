import info


#================================================
# Auxiliary Functions
toHex 	  = lambda x : hex(x)[2:] if x>15 else '0'+hex(x)[2:]
toInt     = lambda x : int(x,16)
toAddr    = lambda x : '.'.join([str(toInt(x[i:i+2])) for i in range(0,len(x),2)])
addrToHex = lambda a : ''.join([toHex(int(x)) for x in a.split('.')])
#================================================


#================================================
# Local Info
mask	= '1'*int(info.myInfo(True)[-1])
mask	= mask + ('0'*(32-len(mask)))
mask	= '.'.join([str(int(mask[i:i+8],2)) for i in range(0,len(mask),8)])
server	= info.myInfo()[-1]

DNS_SERVERS = [server]

MASK_HEX   = addrToHex(mask)
SERVER_HEX = addrToHex(server)
#================================================


#================================================
# DHCP Constants
DHCP_DISCOVER = 1
DHCP_OFFER    = 2
DHCP_REQUEST  = 3
DHCP_ACK      = 5
DHCP_NAK      = 6

lease = "00015180" # Hex for 1 day worth of seconds
#================================================


#================================================
# Writes the default required options
def write(mType):
	t = toHex(53)+toHex(1)+toHex(mType)
	m =  toHex(1)+toHex(4)+MASK_HEX
	r =  toHex(3)+toHex(4)+SERVER_HEX
	l = toHex(51)+toHex(4)+lease
	s = toHex(54)+toHex(4)+SERVER_HEX

	d = toHex(6)+toHex(4*len(DNS_SERVERS))
	for srvr in DNS_SERVERS:
		d += addrToHex(srvr)

	return ''.join([t,m,r,l,s,d]).replace('0x','')
#================================================