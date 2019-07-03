import optionsProcessor as OptProc
from optionsProcessor import toHex, toInt
import codecs


#================================================
# Auxiliary Functions
unbytefy = lambda x : x.encode('hex')
bytefy	 = lambda x : codecs.decode(x,'hex_codec')
toBytes  = lambda x : ''.join([bytefy(x[i:i+2]) if x[i:i+2] != '{}' 
							else '{}' for i in range(0,len(x),2)])
#================================================


#================================================
# Packet Constants
host = '255.255.255.255'
data_payload = 2048
DHCP_SERVER_PORT = 67
cookie = '63825363'

padsize = 192*2
padding = '0'*padsize
size	= 4*8
#================================================


#================================================
# New IPs generator
class IP_Manager:
	def __init__(self):
		server  = toInt(OptProc.SERVER_HEX)
		netmask = toInt(OptProc.MASK_HEX)
		
		self.net = toHex(server & netmask)[:-2]

		if len(self.net) % 2:
			self.net = '0'+self.net
		self.cur = 244

	def next(self):
		ip = self.net + toHex(self.cur)
		self.cur -= 1
		self.last = ip
		return ip
manager = IP_Manager()
#================================================


#================================================
# Writes a teplate for each informed message type
def write(mType):
	fields = []
	fields.append('02') # OptProc
	fields.append('01') # htype
	fields.append('06') # hlen
	fields.append('00') # hops
	fields.append('{}') # XID
	fields.append('0'*4) # secs
	fields.append('0'*4) # flags
	fields.append('0'*8) # CIADDR
	fields.append('{}') # YIADDR
	fields.append(OptProc.SERVER_HEX) # SIADDR
	fields.append('0'*8) # GIADDR
	fields.append('{}') # CHADDR
	fields.append(padding) # Zero Stuffing
	fields.append(cookie) # MAGIC COOKIE
	fields.append(OptProc.write(mType)) # OptProcTIONS
	message = ''.join(fields)+'ff'
	asbytes = toBytes(message)
	return asbytes

TEMPLATE_OFFER = write(OptProc.DHCP_OFFER)
TEMPLATE_ACK   = write(OptProc.DHCP_ACK)
#================================================


#================================================
# Fills the template of the informed type
def fill(mType, XID, CHADDR):
	xid   = toBytes(XID)
	yaddr = toBytes(manager.next())
	addr  = toBytes(pad(CHADDR))

	if mType == 'offer':
		return TEMPLATE_OFFER.format(xid,yaddr,addr)
	return TEMPLATE_ACK.format(xid,yaddr,addr)
#================================================


#================================================
# Adds more stuffing if necessary
def pad(chaddr):
	return chaddr + '0'*(size-len(chaddr))
#================================================


#================================================
# Reads the options of the packet
def getOpts(packet, focus = None):
	values = []

	while packet[0] != 'ff':
		values.append(getVariable(packet))

		if values[-1][0]==focus:
			return values[-1][1]
			
	if focus is not None:
		return None

	return values
#================================================


#================================================
# "Pops" values from the packet
def get(byteList, nbytes):
	value = []

	for i in range(nbytes):
		value += byteList[0]
		del byteList[0]

	return ''.join(value)
#================================================


#================================================
# "Pops" fields with variable size (i.e., options)
def getVariable(byteList):
	head = toInt(get(byteList,1))
	nbytes = toInt(get(byteList,1))
	tail = get(byteList,nbytes)
	return head,tail
#================================================