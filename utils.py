import optionsProcessor
import codecs

unbytefy = lambda x : x.encode('hex')
bytefy	 = lambda x : codecs.decode(x,'hex_codec')
toBytes  = lambda x : ''.join([bytefy(x[i:i+2]) if x[i:i+2] != '{}' 
							else '{}' for i in range(0,len(x),2)])


host = '255.255.255.255'
data_payload = 2048
DHCP_SERVER_PORT = 67
cookie = '63825363'

padsize = 192*4
padding = '0'*padsize
size	= 4*8

def write(mType):
	fields = []
	fields.append('02') # OP
	fields.append('01') # htype
	fields.append('06') # hlen
	fields.append('00') # hops
	fields.append('{}') # XID
	fields.append('0'*4) # secs
	fields.append('0'*4) # flags
	fields.append('0'*8) # CIADDR
	fields.append('{}') # YIADDR
	fields.append(optionsProcessor.SERVER_HEX) # SIADDR
	fields.append('0'*8) # GIADDR
	fields.append('{}') # CHADDR
	fields.append(padding) # CHADDR
	# fields.append(cookie) # MAGIC COOKIE
	fields.append(optionsProcessor.write(mType)) # OPTIONS
	message = ''.join(fields)+'ff'
	asbytes = toBytes(message)
	return asbytes

TEMPLATE_OFFER = write(optionsProcessor.DHCP_OFFER)
TEMPLATE_ACK   = write(optionsProcessor.DHCP_ACK)

def fill(mType, XID, YIADDR, CHADDR):
	print XID
	xid   = toBytes(XID)
	print YIADDR
	yaddr = toBytes(YIADDR)
	print CHADDR
	addr  = toBytes(pad(CHADDR))
	print len(pad(CHADDR)), padsize+size

	if mType == 'offer':
		return TEMPLATE_OFFER.format(xid,yaddr,addr)
	return TEMPLATE_ACK.format(xid,yaddr,addr)

def pad(chaddr):
	return chaddr + '0'*(size-len(chaddr))

def clear_stuffing(byteStr):
	for i in range(len(byteStr),0,-2):
		i -= 1
		if byteStr[i] != '0':
			break
	return byteStr[:i+2]

def getOpts(packet, focus = None):
	values = []
	print packet
	while packet[0] != 'ff':
		values.append(getVariable(packet))

		if values[-1][0]==focus:
			return values[-1][1]
			
	if focus is not None:
		return None
	return values

def get(byteList, nbytes, vis=False):
	ret = ''
	if vis:
		ret = '0x'

	value = []
	for i in range(nbytes):
		value += byteList[0]
		del byteList[0]
	return ret+''.join(value)

def getVariable(byteList):
	head = int(get(byteList,1),16)
	nbytes = int(get(byteList,1),16)
	tail = get(byteList,nbytes)
	return head,tail