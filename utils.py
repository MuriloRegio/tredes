import optionsProcessor

unbytefy = lambda x : x.encode('hex')
bytefy   = lambda x : "\\x{}".format(x).decode('unicode_escape')
toBytes  = lambda x : ''.join([bytefy(x[i:i+2]) if x[i:i+2] != '{}' 
							else '{}' for i in range(0,len(x),2)])


host = '255.255.255.255'
data_payload = 2048
DHCP_SERVER_PORT = 67
cookie = '63825363'

padding = '0'*192

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
	fields.append(cookie) # MAGIC COOKIE
	fields.append(optionsProcessor.write(mType)) # OPTIONS
	message = ''.join(fields)+'ff'
	print message
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
	size = 2*4*4
	return chaddr + '0'*(size-len(chaddr)) + padding

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