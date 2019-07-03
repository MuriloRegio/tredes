import os

#================================================
# Gets the info from the interface that communicates with the Internet
# May return (Interface, MAC, IP)
#	or (IP, Mask)
def myInfo(getMask = False):
	last = ["","",""]
	for line in os.popen("ip a"):
		last = last[1:] + [line.strip()]
		if "global" in line:
			break

	interface = last[0].split(':')[1].strip()
	mac 	  = last[1].split(' ')[1]
	ip, mask  = last[2].split(' ')[1].split('/')

	if getMask:
		return ip, mask

	if '@' in interface:
		interface = interface[:interface.index('@')]

	return interface, mac, ip
#================================================


if __name__ == "__main__":
	print myInfo()