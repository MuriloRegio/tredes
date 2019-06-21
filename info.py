#!/usr/bin/python

import struct
import socket

def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

#Gets the info from the interface that communicates with the Internet
def myInfo(getMask = False):
	import os
	last = ["","",""]
	for line in os.popen("ip a"):
		last = last[1:] + [line.strip()]
		if "global" in line:
			break

	interface = last[0].split(':')[1].strip()
	mac = last[1].split(' ')[1]

	if getMask:
		return last[2].split(' ')[1].split('/')
	
	ip = last[2].split(' ')[1].split('/')[0]

	return interface, mac, ip


if __name__ == "__main__":
	request(myInfo()[-1])
	# print myInfo()