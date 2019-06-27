
import socket
import info
from utils import *
from optionsProcessor import SERVER_HEX

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# 25 here corresponds to SO_BINDTODEVICE, which is not exposed by Python (presumably for portability reasons).
sock.setsockopt(socket.SOL_SOCKET, 25, info.myInfo()[0])
sock.bind(('',67))

# Bind the socket to the port
server_address = (host, DHCP_SERVER_PORT)
print ("Starting up echo server on %s port %s" % server_address)

sock.sendto(fill('offer', '3903F326', SERVER_HEX, SERVER_HEX), ('192.168.0.10',68))