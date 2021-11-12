
# importing libraries and modules
from struct import *
import socket
import struct
import binascii


rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
host_ip = socket.gethostbyname(socket.gethostname())
rawSocket.bind((host_ip, 65535))
print('\n\t\t starting up on %s port %s\n' % rawSocket.getsockname())

rawSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
rawSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print("\t\t Fetching Packets..........\n")
for length in range(1, 11):
    newPacket = rawSocket.recvfrom(66535)
    print("******************** Packet {} Info ***************************".format(length))
    print(newPacket)
    print("******************* End of Packet {} Info ********************\n\n".format(length))

    print("Unpacking Packet {}..........\n".format(length))
    currentPacket = newPacket[0]
    # currentPacket = newPacket[0]
    ipHeader = currentPacket[0:20]
    ethernet_header = currentPacket[0:14]
    net_header = struct.unpack("!6s6s2s", ethernet_header)  # 6 byte destination -> 6 byte source -> 2 byte ether type

    print("Loading Ethernet Header ----->")
    print("\tDestination MAC : {}\n".format(binascii.hexlify(net_header[0])) +
          "\tSource MAC : {}\n".format(binascii.hexlify(net_header[1])) +
          "\tEther Type : {}\n".format(binascii.hexlify(net_header[2])))

    print("Loading Destination IP and Source IP ----->")

    ipaddress_header = struct.unpack("!BBHHHBBH4s4s", ipHeader)
    print("\tSource IP : {}\n".format(socket.inet_ntoa(ipaddress_header[8])) +
          "\tDestination IP : {}\n".format(socket.inet_ntoa(ipaddress_header[9])))

    # write another function to include the website being accessed
    # write packets to a file then create a new .py file to implement the remaining functions
    # use time sensitive functions to examine the intervals of specific IP address
    # use charts or graphs to show the distribution of IP address for the network traffic
    # -Singular Value Decomposition
    # -Data science Engineering
