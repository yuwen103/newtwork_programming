#! encoding:utf-8  
import socket
import struct
from random import randint


def discover():
    s.sendto(packet, ('140.123.104.247',67))

def request(data):
    packet2 = b''
    packet2 += data[0:1]   #OP
    packet2 += data[1:2]   #HTYPE
    packet2 += data[2:3]   #HLEN
    packet2 += data[3:4]   #HOPS 
    packet2 += data[4:8]      #XID
    packet2 += data[8:10]    #SECS
    packet2 += data[10:12]   #FLAGS
    packet2 += data[12:16]   #CIADDR
    packet2 += b'\x00\x00\x00\x00'   #YIADDR
    packet2 += data[20:24]   #SIADDR
    packet2 += data[24:28]   #GIADDR
    packet2 += data[28:32]   #Client MAC address
    packet2 += data[32:36]   #Client hardware address 
    packet2 += data[36:40] #Server host name not given
    packet2 += data[40:44] #Boot file name not given
    packet2 += data[44:48]   #Magic cookie: DHCP
    packet2 +="requ".encode('utf-8')
    packet2 +=b'\x00' * 210
    s.sendto(packet2, ('140.123.104.247',67))	

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
s.bind(('',68))

XID=b''
option="disc"

for i in range(4):
    n=randint(0,255)
    XID +=struct.pack('!B',n)

packet = b''
packet += b'\x01'   #Message type: Boot Request (1)
packet += b'\x01'   #Hardware type: Ethernet
packet += b'\x06'   #Hardware address length: 6
packet += b'\x00'   #Hops: 0 
packet += XID       #Transaction ID
packet += b'\x00\x00'    #Seconds elapsed: 0
packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
#packet += macb
packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
packet += b'\x00' * 67  #Server host name not given
packet += b'\x00' * 125 #Boot file name not given
packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
#packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'
packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
packet += b'\xff'   #End Option

#packet = b''
#packet += b'\x01'   #OP
#packet += b'\x01'   #HTYPE
#packet += b'\x06'   #HLEN
#packet += b'\x00'   #HOPS 
#packet += XID       #XID
#packet += b'\x00\x00'    #SECS
#packet += b'\x80\x00'   #FLAGS
#packet += b'\x00\x00\x00\x00'   #CIADDR
#packet += b'\x00\x00\x00\x00'   #YIADDR
#packet += b'\x00\x00\x00\x00'   #SIADDR
#packet += b'\x00\x00\x00\x00'   #GIADDR
#packet += b'\x00\x26\x9e\x04'   #Client MAC address
#packet += b'\x00\x00\x00\x00'   #Client hardware address 
#packet += b'\x00\x00\x00\x00' #Server host name not given
#packet += b'\x00\x00\x00\x00' #Boot file name not given
#packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
#packet +=option.encode('utf-8')
#packet +=b'\x00' * 210

while True:
    discover()
    str, addr=s.recvfrom(4096)
    print("Get the IP first:",str[16:20],struct.unpack('B',str[16:17])[0],",",struct.unpack('B',str[17:18])[0],",",struct.unpack('B',str[18:19])[0],",",struct.unpack('B',str[19:20])[0])
    break
while True:
    request(str)
    str2, addr2=s.recvfrom(4096)
#last_id=str(struct.unpack('B',str2[16:17])[0])+"."+str(struct.unpack('B',str2[17:18])[0])+"."+str(struct.unpack('B',str2[18:19])[0])+"."+str(struct.unpack('B',str2[19:20])[0])
    print("Get the IP second:",str2[16:20],struct.unpack('B',str2[16:17])[0],",",struct.unpack('B',str2[17:18])[0],",",struct.unpack('B',str2[18:19])[0],",",struct.unpack('B',str2[19:20])[0])
    break
#while True:  
#    msg = input("Input anything:")  
#    if not msg:  
#        break  
#    s.sendto(msg.encode('utf-8'), ('localhost',67))  
#    str, addr=s.recvfrom(2048)
#    if not str:
#       print("no get")
#   else:
#        print(str[0:2])
s.close()