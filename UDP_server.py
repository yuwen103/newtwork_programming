#! encoding:utf-8  
import socket  
import struct
from random import randint


#address = ('127.0.0.1', 31500)  
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
s.bind(('',67))  
ipaddr=[]

for i in range(100):
    ipaddr.append(0)

def getip(data):
    while True:
        n=randint(0,99)
        if ipaddr[n]==0:
            ipaddr[n]=str(struct.unpack('B',data[4:5])[0])+"."+str(struct.unpack('B',data[5:6])[0])+"."+str(struct.unpack('B',data[6:7])[0])+"."+str(struct.unpack('B',data[7:8])[0])
            return 127+n

def regetip(data):
    xid=str(struct.unpack('B',data[4:5])[0])+"."+str(struct.unpack('B',data[5:6])[0])+"."+str(struct.unpack('B',data[6:7])[0])+"."+str(struct.unpack('B',data[7:8])[0])
    for t in range(100):
        if ipaddr[t]==xid:
            n=t+127
            break
    return n

def offer(data,ip):
    packet = b''
    packet += data[0:1]   #OP
    packet += data[1:2]   #HTYPE
    packet += data[2:3]   #HLEN
    packet += data[3:4]   #HOPS 
    packet += data[4:8]      #XID
    packet += data[8:10]    #SECS
    packet += data[10:12]   #FLAGS
    packet += data[12:16]   #CIADDR
    packet += b'\xC0\xA8\x01'+struct.pack('!B',ip)   #YIADDR
    packet += b'\xC0\xA8\x01\x01'   #SIADDR
    packet += data[24:28]   #GIADDR
    packet += data[28:32]   #Client MAC address
    packet += data[32:36]   #Client hardware address 
    packet += data[36:40] #Server host name not given
    packet += data[40:44] #Boot file name not given
    packet += data[44:48]   #Magic cookie: DHCP
    packet +="offe".encode('utf-8')
    return packet

def ACK(data,ip):
    packet2 = b''
    packet2 += data[0:1]   #OP
    packet2 += data[1:2]   #HTYPE
    packet2 += data[2:3]   #HLEN
    packet2 += data[3:4]   #HOPS 
    packet2 += data[4:8]      #XID
    packet2 += data[8:10]    #SECS
    packet2 += data[10:12]   #FLAGS
    packet2 += data[12:16]   #CIADDR
    packet2 += b'\xC0\xA8\x01'+struct.pack('!B',ip)   #YIADDR
    packet2 += b'\xC0\xA8\x01\x01'   #SIADDR
    packet2 += data[24:28]   #GIADDR
    packet2 += data[28:32]   #Client MAC address
    packet2 += data[32:36]   #Client hardware address 
    packet2 += data[36:40] #Server host name not given
    packet2 += data[40:44] #Boot file name not given
    packet2 += data[44:48]   #Magic cookie: DHCP
    packet2 +="offe".encode('utf-8')
    return packet2

data=''
while True:
    try:
        s.settimeout(10.0)
        data, addr = s.recvfrom(2048)
    except:
        print('time out')
    if not data:  
        print("client has not exist")
    else:
        #print(data,addr)
        #s.sendto("Server get client message.".encode('utf-8'),addr)
        if data[48:52]==b'disc':
            new_ip=getip(data)
            new_pack=offer(data,new_ip)
            s.sendto(new_pack,addr)
            #s.sendto("Server get abc.".encode('utf-8'),addr)
        elif data[48:52]==b'requ':
            new_ip2=regetip(data)
            new_pack2=ACK(data,new_ip2)
            s.sendto(new_pack2,addr)
            #s.sendto("Server get abc.".encode('utf-8'),addr)
           # s.sendto("over.".encode('utf-8'),addr)
          #  break
        #else:
            #s.sendto("Not disc".encode('utf-8'),addr)
    data=''
s.close()  