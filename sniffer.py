import socket
import struct
import textwrap

TAB_1 = '\t    '
TAB_2 = '\t\t    '
TAB_3 = '\t\t\t    '
TAB_4 = '\t\t\t\t    '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def ethernet_frame(data):
    #reciever 6B ssender 6B TYPE(proto) 2B
    # only 14 B 6+6+2 = 14B
    dest_mac,src_mac,proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]

def get_mac_addr(bytes_addr):
    # 2 decimal each chunk
    bytes_str = map('{:02x}'.format,bytes_addr)
    #AA:BB:CC:DD:EE:FF
    return ':'.join(bytes_str).upper()

def main():
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,
                        socket.ntohs(3))
    while True:
        raw_data,addr = conn.recvfrom(65536)
        dest_mac,src_mac,proto,data = ethernet_frame(raw_data)
        print ('\nEthernet Frame:')
        print (TAB_1 + 'Destination:{},source:{},Protocol:{}'.format(dest_mac,src_mac,proto))

        if proto == 8:
        	(version,header_length,ttl,proto,src,target,data) = ipv4_packet(data)
        	print (TAB_1+'IPV4 Packet:')
        	print (TAB_2+'Version:{},header_length:{},TTL:{}'.format(version,header_length,ttl))
        	print (TAB_2+'Protocol:{},Source:{},Target:{}'.format(proto,src,target))

        	if proto == 1:
        		icmp_type,code,checksum,data = icmp_packet(data)
        		print (TAB_1 + 'ICMP Packet:')
        		print (TAB_2+ 'Type:{},Code:{},checksum: {}'.format(icmp_type,code,checksum))
        		print (TAB_2+'Data:')
        		print (format_multi_line(DATA_TAB_3,data)) 

        	elif proto == 6:
        		(src_port,dest_port,sequence,acknowledgement,flag,data) = tcp_segment(data)
        		print (TAB_1 + "tcp_segment:")
        		print (TAB_2 + "source port:{},dest port:{}".format(src_port,dest_port))
        		print (TAB_2 + "sequence:{},acknowledgement:{}".format(sequence,acknowledgement))
        		print (TAB_2 + "flags:")
        		print (TAB_3 + "URG:{},ACK:{},PSH:{},RST:{},SYN:{},FIN{}".format(flag[0],flag[1],flag[2],flag[3],flag[4],flag[5]))
        		print (TAB_2 + "Data:")
        		print (format_multi_line(DATA_TAB_3,data))

        	elif proto == 17:
        		src_port,dest_port,length,data = udp_segment(data)
        		print (TAB_1 + 'UDP segment:')
        		print (TAB_2 + 'Source Port:{},Destination port:{},length:{}'.format(src_port,dest_port,length))
        		print (format_multi_line(DATA_TAB_3,data))

        	else:
        		print (TAB_1,'Data:')
        		print (format_multi_line(DATA_TAB_2,data))
        else:
        	print ('Data:')
        	print (format_multi_line(DATA_TAB_1,data))

def ipv4_packet(data):
	version_header_length = data[0]
	#shifting 4 bits left 
	version = version_header_length >> 4
	header_length = (version_header_length & 15)*4
	ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
	return version,header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]

def ipv4(addr):
	return '.'.join(map(str,addr))

def icmp_packet(data):
	icmp_type,code,checksum = struct.unpack('! B B H')
	return icmp_type,code,checksum,data[4:]

def tcp_segment(data):
	(src_port,dest_port,sequence,acknowledgement,offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
	
	flag = []
    #offset = 
	offset = (offset_reserved_flags >> 12)*4
	#flag_urg = 
	flag.append((offset_reserved_flags & 32) >> 5)
	#flag_ack = 
	flag.append((offset_reserved_flags & 16) >> 4)
	#flag_psh = 
	flag.append((offset_reserved_flags & 8) >> 3)
	#flag_rst = 
	flag.append((offset_reserved_flags & 4) >> 2)
	#flag_syn = 
	flag.append((offset_reserved_flags & 2) >> 1)
	#flag_fin = 
	flag.append((offset_reserved_flags & 1))
	return src_port,dest_port,sequence,acknowledgement,flag,data[offset:]

def udp_segment(data):
	src_port,dest_port,size = struct.unpack('! H H 2x H',data[:8])
	return src_port,dest_port,size,data[8:]

#found online
def format_multi_line(prefix,string,size=80):
	size -= len(prefix)
	if isinstance(string,bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])
main()