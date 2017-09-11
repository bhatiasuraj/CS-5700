#!/usr/bin/python
import re
import sys
import urlparse
import socket
from random import randint
from struct import pack, unpack
import time
import array

ACK_TIME_OUT = 60
SERVER_TIME_OUT = 180

# Check if only two arguments are passed: ARG_1 ---> URL
if len(sys.argv) != 2:
                print "Incorrect format, please try again!"
                sys.exit()

url = sys.argv[1]

# Appending http to the URL if not present
if 'http://' == url[:7]:
        new_url = url
else:
        new_url = 'http://'+url

# Check if given URL is valid and reachable
try:
	
        host = urlparse.urlparse(new_url).hostname
        socket.gethostbyname(host)
except socket.gaierror as ex:
        print 'Invalid url!'
        sys.exit()

# Extract host name and path from the URL
segments = url.rpartition('/')
temp = segments[0]
host = urlparse.urlparse(url).hostname
print "Host: "+host
path = urlparse.urlparse(url).path
print "Path: "+path

# Create output files depending on the path
if len(path) == 0 or url.endswith('/'):
	file_name = 'index.html'
else:
	file_name = segments[2]
if len(path) == 0:
	path = '/'
print "File name: "+file_name

# Create HTTP GET request
def get_request(host, path):
	request = 'GET ' + path + ' HTTP/1.0\r\n' + 'User-Agent: Wget/1.14 (linux-gnu)\r\n' + 'Accept: */*\r\n' + 'Host: ' + host + '\r\n' + 'Connection: keep-alive' + '\r\n\r\n'
	if len(request) % 2 != 0:
		request += ' '
	return request

# Find out the local machine IP address (not loopback)
def get_local_ip(host):
        ip_local = ''
        try:
                ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip.connect((host, 80))
                local_ip = ip.getsockname()[0]
                ip.close()
        except:
                pass
        return local_ip

# Function to calculate checksum of TCP packets
def checksum_calculate(s):
	if len(s) & 1:
		s = s + '\0'
	words = array.array('h', s)
	sum = 0
	for word in words:
		sum = sum + (word & 0xffff)
	hi = sum >> 16
	lo = sum & 0xffff
	sum = hi + lo
	sum = sum + (sum >> 16)
	return (~sum) & 0xffff

# Creating TCP header
tcp_checksum = 0
tcp_fin = 0
tcp_syn = 0
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_urg_ptr = 0
tcp_window = socket.htons (5840)
tcp_doff = 5
data = ''

request = get_request(host, path)
source_ip = get_local_ip(host)
dest_ip = socket.gethostbyname(host)
source_port = randint(30000,65535)
dest_port = '80'
seq_num = randint(30000, 65535)
ack_num = 0
print '\nInitialization done, attempting connection to ... '+host+'\n'
# Sending TCP SYN to server as first part of three-way-handshake
tcp_syn = 1

ip_ihl = 5
ip_version = 4
ip_tos = 0
ip_tot_len = 0 
ip_id = randint(10000, 65000)   
ip_frag_off = 0
ip_ttl = 255
ip_protocol = socket.IPPROTO_TCP
ip_checksum = 0    
ip_source= socket.inet_aton(source_ip)   
ip_dest = socket.inet_aton(dest_ip)
 
ip_ihl_version = (ip_version << 4) + ip_ihl

# Creating IP header 
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_version, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_protocol, ip_checksum, ip_source, ip_dest)
 
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
tcp_reset = (tcp_doff << 4) + 0
tcp_header1 = pack('!HHLLBBHHH' , source_port, int(dest_port), seq_num, ack_num, tcp_reset, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)	
total_length = len(tcp_header1) + len(data)

source_add = socket.inet_aton(source_ip)
dest_add = socket.inet_aton(dest_ip)	
reserved = 0
pseudo_header_protocol = socket.IPPROTO_TCP

tcp_pseudo_header = pack('!4s4sBBH', source_add, dest_add, reserved, pseudo_header_protocol, total_length)
temp = tcp_pseudo_header + tcp_header1 + data   

# Calculate checksum for TCP header and data	
tcp_checksum_1 = checksum_calculate(temp)

tcp_header2 =  pack('!HHLLBBH',						
		source_port,
		int(dest_port),
		seq_num,
		ack_num,
		tcp_reset,
		tcp_flags,
		tcp_window) + pack('H',tcp_checksum_1) + pack('!H',tcp_urg_ptr)

packet = ip_header + tcp_header2 + data

def unpack_header(header):
	header = unpack('!HHLLBBHHH', header)
	print header,pack('!H', header[7])	
	header[7] = unpack('H', pack('!H', header[7]))[0]
	return header

try:
	send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#       print 'Send socket created'
except socket.error , error:
	print 'Send socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
        sys.exit()

# Sending TCP SYN packet
try:
	send_socket.sendto(packet, (dest_ip, 0))
	print 'Sending TCP SYN packet, initiating three-way-handshake ...\n'
except:
	print 'Error'

try:
	recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
#	print 'Receive socket created'
except socket.error , error:
	print 'Receive socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
	sys.exit()

# Receive SYN-ACK

while True:
	recv_packet = recv_sock.recv(65565)
	header_temp = unpack('!HHLLBBH', recv_packet[20:36])
	source_port_2 = header_temp[0]
	dest_port_2 = header_temp[1]
	if source_port_2 == 80 and dest_port_2 == source_port :
#		print 'RECEIVED'
		break

header_temp = unpack('!HHLLBBH', recv_packet[20:36])
#header_temp = unpack_header(recv_packet[20:40])
source_port_recv = header_temp[0]
dest_port_recv = header_temp[1]
seq_num_recv = header_temp[2]
ack_num_recv = header_temp[3]
tcp_reset = header_temp[4]
tcp_doff = tcp_reset >> 4
tcp_flags = header_temp[5]

tcp_fin = tcp_flags & 0x01
tcp_syn = (tcp_flags & 0x02) >> 1
tcp_rst = (tcp_flags & 0x04) >> 2
tcp_psh = (tcp_flags & 0x08) >> 3
tcp_ack = (tcp_flags & 0x10) >> 4
tcp_urg = (tcp_flags & 0x20) >> 5
tcp_window = header_temp[6]
[tcp_checksum_recv] = unpack('H', recv_packet[36:38])
#print hex(tcp_checksum_recv)
[tcp_urg_ptr] = unpack('!H', recv_packet[38:40])
data = recv_packet[tcp_doff * 4:]

source_addr = socket.inet_aton(source_ip)
dest_addr = socket.inet_aton(dest_ip)
placeHolder = 0
protocol = socket.IPPROTO_TCP
tcp_length = tcp_doff * 4 + len(data)

pseudoHeader = pack('!4s4sBBH' , source_addr , dest_addr , placeHolder , protocol , tcp_length)
tcp_header_data = recv_packet[:16] + pack('H', 0) + recv_packet[18:]
pseudoHeader = pseudoHeader + tcp_header_data

cwnd1 = 1
if ack_num_recv == (seq_num + 1) and tcp_syn == 1 and tcp_ack == 1:
	print 'TCP SYN-ACK received ...\n'
        ack_num = seq_num_recv + 1
        seq_num = ack_num_recv
       	#increase_cwnd()
	if cwnd1 <= 1000:
		cwnd1 += cwnd1
else:
	print 'Wrong SYN-ACK received'
	cwnd = 1
ip_ihl = 5
ip_version = 4
ip_tos = 0
ip_tot_len = 0  
ip_id = randint(10000, 65000)   
ip_frag_off = 0
ip_ttl = 255
ip_protocol = socket.IPPROTO_TCP
ip_checksum = 0   
ip_source= socket.inet_aton(source_ip)   
ip_dest = socket.inet_aton(dest_ip)
 
ip_ihl_version = (ip_version << 4) + ip_ihl

ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_version, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_protocol, ip_checksum, ip_source, ip_dest)
tcp_checksum = 0
tcp_fin = 0
tcp_syn = 0
tcp_rst = 0
tcp_psh = 0
tcp_ack = 1
tcp_urg = 0
tcp_urg_ptr = 0
tcp_window = socket.htons (5840)
tcp_doff = 5
data = ''

tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
tcp_reset = (tcp_doff << 4) + 0

tcp_header1 = pack('!HHLLBBHHH' , source_port, int(dest_port), seq_num, ack_num, tcp_reset, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)	
total_length = len(tcp_header1) + len(data)
source_add = socket.inet_aton(source_ip)
dest_add = socket.inet_aton(dest_ip)	
reserved = 0
pseudo_header_protocol = socket.IPPROTO_TCP

tcp_pseudo_header = pack('!4s4sBBH', source_add, dest_add, reserved, pseudo_header_protocol, total_length)
temp = tcp_pseudo_header + tcp_header1 + data   
	
tcp_checksum_1 = checksum_calculate(temp)
#print hex(tcp_checksum_1)
tcp_header2 =  pack('!HHLLBBH',						
		source_port,
		int(dest_port),
		seq_num,
		ack_num,
		tcp_reset,
		tcp_flags,
		tcp_window) + pack('H',tcp_checksum_1) + pack('!H',tcp_urg_ptr)

packet = ip_header + tcp_header2 + data

try:
	send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#        print 'Send socket created'
except socket.error , error:
	print 'Send socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
        sys.exit()

# Send TCP ACK to complete three-way-handshake
try:
	send_socket.sendto(packet, (dest_ip, 0))
	print 'Sending TCP ACK to server, finishing three-way-handshake!'
except:
	print 'Could not send ACK packet, Error'

# Create IP header for HTTP GET request to connect to host

ip_ihl = 5
ip_version = 4
ip_tos = 0
ip_tot_len = 0  
ip_id = randint(10000, 65000)   
ip_frag_off = 0
ip_ttl = 255
ip_protocol = socket.IPPROTO_TCP
ip_checksum = 0    
ip_source= socket.inet_aton(source_ip)   
ip_dest = socket.inet_aton(dest_ip)
 
ip_ihl_version = (ip_version << 4) + ip_ihl

# Adding HTTP GET request to data field of TCP header
data = get_request(host, path) 
print 'Sending HTTP GET request ... \n'
print data

ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_version, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_protocol, ip_checksum, ip_source, ip_dest)
tcp_checksum = 0
tcp_fin = 0
tcp_syn = 0
tcp_rst = 0
tcp_psh = 1
tcp_ack = 1
tcp_urg = 0
tcp_urg_ptr = 0
tcp_window = socket.htons (5840)
tcp_doff = 5

tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
tcp_reset = (tcp_doff << 4) + 0

tcp_header1 = pack('!HHLLBBHHH' , source_port, int(dest_port), seq_num, ack_num, tcp_reset, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)	
total_length = len(tcp_header1) + len(data)
source_add = socket.inet_aton(source_ip)
dest_add = socket.inet_aton(dest_ip)	
reserved = 0
pseudo_header_protocol = socket.IPPROTO_TCP

tcp_pseudo_header = pack('!4s4sBBH', source_add, dest_add, reserved, pseudo_header_protocol, total_length)
temp = tcp_pseudo_header + tcp_header1 + data   
	
tcp_checksum_1 = checksum_calculate(temp)
#print hex(tcp_checksum_1)
tcp_header2 =  pack('!HHLLBBH',						
		source_port,
		int(dest_port),
		seq_num,
		ack_num,
		tcp_reset,
		tcp_flags,
		tcp_window) + pack('H',tcp_checksum_1) + pack('!H',tcp_urg_ptr)

packet = ip_header + tcp_header2 + data

try:
	send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#        print 'Send socket created'
except socket.error , error:
	print 'Send socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
        sys.exit()

# Send HTTP GET request to server
try:
	send_socket.sendto(packet, (dest_ip, 0))
	print 'HTTP GET request sent!'
except:
	print 'Could not send HTTP GET request, Error'

try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
#       print 'Receive socket created'
except socket.error , error:
        print 'Receive socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
        sys.exit()
recvd_packet = {}
recvd_packet_length = 0
recvd_data = ''
print 'Receving packets ...',
# Receive loop ---> Receive chunks of data, ACK every packet and if TCP FIN received, exit loop
while True:
	packet = recv_sock.recvfrom(65565)
	packet = packet[0]
	ip_header = packet[0:20]   
	iph = unpack('!BBHHHBBH4s4s' , ip_header)
	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF     
	iph_length = ihl * 4     
	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);
	# Check if HTTP response is 200

	tcp_header = packet[iph_length:iph_length+20]
	tcph = unpack('!HHLLBBHHH' , tcp_header)
	src_port = tcph[0]
	dst_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcp_flags = tcph[5]
	tcph_length = doff_reserved >> 4
	recvd_data_length = len(packet[40:])
	recvd_data += packet[40:]

	#print recvd_data	
	tcp_fin = tcp_flags & 0x01
        tcp_syn = (tcp_flags & 0x02) >> 1
        tcp_rst = (tcp_flags & 0x04) >> 2
        tcp_psh = (tcp_flags & 0x08) >> 3
        tcp_ack = (tcp_flags & 0x10) >> 4
        tcp_urg = (tcp_flags & 0x20) >> 5
	
	tcp_window = tcph[6]
	recvd_packet_length += len(recvd_data)
	#recv_packet[sequence] = recvd_data
	
	pos = packet.find("\r\n\r\n")
        contentLengthPos = packet.find("Content-Length:")
        content_length = -1
	
	# Calculate content length of TCP packet data
	if pos > 0:
                httpHeaderEnd = pos + 4
                recvd_packet_length -= httpHeaderEnd
                
                if contentLengthPos > 0:
                    l = re.search("Content-Length: (\d+)", recvd_data)
                    content_length = int(l.group(1))
	
	# Exit loop if TCP FIN flag is set
	if tcp_fin == 1:
		print '\nInitiate teardown ...\n'
		#print 'RECVD DATA: \n\n'+str(recvd_data)
		break
		
	# Acknowledge every packet received ---> Recalculate acknowledgement and sequence numbers depending on received packet
	ack_num = sequence + recvd_data_length
	src_port = source_port
        dst_port = dst_port
        src_ip = source_ip
        dst_ip = dest_ip
        seq_num = acknowledgement
	tcp_ack = 1
	ip_ihl = 5
	ip_version = 4
	ip_tos = 0
	ip_tot_len = 0  
	ip_id = randint(10000, 65000)   
	ip_frag_off = 0
	ip_ttl = 255
	ip_protocol = socket.IPPROTO_TCP
	ip_checksum = 0   
	ip_source= socket.inet_aton(source_ip)   
	ip_dest = socket.inet_aton(dest_ip)
 
	ip_ihl_version = (ip_version << 4) + ip_ihl

	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_version, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_protocol, ip_checksum, ip_source, ip_dest)
	tcp_checksum = 0
	tcp_fin = 0
	tcp_syn = 0
	tcp_rst = 0
	tcp_psh = 0
	tcp_ack = 1
	tcp_urg = 0
	tcp_urg_ptr = 0
	tcp_window = socket.htons (5840)
	tcp_doff = 5
	data = ''
	
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
	tcp_reset = (tcp_doff << 4) + 0

	tcp_header1 = pack('!HHLLBBHHH' , source_port, int(dest_port), seq_num, ack_num, tcp_reset, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)	
	total_length = len(tcp_header1) + len(data)
	source_add = socket.inet_aton(source_ip)
	dest_add = socket.inet_aton(dest_ip)	
	reserved = 0
	pseudo_header_protocol = socket.IPPROTO_TCP

	tcp_pseudo_header = pack('!4s4sBBH', source_add, dest_add, reserved, pseudo_header_protocol, total_length)
	temp = tcp_pseudo_header + tcp_header1 + data   
	
	tcp_checksum_1 = checksum_calculate(temp)
	#print hex(tcp_checksum_1)
	tcp_header2 =  pack('!HHLLBBH',						
		source_port,
		int(dest_port),
		seq_num,
		ack_num,
		tcp_reset,
		tcp_flags,
		tcp_window) + pack('H',tcp_checksum_1) + pack('!H',tcp_urg_ptr)

	packet = ip_header + tcp_header2 + data

	try:
		send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	#        print 'Send socket created'
	except socket.error , error:
		print 'Send socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
	        sys.exit()
	
	cwnd = cwnd1
	
	# Send Acknowledge and increase window size
	try:
		send_socket.sendto(packet, (dest_ip, 0))
	#	print 'SENT'
		if cwnd <= 1000:
			cwnd += cwnd
	
	except:
		print 'Could not send ACK packet, Error'
		cwnd = 1

	# Exit receive loop if all data is received
	if content_length > 0:
                if recvd_packet_length == content_length:
			print 'Initate breakdown due to content length'		
                	break

# Check if HTTP 200 response is received, else terminate connection and exit program	

if not recvd_data.startswith("HTTP/1.1 200 OK"):
        print ('Non-200 HTTP status code is not supported')
	ack_num = sequence + recvd_data_length + 1
	seq_num = acknowledgement
	src_port = source_port
	dst_port = dest_port
	src_ip = source_ip
	dst_ip = dest_ip

	ip_ihl = 5
	ip_version = 4
	ip_tos = 0
	ip_tot_len = 0  
	ip_id = randint(10000, 65000)   
	ip_frag_off = 0
	ip_ttl = 255
	ip_protocol = socket.IPPROTO_TCP
	ip_checksum = 0    
	ip_source= socket.inet_aton(source_ip)   
	ip_dest = socket.inet_aton(dest_ip)
 
	ip_ihl_version = (ip_version << 4) + ip_ihl
	
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_version, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_protocol, ip_checksum, 	ip_source, ip_dest)
	tcp_checksum = 0
	tcp_fin = 1
	tcp_syn = 0
	tcp_rst = 0
	tcp_psh = 0
	tcp_ack = 1
	tcp_urg = 0
	tcp_urg_ptr = 0
	tcp_window = socket.htons (5840)
	tcp_doff = 5
	data = ''
			
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
	tcp_reset = (tcp_doff << 4) + 0
	
	tcp_header1 = pack('!HHLLBBHHH' , source_port, int(dest_port), seq_num, ack_num, tcp_reset, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)	
	total_length = len(tcp_header1) + len(data)
	source_add = socket.inet_aton(source_ip)
	dest_add = socket.inet_aton(dest_ip)	
	reserved = 0
	pseudo_header_protocol = socket.IPPROTO_TCP
	
	tcp_pseudo_header = pack('!4s4sBBH', source_add, dest_add, reserved, pseudo_header_protocol, total_length)
	temp = tcp_pseudo_header + tcp_header1 + data   
		
	tcp_checksum_1 = checksum_calculate(temp)
	#print hex(tcp_checksum_1)
	tcp_header2 =  pack('!HHLLBBH',						
		source_port,
		int(dest_port),
		seq_num,
		ack_num,
		tcp_reset,
		tcp_flags,
		tcp_window) + pack('H',tcp_checksum_1) + pack('!H',tcp_urg_ptr)

	packet = ip_header + tcp_header2 + data
	
	try:
		send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		#        print 'Send socket created'
	except socket.error , error:
		print 'Send socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
		sys.exit()
		
	try:
		send_socket.sendto(packet, (dest_ip, 0))
		#print 'Sending TCP FIN to server ...'
	except:
		print 'Could not send ACK packet, Error'


	try:
	        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		#print 'Receive socket created'
	except socket.error , error:
	        print 'Receive socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
	        sys.exit()
	sys.exit(0)
	
# Remove HTTP header from data
pos = recvd_data.find("\r\n\r\n")
if pos > -1:
        pos += 4
        recvd_data = recvd_data[pos:]
	
print 'All data received, creating file and writing data to '+file_name

# Opening and writing HTML data to the related file 
f = open(file_name, "w+")
f.write(recvd_data)
f.close()

# Sending last acknowledgement to server
ack_num = sequence + recvd_data_length + 1
seq_num = acknowledgement
src_port = source_port
dst_port = dest_port
src_ip = source_ip
dst_ip = dest_ip

ip_ihl = 5
ip_version = 4
ip_tos = 0
ip_tot_len = 0  
ip_id = randint(10000, 65000)   
ip_frag_off = 0
ip_ttl = 255
ip_protocol = socket.IPPROTO_TCP
ip_checksum = 0    
ip_source= socket.inet_aton(source_ip)   
ip_dest = socket.inet_aton(dest_ip)
 
ip_ihl_version = (ip_version << 4) + ip_ihl

ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_version, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_protocol, ip_checksum, ip_source, ip_dest)
tcp_checksum = 0
tcp_fin = 1
tcp_syn = 0
tcp_rst = 0
tcp_psh = 0
tcp_ack = 1
tcp_urg = 0
tcp_urg_ptr = 0
tcp_window = socket.htons (5840)
tcp_doff = 5
data = ''
		
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
tcp_reset = (tcp_doff << 4) + 0

tcp_header1 = pack('!HHLLBBHHH' , source_port, int(dest_port), seq_num, ack_num, tcp_reset, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)	
total_length = len(tcp_header1) + len(data)
source_add = socket.inet_aton(source_ip)
dest_add = socket.inet_aton(dest_ip)	
reserved = 0
pseudo_header_protocol = socket.IPPROTO_TCP
	
tcp_pseudo_header = pack('!4s4sBBH', source_add, dest_add, reserved, pseudo_header_protocol, total_length)
temp = tcp_pseudo_header + tcp_header1 + data   
		
tcp_checksum_1 = checksum_calculate(temp)
#print hex(tcp_checksum_1)
tcp_header2 =  pack('!HHLLBBH',						
		source_port,
		int(dest_port),
		seq_num,
		ack_num,
		tcp_reset,
		tcp_flags,
		tcp_window) + pack('H',tcp_checksum_1) + pack('!H',tcp_urg_ptr)

packet = ip_header + tcp_header2 + data
	
try:
	send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	#        print 'Send socket created'
except socket.error , error:
	print 'Send socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
	sys.exit()
		
try:
	send_socket.sendto(packet, (dest_ip, 0))
	print 'Sending TCP FIN to server ...'
except:
	print 'Could not send ACK packet, Error'


try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	#print 'Receive socket created'
except socket.error , error:
        print 'Receive socket could not be created. Error Code : ' + str(error[0]) + ' Message ' + error[1]
        sys.exit()
#try:
#	packet = recv_sock.recvfrom(65565)
#	print 'Received ACK from server, closing connection!'
#except:
#	print 'Could not receieve ACK'
#	sys.exit()			     

print 'Received ACK from server, closing connection!'
send_socket.close()
recv_sock.close()
print '\nOpen file '+file_name+' to see downloaded content from '+url




