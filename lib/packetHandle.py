import os
import sys
import time
import array
from random import *
from struct import *
from lib.socketHandle import *

sys.dont_write_bytecode=True


def macth_ttl():
	if sys.platform == 'linux2':
		return 64
	elif sys.platform == 'win32':
		return 128
	else:
		return 255

def macth_winz():
	if sys.platform == 'linux2':
		return 5840
	elif sys.platform == 'win32':
		return 8192
	else:
		return 4128

def macth_flag(type):
	tcp_fin	 = 0
	tcp_syn	 = 0
	tcp_rst	 = 0
	tcp_psh	 = 0
	tcp_ack	 = 0
	tcp_urg	 = 0

	if type == 'fin':
		tcp_fin += 1
		
	elif type == 'syn':
		tcp_syn += 1

	elif type == 'ack':
		tcp_ack += 1

	elif type == 'xmas':
		tcp_fin += 1
		tcp_urg += 1

	return (tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg)

class PingHeader(object):
	def __init__(self,ip):
		self.ip = ip
		self.type = 8
		self.code = 0
		self.cksum = 0
		self.toip = []
		self.id = os.getpid() & 0xFFFF

	def checksum(self,data):
		data = data.decode('ISO-8859-1')
		csum = 0
		countTo = (len(data) / 2) * 2
		count = 0
		while count < countTo:
			thisVal = ord(data[count+1]) * 256 + ord(data[count])
			csum = csum + thisVal
			csum = csum & 0xffffffff
			count = count + 2
		if countTo < len(data):
			csum = csum + ord(data[len(data) - 1])
			csum = csum & 0xffffffff
		csum = (csum >> 16) + (csum & 0xffff)
		csum = csum + (csum >> 16)
		answer = ~csum
		answer = answer & 0xffff
		answer = answer >> 8 | (answer << 8 & 0xff00)
		return answer

	def building_packet(self):
		header = pack('bbHHh',self.type,self.code,self.cksum,self.id,1)
		data = pack('d',time.time())
		mycksum = self.checksum(header+data)
		
		if sys.platform == 'darwin':
			mycksum = htons(mycksum) & 0xffff
		else:
			mycksum = htons(mycksum)
		header = pack('bbHHh',self.type,self.code,mycksum,self.id,1)
		packet = header+data

		return packet

class UnpackPacket:
	def __init__(self,packet,quite,portResult):
		self.packet = packet.decode("ISO-8859-1")
		self.quite = quite
		self.skip_port = []
		self.portResult = portResult
		self.reason = 'syn-ack'
		self.state = 'open'

	def _unpackTCP(self):
		data = self.packet[14:]
		ttl=ord(data[8])
		header_len = ord(data[0]) & 0x0f
		data = data[4*header_len:]
		(tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr) = unpack('!HHLLBBHHH', data[:20].encode('ISO-8859-1'))
		if tcp_source:
			port=self.portResult._handle(tcp_source)
			if port == None:
				pass
			else:
				serv=getportserv(port)
				
				if self.quite == True:
					return (str(port),serv,tcp_window,ttl,self.reason)
				else:
					return (port,self.state,serv,self.reason)

class TCPPacket:
	def __init__(self,  
				tgt,
				dport,
				ouraddr,
				type):
		self.tgt	 = tgt
		self.dport   = dport
		self.ouraddr = ouraddr
		self.type	= type

	def cksum(self,packet):
		s = 0
		packet = packet.decode("ISO-8859-1")
		for i in range(0,len(packet),2):
			w = (ord(packet[i]) << 8) + (ord(packet[i+1]))
			s = s + w
		s = (s >> 16) + (s & 0xffff);
		s = s + (s >> 16);
		s =~ s & 0xffff
		return s

	def building_packet(self):

		ip_ihl	  = 5 
		ip_ver	  = 4
		ip_tos	  = 0 
		ip_tot_len  = 20+20
		ip_id	   = 54321
		ip_frag_off = (1 << 1) << 13
		ip_ttl	  = macth_ttl()
		ip_proto	= IPPROTO_TCP 
		ip_check	= 0
		myip		= convert_ip(self.ouraddr,self.tgt)
		ip_saddr	= myip[0]
		ip_daddr	= myip[1]

		ip_ihl_ver  = (ip_ver << 4) + ip_ihl

		ip_header   = pack('!BBHHHBBH4s4s', 
						   ip_ihl_ver, 
						   ip_tos, 
						   ip_tot_len, 
						   ip_id, 
						   ip_frag_off, 
						   ip_ttl, 
						   ip_proto, 
						   ip_check,
						   ip_saddr, 
						   ip_daddr)

		tcp_source = randrange(1024,65535)
		tcp_dest = (self.dport)
		tcp_seq	= 123456
		tcp_ack_seq = 0
		tcp_doff = 6

		(tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg) = macth_flag(self.type)

		tcp_window  = convert_int(macth_winz())
		tcp_check   = 0 
		tcp_urg_ptr = 0


		tcp_offset_res = (tcp_doff << 4) 
		tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

		options = (2 << 24) | (4 << 16) | (1460 << 0)

		tcp_header = pack('!HHLLBBHHHL', 
							   tcp_source, 
							   tcp_dest, 
							   tcp_seq, 
							   tcp_ack_seq, 
							   tcp_offset_res, 
							   tcp_flags, 
							   tcp_window, 
							   tcp_check, 
							   tcp_urg_ptr,
							   options)
		tcp_header.decode('ISO-8859-1')

		user_data = ''.encode('ascii')
		tcp_length = len(tcp_header + user_data)

		psh = pack('!4s4sBBH', 
					ip_saddr, 
					ip_daddr, 
					0, 
					ip_proto, 
					tcp_length
				);
		psh.decode('ISO-8859-1')

		psh = psh + tcp_header;

		tcp_check = self.cksum(psh)
		tcp_header = pack('!HHLLBBHHHL', 
							tcp_source, 
							tcp_dest, 
							tcp_seq, 
							tcp_ack_seq, 
							tcp_offset_res, 
							tcp_flags, 
							tcp_window, 
							tcp_check, 
							tcp_urg_ptr,
							options
					)

		return  (ip_header + tcp_header)

class UDPPacket(object):
	def __init__(self,data="",dport=4242,sport=4242,ouraddr=None,tgt=None):
		self.data	= data.encode('ascii')
		self.dport   = dport
		self.sport   = sport
		self.ouraddr = ouraddr
		self.tgt	 = tgt
		self.cksum   = 0
		self.length  = len(self.data) + 8

	def assemble(self):
	  part1 = inet_aton(self.ouraddr) +\
				   inet_aton(self.tgt)	  +\
				   pack('!BBH',
						 0,
						 IPPROTO_UDP,
						 self.length)
	  udp_header = pack('!HHHH',
						 self.sport,
						 self.dport,
						 self.length,
						 0)
	  cksum = self.checksum(part1 + udp_header)

	  packet = pack('!HHHH',
						 self.sport,
						 self.dport,
						 self.length,
						 cksum) +\
				   self.data

	  return packet

	@classmethod
	def checksum(self,data):
		if pack('H',1) == '\x00\x01':
			if len(data) % 2 == 1:
				data += '\0'
			s=sum(array.array('H',data))
			s=(s >> 16) + (s & 0xffff)
			s+=s >> 16
			s=~s
			return s & 0xffff
		else:
			if len(data) % 2 == 1:
				data += '\0'
			s=sum(array.array('H',data))
			s=(s >> 16) + (s & 0xffff)
			s+=s >> 16
			s=~s
			return (((s >> 8)&0xff)|s << 8) & 0xffff

	def disassemble(self,data,portresult):
		eth_length = 14
		eth_header = data[:eth_length]
		eth = unpack('!6s6sH' , eth_header)
		eth_protocol = ntohs(eth[2])

		if eth_protocol == 8 :
			ip_header = data[eth_length:20+eth_length]
			iph = unpack('!BBHHHBBH4s4s' , ip_header)
			version_ihl = iph[0]
			version = version_ihl >> 4
			ihl = version_ihl & 0xF
			iph_length  = ihl * 4
			ttl = iph[5]
			protocol = iph[6]
			s_addr = inet_ntoa(iph[8]);
			d_addr = inet_ntoa(iph[9]);

			if protocol == 1:
				u = iph_length + eth_length
				icmph_length = 4
				icmp_header  = data[u:u+4]
				icmph = unpack('!BBH' , icmp_header)
				type = icmph[0]
				code = icmph[1]
				checksum = icmph[2]
				h_size = eth_length + iph_length + icmph_length
				mydata = data[h_size+4:]

				extracted_data = unpack('!HH',mydata[20:24])
				(dport,sport)  = extracted_data
				if sport:
					port = portresult._handle(sport)
					if port == None:
						pass
					else:
						serv = getportserv(sport)
						if code:
							r = UDPPacket()
							reason = r._UDPPacket__match_code_reason(code)
							return (port,'closed',serv,reason)

			elif protocol == 6 :
				t = iph_length + eth_length
				tcp_header = self.packet[t:t+20]
				tcph = unpack('!HHLLBBHHH' , tcp_header)   
				source_port = tcph[0]
				dest_port = tcph[1]
				sequence = tcph[2]
				acknowledgement = tcph[3]
				doff_reserved = tcph[4]
				tcph_length = doff_reserved >> 4

				if source_port:
					serv = getportserv(source_port)
					return (str(port),'filtered',serv,self.reason)

			elif protocol == 17:
				u = iph_length + eth_length
				udph_length = 8
				udp_header = data[u:u+8]
				udph = unpack('!HHHH' , udp_header)
				source_port = udph[0]
				dest_port = udph[1]
				length = udph[2]
				checksum = udph[3]

				if source_port:
					port = portresult._handle(source_port)
					if port == None:
						pass
					else:
						serv = getportserv(source_port)
						return (source_port,'open',serv,'udp-response')

	def __match_code_reason(self,code):
		if code == 0:
			return 'Net unreachable'
		elif code == 1:
			return 'Host unreachable'
		elif code == 2:
			return 'Protocol unreachable'
		elif code == 3:
			return 'Port unreachable'
		elif code == 4:
			return 'Fragmentation needed and Don\'t fragment was set'
		elif code == 5:
			return 'Source route failed'
		elif code == 6:
			return 'Destination network unknown'
		elif code == 7:
			return 'Destination host isolated'
		elif code == 9:
			return 'Network prohibited'
		elif code == 10:
			return 'Host prohibited'
		elif code == 11:
			return 'DST network unreachable for type of service'
		elif code == 12:
			return 'DST host unreachable for type of service'
		elif code == 13:
			return 'Communication Administratively Prohibited'
		elif code == 14:
			return 'Host Precedence Violation'
		elif code == 15:
			return 'Precedence cutoff in effect'