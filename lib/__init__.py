import os
import sys
import os.path
import pcapy
import xml.etree.ElementTree

from ping import Ping
from random import *
from core.printf import *
from lib.packetHandle import *
from lib.socketHandle import *
from urllib.parse import urlparse
from os.path import dirname,abspath
from core import Exceptions as exce

sys.dont_write_bytecode=True

def parseURL(url):
	if url.startswith('http') or url.startswith('ftp'):
		parsed_uri = urlparse(url)
		old_uri = '{uri.netloc}'.format(uri=parsed_uri)
		url = old_uri
	return url

def get_ports():
	_ROOT = abspath(dirname(__file__))
	file = os.path.join(_ROOT,'portsDB',"tcpports.xml")
	return file

def portHandler(port,port_list=[]):
	if port == None:
		database = get_ports()
		parse_database = xml.etree.ElementTree.parse(database).getroot()
		for type in parse_database.findall('scaninfo'):
			ports = type.get('services')
		ports = ports.split(',')
		for port1 in ports:
			if port1.count('-') == 1:
				port2 = port1.split('-')
				for port in range(int(port2[0]),int(port2[1])+1):
					port_list.append(port)
			else:
				port_list.append(port1)
		return(port_list)

	else:
		if port.count(',') != 0:
			ports = tuple(port.split(','))
			for _ in ports:
				try:
					if isinstance(int(_),int) : pass
				except:
					sys.exit(msgStat
						(exce.ValuesError(),err=True
							)()
						)
		elif port.count('-') != 0:
			ports = port.split('-')
			for _ in ports:
				try:
					if isinstance(int(_),int):
						pass
				except:
					sys.exit(msgStat
						(exce.ValuesError(),err=True
							)()
						)
			_min = int(min([int(x) for x in ports]))
			_max = int(max([int(x) for x in ports]))
			for port in range(_min,_max+1):
				port_list.append(str(port))
			ports = port_list
			
		elif port.count(',') == 0 and port.count('-') == 0:
			ports = [port]
			
		return ports

class portResult(object):
	def __init__(self):
		self.skipports = []

	def _handle(self,port):
		if port not in self.skipports:
			self.skipports.append(port)
			return port

		else : return

class Capture(object):

	def __init__(self,tgt):
		self.tgt = tgt
		self.dev = self._get_online_device()

	def _set_tcp(self):
		p = pcapy.open_live(self.dev, 65535, 0, 1500)
		p.setfilter(('src host ') + str(self.tgt))
		return p

	def _set_udp(self):
		p = pcapy.open_live(self.dev, 99999, False, 1500)
		p.setfilter(('src host ') + str(self.tgt))
		return p

	@staticmethod
	def _get_online_device():
		_i = os.popen('ip link | grep \"state\" | awk {\'print $2 $9\'}').read()
		ifaces = _i.split('\n')
		_l = len(ifaces)
		ifaces.pop(_l-1)

		for i in ifaces:
			if "UP" in i:
				dev = i.split(":")
				_iface = dev[0]

		if _iface == None:
			sys.exit(msgStat
				(
					exce.NoOnlineDev(),err=True
				)()
			)
		else:
			return _iface

class Header(object):
	def __init__(self,scan_type,*args):
		super(Header,self).__init__()
		self.target = args[0]
		self.ports = args[1]
		self.threads = args[2]
		self.timeout = args[3]
		self.quite = args[4]
		self.opened = []
		self.refused = []
		self.filtered = []
		self.packets = []
		self.conn_type = ""
		self.data = '\x00' * 20
		self.scan_type = scan_type
		self.sip = get_our_addr()
		self.portresult = portResult()
		self.sport = randrange(1,65535)
		
		self.udp_packet = UDPPacket()
		self.port_len = len(self.ports)-1
		self.ip = domain_resolver(self.target,True)
		self.response_time = Ping(self.target,self.timeout)._start_icmp()

		if self.scan_type == "conn" or self.scan_type == "syn":
			self.conn_type += "tcp"
		elif self.scan_type == "udp":
			self.conn_type = self.scan_type

		try:
			self.ipv6 = [str(ip) for ip in resolve_ipv6(self.target)]
		except:
			self.ipv6 = None
		
		self.rdns = resolve_PTR(self.ip)
		if self.rdns != None:
			self.rdns = self.rdns[0]

		self.resolved_ips = [str(ip) for ip in resolve_ips(self.target)]
		if len(self.resolved_ips) > 1:
			if self.ip in self.resolved_ips:
				self.resolved_ips.remove(self.ip)
		
		if self.scan_type == "udp":
			self.udp_packet_capture = Capture(self.ip)._set_udp()

		else:
			self.tcp_packet_capture = Capture(self.ip)._set_tcp()

	def _start(self):
		Banner.portscanner()
		msgStat('[{0}] Started port scan process.'.format(timed()),warn=True)()

		msgStat('|--- Warning: host name {0} resolves to {1} IPs. Using {2}'.format(
				self.target,\
				len(self.resolved_ips),\
				self.ip),warn=True)()
		if self.response_time != None:
			init('|--- Host is up ({}s latency).'.format(str(self.response_time)[:5]))
		init('|--- rDNS record for {0}: {1}'.format(self.ip,self.rdns))
		init('[{0}] Initiating scan.'.format(timed()))
		init('[{0}] Scanning {1} ({2}) [{3} ports]'.format(timed(),\
				self.target,\
				self.ip,\
				str(self.port_len)	
				)
			)