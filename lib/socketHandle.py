import sys
import dns.resolver

from socket import *
from dns import rdata
from dns import reversename

from core.printf import msgStat
from core import Exceptions as exce

sys.dont_write_bytecode=True


def convert_int(num):
	return htons(num)

def resolve_ips(domain):
	try:
		ips = dns.resolver.query(domain,'A')
	except:
		ips = domain
	return ips

def resolve_ipv6(domain):
	try:
		ipv6 = dns.resolver.query(domain,'AAAA')
	except:
		ipv6 = None
	return ipv6

def getportserv(port):
	try:
		s = str(getservbyport(port))
	except:
		s = ("unknown")
	return s

def resolve_PTR(ip):
	try:
		addr = str(reversename.from_address(ip)).rstrip('.')
		data = dns.resolver.query(addr,'PTR')
		return data
	except:
		return None

def domain_resolver(domain,_return=False):
	try:
		ip = gethostbyname(domain)
	except:
		sys.exit(msgStat(exce.DomainError(),err=True)())
	else:
		if _return : return ip

def get_our_addr():
	s=socket(AF_INET,SOCK_DGRAM)
	s.connect(('google.com',0))
	return s.getsockname()[0]

def convert_ip(sip,dip):
	saddr=inet_aton(sip)
	daddr=inet_aton(dip)
	return (saddr,daddr)

def create_icmp_socket(to):
	try:
		mysock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)
		mysock.settimeout(to)
	except Exception as e:
		sys.exit(msgStat(e,err=True)())
		
	return mysock

def create_tcp_socket(type,to):
	if type == 'conn':
		mysock = socket(AF_INET,SOCK_STREAM)
		mysock.settimeout(to)
	else:
		try:
			mysock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)
			mysock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)
			mysock.settimeout(to)
		except Exception as e:
			sys.exit(msgStat(e,err=True)())
	return mysock

def create_udp_socket(to):
	try:
		mysock = socket(AF_INET,SOCK_RAW,IPPROTO_UDP)
		mysock.settimeout(to)
	except Exception as e:
		sys.exit(msgStat(e,err=True)())
	return mysock
