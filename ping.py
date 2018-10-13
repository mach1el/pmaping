import os
import time
import struct
import select
from lib.socketHandle import *
from lib.packetHandle import PingHeader

import time
sys.dont_write_bycode=True

class Ping:
	def __init__(self,tgt,to):
		self.tgt = domain_resolver(tgt,True)
		self.to = to
		self.id = os.getpid() & 0xFFFF
		self.my_socket = create_icmp_socket(self.to)
		builder = PingHeader(self.tgt)
		self.pkt = builder.building_packet()

	def send(self):
		send_time = time.time()
		self.my_socket.sendto(self.pkt, (self.tgt, 1))
		return send_time

	def receive(self):
		while True:
			select_start = time.time()
			inputready, outputready, exceptready = select.select([self.my_socket], [], [], self.to)
			select_duration = (time.time() - select_start)
			if inputready == []:
				return 0, 0, 0, None, None

			packet, address = self.my_socket.recvfrom(65536)

			receive_time = time.time()

			icmpHeader = packet[20:28]
			type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
			if packetID == self.id:
				return receive_time

			timeout = timeout - select_duration

			if timeout <= 0:
				return 0, 0, 0, None, None

	def _start_icmp(self):
		
		for i in range(0,1):
			try:
				send_time = self.send()
				receive_time = self.receive()
			except:
				return None

		return (receive_time - send_time) * 10