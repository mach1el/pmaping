import sys
import time
import queue

from lib import Header
from lib import parseURL

from threading import *
from core.printf import *
from lib.socketHandle import *
from lib.packetHandle import *
from core import Exceptions as exce

sys.dont_write_bytecode=True

resolved = queue.Queue()
unresolved = queue.Queue()
threads_lock = Semaphore(1000)

class Scanner(Header):
	def __init__(self,target,*args):
		Header.__init__(self,target,*args)
		self._start()

		if type(self.ports) == tuple or len(self.ports) == 1:
			self._Non_thread_scanning()
		else:
			self._Multi_threads_scanning()

	def _Non_thread_scanning(self):
		start = time.time()

		try:
			for port in self.ports:
				if self.scan_type == "conn":
					try:
						mysocket = create_tcp_socket(self.scan_type,self.timeout)
						mysocket.connect((self.ip,int(port)))
					except timeout:
						self.filtered.append(port)
					except ConnectionRefusedError:
						self.refused.append(port)
					else:
						mysocket.send('\x01\x40\x00\r\n'.encode('utf-8'))
						data = mysocket.recv(2048)
						mysocket.close()
						init('|--- Discovered open port {0}/tcp on {1}'.format(str(port),self.ip))
						self.opened.append(port)
					time.sleep(.3)

				elif self.scan_type == "syn":
					mysocket = create_tcp_socket(self.scan_type,self.timeout)
					setup_packet = TCPPacket(self.ip,int(port),self.sip,'syn')
					mysocket.sendto(setup_packet.building_packet(),(self.ip,0))
					packet = self.tcp_packet_capture.next()
					if packet[1] == b"":
						self.filtered.append(port)

					else:
						upack = UnpackPacket(packet[1],self.quite,self.portresult)
						data = upack._unpackTCP()
						self.opened.append(data)
					time.sleep(.3)

				elif self.scan_type == "udp":
					try:

						mysocket = create_udp_socket(self.timeout)
						setup_packet = UDPPacket(self.data,int(port),self.sport,self.ip,self.sip)
						mysocket.sendto(setup_packet.assemble(),(self.ip,0))
						packet = self.udp_packet_capture.next()

						if packet[1] == b"":
							self.filtered.append(port)

						else:
							data = self.udp_packet.disassemble(packet[1],self.portresult)
							if data[1] == "closed":
								self.refused.append(data)

							else:
								self.open.append(data)

					except Exception as e:
						sys.exit(msgStat(e,err=True)())

					time.sleep(.3)

			end = time.time()
			total_time = end - start

			strs = '[{0}] Completed Scan,{1}s elapsed [{2} total port(s)]'.format (
						timed(),\
						str(total_time)[:4],\
						len(self.ports)
					)
			msgStat(strs,nor=True)()

			if self.ipv6 != None:
				init('|--- Other address from {0} (not scanned): {1}'.format(self.target,self.ipv6))
			init('[{0}] Pmap process completed for: {1}'.format(
						timed(),
						self.target
					)
				)
			init(psheader())

			if self.scan_type == "conn":
				for port in self.opened:
					port_serv = getportserv(int(port))
					init( PortResult (
							"tcp",port,'open',port_serv,'syn-ack'
							)
						)

			elif self.scan_type == "syn":
				for port,state,port_serv,reason in self.opened:
					init( PortResult (
							"tcp",port,state,port_serv,reason
						)
					)

			else:
				for port,state,port_serv,reason in self.opened:
					init( PortResult (
							"udp",port,state,port_serv,reason
						)
					)


			for port in self.filtered:
				port_serv = getportserv(int(port))

				if self.scan_type == "conn" or self.scan_type == "syn":
					init( PortResult (
							"tcp",port,'filtered',port_serv,'no-response'
						)
					)

				elif self.scan_type == "udp":
					init( PortResult (
							"udp",port,'open|filtered',port_serv,'no-response'
						)
					)

			if self.scan_type == "conn":
				for port in self.refused:
					port_serv = getportserv(int(port))
					init( PortResult (
							"tcp",port,'closed',port_serv,'conn-resfused'
						)
					)

			elif self.scan_type == "udp":
				for port,state,port_serv,reason in self.refused:
					init( PortResult (
							"udp",port,state,port_serv,reason
						)
					)

		except KeyboardInterrupt:
			sys.exit(msgStat(exce.UserInterrupt(),err=True)())

	def _Multi_threads_scanning(self):
		start = time.time()

		filtered = self.port_len
		
		try:
			for port in self.ports:
				unresolved.put((self.ip,int(port),self.timeout))

			for _ in range(self.threads):
				proc = Thread(target=self._Scan_proc)
				proc.daemon = True
				proc.start()

			for _ in range(self.threads):
				proc.join()

			end = time.time()
			total_time = end - start
			strs = '[{0}] Completed Scan,{1}s elapsed [{2} total port(s)]'.format(
					timed(),\
					str(total_time)[:5],\
					self.port_len
			)
			msgStat(strs,nor=True)()

			if self.ipv6 != None:
				init('|--- Other address from {0} (not scanned): {1}'.format(self.target,self.ipv6))

			init(psheader())

			while 1:
				if not resolved.empty():
					with threads_lock:
						port,state,serv,reason = resolved.get()
						if state == "open" or state == "closed":
							filtered -= 1

						init( PortResult (
								self.conn_type,port,state,serv,reason
								)
							)
					resolved.task_done()

				else : break

			init("")

			if len(self.ports) > 100:
				if self.scan_type == "udp":
					init('|--- Not shown: %d open|filtered ports' % filtered)

				else:	
					init('|--- Not shown: %d filtered ports' % filtered)

				init('|--- Reason: %d ports are no-responses' % filtered)

			init('[{0}] Pmap process completed for: {1}'.format(
						timed(),
						self.target
					)
				)
		except KeyboardInterrupt:
			sys.exit(msgStat(exce.UserInterrupt(),err=True)())

	def _Scan_proc(self):
		count = 0

		try:
			while 1:
				if not unresolved.empty():
					with threads_lock:
						ip,port,timeout = unresolved.get()

					if self.scan_type == "conn":

						mysocket = create_tcp_socket(self.scan_type,timeout)
						status = mysocket.connect_ex((ip,port))
						mysocket.close()

						if status == 0:
							with threads_lock:
								count += 1
								serv = getportserv(port)
								init('|--- Discovered open port {0}/tcp on {1}'.format(str(port),ip))
								resolved.put((port,'open',serv,'syn-ack'))

						elif status == 11:
							with threads_lock:
								count+=1
								if self.port_len <= 100:
									resolved.put((port,'filtered',serv,'no-response'))

						elif status == 111:
							with threads_lock:
								count += 1
								resolved.put((port,'closed',serv,'conn-resfused'))

						else:
							with threads_lock:
								count += 1

					elif self.scan_type == "syn":
						mysocket = create_tcp_socket(self.scan_type,self.timeout)
						setup_packet = TCPPacket(self.ip,int(port),self.sip,'syn')
						mysocket.sendto(setup_packet.building_packet(),(self.ip,0))
						with threads_lock:
							packet = self.tcp_packet_capture.next()

						if packet[1] == b"":
							with threads_lock:
								count += 1
								serv = getportserv(int(port))
								if len(self.ports) <= 100:
									resolved.put((port,"filtered",serv,"no-response"))

						else:
							with threads_lock:
								count += 1
								upack = UnpackPacket(packet[1],self.quite,self.portresult)
								data = upack._unpackTCP()
								resolved.put(data)

					elif self.scan_type == "udp":
						mysocket = create_udp_socket(timeout)
						setup_packet = UDPPacket(self.data,int(port),self.sport,self.ip,self.sip)
						mysocket.sendto(setup_packet.assemble(),(self.ip,0))
						
						with threads_lock:
							packet = self.udp_packet_capture.next()

						if packet[1] == b"":
							with threads_lock:
								count += 1
								serv = getportserv(int(port))
								if len(self.ports) <= 100:
									resolved.put((port,'open|filtered',serv,'no-response'))
						else:
							with threads_lock:
								count += 1
								data = self.udp_packet.disassemble(packet[1],self.portresult)
								resolved.put(data)

					unresolved.task_done()

				else : break

				#time.sleep(.3)

		except Exception as e:
			sys.exit(msgStat(e,err=True)())

		except KeyboardInterrupt:
			sys.exit(msgStat(exce.UserInterrupt(),err=True)())