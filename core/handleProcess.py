import os
import sys
from core.printf import *
from lib import portHandler
from core import Exceptions as exce
from lib.socketHandle import domain_resolver
from lib.scanner import Header,Scanner,parseURL

sys.dont_write_bytecode=True

class getProcess(object):
	def __init__(self,args):
		super(getProcess, self).__init__()
		self._list = self._get_processes(args)
		self.process = self._check_if_true(self._list)

	@staticmethod
	def _check_if_true(list):
		process = []
		for _ in list.items():
			if _[1] == True:
				process.append(_[0])
		return process

	@staticmethod
	def _get_processes(args):
		data = {}
		data.update({"tcpscan" : args.cS})
		data.update({"syn" : args.sS})
		data.update({"udp" : args.uS})
		return data

	def __call__(self):
		return(self.process)

class Handle(object):
	def __init__(self,process,args):
		super(Handle,self).__init__()
		host = parseURL(args.target)
		domain_resolver(host)
		self._setting_up_the_process(process,args)
		
	@staticmethod
	def _setting_up_the_process(process,args):
		uid = os.getuid()

		target = args.target
		threads = args.Threads
		quite = args.quite
		timeout = args.timeout
		ports = portHandler(args.port)

		if process == "tcpscan":
			Scanner("conn",target,ports,threads,timeout,quite)
		else:
			if uid == 1000:
				sys.exit(msgStat(exce.PermissionDenied(),err=True)())
			elif uid == 0:
				Scanner(process,target,ports,threads,timeout,quite)