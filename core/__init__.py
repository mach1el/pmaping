import sys
sys.dont_write_bytecode=True

class Exceptions(object):
	def Timedout():
		return("[-] Timed out!!!")

	def ValuesError():
		return("[-] Found another type instead int in port range.")

	def UserInterrupt():
		return("Cancelled by user.")

	def DomainError():
		return("[-] Couldn't resolve your target.")
		
	def PermissionDenied():
		return("[-] Permission denided.")

	def NoOnlineDev():
		return("[-] Not found online device.")