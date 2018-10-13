import sys
from time import strftime,localtime
sys.dont_write_bytecode=True

def timed():
    return(strftime("%H:%M:%S",localtime()))

def init(text,flush=False):
	text=str(text)
	if flush:
		sys.stdout.write(text)
		sys.stdout.flush()
	else:
		text = str(text)+"\n"
		sys.stdout.write(text)

def psheader():
	return("\n{PORT:<12}┃ {STATE:<14s}┃ {SERV:<17s}┃ {REASON}".format(
				PORT="PORT",
				STATE="STATE",
				SERV="SERV",
				REASON="REASON"
			) + "\n" + "{0}┃{1}┃{2}┃{3}".format(
					"¯"*12,
					"¯"*15,
					"¯"*18,
					"¯"*18
				)
		)

def PortResult(	
				type,
				port,
				state,
				serv,
				reason,
				open='\033[1;32;40m',
				close='\033[1;31;40m',
				filtered='\033[1;33;40m',
				end='\x1b[0m'
			):
				type = "/" + type

				if state == "open":
					state = open + state + end
				elif state == "closed":
					state = close + state + end
				else:
					state = filtered + state + end
				result = "{Port:<12s}┃ {State:<28s}┃ {Serv:<17s}┃ {Reason}".format(
							Port=str(port)+type,
							State=state,
							Serv=serv,
							Reason=reason
					)

				return (result)


class msgStat(object):
	def __init__(self,msg,err=False,warn=False,nor=False,resp=False):
		self.msg = str(msg)
		self.err = '\033[1;91m'
		self.warn = '\033[1;93m'
		self.nor = '\033[1;94m'
		self.resp = '\033[1;92m'
		self.end = '\x1b[0m\n'

		if err:
			self.str = self.err + self.msg + self.end
		elif warn:
			self.str = self.warn + self.msg + self.end
		elif nor:
			self.str = self.nor + self.msg + self.end
		elif resp:
			self.str = self.resp + self.msg + self.end
		else:
			self.str = self.msg + self.end

	def __call__(self):
		sys.stdout.write(self.str)

class ProgressBar(object):
	def __init__(self,
		        total=100,
		        prefix='Process',
		        stuffix='Completed',
		        decimals=1,
		        barLength=30):
		super(ProgressBar,self).__init__()
		self.total	    = total
		self.prefix     = prefix
		self.stuffix    = stuffix
		self.decimals   = decimals
		self.barLength  = barLength
		self.num 		= 0

	def Count(self):
		self.num+=1
		try:
			formatStr       = "{0:." + str(self.decimals) + "f}"
			percents        = formatStr.format(100 * (self.num / float(self.total)))
			filledLength    = int(round(self.barLength * (self.num) / float(self.total)))
			bar             = '█' * filledLength + '-' * (self.barLength - filledLength)
			sys.stdout.write('%s |%s| %s%s %s\r' % (self.prefix, bar, percents, '%', self.stuffix))
			if self.num == self.total:
				sys.stdout.write('\n')
			sys.stdout.flush()

		except Exception as e:
			msgStat(e,err=True)()
		except KeyboardInterrupt:
			sys.exit(msgStat("Cancelled by user",err=True)())


class Banner(object):

	@staticmethod
	def portscanner():
		banner = '\033[33m'+'''
    ___       ___       ___       ___       ___       ___       ___   
   /\  \     /\__\     /\  \     /\  \     /\  \     /\__\     /\  \  
  /::\  \   /::L_L_   /::\  \   /::\  \   _\:\  \   /:| _|_   /::\  \ 
 /::\:\__\ /:/L:\__\ /::\:\__\ /::\:\__\ /\/::\__\ /::|/\__\ /:/\:\__\

 \/\::/  / \/_/:/  / \/\::/  / \/\::/  / \::/\/__/ \/|::/  / \:\:\/__/
    \/__/    /:/  /    /:/  /     \/__/   \:\__\     |:/  /   \::/  / 
             \/__/     \/__/               \/__/     \/__/     \/__/
'''+'¯'*40
		print(banner)
