import sys
from argparse import ArgumentParser,RawTextHelpFormatter
sys.dont_write_bytecode=True

ORANGE = '\033[33m'
WHITE = '\x1b[0m'

__author__ = '\033[92m' + "[sp3cTr3]" + '\033[33m'
__script__ = sys.argv[0]
__version__ = "pmaping version 1.0"
__banner__ = ORANGE+'''
    ___       ___       ___       ___       ___       ___       ___   
   /\  \     /\__\     /\  \     /\  \     /\  \     /\__\     /\  \  
  /::\  \   /::L_L_   /::\  \   /::\  \   _\:\  \   /:| _|_   /::\  \ 
 /::\:\__\ /:/L:\__\ /::\:\__\ /::\:\__\ /\/::\__\ /::|/\__\ /:/\:\__\

 \/\::/  / \/_/:/  / \/\::/  / \/\::/  / \::/\/__/ \/|::/  / \:\:\/__/
    \/__/    /:/  /    /:/  /     \/__/   \:\__\     |:/  /   \::/  / 
             \/__/     \/__/               \/__/     \/__/     \/__/
[Author]:# {0}
[Version]:# {1}
[URL]:# 
'''.format(__author__,__version__)

def UsageMain():
	print(__banner__)
	print("Usage: -t [TARGET] [OPTIONS]")
	print("REQUIRE:")
	print("  -t, --target: Specify your target.")
	print("HOST DISCOVERY:")
	print("  -cS/sS: Connect/TCP SYN scan.")
	print("  -uS: UDP scan.")
	print("OPTIONAL:")
	print("  -q, --quite: Quite.")
	print("  -h, --help: Print help screen and exit.")
	print("  -f, --file: Specify your word list file.")
	print("  -p, --port=port: Specify port range or list port.")
	print("  -T, --Threads=num: Set threads for process.")
	print("  --timeout=float: Set timeout for connection.")

class PArguments():
	def Main_Arguments():
		parser = ArgumentParser(
			add_help=False,
			usage='%(prog)s  -t [TARGET] [OPTIONS]',
			formatter_class=RawTextHelpFormatter,
			prog=__script__,
			description=__banner__,
			epilog= '''\
Examples:
%(prog)s example.com -cS --port=0-2000
''')
		require = parser.add_argument_group("REQUIRE")
		require.add_argument("-t","--target",metavar="",help="Specify your target.",default=False)
		host_discovery = parser.add_argument_group("HOST DISCOVERY")
		host_discovery.add_argument("-cS",action="store_true",help="Collecting port(s) via TCP connection.")
		host_discovery.add_argument("-sS",action="store_true",help="TCP SYN scan.")
		host_discovery.add_argument("-uS",action="store_true",help="UDP scan.")
		optional = parser.add_argument_group("OPTIONAL")
		optional.add_argument("-q","--quite",action="store_true",help="Quite.")
		optional.add_argument("-h","--help",action="store_true",help="Print help and exit.")
		optional.add_argument("-f","--file",metavar="",type=str,help="Specify your wordlist file.",default=False)
		optional.add_argument("-p","--port",metavar="",help="Set port range.")
		optional.add_argument("-T","--Threads",metavar="",type=int,help="Set threads for process.",default=8)
		optional.add_argument('--timeout',metavar="",type=(float or int),help='Set timeout for connection.',default=3.0)
		args = parser.parse_args()
		return (parser,args)