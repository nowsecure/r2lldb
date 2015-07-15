# http://www.objc.io/issue-19/lldb-debugging.html


# (lldb)
# command script clear
# command script import /Users/pancake/prg/nowsecure/r2lldb/main.py

from r2rap import RapServer
from backend.lldb import dbg
from backend import trace
import exceptions
import traceback
import r2pipe
import sys
import re

def rap(debugger, command, result, dict):
	def r2cmd(c):
		print ("_____(%s)___"%c)
		if c == "q":
			print ("STOP")
			rs.stop()
			return "OK"
		elif c[0:7] == "setenv ":
			a = c[7:].strip().split(" ",1)
			return dbg.setenv(a[0],a[1])
		elif c == "env":
			return dbg.cmd("print $environ")
		elif c[0:7] == "dlopen ":
			return dbg.dlopen(a[7:].strip())
		elif c[0:2] == "o ":
			return dbg.cmd("target create %s"%c[2:])
		elif c[0] == "o":
			return "TODO: show target"
		elif c == "objc":
			return dbg.objcListClasses()
		elif c == "run":
			return dbg.cmd("run");
		elif c == "dc":
			return dbg.cont()
		elif c == "ds":
			return dbg.cmd("stepi")
		elif c == "dso":
			return dbg.cmd("next") # thread step-over
		elif c == "dbt":
			res = ''
			for a in dbg.frames():
				line = "%d %s %s %s\n"%(a['index'], a['addr'], a['file'], a['meth'])
				res = res + line
			return res
		elif c == "i":
			s = ""
			#if dbg.isThumb():
			#	s = s + "e asm.bits=16 # thumb\n"
			# TODO 
			#(lldb) target list
			#Current targets:
			#* target #0: path-to-bin ( arch=i386-apple-ios, platform=ios-simulator, pid=21617, state=stopped )
			s = s + cmd("target list")
			return s
		elif c == "dbc":
			return "TODO: dbc"
		elif c[0:3] == "dt ":
			try:
				args = c[3:].split(' ', 1)
				if len(args)>1:
					if trace.add (args[0], args[1]):
						return "Trace added"
				else:
					if not trace.add(args[0], "?e trace"):
						return "Trace add fail"
			except:
				return "Trace exception"
			return ""
		elif c == "dt":
			return trace.list()
		elif c == "dcta":
			print(s)
			return "Set 0 traces"
		elif c == "dct":
			while True:
				try:
					dbg.cmd("continue")
					pc = dbg.getRegister("pc")
					if pc == '0':
						break
					t = None
					try:
						t = trace.get(pc)
					except:
						pass
					if not t:
						print ("Address not traced",pc)
						break
					rs.system(t)
				except e:
					print(e)
					traceback.print_stack()
					return "Exception happens"
			print ("Trace Done")
			return "Trace Done"
		elif c == "dks":
			dbg.stop()
		elif c == "is":
			syms = dbg.symbols()
			symbols = ""
			for a in syms:
				name = a['name']
				# XXX: filter flag name
				name = name.replace("'",'_')
				name = name.replace(' ','_')
				name = name.replace(' ','_')
				name = name.replace('-','_')
				name = name.replace('~','_')
				name = name.replace('+','_')
				name = name.replace('$','_')
				name = name.replace('&','_')
				name = name.replace('@','_')
				name = name.replace('|','_')
				name = name.replace('%','_')
				name = name.replace(';','_')
				name = name.replace('!','_')
				name = name.replace('`','_')
				name = name.replace(',','_')
				name = name.replace('/','_')
				name = name.replace('*','_')
				name = name.replace('(','_')
				name = name.replace(')','_')
				name = name.replace('[','_')
				name = name.replace(']','_')
				name = name.replace('<','_')
				name = name.replace('>','_')
				# TODO: many symbols are defined multiple times
				if name[0:2]!='0x':
					line = "f sym.%s = %s\n"%(name,a['addr'])
					symbols = symbols + line
			return symbols
		elif c == "db-*":
			return dbg.bp_clear()
		elif c[0:5] == "db 0x":
			return dbg.bp_addr(c[3:])
		elif c[0:3] == "db ":
			return dbg.bp_symbol(c[3:])
		elif c[0:4] == "dbo ":
			a = c[4:].strip().split(' ')
			if len(a) != 2:
				return "Usage: dbo OBJCLASS OBJCMETHOD"
			return dbg.bp_obj(a[0], a[1])
		elif c == "db":
			bps = dbg.bp_list()
			n = 0
			out = ''
			for a in bps:
				line = ("%d  %s  %s\n"%(n, a['type'], a[a['type']]))
				n = n + 1
				out = out + line
			#print(dbg.bp_list())
			return out + "\nFound %d breakpoints"%n
			#dbg.cmd("break list")
		elif c == "dm?":
			return """Usage: dm"
			dm         list maps
			dm [addr]  show address information
			"""
		elif c == "dm":
			return dbg.cmd('image list')
		elif c[0:3] == "dm ":
			return dbg.cmd('image lookup --address %s'%c[4:])
		elif c == "dfv":
			return dbg.cmd("fr v") # -a
		elif c == "dcue":
			return dbg.run_to_entry()
		elif c == "dr":
			return dbg.cmd('reg read')
		elif c == "dra":
			return dbg.cmd('reg read -a')
		elif c == "dr*":
			regs = dbg.cmd("reg read").strip().split("\n")
			res = ""
			for a in regs:
				a = a.strip()
				if a.find(" = ") == -1:
					next
				mo = re.match( r'(.*) = ([^ ]*)', a , re.M|re.I)
				if mo:
					line = "f %s = %s\n"%(mo.group(1), mo.group(2))
					line = "ar %s = %s\n"%(mo.group(1), mo.group(2))
					res = res + line
			#regs = dbg.getRegister("pc")
			return res
		elif c == "?":
			return """Usage: =![cmd] ...       # r2lldb integration
=!?                      # show r2lldb's help (this one)
=!help                   # show lldb's help
=!i                      # target information
=!is                     # list symbols
=!dfv                    # show frame variables (arguments + locals)
=!up,down,list           # lldb's command to list select frames and show source
=!dks                    # stop debugged process
=!dm                     # show maps (image list)
=!dr                     # show registers
=!dra                    # show all registers
=!dr*                    # "" "" in r2 commands
=!dr-*                   # remove all breakpoints
=!db                     # list breakpoints
=!db 0x12924             # set breakpoint at address
=!db objc_msgSend        # set breakpoint on symbol
=!dbo NSString init:     # set objc breakpoint
=!dbt                    # show backtrace
=!ds                     # step
=!dcue			 # continue until entrypoint
=!dso                    # step over
=!dt                     # list all trace points
=!dt 0x804040 =!dr       # add tracepoint for this address
=!dc                     # continue
=!dct                    # continue with tracing
=!env                    # show process environment
=!objc                   # list all objc classes
=!setenv k v             # set variable in target process
=!dlopen /path/to/lib    # dlopen lib (libr2.so, frida?)
"""
		return None
	port = int(command)
	rs = RapServer()
	def __read(sz):
		return dbg.read(rs.offset, sz)
	def __write(buf):
		return dbg.write(rs.offset, buf)
	def __seek(off,when):
		if when == 2:
			return 0xffffffffffffffff
		rs.offset = off
		return dbg.seek(off, when)
	def __cmd(c):
		c = c[0:len(c)-1].strip()
		res = r2cmd(c)
		if res:
			return res
		return dbg.cmd(c)
	rs.handle_system = __cmd
	rs.handle_cmd = __cmd
	rs.handle_read = __read
	rs.handle_write = __write
	rs.handle_seek = __seek
	rs.listen_tcp (port)

import signal
import sys
def signal_handler(signal, frame):
        print('')
	# TODO: close rap server here
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
#signal.pause()

PORT = "9999"

# sys.argv not defined inside lldbb
def main():
	try:
		rap(0, PORT, "", "")
	except exceptions.SystemExit:
		pass
	except:
		print "Unexpected error:", sys.exc_info()[0]
		print("Rap exception cannot listen")

# Register r2rap command in the lldb shell
#def __lldb_init_module (debugger, dict):
#	debugger.HandleCommand('command script add -f main.rap r2rap')
	#print 'The r2rap command has been installed'

main()
