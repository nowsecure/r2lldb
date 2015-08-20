try:
	import lldb
except:
	print
	print "ERROR: import lldb only works in the lldb shell"
	print
	raise

import time
# for dbg.read, etc.. must reuse instead of reimplement here
import dbg

dead = False
running = False
traces = []
print "LOOP INIT"

def memWrite(addr, buf):
	data = ''
	target = lldb.debugger.GetSelectedTarget()
	error = lldb.SBError()
	res = target.process.WriteMemory (addr, buf, error)
	#if not error.Success() or res != 1:
	if res == 0:
		print(error)
		print ("WRITE FAIL AT 0x%x"%(addr))
	return res 

class Tracepoint:
	def __init__(self):
		nothing = True

def cmd(x):
	res = lldb.SBCommandReturnObject()
	lldb.debugger.GetCommandInterpreter().HandleCommand(x, res)
	return res.GetOutput()

def getAddressForSymbol(symname):
	try:
		res = cmd("image lookup -s %s"%(symname)).split("\n")[1]
		res = res.replace("]","[").split("[")[1]
		return res
	except:
		return None

def setTracepoint(symname):
	a = Tracepoint()
	a.name = symname
	#res = cmd("breakpoint set -n %s"%(symname))
	addr = getAddressForSymbol(symname)
	if addr is None:
		print("Cant find address for %s"%(symname))
		return None
	a.addr = addr
	res = cmd("breakpoint set -a %s"%(addr))
	print res
	traces.append(a)
	print "SET TRACE %s at %s"%(symname, a.addr)
	return a
# 	try:
# 		a.addr = res.split("= ")[2].split("\n")[0]
# 	except:
# 		print("Cant find address for %s"%(symname))
# 		return None
#	return a

def listTracepoints():
	out = ""
	for a in traces:
		s = "0x%x  %s\n"%(a.addr, a.name)
		out = out + s
	return out

def getTracepoint(addr):
	for a in traces:
		if a.addr == addr:
			return a
	return None

def getCurrentPC():
	res = ""
	try:
		res = cmd ("register read rip").split("= ")[1].split(" ")[0]
	except:
		return None
	return res

def mainLoop():
	global dead, running
	print time.time()
	if not running:
		running = True
		o=cmd("run")
	else:
		o=cmd("continue")
	if o.find("EXC_BAD") != -1:
		print ("IS DEAD")
		dead = True
	print (o)
	print time.time()
	pc = getCurrentPC()
	if not pc:
		dead = True
	t = getTracepoint(pc)
	if t is not None:
		print (cmd("bt"))
		print ("TRACE %s"%(t.name))
		if hasattr(t, "cmd"):
			print ("RUNNING COMMAND")
			t.cmd ()
	print "STOP AT (%s)"%(pc)

# ERR
# XXX. this must be defined by the user or something
RETADDR="0x1000bb484"

# OK
#RETADDR="0x1000bb074"

def PatchReturn0():
	cmd("register write rax 0")
	cmd("register write rip %s"%(RETADDR))
	print "PATCHED RETURN VALUE TO 0"

def PatchReturn1():
	cmd("register write rax 1")
	cmd("register write rip %s"%(RETADDR))
	print "PATCHED RETURN VALUE TO 1"

#t = setTracepoint("strcmp")
#t.cmd = PatchReturn0

def runLoop():
	while not dead:
		#memWrite(0x10008c657, "\x90\x90\x90\x90\x90\x90")
		mainLoop()
