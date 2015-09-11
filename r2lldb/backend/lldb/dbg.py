try:
	import lldb
except:
	print
	print "ERROR: import lldb only works in the lldb shell"
	print
	raise

import traceback

# (lldb) process launch --stop-at-entry -- -program_arg value 

#from backend import bp

def cont():
	return cmd("continue")

def run_to_entry():
	return cmd("run")

def system_cat(path, head=False):
	ret = ""
	try:
		fd = runCode('(void*)open((char*)"'+path+'",0);')
		print ("FD "+fd)
		if int(fd,16) == 4294967295:
			return "Cannot open file"
		buf = runCode('(void*)malloc((int)10240)')
		print "open("+buf+")"
		i = 0
		while True:
			de = runCode('(int)read((int)'+str(fd)+',(void*)'+str(buf)+',(int)1024);');
			count = int (de, 16)
			print ("read("+str(i)+")="+str(count))
			try:
				data = read(int(buf,16), count)
				ret = ret + str(data)
			except:
				traceback.print_last()
				ret = ret + ".\n"
			if count != 1024 and count != 0x1024:
				break
			if head:
				break
			i = i + 1
	except:
		traceback.print_last()
		ret = ret + "ERR\n";
	cmd('e (void)free((void*)'+buf+')')
	cmd('e (int)close((int)'+fd+')')
	return ret

def system_ls(path):
	ret = ""
	print ("LS("+path+")")
	try:
		ptr = runCode('(void*)opendir((char*)"'+path+'");')
		if int(ptr,16) == 0:
			return "Cannot find directory"
		print "opendir("+ptr+")"
		while True:
			de = runCode('(void*)readdir((void*)'+ptr+');');
			#print ("readdir()="+de)
			if int(de,16) == 0:
				break
			row = cmd('x/1s '+de+'+0x15')
			print (row.strip())
			ret = ret + row
		runCode('(int)closedir((void*)'+ptr+')')
	except:
		traceback.print_last()
		ret = ret + "ERR\n";
	return ret

def setenv(x,y):
	# TODO: if process not running
	# dbg.cmd("set env %s %s"%(a[0],a[1])
	runC("(void)setenv(\"%s\",\"%s\",1)"%(x,y))

def dlopen(x):
	runC("(void)dlopen(\"%s\")"%x)

def cmd(x):
	res = lldb.SBCommandReturnObject()
	lldb.debugger.GetCommandInterpreter().HandleCommand(x, res)
	return res.GetOutput()

#(lldb) e char *$str = (char *)malloc(8)
#(lldb) e (void)strcpy($str, "munkeys")
#(lldb) e $str[1] = 'o'
#(char) $0 = 'o'
#(lldb) p $str
#(char *) $str = 0x00007fd04a900040 "monkeys"
def getString(x):
	return cmd("print $%s"%x) #x/s $%s"%x)
	try:
		return cmd("x/s $%s"%x).split(":",1)[1].strip()
	except:
		return ""

def getValue(x):
	return cmd("print $%s"%x)

def setValue(x,y):
	runC("int $%s = %s"%(x,y))

def getRegister(r):
	try:
		return cmd("reg read %s"%r).strip().split(' ')[2]
	except:
		print("FAILED TO GET REG %s"%r)
		return '0'

def setRegister(r,v):
	cmd("reg write %s %s"%(r,v))
	
# TODO : preprocessor here
def runC(code):
	for a in code.split("\n"):
		if a != '':
			print(a)
			cmd("e "+a)
def runCode(code):
	res = cmd("e "+code)
	try:
		return res.split("=")[1].strip()
	except:
		print "EXCEPTION"
		return res

#  runC("""
#  (void)sleep(2)
#  void *$fd = (void*)fopen ("/tmp/test.txt", "w")
#  (void)fputs ("Hi\\n", $fd)
#  (void)fclose ($fd)
#  """)
#  
#  e for ($i = 0; $i<$count; $i++) { printf ("%s\\n", (char*)class_getName($classes[$i])); }

def objcListClasses():
	cmd('e int $count = (int)objc_getClassList(NULL, 0);')
	cmd('e Class *$classes = (Class*)malloc(sizeof(Class)*$count);')
	cmd('e (void)objc_getClassList($classes, $count);')
	cmd('e void *$dst = (void*)calloc($count, 128);')
	cmd('e int $i = 0;')
	cmd('e for ($i = 0; $i<$count; $i++) { (void)strcat ($dst, (char*)class_getName($classes[$i])); (void)strcat($dst,"\\n"); }')
	cmd('e (void)free($classes);')
	return cmd('print $dst')
#	runC("""
#e int $count = (int)objc_getClassList(NULL, 0);
#e Class *$classes = (Class*)malloc(sizeof(Class)*$count);
#e (void)objc_getClassList($classes, $count);
#e void *$dst = (void*)calloc($count, 128);
#e int $i = 0;
#e for ($i = 0; $i<$count; $i++) { (void)strcat ($dst, (char*)class_getName($classes[$i])); (void)strcat($dst,"\\n"); }
#e (void)free($classes);
#	""")
#	res = cmd("print $dst")
#	return "RESULT %s"%res
# TODO: fix memleak
	#return getValue("dst")
#	runC("""
#e (void)free($dst); $dst = NULL;
#""")

# Global seek address
curoff = 0

def seek(off, when):
	curoff = off
	return off

BSZ=1024

def read(addr, size):
	i = 0 
	data = '' 
	if size<BSZ:
		bs = size
	else:
		bs = BSZ 
	while i<size:
		target = lldb.debugger.GetSelectedTarget()
		error = lldb.SBError()
		if i+bs>size:
			bs = size-i
		res = target.process.ReadMemory (addr+i, bs, error)
		if len (res) == 0:
			print(error)
			#print ("READ FAIL AT 0x%x"%(addr+i))
			i = i + bs
			continue
		if data == None:
			data = res
		elif res:
			data = data + res
		i = i + bs 
	return data

def write(addr, buf):
	i = 0
	data = ''
	target = lldb.debugger.GetSelectedTarget()
	error = lldb.SBError()
	res = target.process.WriteMemory (addr+i, buf, error)
	#if not error.Success() or res != 1:
	print ("RES")
	print (res)
	if res == 0:
		print(error)
		#print ("WRITE FAIL AT 0x%x"%(addr+i))
		return 0
	return size

#[ 99] 29886CD7-2AC8-3578-8389-7D5BEE405F53 0x08a38000 /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk/System/Library/PrivateFrameworks/FaceCore.framework/FaceCore 

def maps():
	maps = cmd ("image list").split("\n")
	res = []
	index = 0
	for a in maps:
		try:
			obj = {}
			line = a.split('] ', 1)[1].split(' ')
			if not line[0]:
				continue
			obj['index'] = index
			obj['uuid'] = line[0]
			obj['addr'] = line[1]
			obj['file'] = line[2]
			res.append(obj)
			index = index + 1
		except:
			pass
	return res 

def frames():
	res = []
	frames = cmd ("bt").strip().split("\n")[1:]
	index = len(frames)-1
	for a in frames:
		line = a.replace(' * ','').strip().replace('`',' ').split(' ')
		if len(line)<4:
			break
		print(line)
		obj = {}
		obj['index'] = index
		obj['addr'] = line[2]
		obj['file'] = line[3]
		obj['meth'] = line[4:]
		index = index - 1
		res.append (obj)
	return res

def bp_list():
	bps = cmd ("break list").split('\n')
	addr = ''
	name = ''
	cunt = 0
	res = []
	for a in bps:
		print(a)
		try:
			indx = a.index(": name = '")
			name = a.split("'")[1]
			#print ("%d  %s", cunt, name)
			cunt = cunt + 1
			obj = {}
			obj['type'] = 'name'
			obj['name'] = name
			res.append(obj)
		except:
			# Fails if no name in line
			try:
				if a[0] != ' ':
					indx = a.index(": address = 0x")
					addr = a.split(",")[0][indx+12:]
					#print ("---- %d  %s"%(cunt, addr))
					cunt = cunt + 1
					obj = {}
					obj['type'] = 'addr'
					obj['addr'] = addr
					res.append(obj)
			except:
				# Fails if no name in line
				pass
			pass
	return res

def bp_clear():
	cmd ("br del -f")

def bp_selector(name):
	bpinfo = cmd ("br set -S %s"%name)
	# Breakpoint 2: 613 locations.

def bp_addr(addr):
	bpinfo = cmd ("br set -a %s"%addr)

def bp_symbol(name):
	bpinfo = cmd ("br set -F %s"%name)

def bp_objc(cls,sel):
	bpinfo = cmd ("br set -n -[%s %s]"%(cls,sel))
	# Breakpoint 3: where = libobjc.A.dylib`objc_msgSend, address = 0x01bbc0a4

def wp_add():
	pass

def traceLoop():
	while True:
		cmd ("continue")
		pcinfo = cmd ("reg read pc")

def symbols():
	syms = []
	for a in cmd("image dump symtab").split("\n"):
		try:
			sym = a[27:].split()
			obj = {}
			if sym[1][0:2] != '0x':
				continue
			obj['addr'] = sym[1]
			obj['base'] = sym[0]
			obj['size'] = sym[2]
			obj['name'] = '_'.join(sym[4:])
			if obj['name'] == '':
				continue
			if obj['name'][0:2] != '0x':
				syms.append(obj)
		except:
			pass
	return syms

def stop():
	cmd("process interrupt")

print ("")
print ("Running r2lldb script...")

#print(backtrace())

#bp_objc('NSString', 'stringWithFormat:')
#traceLoop()

#maps = lldb_maps()
#print(maps)
#  runC("""
#  (void)sleep(2)
#  void *$fd = (void*)fopen ("/tmp/test.txt", "w")
#  (void)fputs ("Hi\\n", $fd)
#  (void)fclose ($fd)
#  """)


#  
#  target methods
#  
#  ['AddModule', 'Attach', 'AttachToProcessWithID', 'AttachToProcessWithName', 'BreakpointCreateByAddress', 'BreakpointCreateByLocation', 'BreakpointCreateByName', 'BreakpointCreateByNames', 'BreakpointCreateByRegex', 'BreakpointCreateBySourceRegex', 'BreakpointCreateForException', 'BreakpointDelete', 'Clear', 'ClearModuleLoadAddress', 'ClearSectionLoadAddress', 'ConnectRemote', 'CreateValueFromAddress', 'CreateValueFromData', 'CreateValueFromExpression', 'DeleteAllBreakpoints', 'DeleteAllWatchpoints', 'DeleteWatchpoint', 'DisableAllBreakpoints', 'DisableAllWatchpoints', 'EnableAllBreakpoints', 'EnableAllWatchpoints', 'EvaluateExpression', 'FindBreakpointByID', 'FindFirstGlobalVariable', 'FindFirstType', 'FindFunctions', 'FindGlobalFunctions', 'FindGlobalVariables', 'FindModule', 'FindSymbols', 'FindTypes', 'FindWatchpointByID', 'GetAddressByteSize', 'GetBasicType', 'GetBreakpointAtIndex', 'GetBroadcaster', 'GetBroadcasterClassName', 'GetByteOrder', 'GetCodeByteSize', 'GetDataByteSize', 'GetDebugger', 'GetDescription', 'GetExecutable', 'GetInstructions', 'GetInstructionsWithFlavor', 'GetModuleAtIndex', 'GetNumBreakpoints', 'GetNumModules', 'GetNumWatchpoints', 'GetPlatform', 'GetProcess', 'GetSourceManager', 'GetStackRedZoneSize', 'GetTriple', 'GetWatchpointAtIndex', 'Install', 'IsValid', 'Launch', 'LaunchSimple', 'LoadCore', 'ReadInstructions', 'ReadMemory', 'RemoveModule', 'ResolveFileAddress', 'ResolveLoadAddress', 'ResolvePastLoadAddress', 'ResolveSymbolContextForAddress', 'SetModuleLoadAddress', 'SetSectionLoadAddress', 'WatchAddress', 

def parseCPSR(frame):
	""" Check Thumb flag from CPSR """
	try:
		regs = frame.GetRegisters()[0]	# general purpose registers
		cpsr = [reg for reg in regs if reg.GetName()=='cpsr'][0]
		thumb_bit = int(cpsr.GetValue(), 16) & 0x20
		if thumb_bit >> 5 != 0:
			print "5: thumb"
		else:
			print "5: arm"
		return True
	except:
		pass
	return False

def isThumb(frame):
	""" Check Thumb flag from CPSR """
	try:
		regs = frame.GetRegisters()[0]	# general purpose registers
		cpsr = [reg for reg in regs if reg.GetName()=='cpsr'][0]
		thumb_bit = int(cpsr.GetValue(), 16) & 0x20
		if thumb_bit >> 5 != 0:
			return True
	except:
		pass
	return False

# list methods
#int unsigned numMethods;
#Method *methods = class_copyMethodList(objc_getMetaClass("NSArray"), &numMethods);
#for (int i = 0; i < numMethods; i++) {
#    NSLog(@"%@", NSStringFromSelector(method_getName(methods[i])));
#}
