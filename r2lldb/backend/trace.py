# TODO: implement tracing helpers here

traces = {}

def add(at,cmd):
	try:
		#at = "0x%x"%int(at, 16)
		print("ADD",at)
		print(traces[at])
		if traces[at]:
			return False
	except:
		pass
	traces[at] = cmd
	return True

def get(at):
	try:
		try:
			at = "0x%x"%int(at, 16)
		except:
			pass
		print("GET",at)
		return traces[at]
	except e:
		print(e)
		return None

def contains(at):
	at = "0x%x"%int(at, 16)
	print("CHK",at)
	return get(at) != None

def list():
	s = ""
	for a in traces.keys():
		line = ""
		try:
			line = "dt 0x%x %s\n"%(int(a,16),traces[a])
		except:
			line = "dt "+a+" "+traces[a] + "\n"
		s = s + line
	return s
	
