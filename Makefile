all:
	@echo
	-pkill r2
	-pkill debugserver
	-pkill lldb

lint:
	for a in `find * | grep py$$` ; do python ___lint.py $$a ; done
