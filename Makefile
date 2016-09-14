DESTDIR=/
PREFIX=/usr/local
BINDIR=${PREFIX}/bin

PYPATH=$(shell python -c 'import sys;print sys.path[-1]')
LINT=import sys;import py_compile;py_compile.compile(sys.argv[0])
CWD=$(shell pwd)

all:
	@echo
	-pkill r2
	-pkill debugserver
	-pkill lldb

install:
	ln -fs ${CWD}/bin/r2lldb ${DESTDIR}/${BINDIR}/r2lldb
	rm -rf ${DESTDIR}/${PYPATH}/r2lldb*
	ln -fs ${CWD}/r2lldb ${DESTDIR}/${PYPATH}/r2lldb

uninstall:
	rm -f ${DESTDIR}/${BINDIR}/r2lldb
	rm -rf ${DESTDIR}/${PYPATH}/r2lldb*

lint:
	for a in `find r2lldb -iname '*.py'` ; do \
		echo $$a ; \
		python -c '${LINT}' $$a ; \
	done
