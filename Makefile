# Example makefile for CPE 464
#

CC = gcc
CFLAGS = -g -Wall -Werror -Wextra -std=gnu99
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  trace-$(EXEC_SUFFIX)

trace-$(EXEC_SUFFIX): trace.c
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ trace.c checksum.c smartalloc.c -lpcap

handin: README
	~bellardo/bin/rcvhandin bellardo p1 README smartalloc.c smartalloc.h checksum.c checksum.h trace.c Makefile

clean:
	rm -rf trace-* trace-*.dSYM
