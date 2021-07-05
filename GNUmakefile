# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	mydba_local

CLEANFILES = $(PROGS) send_reset.o mydba_local.o

SRCDIR ?= .
VPATH = $(SRCDIR).

NO_MAN=
CFLAGS = -O2 -pipe
#CFLAGS += -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include 
#CFLAGS += -Wextra -std=gnu99
CFLAGS += -std=gnu99
#CFLAGS += -lpcre -lpthread -lpcap

LDFLAGS +=  proto_analysis.o 
LDLIBS += -lrt	# on linux
LDLIBS += -lpcre -lpthread -lpcap

PREFIX ?= /usr/local
MAN_PREFIX = $(if $(filter-out /,$(PREFIX)),$(PREFIX),/usr)/share/man

all: $(PROGS)

clean:
	-@rm -rf $(CLEANFILES)

mydba_local.o: mydba_local.c send_reset.o
	$(CC) $(CFLAGS) -c $^ -o $@ 

send_reset.o: 
	$(CC) $(CFLAGS) -c -o send_reset.o send_reset.c

