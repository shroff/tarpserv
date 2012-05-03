BINS=tarpserv
CFLAGS=-Wall -Werror -pedantic -g
LDFLAGS=-lpcap

.PHONY: all clean

all: $(BINS)

tarpserv: tarpserv.o packets.o dhcputils.o netutils.o

clean:
	rm -rf $(BINS)
	rm -rf *.o
