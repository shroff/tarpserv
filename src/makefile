BINS=tarpserv
CFLAGS=-Wall -Werror -pedantic -g
LDFLAGS=-lpcap -lssl -lcrypto

.PHONY: all clean

all: $(BINS)

tarpserv: tarpserv.o packets.o dhcputils.o netutils.o tarp_lta.o

clean:
	rm -rf $(BINS)
	rm -rf *.o
