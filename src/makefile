BINS=tarpserv
CFLAGS=-Wall -Werror -ansi -pedantic
LDFLAGS=-lpcap

.PHONY: all clean

all: $(BINS)

tarpserv: tarpserv.o packets.o

clean:
	rm -rf $(BINS)
	rm -rf *.o
