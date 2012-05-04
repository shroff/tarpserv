BINS=tarpserv tarpclient
ODIR=obj
SDIR=src
CFLAGS=-Wall -Werror -pedantic -g
LDFLAGS=-lpcap -lssl -lcrypto

.PHONY: all clean

all: $(BINS)

tarpserv: $(ODIR)/tarpserv.o $(ODIR)/packets.o $(ODIR)/dhcputils.o $(ODIR)/netutils.o $(ODIR)/tarp_lta.o
	$(CC) $(LDFLAGS) -o $@ $^
tarpclient: $(ODIR)/tarpclient.o $(ODIR)/packets.o $(ODIR)/dhcputils.o $(ODIR)/netutils.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -rf $(BINS)
	rm -rf $(ODIR)

$(ODIR)/%.o: $(SDIR)/%.c
	mkdir -p $(ODIR)
	$(CC) $(CFLAGS) -c -o $@ $<


$(ODIR)/dhcputils.o: $(SDIR)/dhcputils.h $(SDIR)/packets.h $(SDIR)/netutils.h
$(ODIR)/netutils.o: $(SDIR)/netutils.h $(SDIR)/packets.h
$(ODIR)/packets.o: $(SDIR)/packets.h $(SDIR)/packets.o
$(ODIR)/tarp_lta.o: $(SDIR)/packets.h
$(ODIR)/tarpserv.o: $(SDIR)/packets.h $(SDIR)/dhcputils.h $(SDIR)/netutils.h $(SDIR)/tarp_lta.h
$(ODIR)/tarpclient.o: $(SDIR)/packets.h $(SDIR)/dhcputils.h $(SDIR)/netutils.h

