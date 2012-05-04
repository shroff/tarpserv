# Copyright (C) 2012 Abhishek Shroff
# 
# This file is a part of tarpserv.
# 
# tarpserv is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# tarpserv is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

BINS=tarpserv tarpclient tarp_genkeys
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
tarp_genkeys: $(ODIR)/tarp_genkeys.o
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

