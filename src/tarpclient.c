/*
Copyright (C) 2012 Abhishek Shroff

This file is a part of tarpserv.

tarpserv is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

tarpserv is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "packets.h"
#include "dhcputils.h"
#include "netutils.h"
#include "tarp_lta.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <time.h>

#define MAX_CAP_SIZE 20480

u_char buffer[MAX_CAP_SIZE];
dhcp_packet request;

dhcp_lease leases[256];

/* Function Prototypes */
pcap_t* tarpserv_open_pcap(char*, char*);
void dhcp_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

char *ticketname = "/etc/tarp/local.tkt";
char *device;
pcap_t* dhcp_session;

int main(int argc, char **argv) {
  if(argc < 2) {
    fprintf(stderr, "Usage: %s <device-name>\n", argv[0]);
    return 1;
  }
  device = argv[1];
  dhcp_session = tarpserv_open_pcap(device, "udp and port 67");
  pcap_loop(dhcp_session, -1, dhcp_handler, NULL);

  return 0;
}

pcap_t* tarpserv_open_pcap(char* dev, char* filter) {
  char errbuf[1000];
  struct bpf_program cfexp;
  bpf_u_int32 netmask;
  bpf_u_int32 ip;
  pcap_t *pcap_session;

  if (pcap_lookupnet(dev, &ip, &netmask, errbuf) == -1) {
    fprintf(stderr, "Could not get netmask for %s: %s\n", dev, errbuf);
    ip = netmask = 0;
  }

  if (!(pcap_session= pcap_open_live(dev, MAX_CAP_SIZE, 1, 1000, errbuf))) {
    printf("Could not open device %s: %s\n", dev, errbuf);
    return NULL;
  }

  if (pcap_compile(pcap_session, &cfexp, filter, 0, netmask) == -1) {
    fprintf(stderr, "Could not compile filter '%s'\n", filter);
    return NULL;
  }

  if (pcap_setfilter(pcap_session, &cfexp) == -1) {
    fprintf(stderr, "Could not install filter '%s'\n", filter);
    return NULL;
  }

  return pcap_session;
} 

void dhcp_handler(u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet) {
  dhcp_option* option;
  FILE *ticket;

	if(header->len != header->caplen) {	/* Incomplete packet */
		printf("Unequal lengths: should be %d, got %d\n", header->len, header->caplen);
		return;
	}

	extract_dhcp(&request, packet, header->caplen);
  option = dhcp_get_option(&request, 53);

  if(option && option->data[0] == 5) { /* DISCOVER */

    option = dhcp_get_option(&request, 240);
    if(option) {
      ticket = fopen(ticketname, "w");
      do {
        fwrite(option->data, 1, option->len, ticket);
        if(option->len != 255) {
          break;
        }
        option = option->next;
      } while (1);
      fclose(ticket);
    }
  }

  dhcp_free_stuff(&request);
}
