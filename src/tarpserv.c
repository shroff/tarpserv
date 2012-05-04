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
dhcp_packet request, reply;

dhcp_lease leases[256];

/* Function Prototypes */
pcap_t* tarpserv_open_pcap(char*, char*);
void dhcp_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
void initialize_leases(void);
void add_options(dhcp_packet*);

char *key;
char *device;
pcap_t* dhcp_session;

int main(int argc, char **argv) {
  if(argc < 3) {
    fprintf(stderr, "Usage: %s <device-name> <tarp-private-key>", argv[0]);
    return 1;
  }
  device = argv[1];
  key = argv[2];
  initialize_leases();
  dhcp_session = tarpserv_open_pcap(device, "udp and port 67");
  pcap_loop(dhcp_session, -1, dhcp_handler, NULL);

  return 0;
}

void initialize_leases() {
  int i;
  u_char hwaddr[6];

  for(i=0; i<255; i++) {
    leases[i].time = 0;
    leases[i].dyn = 1;
    leases[i].ticketfile = NULL;
  }

	read_iface_config(hwaddr, &i, device);
  i = htonl(i) & 0xff;
  /* Always mark own IP address and subnet IP address (.0) as used */
  leases[i].time = (unsigned long) -1l;
  leases[i].dyn = 0;
  leases[0].time = (unsigned long) -1l;
  leases[0].dyn = 0;
}

int get_lease(int request, u_char* hwaddr) {
  time_t seconds = time(NULL);
  if(request == -1) { /* Search for IP address */
    for(request = 1; request < 255; request++) {
      if(leases[request].dyn && seconds -  leases[request].time > 86400) {
        return request;
      }
    }
    return -1;
  } else { /* Check to see if the requested IP can be assigned.*/
    if(!strncmp((char*)hwaddr, (char*)leases[request].hwaddr, 6)) {
      return request;
    }
    return -1;
  }
}

void add_options(dhcp_packet* packet) {
  dhcp_option *option = dhcp_create_option(packet);
  option->type = 51;
  option->len = 4;
  packet->opLen += 4;
  *((u_int*)(option->data)) = htonl(86400);

  option = dhcp_create_option(packet);
  option->type = 1;
  option->len = 4;
  packet->opLen += 4;
  option->data[0] = option->data[1] = option->data[2] = 255;
  option->data[3] = 0;

  option = dhcp_create_option(packet);
  option->type = 28;
  option->len = 4;
  packet->opLen += 4;
  memcpy(option->data, &packet->ip.ip_src, 4);
  option->data[3] = 0;
  
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
  int lease;
  int len;
  int done;
  char* ticket;

	if(header->len != header->caplen) {	/* Incomplete packet */
		printf("Unequal lengths: should be %d, got %d\n", header->len, header->caplen);
		return;
	}

	extract_dhcp(&request, packet, header->caplen);
  option = dhcp_get_option(&request, 53);

  dhcp_init_packet(&reply, device);
  if(option && option->data[0] == 1) { /* DISCOVER */
    reply.opHead->data[0] = 2;

    dhcp_make_reply_packet(&reply, &request);
    lease = get_lease(-1, request.eth.eth_shost);
    printf("Leasing %d\n", lease);
    reply.dhcp.yiaddr.byte4 = lease;
    reply.ip.ip_dst.byte4 = lease;

    dhcp_finalize_packet(&reply);
    memcpy(buffer, &reply, SIZE_HEADERS);
    memcpy(buffer+SIZE_HEADERS, reply.ops, reply.opLen);
	  pcap_inject(dhcp_session, buffer, SIZE_HEADERS + reply.opLen);
  } else if(option && option->data[0] == 3) { /* DHCPREQUEST */
    reply.opHead->data[0] = 5;

    option = dhcp_get_option(&request, 50);
    if(!option) {
      reply.opHead->data[0] = 6;
    } else {
      lease = option->data[3];
      lease = get_lease(-1, request.eth.eth_shost);
      dhcp_make_reply_packet(&reply, &request);
      if(lease == -1) {
        reply.opHead->data[0] = 6;
      } else {    /* Lease is considered granted by this point. Update mapping*/
        leases[lease].time = time(NULL);
        memcpy(leases[lease].hwaddr, request.eth.eth_shost, 6);
        reply.dhcp.yiaddr.byte4 = lease;
        reply.ip.ip_dst.byte4 = lease;
        add_options(&reply);
        /* TODO: Generate, asssign, and send ticket. */
        ticket = tarp_create_ticket(reply.eth.eth_dhost, &reply.ip.ip_dst, key);
        len = strlen(ticket);
        printf("Ticket: %d\n%s\n" , len, ticket);
        for(done=0; done<len; done += 255) {
          option = dhcp_create_option(&reply);
          option->type = 240;
          option->len = (len-done > 255) ? 255 : (len-done);
          reply.opLen += option->len;
          memcpy(option->data, ticket+done, option->len);
        }
      }
    }

    dhcp_finalize_packet(&reply);
    memcpy(buffer, &reply, SIZE_HEADERS);
    memcpy(buffer+SIZE_HEADERS, reply.ops, reply.opLen);
	  pcap_inject(dhcp_session, buffer, SIZE_HEADERS + reply.opLen);
  }

  dhcp_free_stuff(&request);
  dhcp_free_stuff(&reply);
}
