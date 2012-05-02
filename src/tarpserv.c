#include "packets.h"
#include "dhcputils.h"
#include <stdio.h>
#include <pcap.h>

#define MAX_CAP_SIZE 20480

dhcp_packet reply;

/* Function Prototypes */
pcap_t* tarpserv_open_pcap(char*, char*);
void dhcp_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

int main() {
  /* TODO: Do not compile fixed device name */
  pcap_t* dhcp_session = tarpserv_open_pcap("vboxnet0", "udp and port 68");
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

	if(header->len != header->caplen) {	/* Incomplete packet */
		printf("Unequal lengths: should be %d, got %d\n", header->len, header->caplen);
		return;
	}

	extract_dhcp(&reply, packet, header->caplen);
  printf("From: ");
  print_mac((const u_char*)&(reply.eth.eth_shost), 6);
  printf("\nTo: ");
  print_mac((const u_char*)&(reply.eth.eth_dhost), 6);
  printf("\n");
  option = dhcp_get_option(&reply, 53);
  if(option) {
    printf("Message Type: %d", option->data[0]);
  }

	reply.udp.udp_sum = 0;
  dhcp_generate_options(&reply);
	printf("Checksums: %d (original), %d (calculated)\n",
      reply.udp.udp_sum,
      dhcp_udp_checksum(&reply));

}
