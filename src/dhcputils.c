#include "dhcputils.h"
#include "netutils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

void extract_dhcp(dhcp_packet *packet, const u_char *data, int capture_size) {
	memcpy(packet, data, SIZE_HEADERS);
  packet->opHead = packet->opTail = NULL;
  packet->opLen = packet->opCount = 0;
  packet->ops = NULL;
  data += SIZE_HEADERS;
  if(data[0] == 0xff) {
    return;
  }
  packet->opHead = (dhcp_option*)malloc(sizeof(dhcp_option));
  packet->opTail = packet->opHead;
  packet->opTail->type = data[0];
  packet->opTail->len = data[1];
  memcpy(packet->opTail->data, data+2, data[1]);
  packet->opTail->next = NULL;
  packet->opLen += data[1]+2;
  packet->opCount++;
  data += data[1]+2;
  while(data[0] != 0xff) {
    packet->opTail->next = (dhcp_option*)malloc(sizeof(dhcp_option));
    packet->opTail = packet->opTail->next;
    packet->opTail->next = NULL;
    packet->opTail->type = data[0];
    packet->opTail->len = data[1];
    memcpy(packet->opTail->data, data+2, data[1]);
    packet->opLen += data[1]+2;
    packet->opCount++;
    data += data[1]+2;
  }
  packet->opLen++;      /* For 'end' option 0xff */
}

dhcp_option* dhcp_get_option(dhcp_packet *packet, u_char type) {
  dhcp_option *option = packet->opHead;
  while(option != NULL && option->type != type)
    option = option->next;
  return option;
}

dhcp_option* dhcp_create_option(dhcp_packet *packet) {
  dhcp_option *option = (dhcp_option*)malloc(sizeof(dhcp_option));
  option->next = NULL;
  option->len = 0;
  option->type = 0;
  packet->opTail->next = option;
  packet->opTail = option;
  packet->opCount++;
  packet->opLen += 2;
  return option;
}

void dhcp_generate_options(dhcp_packet *packet) {
  dhcp_option *option = packet->opHead;
  u_char* ptr = malloc((packet->opLen)+1);
  /* +1 Just in case for even padding */
  packet->ops = ptr;
  ptr[packet->opLen] = '\0';  /* Set the possible pad character to 0 */

  while(option != NULL) {
    ptr[0] = option->type;
    ptr[1] = option->len;
    memcpy(ptr+2, option->data, option->len);
    ptr += option->len+2;
    option = option->next;
  }
  ptr[0] = 0xff;
}
void dhcp_init_packet(dhcp_packet * dhcpacket, const char *dev) {
  memset(dhcpacket, 0, SIZE_HEADERS);
	read_iface_config((u_char *)dhcpacket->eth.eth_shost,
      (int *)&dhcpacket->ip.ip_src, dev);
	dhcpacket->eth.eth_type = htons(0x0800);

	dhcpacket->ip.ip_vhl = 0x45;
	dhcpacket->ip.ip_tos = 0x10;
	dhcpacket->ip.ip_id = 0x0000;
	dhcpacket->ip.ip_off = 0x0000;
	dhcpacket->ip.ip_ttl = 0x80;
	dhcpacket->ip.ip_p = 0x11;
  dhcpacket->ip.ip_sum = 0;

	dhcpacket->udp.sport = htons(0x0043);
	dhcpacket->udp.dport = htons(0x0044);
	
	dhcpacket->dhcp.msg_type = 0x02;
	dhcpacket->dhcp.hw_type = 0x01;
	dhcpacket->dhcp.hw_len = 0x06;
	dhcpacket->dhcp.magic[0] = 0x63;
	dhcpacket->dhcp.magic[1] = 0x82;
	dhcpacket->dhcp.magic[2] = 0x53;
	dhcpacket->dhcp.magic[3] = 0x63;

  dhcpacket->opHead = (dhcp_option*)malloc(sizeof(dhcp_option));
  dhcpacket->opTail = dhcpacket->opHead;
  dhcpacket->opTail->type = 53;
  dhcpacket->opTail->len = 1;
  dhcpacket->opTail->next = NULL;
  dhcpacket->opCount = 1;
  dhcpacket->opLen = 4;
}

void dhcp_finalize_packet(dhcp_packet *packet) {
  packet->ip.ip_len = SIZE_HEADERS - SIZE_ETHERNET + packet->opLen;
  packet->udp.len = htons(packet->ip.ip_len - SIZE_IP);
  packet->ip.ip_len = htons(packet->ip.ip_len);

  packet->udp.udp_sum = 0;
  dhcp_generate_options(packet);
  packet->udp.udp_sum = dhcp_udp_checksum(packet);

  packet->ip.ip_sum = 0;
	packet->ip.ip_sum =
      checksum((u_short*)(&(packet->ip.ip_vhl)), IP_HL(&(packet->ip))<<1);
}

u_short dhcp_udp_checksum(dhcp_packet *packet) {
	/* Create IP pseudo header for checksum*/
	u_char *pseudo_header = (u_char *)malloc(12);
  u_short sum_pseudo_header, sum_fixed, sum_ops, sum;
	memcpy(pseudo_header, &packet->ip.ip_src, 8);
	pseudo_header[8] = 0x00;
	pseudo_header[9] = 0x11;	/* DHCP protocol code 0x11 */
	((u_short*)pseudo_header)[5] = htons(sizeof(udp_header) +
                                        sizeof(dhcp_header) +
                                        packet->opLen);

	sum_pseudo_header = checksum((u_short*)pseudo_header, 6);

	sum_fixed = checksum((u_short *)&packet->udp,
                        (sizeof(udp_header) + sizeof(dhcp_header))/2);

	sum_ops = checksum((u_short *)packet->ops, (packet->opLen+1)/2);
	((u_short*)pseudo_header)[0] = ~sum_pseudo_header;
	((u_short*)pseudo_header)[1] = ~sum_fixed;
	((u_short*)pseudo_header)[2] = ~sum_ops;

	sum = checksum((u_short*)pseudo_header, 3);

	if(sum == 0)
		sum = 0xFFFF; /* set to all 1s if checksum is 0 */

	free(pseudo_header);

	return sum;
}
void dhcp_debug_packet(dhcp_packet *packet) {
  dhcp_option *option = packet->opHead;
  int i;
  printf ("Options count: %d\n", packet->opCount);
  printf ("Options length: %d\n", packet->opLen);
  printf ("Options:\n");
  while(option) {
    printf("  Type: %d\n", option->type);
    printf("  Length: %d\n", option->len);
    printf("  Data:");
    for(i=0; i<option->len; i++) {
      printf("%.2x ", option->data[i]);
    }
    printf("\n");
    option = option->next;
  }
}

void dhcp_free_stuff(dhcp_packet *packet) {
  dhcp_option *ptr = packet->opHead;
  dhcp_option *temp;
  packet->opHead = NULL;

  while(ptr) {
    temp = ptr->next;
    free(ptr);
    ptr = temp;
  }
  if(packet->ops) {
    free(packet->ops);
    packet->ops = NULL;
  }
}
