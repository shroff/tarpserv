#include "dhcputils.h"
#include <string.h>
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

void dhcp_add_option(dhcp_packet *packet, dhcp_option *option) {
  option->next = NULL;
  packet->opTail->next = option;
  packet->opTail = option;
}

void dhcp_generate_options(dhcp_packet *packet) {
  dhcp_option *option = packet->opHead;
  u_char* ptr;
  packet->ops = malloc((packet->opLen)+1);
  ptr = packet->ops;
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

void dhcp_free_stuff(dhcp_packet *packet) {
  dhcp_option *ptr = packet->opHead;
  dhcp_option *temp;

  while(ptr) {
    temp = ptr->next;
    free(ptr);
    ptr = temp;
  }
  if(packet->ops) {
    free(packet->ops);
  }
}
