#include "dhcputils.h"
#include <string.h>
#include <stdlib.h>

void extract_dhcp(dhcp_packet *packet, const u_char *data, int capture_size) {
	memcpy(packet, data, SIZE_HEADERS);
  packet->opHead = packet->opTail = NULL;
  packet->opLen = packet->opCount = 0;
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
  packet->opLen += data[1];
  packet->opCount++;
  data += data[1]+2;
  while(data[0] != 0xff) {
    packet->opTail->next = (dhcp_option*)malloc(sizeof(dhcp_option));
    packet->opTail = packet->opTail->next;
    packet->opTail->type = data[0];
    packet->opTail->len = data[1];
    memcpy(packet->opTail->data, data+2, data[1]);
    packet->opTail->next = NULL;
    packet->opLen += data[1];
    packet->opCount++;
    data += data[1]+2;
  }
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
