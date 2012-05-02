#include "dhcputils.h"
#include <string.h>
#include <stdlib.h>

void extract_dhcp(dhcp_packet *packet, const u_char *data, int capture_size) {
	memcpy(packet, data, SIZE_HEADERS);
  data += SIZE_HEADERS;
  if(data[0] == 0xff) {
    packet->opHead = NULL;
    packet->opTail = NULL;
  }
  packet->opHead = (dhcp_option*)malloc(sizeof(dhcp_option));
  packet->opTail = packet->opHead;
  packet->opTail->type = data[0];
  packet->opTail->len = data[1];
  memcpy(packet->opTail->data, data+2, data[1]);
  packet->opTail->next = NULL;
  data += data[1]+2;
  while(data[0] != 0xff) {
    packet->opTail->next = (dhcp_option*)malloc(sizeof(dhcp_option));
    packet->opTail = packet->opTail->next;
    packet->opTail->type = data[0];
    packet->opTail->len = data[1];
    memcpy(packet->opTail->data, data+2, data[1]);
    packet->opTail->next = NULL;
    data += data[1]+2;
  }
}
