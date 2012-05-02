#include "dhcputils.h"
#include <string.h>

void extract_dhcp(dhcp_packet *packet, const u_char *data, int capture_size) {
	memcpy(packet, data, SIZE_HEADERS);
	
	packet->options = (u_char *)data + SIZE_HEADERS;
	packet->options_len = capture_size - SIZE_HEADERS;
}
