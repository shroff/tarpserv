#ifndef _DHCPUTILS_H__
#define _DHCPUTILS_H__

#include "packets.h"

void extract_dhcp(dhcp_packet *, const u_char *, int);
dhcp_option* dhcp_get_option(dhcp_packet *, u_char);
void dhcp_add_option(dhcp_packet *, dhcp_option *);

#endif
