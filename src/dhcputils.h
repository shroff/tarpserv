#ifndef _DHCPUTILS_H__
#define _DHCPUTILS_H__

#include "packets.h"

void extract_dhcp(dhcp_packet *, const u_char *, int);
dhcp_option* get_dhcp_option(dhcp_packet *, u_char);
void add_dhcp_option(dhcp_packet *, dhcp_option *);

#endif
