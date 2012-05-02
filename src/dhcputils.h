#ifndef _DHCPUTILS_H__
#define _DHCPUTILS_H__

#include "packets.h"

void extract_dhcp(dhcp_packet *, const u_char *, int);

#endif
