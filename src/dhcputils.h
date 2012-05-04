#ifndef _DHCPUTILS_H__
#define _DHCPUTILS_H__

#include "packets.h"
#include <time.h>

typedef struct dhcp_lease_s {
  u_char hwaddr[6];
  char *ticketfile;
  time_t time;
  u_char dyn;
} dhcp_lease;

void extract_dhcp(dhcp_packet *, const u_char *, int);
dhcp_option* dhcp_get_option(dhcp_packet *, u_char);
dhcp_option* dhcp_create_option(dhcp_packet *);
void dhcp_generate_options(dhcp_packet *);
u_short dhcp_udp_checksum(dhcp_packet *);
void dhcp_free_stuff(dhcp_packet *packet);
void dhcp_init_packet(dhcp_packet *, const char *);
void dhcp_make_reply_packet(dhcp_packet *, const dhcp_packet *);
void dhcp_finalize_packet(dhcp_packet *);
void dhcp_debug_packet(dhcp_packet *);

#endif
