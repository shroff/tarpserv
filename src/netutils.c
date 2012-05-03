#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>    
#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "netutils.h"

#define GW_BUFSIZE 8192


void read_iface_config(u_char * addr, int *ip, const char *iface) {
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, iface);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	shutdown(s, 1);


	if(addr != NULL)
		memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);

	s = socket(PF_INET, SOCK_STREAM, 0);
	ioctl(s, SIOCGIFADDR, &ifr);
	shutdown(s, 1);
	if(ip != NULL)
		*ip = ((struct sockaddr_in *)(&(ifr.ifr_addr)))->sin_addr.s_addr;
}
