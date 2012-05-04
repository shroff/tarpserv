/*
Copyright (C) 2012 Abhishek Shroff

This file is a part of tarpserv.

tarpserv is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

tarpserv is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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
