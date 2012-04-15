#include "packets.h"
#include <stdio.h>


/* Set fields in an ip_address structure */
void set_ip(ip_address *ip, u_char byte1, u_char byte2, u_char byte3, u_char byte4) {
  ip->byte1 = byte1;
  ip->byte2 = byte2;
  ip->byte3 = byte3;
  ip->byte4 = byte4;
}

void print_packet(const u_char * ptr, int len) {
  int i;
  for(i=0; i<len; i++)
    printf("%.2x|", ptr[i]);
  printf("\n");
}

void print_mac(const u_char *ptr, int len) {
  for(; len>1; len--)
    printf("%.2x:", *ptr++);
  printf("%.2x", *ptr);
}

void print_ip(const ip_address* ip) {
  printf("%d.%d.%d.%d", ip->byte1, ip->byte2, ip->byte3, ip->byte4);
}


/* Returns a short in network order */
u_short checksum(u_short *ptr, u_short len) {
  int i;

  u_short cur_sum = 0;
  u_int sum;
  for (i = 0; i < len;i++) {
    sum = cur_sum + *ptr++;
    cur_sum = sum + (sum >> 16);
  }

  return ~cur_sum;
}

