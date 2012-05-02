#ifndef __PACKETS_H
#define __PACKETS_H


/* TYPEDEFS */

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;


/* MACROS */

#define IP_HL(ip)    ((((ip)->ip_vhl) & 0x0f))
#define IP_V(ip)    (((ip)->ip_vhl) >> 4)

#define SIZE_ETHERNET 14
#define SIZE_IP 20
#define SIZE_UDP 8
#define SIZE_DHCP_HEADER 240
#define SIZE_HEADERS 282


/* STRUCTS */

/* Ethernet header */
typedef struct eth_header_s {
  u_char eth_dhost[6];
  u_char eth_shost[6];
  u_short eth_type;
} eth_header;

/* IP address */
typedef struct ip_address_s {
  u_char byte1;
  u_char byte2;
  u_char byte3;
  u_char byte4;
} ip_address;

/* IP header */
typedef struct ip_header_s {
  u_char ip_vhl;        /* version << 4 | header length >> 2 */
  u_char ip_tos;        /* type of service */
  u_short ip_len;       /* packet length */
  u_short ip_id;        /* identification */
  u_short ip_off;       /* fragment offset field */
  u_char ip_ttl;        /* time to live */
  u_char ip_p;          /* protocol */
  u_short ip_sum;       /* checksum */
  ip_address ip_src;    /* source IP address */
  ip_address ip_dst;    /* destination IP address */
} ip_header;

/* UDP header -- 8 bytes */
typedef struct udp_header_s {
  u_short sport;
  u_short dport;
  u_short len;
  u_short udp_sum;
} udp_header;

/* DHCP header -- 8 bytes */
typedef struct dhcp_header_s {
  u_char  msg_type;     /* 0x01 = Request; 0x02 = Reply */
  u_char  hw_type;      /* Must be 0x01 = Ethernet */
  u_char  hw_len;       /* Must be 0x06 */
  u_char  hops;
  u_char  trans_id[4];
  u_char  seconds[2];   /* Seconds; 0 */
  u_char  flags[2];
  ip_address ciaddr;    /* Client IP address; 0 */
  ip_address yiaddr;    /* Offered IP address; addr to be assigned */
  ip_address siaddr;    /* Next Server (for PXE) */
  ip_address giaddr;    /* Gateway IP */
  u_char  chaddr[16];   /* Client hwaddr; padded with 0 */
  u_char  sname[64];    /* Server name */
  u_char  file[128];    /* Filename; for PXE */
  u_char  magic[4];     /* Magic Cookie; 0x63 0x82 0x53 0x63 */
} dhcp_header;

typedef struct dhcp_option_s {
  u_char type;
  u_char len;
  u_char data[255];
  struct dhcp_option_s* next;
} dhcp_option;

/* Actual DHCP packet */
typedef struct dhcp_packet_s {
  eth_header eth;
  ip_header ip;
  udp_header udp;
  dhcp_header dhcp;

  /* Option data will need to be parsed */
  dhcp_option *opHead;
  dhcp_option *opTail;

  /* This data is purely for accounting purposes */
  int opLen;
  int opCount;
} dhcp_packet;


/* Function Prototypes */
void set_ip(ip_address*, u_char, u_char, u_char, u_char);
void print_packet(const u_char*, int);
void print_mac(const u_char*, int);
void print_ip(const ip_address*);
u_short checksum(u_short*, u_short);

#endif
