/*  
   tarp_lta.c -- This program is used to generate TARP tickets

 
   Copyright (C) 2005  Wesam Lootah, Abhishek Shroff

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, 
   Boston, MA 02110-1301,USA.

   This software is based on previous work done by ALoR. 
   However, it has been extensively modified by the Wesam Lootah.
   Please direct your comments and questions to:

   Wesam Lootah
   lootah@cse.psu.edu

   Note: This version of TARP is NOT suited for production environments.
   This version was developed for research purposes only.
*/

/*
 * Wesam Lootah
 *
 * Generate a tarp ticket
 *
 */

#include "packets.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define RSA_KEY_LEN 1024
#define RSA_EXPO 3
#define TICKET_LENGTH 30

#define MAGIC 0
#define TYPE 4
#define MAC 8
#define IP 14
#define TIMESTAMP 18
#define TIME_FROM 22
#define TIME_TO 26

int get_time() {
  int val;
  struct timeval t;              
  gettimeofday(&t, 0);           
  val = t.tv_sec;
  return val;
}

int raw_to_b64(char *r, int l, char **b)
{
   BIO *b64bio, *bio, *mbio;
   u_char *p; 
   int h;
   
   mbio = BIO_new(BIO_s_mem());
   b64bio = BIO_new(BIO_f_base64());
   bio = BIO_push(b64bio, mbio);
   BIO_write(bio, r, l);
   BIO_flush(bio);
   
   h = BIO_get_mem_data(mbio, &p);
  
   *b = strndup((char*)p, h);

   BIO_free_all(bio);
   
   return h;
}

char* tarp_create_ticket(u_char *smac, ip_address *sip, char *key) {
  RSA *r = NULL;
  unsigned char hash[20]; 
  FILE *key_file;
  unsigned int signlen;
  unsigned char *sign;
  char *sign_b64;
  char *data_b64;
  int magic = 0x789a0102;
  int type  = 0xffff0000;
  int time_stamp, from_time, to_time;
  char *strdata;
  unsigned char data[TICKET_LENGTH] = {0x00};

  if ((key_file = fopen(key, "r")) == NULL) {
     fprintf(stderr, "Cannot open %s\n", key);
	   exit(0);
  }

  if ((r = PEM_read_RSAPrivateKey(key_file, NULL,0,NULL)) == NULL) {
    perror("Error reading private key\n");
    exit(0);
  }

  sign = malloc(RSA_size(r));

  magic = htonl(magic);
  time_stamp = htonl(get_time());
  from_time = time_stamp;
  to_time = htonl(0x7fffffff);

  memcpy(data+MAGIC,&magic,4);  
  memcpy(data+TYPE,&type,4);
  memcpy(data+MAC,smac,6);
  memcpy(data+IP,&sip,4);
  memcpy(data+TIMESTAMP,&time_stamp,4);
  memcpy(data+TIME_FROM,&from_time,4);
  memcpy(data+TIME_TO,&to_time,4);
 
  /* create the ticket */
  /* sMAC, sIP, tMAC, tIP, magic, type, siglen, tstamp, tfrom, tto */
  
  if (!SHA(data, TICKET_LENGTH, hash)) {
    printf("Error hashing data\n");
    exit(0);
  }
  
  if (RSA_sign(NID_sha1, hash, 20, sign, &signlen, r) != 1) {
    printf("Error signing the data\n");
    exit(0);
  }
  raw_to_b64((char *)data,TICKET_LENGTH,&data_b64);
  raw_to_b64((char *)sign,signlen,&sign_b64);

  strdata = malloc(strlen(data_b64) + strlen(sign_b64) + 3);
  sprintf(strdata, "%s\n%s\n",data_b64,sign_b64);
  return strdata;
}

