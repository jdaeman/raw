#ifndef __PKTPARSE_H_
#define __PKTPARSE_H_

typedef unsigned char * (*parse)(unsigned char *, unsigned char *, int);
extern parse next;

unsigned char * tcp_handle(unsigned char * pkt, unsigned char * buf, int len);

unsigned char * udp_handle(unsigned char * pkt, unsigned char * buf, int len);

unsigned char * icmp_handle(unsigned char * pkt, unsigned char * buf, int len);

unsigned char * ip_handle(unsigned char * pkt, unsigned char * buf, int len);

unsigned char * arp_handle(unsigned char * pkt, unsigned char * buf, int len);

unsigned char * eth_handle(unsigned char * pkt, unsigned char * buf, int len);

#endif
