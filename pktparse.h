#ifndef __PKTPARSE_H_
#define __PKTPARSE_H_

enum {
	ARP = 1, ICMP, TCP, UDP
};

typedef unsigned char * (*parse)(unsigned char *, unsigned char *, int);
extern parse next;

extern unsigned char * tcp_handle(unsigned char * pkt, unsigned char * buf, int len);

extern unsigned char * udp_handle(unsigned char * pkt, unsigned char * buf, int len);

extern unsigned char * icmp_handle(unsigned char * pkt, unsigned char * buf, int len);

extern unsigned char * ip_handle(unsigned char * pkt, unsigned char * buf, int len);

extern unsigned char * arp_handle(unsigned char * pkt, unsigned char * buf, int len);

extern unsigned char * eth_handle(unsigned char * pkt, unsigned char * buf, int len);

extern void set_filter(int * list, int len);

extern int is_avail(void);

extern unsigned char * ieee80211_handle(unsigned char * pkt, unsigned char * buf, int len);

#endif

