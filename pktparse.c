#include <stdio.h>
#include <arpa/inet.h>
#include <linux/tcp.h> //tcp header
#include <linux/udp.h> //upd header
#include <linux/icmp.h> //icmp header
#include <linux/ip.h> //ip header
#include <linux/if_ether.h> //ethernet header
#include <linux/if_arp.h> //arp header

#define BUF_SIZE 65536

struct ether_addr;
extern char * ether_ntoa(struct ether_addr *); //library fucntion

char * tcp_handle(const char * pkt, char * buf, int len)
{
	static const char * flags[] = {"CWR", "ECE", "URG", "ACK",
					"PSH", "RST", "SYN", "FIN",
					"DOFF", "X", "X", "RES1"};

	struct tcphdr * tcp = (struct tcphdr *)pkt;
	unsigned short src, dst;
	unsigned int seq, ack_seq;
	unsigned short flag;	
	int off;

	src = ntohs(tcp->source);
	dst = ntohs(tcp->dest);
	seq = ntohl(tcp->seq);
	ack_seq = ntohl(tcp->ack_seq);
	flag = ntohl(tcp->res1);
	
	for (off = 0; flag & (1 << off); off++);
	
	sprintf(buf, "-----TCP-%s-----\n"
			"source: %u\tdest: %u\n"
			"seq: %u\tack_seq: %u\n",
			flags[off], src, dst, seq, ack_seq);
	return buf;
}
		
char * udp_handle(const char * pkt, char * buf, int len)
{
	struct udphdr * udp = (struct udphdr *)pkt;
	unsigned short src, dst;
	unsigned int length;

	src = ntohs(udp->source);
	dst = ntohs(udp->dest);
	length = ntohl(udp->len);

	sprintf(buf, "-----UDP-----\n"
			"soruce: %u\tdest: %u\n"
			"length: %u\n", src, dst, length);
	return buf;
}

char * icmp_handle(const char * pkt, char * buf, int len)
{
	static const char * description[][4] = {
		"ECHO Reply", "X", "X", "X", //type 0
		"Dest network unreachable", "Dest host unreachable", 
		"Dest protocol unreachable","Dest port unreacheable", //type 3
		"Redirect Message", "X", "X", "X", //type 5
		"ECHO Request", "X", "X", "X", //type 8
		"Time Exceeded", "X", "X", "X" //type 11
	};
	static int type_to_row[] = {0, -1, -1, 1, -1, 2, -1, -1, 3, -1, -1, 5}; 
		
	struct icmphdr * icmp = (struct icmphdr *)pkt;
	unsigned char type = icmp->type;
	unsigned char code = icmp->code;

	if (type >= sizeof(type_to_row) / sizeof(int))
		goto unknown_type;
	else if (type_to_row[type] < 0)
		goto unknown_type;	
	else if (code >= 4)
		goto unknown_type;
	else
	{
		int row = type_to_row[type];
		sprintf(buf, "-----ICMP-%s-----\n", description[row][code]);
		return buf;
	}

unknown_type:
	sprintf(buf, "-----ICMP-Unknown type-----\n");
	return buf;
}	
