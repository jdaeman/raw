#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/tcp.h> //tcp header
#include <linux/udp.h> //upd header
#include <linux/icmp.h> //icmp header
#include <linux/ip.h> //ip header
#include <linux/if_arp.h> //arp header
#include <linux/if_ether.h> //ethernet header

struct ether_addr;
extern char * ether_ntoa(struct ether_addr *); //library fucntion

unsigned char * tcp_handle(unsigned char * pkt, unsigned char * buf, int len)
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
	return (unsigned char *)(tcp + 1); //application data
}
		
unsigned char * udp_handle(unsigned char * pkt, unsigned char * buf, int len)
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
	return (unsigned char *)(udp + 1); //application data
}

unsigned char * icmp_handle(unsigned char * pkt, unsigned char * buf, int len)
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
		return (unsigned char *)(icmp + 1);
	}

unknown_type:
	sprintf(buf, "-----ICMP-Unknown type-----\n");
	return (unsigned char *)(icmp + 1);
}

unsigned char * ip_handle(unsigned char * pkt, unsigned char * buf, int len)
{
	static const char * protocol[] = {"IP", "ICMP", "IGMP", "X", "IPIP", "X", "TCP", "X", "EGP",
						"X", "X", "X", "PUP", "X", "X", "X", "X", "UDP"};

	struct iphdr * ip = (struct iphdr *)pkt;
	unsigned char ttl, proto;
	unsigned short tot_len;
	unsigned char src[16], dst[16];
	
	ttl = ip->ttl;
	proto = ip->protocol;
	tot_len = ntohs(ip->tot_len);
	strcpy(src, inet_ntoa(*(struct in_addr *)&ip->saddr));
	strcpy(dst, inet_ntoa(*(struct in_addr *)&ip->daddr));
	
	if (proto >= sizeof(protocol) / sizeof(char *))
		proto = 0;

	sprintf(buf, "-----IP-----\n"
			"total_length: %u\n"
			"ttl: %u\tprotocol: %s\n"
			"src: %s\tdest: %s\n", tot_len, ttl, protocol[proto], src, dst);

	return (unsigned char *)(ip + 1); //next header
}

unsigned char * arp_handle(unsigned char * pkt, unsigned char * buf, int len)
{
	static const char * operation[] = {"X", "Request", "Reply", "Reverse Request", "Reverse Reply"};
	
	struct arphdr * arp = (struct arphdr *)pkt;
	unsigned short op;
	unsigned char sha[32], tha[32];
	unsigned char sip[16], tip[16];	
	unsigned char * payload = (unsigned char *)(arp + 1);

	op = ntohs(arp->ar_op);
	strcpy(sha, ether_ntoa((struct ether_addr *)payload));
	payload += 6;
	strcpy(sip, inet_ntoa(*(struct in_addr *)payload));
	payload += 4;
	strcpy(tha, ether_ntoa((struct ether_addr *)payload));
	payload += 6;
	strcpy(tip, inet_ntoa(*(struct in_addr *)payload));

	if (op >= sizeof(operation) / sizeof(char *))
		op = 0;
	
	sprintf(buf, "-----ARP-%s-----\n"
			"src: %s(%s)\n"
			"dest: %s(%s)\n", operation[op], sha, sip, tha, tip);

	return NULL; //there is no next header
}


unsigned char * eth_handle(unsigned char * pkt, unsigned char * buf, int len)
{
	struct ethhdr * eth = (struct ethhdr *)pkt;
	unsigned char src[32], dst[32];
	unsigned short proto;

	strcpy(src, ether_ntoa((struct ether_addr *)eth->h_source));
	strcpy(dst, ether_ntoa((struct ether_addr *)eth->h_dest));
	proto = ntohs(eth->h_proto);

	sprintf(buf, "-----ETHERNET-----\n"
			"src: %s\tdest: %s\n", src, dst);
	return (unsigned char *)(eth + 1); //next header
}

