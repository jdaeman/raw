#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include "util.c"

int main(int argc, char ** argv)
{
	int sock;
	struct sockaddr_in addr;
	unsigned short port = 80;
	unsigned char pkt[1024], * tt;
	struct tcphdr * tcp;
	struct iphdr * ip;
	int on = 1, ret;

	sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket() error");
		return -1;
	}

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = inet_addr("192.168.0.1");
	addr.sin_port = htons(port);

	memset(pkt, 0, sizeof(pkt));
	
	tcp = (struct tcphdr *)(pkt + 20);

	tt = (unsigned char *)(tcp + 1);
	tt[0] = 2;
	tt[1] = 4;
	tt[2] = 0x05;
	tt[3] = 0xb4;

	tcp->source = htons(51234);
	tcp->dest = htons(port);
	tcp->seq = htonl(172147);
	tcp->ack_seq = 0;
	tcp->doff = 6;
	tcp->syn = 1;			
	tcp->window = htons(1024);
	tcp->check = cksum(pkt + 20, 24);

	printf("%d\n", cksum(pkt + 20, 24));

	ip = (struct iphdr *)pkt;
	ip->ihl = 5;
	ip->version = 4;	
	ip->tos = 0;
	ip->tot_len = 44;
	ip->id = htons(1234);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = inet_addr("192.168.0.7");
	ip->daddr = inet_addr("192.168.0.1"); 
	ip->check = cksum(pkt, 44); 

	printf("%d\n", cksum(pkt, 44));

	if (sendto(sock, pkt, 44, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("sendto() error");
		return -1;
	}

	ret = recvfrom(sock, pkt, sizeof(pkt), 0, NULL, NULL); 
	if (ret < 0)
	{
		perror("recvfrom() error");
		return -1;
	}

	close(sock);
	return 0;
}
