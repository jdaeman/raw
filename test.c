#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include "util.c"

struct pseudo
{
	unsigned int src;
	unsigned int dst;
	unsigned char resv;
	unsigned char proto;
	unsigned short tcpseg_len;

	unsigned char ptr[1024];
};

int main(int argc, char ** argv)
{
	int sock;
	struct sockaddr_in addr;
	unsigned short port = 80;
	unsigned char pkt[1024], * tt;
	unsigned char pseudo[12];
	struct tcphdr * tcp;
	struct iphdr * ip;
	int on = 1, ret;
	int proto = IPPROTO_TCP, tcp_len = 20;
	struct pseudo pp;

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
	tcp->source = htons(51234);
	tcp->dest = htons(port);
	tcp->seq = htonl(172147);
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->syn = 1;			
	tcp->window = htons(1024);
	//1. pseudo-header
	//|- src-addr(4) + dst-addr(4) + reserved(1) + protocol(1) + tcp-length(2)
	//2. tcp-header
	//3. tcp-payload

	ip = (struct iphdr *)pkt;
	ip->ihl = 5;
	ip->version = 4;	
	ip->tos = 0;
	ip->tot_len = 40;
	ip->id = htons(21423);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = inet_addr("192.168.0.7");
	ip->daddr = inet_addr("192.168.0.1");
	
	memset(&pp, 0, sizeof(pp));
	pp.src = ip->saddr;
	pp.dst = ip->daddr;
	pp.proto = IPPROTO_TCP;
	pp.tcpseg_len = tcp->doff << 2;
	memcpy(pp.ptr, tcp, tcp->doff << 2);
 
	tcp->check = cksum((unsigned char *)&pp , 12 + 20);
	ip->check = cksum(pkt, 40); 

	if (sendto(sock, pkt, 40, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
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

// https://stackoverflow.com/questions/29877735/not-receiving-syn-ack-after-sending-syn-using-raw-socket

