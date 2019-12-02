#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include "util.c"

#define LIST_LEN 8

struct pseudo
{
	unsigned int src;
	unsigned int dst;
	unsigned char resv;
	unsigned char proto;
	unsigned short tcpseg_len;
};

typedef int (*routine)(void *);

int open_scan(void * args);
int half_scan(void * args);

static unsigned int src_ip;
static unsigned int tar_list[LIST_LEN];
static unsigned int use_port[LIST_LEN];

static routine action;

static int param_parse(int argc, char ** argv)
{
	int idx;

	if (argc == 1)
		goto parse_fail;	

	if (get_host_address(argv[1], &src_ip) < 0)
		goto parse_fail;

	for (idx = 2; idx < argc; idx += 2)
	{
		if (idx + 1 >= argc)
			goto parse_fail;

		if (argv[idx][0] == 'o' || argv[idx][1] == 'o') //operation
		{
			if (argv[idx + 1][0] == 'O') //Open Connection
				action = open_scan;
			else if (argv[idx + 1][0] == 'H') //Half-open Connection
				action = half_scan;
			else
				goto parse_fail;
		}
		else if (argv[idx][0] == 't' || argv[idx][1] == 't') //target
		{
			if (get_domain_ip(tar_list, LIST_LEN, argv[idx + 1]) < 0) //Unknown host
				goto parse_fail;
		}
		else
			goto parse_fail;	
		
	}

	return 0;

parse_fail:
	printf("Usage: \n");
	exit(-1);
}

static int target_lookup(unsigned int * table, int len, unsigned int who)
{
	int cnt;
	for (cnt = 0; cnt < len; cnt++)
	{
		if (table[cnt] == who)
			return 0;
		if (table[cnt] == 0)
			break;
	}
	return -1;
}

static void init_use_port(void)
{
	int idx;
	for (idx = 0; idx < LIST_LEN; idx++)
		use_port[idx] = 50000 + (rand() % 3000);
}

static void * rcv_handler(void * args)
{
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	unsigned char buf[64];
	int rcv_len;
	unsigned int src, cnt;
	
	struct iphdr * ip;
	struct tcphdr * tcp;

	while ((rcv_len = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL)) > 0)
	{
		buf[rcv_len] = 0;

		ip = (struct iphdr *)buf;
		if (target_lookup(tar_list, LIST_LEN, ip->saddr) < 0) //not target ip
			continue;

		tcp = (struct tcphdr *)(ip + 1);
		if (target_lookup(use_port, LIST_LEN, tcp->dest) < 0) //not correct port
			continue;
		
		printf("[%u] is opend\n", ntohs(tcp->source));
	}
		
	return NULL;
}


int main(int argc, char ** argv)
{
	param_parse(argc, argv);
	srand(time(NULL));
	init_use_port();
	action(NULL);
	return 0;
}

int open_scan(void * argc)
{
	return 0;
}

int half_scan(void * args)
{
	int sock;
	struct sockaddr_in addr;
	unsigned short port = 8080;
	unsigned char pkt[1024];
	struct tcphdr * tcp;
	struct pseudo * pp;
	int cnt;

	static unsigned int target_port[65536];
	int tot = 0;

	sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket() error");
		return -1;
	}

	for (cnt = 0; tar_list[cnt]; cnt++)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = PF_INET;
		addr.sin_addr.s_addr = tar_list[cnt];

		for (port = 0; port < 10000; port++ )
		{
			/*port = rand() % 65536;
			if (target_port[port])
				continue;
			
			target_port[port] = 1;
			tot += 1;*/

			addr.sin_port = htons(port);

			memset(pkt, 0, sizeof(pkt));
			tcp = (struct tcphdr *)(pkt + 12);
			tcp->source = htons(use_port[rand() % LIST_LEN]); //random
			tcp->dest = htons(port);
			tcp->seq = htonl(rand()); //random
			tcp->ack_seq = 0;
			tcp->doff = 5;
			tcp->syn = 1;			
			tcp->window = htons(1024);

			pp = (struct pseudo *)pkt;
			pp->src = src_ip;
			pp->dst = tar_list[cnt];
			pp->proto = IPPROTO_TCP;
			pp->tcpseg_len = htons(tcp->doff << 2);

			tcp->check = cksum(pkt, 12 + 20);

			if (sendto(sock, pkt + 12, 20, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
			{
				perror("sendto() error");
				return -1;
			}

			usleep(2000);
		}
	}
	
	close(sock);
	return 0;
}

/*int backup(void * args)
{
	int sock;
	struct sockaddr_in addr;
	unsigned short port = 8080;
	unsigned char pkt[1024], * tt;
	unsigned char pseudo[12];
	struct tcphdr * tcp;
	struct iphdr * ip;
	int on = 1, ret;
	int proto = IPPROTO_TCP, tcp_len = 20;
	struct pseudo * pp;
	struct sockaddr_in aaa;
	int zzz;

	sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket() error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = inet_addr("10.20.0.1");
	addr.sin_port = htons(port);

	memset(pkt, 0, sizeof(pkt));
	
	tcp = (struct tcphdr *)(pkt + 12);
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
	pp = (struct pseudo *)pkt;
	pp->src = inet_addr("10.20.17.245");
	pp->dst = inet_addr("10.20.0.1");
	pp->proto = IPPROTO_TCP;
	pp->tcpseg_len = htons(tcp->doff << 2);

	tcp->check = cksum(pkt, 12 + 20);

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

	if (sendto(sock, pkt + 12, 20, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("sendto() error");
		return -1;
	}

	ret = recvfrom(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&aaa, &zzz); 
	if (ret < 0)
	{
		perror("recvfrom() error");
		return -1;
	}
	else
		printf("%d received\n", ret);

	printf("port: %u\n", ntohs(aaa.sin_port));
	printf("src: %s\n", inet_ntoa(aaa.sin_addr));

	close(sock);
	return 0;
}*/

// https://stackoverflow.com/questions/29877735/not-receiving-syn-ack-after-sending-syn-using-raw-socket

