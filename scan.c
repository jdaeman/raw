#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include "util.h"

#include <termios.h>
#include <sys/ioctl.h>

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
	const char * usage =
		"./scan interfacename\n"
		"-o : operation\n"
		"\tO: TCP open connection, H: TCP half-open connection\n"
		"-t : target domain or ip\n";

	int idx;

	if (argc == 1)
		goto parse_fail;	

	if (get_host_address(argv[1], &src_ip) < 0)
	{
		perror("");
		exit(-1);
	}

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
				goto invalid_param;
		}
		else if (argv[idx][0] == 't' || argv[idx][1] == 't') //target
		{
			if (get_domain_ip(tar_list, LIST_LEN, argv[idx + 1]) < 0) //Unknown host
			{
				herror("");
				exit(-1);
			}
		}
		else
			goto invalid_param;	
		
	}

	return 0;

invalid_param:
	printf("Invalid parameter\n");
	exit(-1);
parse_fail:
	printf("Usage: %s\n", usage);
	exit(-1);
}

static int target_lookup(unsigned int * table, int len, unsigned int who)
{
	int cnt;
	for (cnt = 0; cnt < len && table[cnt]; cnt++)
	{
		if (table[cnt] == who)
			return 0;
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
	
	struct iphdr * ip;
	struct tcphdr * tcp;

	while ((rcv_len = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL)) > 0)
	{
		buf[rcv_len] = 0;

		ip = (struct iphdr *)buf;
		if (target_lookup(tar_list, LIST_LEN, ip->saddr) < 0) //not target ip
			continue;

		tcp = (struct tcphdr *)(ip + 1);
		if (target_lookup(use_port, LIST_LEN, ntohs(tcp->dest)) < 0) //not correct port
			continue;
	
		if (!(tcp->syn && tcp->ack)) //not syn-ack
			continue;

		printf("Port [%u] is opened\n", ntohs(tcp->source));
	}
	
	close(sock);	
	return NULL;
}


int main(int argc, char ** argv)
{
	/*struct winsize ws;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
	printf("%d %d\n", ws.ws_row, ws.ws_col);*/

	param_parse(argc, argv);

	srand(time(NULL));
	init_use_port();

	action(NULL);

	return 0;
}

int open_scan(void * argc)
{
	printf("implementing...\n");
	return 0;
}

int half_scan(void * args)
{
	int sock, cnt;
	struct sockaddr_in addr;
	unsigned int port = 8080;
	unsigned char pkt[1024];
	struct tcphdr * tcp;
	struct pseudo * ph;
	pthread_t tid;

	sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket() error");
		return -1;
	}

	//receive handler
	if (pthread_create(&tid, NULL, rcv_handler, NULL) < 0)
	{
		perror("pthread_create() error");
		return -1;
	}

	for (cnt = 0; tar_list[cnt]; cnt++)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = PF_INET;
		addr.sin_addr.s_addr = tar_list[cnt];

		printf("Start port scan to %s\n", inet_ntoa(*(struct in_addr *)&tar_list[cnt]));
			
		for (port = 0; port <= 65535; port++)
		{	
			addr.sin_port = htons(port);

			memset(pkt, 0, sizeof(pkt)); //reset

			tcp = (struct tcphdr *)(pkt + 12); 
			tcp->source = htons(use_port[rand() % LIST_LEN]); //source port, random
			tcp->dest = htons(port); //destination port
			tcp->seq = htonl(rand()); //random seq number
			tcp->ack_seq = 0; //zero ack
			tcp->doff = 5; //packet length, 5*4 = 20Bytes
			tcp->syn = 1; //SYN packet		
			tcp->window = htons(1024); //buffer size

			ph = (struct pseudo *)pkt; //pseudo header
			ph->src = src_ip; //source ip
			ph->dst = tar_list[cnt]; //destination ip
			ph->proto = IPPROTO_TCP; //protocol
			ph->tcpseg_len = htons(tcp->doff << 2 + 0); //there no payload

			tcp->check = cksum(pkt, 12 + 20);

			if (sendto(sock, pkt + 12, 20, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
			{
				perror("sendto() error");
				goto exit_state;
			}

			usleep(500);
		}
		puts("");
	}

exit_state:
	pthread_cancel(tid);
	pthread_join(tid, NULL);
	close(sock);
	return 0;
}


//ref, https://stackoverflow.com/questions/29877735/not-receiving-syn-ack-after-sending-syn-using-raw-socket
//ref, https://stackoverflow.com/questions/26423537/how-to-position-the-input-text-cursor-in-c/26423946
//https://stackoverflow.com/questions/33025599/move-the-cursor-in-a-c-program
//https://unix.stackexchange.com/questions/422698/how-to-set-absolute-mouse-cursor-position-in-wayland-without-using-mouse
//
//0 ~ 1023: Well-known port
//1024 ~ 49151: Registered
//49152 ~ 65535: Dynamic or private
