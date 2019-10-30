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

#define BUF_SIZE 65536

typedef struct
{
	unsigned int ip;
	unsigned int subnet;
	unsigned char mac[6];
}host;

typedef void (*routine)(int);

void scanning(int);
void spoofing(int);

static host this;
static unsigned int gateway;

static routine actions[3] = {scanning, spoofing, NULL};
static int action = 0;

void param_parse(int argc, char * argv[])
{
	static const char * manual[] = {"hostscan", "spoof"};

	if (argc <= 2)
	{
		int idx = 0;
		printf("Usage: %s \"gateway ip\" parameters\n", argv[0]);
		printf("Paramter lists\n");
		for (; idx < sizeof(manual) / sizeof(char *); idx++)
			printf("---%s\n", manual[idx]);
		exit(-1);
	}
	else
	{
		int idx = 2;

		gateway = inet_addr(argv[1]);	
		if (!strcmp(argv[idx], "hostscan"))
		{
			action = 0;	
		}
		else if (!strcmp(argv[idx], "spoof"))
		{
			action = 1;
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

unsigned char * create_arp_packet(unsigned char * buf, unsigned short op, unsigned char * target, unsigned int dest)
{
	unsigned char * ptr;
	struct ethhdr * eth;
	struct arphdr * arp;

	eth = (struct ethhdr *)buf;
	//set ethernet header
	memcpy(eth->h_source, this.mac, 6); //MAC address length
	if (!target)
		memset(eth->h_dest, 0xff, 6);
	else
		memcpy(eth->h_dest, target, 6);
	eth->h_proto = htons(ETH_P_ARP);

	arp = (struct arphdr *)(eth + 1);
	//set arp header
	arp->ar_hrd = htons(1); //Ethernet
	arp->ar_pro = htons(ETH_P_IP); //IPv4
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op = htons(op);

	ptr = (unsigned char *)(arp + 1);
	//payload
	memcpy(ptr, this.mac, 6); //sha
	ptr += 6;
	memcpy(ptr, &this.ip, 4); //spa
	ptr += 4;
	if (!target) //tha
		memset(ptr, 0, 6);
	else
		memcpy(ptr, target, 6);
	ptr += 6;
	memcpy(ptr, &dest, 4); //tpa
}


void reply_handle(int sock)
{
	unsigned char buf[BUF_SIZE], * ptr;
	struct arphdr * arp;

	static unsigned char host_list[65536];
	memset(host_list, 0, sizeof(host_list));

	while (1)
	{
		int len = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);
		unsigned int host;

		if (len < 0)
			perror("recvfrom() error\n");
		if (len == 0)
			continue;

		buf[len] = 0;
		ptr = buf;
		ptr += sizeof(struct ethhdr);
		arp = (struct arphdr *)ptr;
	
		if (ntohs(arp->ar_op) != ARPOP_REPLY)
			continue;

		ptr += sizeof(struct arphdr);
		ptr += 6;

		host = (*(unsigned int *)ptr);
		host = ntohl(host & ~this.subnet);
		if (host_list[host])
			continue;

		printf("%s is alive\n", inet_ntoa(*(struct in_addr *)ptr));
		host_list[host] = 1;
	}	

	close(sock);
	exit(0);
}

void scanning(int idx)
{
	unsigned int host = 1;
	unsigned int network_addr = this.ip & this.subnet;
	unsigned int target;
	int arp_sock, pkt_size = sizeof(struct ethhdr) + sizeof(struct arphdr) + 20;
	unsigned int max;
	pid_t cp;
	unsigned char buf[BUF_SIZE];
	struct ethhdr * eth;
	struct arphdr * arp;
	struct sockaddr_ll device;

	arp_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	cp = fork();
	if (!cp) //child process
		reply_handle(arp_sock);

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = idx;
	device.sll_halen = ETH_ALEN;
	memcpy(device.sll_addr, this.mac, 6);

	max = ntohl(~this.subnet);

	while (host <= max)
	{
		target = network_addr | htonl(host++);
		create_arp_packet(buf, ARPOP_REQUEST, NULL, target);
		sendto(arp_sock, buf, pkt_size, 0, (struct sockaddr *)&device, sizeof(device));
	}
	
	sleep(1);
	kill(cp, SIGKILL);
	waitpid(cp, NULL, 0);	
	close(arp_sock);
}

void spoofing(int tmp)
{
	printf("SPOOFING\n");
}


int main(int argc, char * argv[])
{
	int idx;

	param_parse(argc, argv);
	idx = init_base();
	actions[action](idx);	
	
	return 0;
}
