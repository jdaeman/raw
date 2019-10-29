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

#define BUF_SIZE 65536

typedef struct
{
	unsigned int ip;
	unsigned int subnet;
	unsigned char mac[6];
}host;

typedef void (*routine)(int);

void scanning(int tmp);
void spoofing(int tmp);

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
			action = 0;
		}
		else
		{
			printf("Invalid parameter: %s\n", argv[idx]);
			exit(-1);
		}
	}	
}

void init_base()
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

	/*printf("%s\n", inet_ntoa(*(struct in_addr *)&this.ip));
	printf("%s\n", inet_ntoa(*(struct in_addr *)&this.subnet));
	printf("%x:%x:%x:%x:%x:%x\n", this.mac[0],this.mac[1],this.mac[2],this.mac[3],this.mac[4],this.mac[5]);
	*/

	close(sock);
	return;

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

void scanning(int tmp)
{
	unsigned int host = 1;
	unsigned int network_addr = this.ip & this.subnet;
	unsigned int target;
	int arp_sock;
	unsigned char buf[BUF_SIZE], * ptr;
	struct ethhdr * eth;
	struct arphdr * arp;

	arp_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

{

	target = network_addr | htonl(host++);
	eth = (struct ethhdr *)buf;
	
	memcpy(eth->h_source, this.mac, sizeof(eth->h_source));
	memset(eth->h_dest, 0xff, sizeof(eth->h_dest));
	eth->h_proto = htons(ETH_P_ARP);

	arp = (struct arphdr *)(eth + 1);

	arp->ar_hrd = htons(1); //Ethernet
	arp->ar_pro = htons(ETH_P_IP); //IPv4
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_REQUEST);

	ptr = (unsigned char *)(arp + 1); //sha
	memcpy(ptr, this.mac, 6);

	ptr += 6; //spa
	memcpy(ptr, &this.ip, 4);

	ptr += 4; //tha
	memset(ptr, 0, 6);	

	ptr += 6; //tpa
	memcpy(ptr, &target, 4);
}
	
}

void spoofing(int tmp)
{
	printf("SPOOFING\n");
}


int main(int argc, char * argv[])
{
	param_parse(argc, argv);
	init_base();
	actions[action](0);	
	

	return 0;
}
