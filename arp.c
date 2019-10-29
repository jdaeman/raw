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

typedef struct
{
	unsigned int ip;
	unsigned int subnet;
	unsigned char mac[6];
}host;

host this;

void param_parse(int argc, char * argv[])
{
	static const char * manual[] = {"hostscan", "spoof"};

	if (argc == 1)
	{
		int idx = 0;
		printf("Usage: %s {", argv[0]);
		for (; idx < sizeof(manual) / sizeof(char*) - 1; idx++)
			printf("%s or ", manual[idx]);
		printf("%s}\n", manual[idx]);
		exit(-1);
	}
	else
	{
		int idx = 1;
		if (!strcmp(argv[idx], "hostscan"))
		{
			
		}
		else if (!strcmp(argv[idx], "spoof"))
		{

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

int main(int argc, char * argv[])
{
	param_parse(argc, argv);
	init_base();
	return 0;
}
