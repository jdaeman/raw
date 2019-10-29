#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include "pktparse.h"

#define BUF_SIZE 65536
#define PARSE_SIZE 1024

static int open_mode;

static void param_parse(int argc, char * argv[])
{
	int list[12];
	int len = 0;

	if (argc <= 1)
		open_mode = 0;
	else
	{
		int idx = 1;
		for ( ; idx < argc; idx++)
		{	
			if (!strcmp(argv[idx], "promisc"))
				open_mode = 1;
			else if (!strcmp(argv[idx], "arp"))
			{
				list[len++] = ARP;	
			}
			else if (!strcmp(argv[idx], "icmp"))
			{
				list[len++] = ICMP;
			}
			else if (!strcmp(argv[idx], "udp"))
			{
				list[len++] = UDP;
			}
			else if (!strcmp(argv[idx], "tcp"))
			{
				list[len++] = TCP;
			}
			else
				goto invalid_type;
		}

	
	}

	set_filter(list, len);
	return;

invalid_type:
	printf("Invalid parameter\n");
	exit(-1);
}

static int get_nic_index()
{
	struct if_nameindex * if_arr, * itf;
	struct ifreq ifr;
	int index;

	if_arr = if_nameindex();
	if (!if_arr)
		goto err;

	printf("-----network interface list-----\n");
	for (itf = if_arr; itf->if_index != 0 || itf->if_name != NULL; itf++)
	{
		printf("%s(%d)\n", itf->if_name, itf->if_index);
	}
	
	if_freenameindex(if_arr);

	printf("\nChoose interface index\n>> ");
	scanf("%d", &index);

	return index;
err:
	perror("if_nameindex() error");
	exit(-1);
}


static void sniff_start(int sock)
{
	static unsigned char buf[BUF_SIZE];
	unsigned char parse[5][PARSE_SIZE];
	unsigned char * ptr;
	
	while (1)
	{
		int layer = 0;
		int rcvs = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);

		if (rcvs <= 0)
			continue;

		buf[rcvs] = 0;
		ptr = eth_handle(buf, parse[layer++], PARSE_SIZE);
		while (ptr && next)
			ptr = next(ptr, parse[layer++], PARSE_SIZE);

		if (is_avail())
		{
			int cur = 0;
			for (; cur < layer; cur++)
				printf("%s\n", parse[cur]);
			if (ptr)	
				printf("-----payload-----\n%s\n", ptr);
			puts("");
		}	
	}		
}

static int socket_open(int interface_index)
{
	struct sockaddr_ll sll;
	struct packet_mreq pm;
	
	int sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sniff_sock < 0)
		goto socket_err;
	
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_ifindex = interface_index;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sniff_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		goto bind_err;

	if (open_mode)
	{
		memset(&pm, 0, sizeof(pm));
		pm.mr_ifindex = interface_index;
		pm.mr_type = PACKET_MR_PROMISC;
		if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &pm, sizeof(pm)) < 0)
			goto setsockopt_err;
	}

	return sniff_sock;

setsockopt_err:
	perror("setsockopt() error");
	close(sniff_sock);
	exit(-1);
bind_err:
	perror("bind() error");
	close(sniff_sock);
	exit(-1);
socket_err:
	perror("socket() error");
	exit(-1);
}

int main(int argc, char * argv[])
{
	int sniff_sock;
	int interface_index;
	
	param_parse(argc, argv);

	interface_index = get_nic_index();
	
	sniff_sock = socket_open(interface_index);

	sniff_start(sniff_sock);

	close(sniff_sock);

	return 0;
}
