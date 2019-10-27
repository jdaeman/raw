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

static int open_mode;

static void param_parse(int argc, char * argv[])
{
	if (argc <= 1)
		open_mode = 0;
	else
	{
		int idx = 1;
		for ( ; idx < argc; idx++)
		{	
			if (!strcmp(argv[idx], "promisc"))
				open_mode = 1;
			else
			{
				printf("Invalid parameter: %s\n", argv[idx]);
				exit(-1);
			}
		}
	}
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

	printf("\nChoose interface index\n>>");
	scanf("%d", &index);

	return index;
err:
	perror("if_nameindex() error");
	exit(-1);
}


static void sniff_start(int sock)
{
	unsigned char buf[BUF_SIZE];
	unsigned char parse[BUF_SIZE];
	unsigned char * ptr;

	while (1)
	{
		int rcvs = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);

		if (rcvs < 0)
			break;

		buf[rcvs] = 0;
		ptr = eth_handle(buf, parse, BUF_SIZE);
		printf("%s\n", parse);
		while (ptr && next)
		{
			ptr = next(ptr, parse, BUF_SIZE);
			printf("%s\n", parse);
		}
		if (ptr)
			printf("-----payload-----\n%s\n", ptr);
		puts("");	
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

	if (open_mode == 0 || open_mode == 1) //no filter
		sniff_start(sniff_sock);


	close(sniff_sock);
	return 0;
}
