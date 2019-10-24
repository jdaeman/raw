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

int main(int argc, char ** argv[])
{
	int sniff_sock;
	struct sockaddr_ll sll;
	struct packet_mreq pm;
	int interface_index;
	
	interface_index = get_nic_index();

	sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sniff_sock < 0)
		goto socket_err;
	
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_ifindex = interface_index;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sniff_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		goto bind_err;

	memset(&pm, 0, sizeof(pm));
	pm.mr_ifindex = interface_index;
	pm.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &pm, sizeof(pm)) < 0)
		goto setsockopt_err;

	if (argc == 1) //no filter
	{
		sniff_start(sniff_sock);
	}

	close(sniff_sock);
	return 0;

setsockopt_err:
	perror("setsockopt() error");
	close(sniff_sock);
	return -1;
bind_err:
	perror("bind() error");
	close(sniff_sock);
	return -1;
socket_err:
	perror("socket() error");
	return -1;
}
