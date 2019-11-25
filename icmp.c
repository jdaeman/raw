#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/icmp.h>
#include "util.h"

static int param_parse(int argc, char ** argv[])
{
	int ret = 0, idx = 1;

	if (argc == 1)
	{
		//print usage
		exit(-1);
	}
	
	if (!strcmp(argv[idx], "ping"))
	{
		ret = 0;
	}
	else if (!strcmp(argv[idx]), "trace")
	{
		ret = 1;
	}
	else
	{
		printf("Invalid command: %s\n", argv[idx]);
		exit(-1);
	}

		
		
}

//simple echo request
//trace route
//
//./icmp ping ip-address message -- IP_HDRINCL (x)
//./icmp trace ip-address -- IP_HDRINCL (o)
//gethostbyaddr() : domain -> ip
//need not interface name
int main(int argc, char ** argv)
{
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	unsigned char buf[4096];
	struct sockaddr_in addr;
	struct icmphdr * icmp;

	memset(buf, 0, sizeof(buf));
	icmp = (struct icmphdr *)buf;

	icmp->type = 8;
	icmp->code = 0;
	icmp->checksum = 0;
	(icmp->un).echo.id = 1111;
	(icmp->un).echo.sequence = 15;

	strcpy((char *)(icmp + 1), "Hello");

	icmp->checksum = cksum((unsigned short * )buf, 8 + 5);

	printf("%#04x\n", icmp->checksum);

	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);

	sendto(sock, buf, 8 + 5,  0, (struct sockaddr *)&addr, sizeof(addr));

	return 0;
}		

