#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/icmp.h>
#include <netdb.h>
#include "util.h"

#define BUF_SIZE 4096

static unsigned int target[128];
static int count;

static const char * message = "Hello";

static int param_parse(int argc, char ** argv)
{
	const char * usage = "\tUsage\n"
		"#./icmp {target ip or domain} {message}\n";

	int ret = 0, idx = 1;
	struct hostent * hostent = NULL;

	if (argc == 1)
	{
		printf("%s\n", usage);
		exit(-1);
	}
	
	if (!strcmp(argv[idx], "ping"))
	{
		ret = 0;
	}
	else if (!strcmp(argv[idx], "trace"))
	{
		ret = 1;
	}
	else
	{
		printf("Invalid command: %s\n", argv[idx]);
		exit(-1);
	}

	if (idx + 1 < argc)
		hostent = gethostbyname(argv[idx + 1]);
		
	if (!hostent)
	{
		herror("gethostbyname() error");
		exit(-1);
	}				
	else
	{
		printf("Official Name: %s\n", hostent->h_name);
		for (count = 0; hostent->h_addr_list[count]; count++)
		{
			target[count] = *(unsigned int *)hostent->h_addr_list[count];
			printf("aliase: %s\n", 
				inet_ntoa(*(struct in_addr*)&target[count]));
		}
	}	


	if (idx + 2 < argc)
		message = argv[idx + 2];

	return ret;
}

static int ping(const char * msg)
{
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	unsigned char buf[4096];
	struct sockaddr_in addr;
	struct icmphdr * icmp;
	int len = sizeof(struct icmphdr) + strlen(msg);
	int cnt;

	if (sock < 0)
	{
		perror("socket() error");
		exit(-1);
	}

	memset(buf, 0, sizeof(buf));
	icmp = (struct icmphdr *)buf;

	icmp->type = 8;
	icmp->code = 0;
	icmp->checksum = 0;
	(icmp->un).echo.id = 1234;
	(icmp->un).echo.sequence = 56;

	strcpy((char *)(icmp + 1), msg);

	icmp->checksum = cksum((unsigned short * )buf, len);

	for (cnt = 0; cnt < count; cnt++)
	{
		addr.sin_family = PF_INET;
		addr.sin_addr.s_addr = target[cnt];

		sendto(sock, buf, len,  0, (struct sockaddr *)&addr, sizeof(addr));
		sleep(1);
	}

	//recvfrom()
	//
	//

	close(sock);	
	return 0;
}


int main(int argc, char ** argv)
{
	int func = param_parse(argc, argv);

	ping(message);






	return 0;
}








//simple echo request
//trace route
//
//./icmp ping ip-address message -- IP_HDRINCL (x)
//./icmp trace ip-address -- IP_HDRINCL (o)
//gethostbyaddr() : domain -> ip
//need not interface name
/*int main(int argc, char ** argv)
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
}*/		

