#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/icmp.h>
#include <netdb.h>
#include "util.h"

#include <errno.h>

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
	{
		if (get_domain_ip(target, 128, argv[idx + 1]) < 0)
		{
			herror("DNS error");
			exit(-1);
		}
	}		
		
	if (idx + 2 < argc)
		message = argv[idx + 2];

	return ret;
}

static int set_timeout_socket(int sock)
{
	struct timeval timeout;

	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	if (setsockopt(sock, IPPROTO_ICMP, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}
	return 0;
}

static int set_ip_handle(int sock)
{
	int on = 1;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}

	return 0;
}

static inline int set_ip_ttl(int sock, int ttl)
{
	return setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

static int create_ip_packet(unsigned char * pkt, unsigned int src, unsigned int dst,
	       int ttl, int proto)
{

	return 0;
}	

static int create_icmp_packet(unsigned char * pkt, int type, int code, const char * msg)
{
	struct icmphdr * icmp = (struct icmphdr *)(pkt);
	int len = sizeof(struct icmphdr) + strlen(msg);
	
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = 0; //reset

	if (msg)
		strcpy((char *)(icmp + 1), msg);
	
	icmp->checksum = cksum(pkt, len);

	return len;
}

static int ping(const char * msg)
{
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	unsigned char buf[BUF_SIZE], reply[BUF_SIZE];
	struct sockaddr_in addr;
	struct icmphdr * icmp;
	int len, cnt, addr_len; 

	if (sock < 0 || set_timeout_socket(sock) < 0)
	{
		if (sock < 0)
			perror("socket() error");
		exit(-1);
	}

	memset(buf, 0, sizeof(buf));
	len = create_icmp_packet(buf, 8, 0, msg);


	printf("\tSending echo request...\n");
	for (cnt = 0; target[cnt]; cnt++)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = PF_INET;
		addr.sin_addr.s_addr = target[cnt];

		//send icmp packet,
		sendto(sock, buf, len,  0, (struct sockaddr *)&addr, sizeof(addr));

		len = recvfrom(sock, reply, 4096, 0, (struct sockaddr *)&addr, &addr_len);
		if (len < 0)
		{
			printf("%d \n", errno);
			perror("recvfrom() error");
			continue;
		}

		printf("Len: %d\tfrom: %s\n", len, inet_ntoa(*(struct in_addr *)&addr.sin_addr.s_addr));
	}


	close(sock);	
	return 0;
}


static int trace(const char * msg)
{
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	struct sockaddr_in addr;

	if (sock < 0 || set_ip_handle(sock))
	{
		if (sock < 0)
			perror("socket() error");
		exit(-1);
	}

	//TTL:0 ~ 

}

int main(int argc, char ** argv)
{
	int func = param_parse(argc, argv);
	char buf[BUF_SIZE];

	unsigned int ip;
	char * ptr;

	/*struct protoent * eee = getprotobynumber(IPPROTO_ICMP);

	if (!eee)
	{
		perror("error");
		return -1;
	}

	printf("%s\n", eee->p_name);
	printf("%d\n", eee->p_proto);
	for (ip = 0; eee->p_aliases[ip]; ip++)
		printf("%s\n", eee->p_aliases[ip]);

	return 0;*/
	/*if (get_host_address(socket(PF_INET, SOCK_RAW, IPPROTO_ICMP), "wlan0", &ip) < 0)
		return -1;*/



	ping(message);






	return 0;
}
	

