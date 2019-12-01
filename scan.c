#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include "util.c"

/*for (port= 443; port <= 65536; port++)
	{
		sock = socket(PF_INET, SOCK_STREAM, 0);
		if (sock < 0)
		{
			perror("socket() error");
			break;
		}

		if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
		{
			perror("setsockopt() error");
			break;
		}
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
		{
			perror("ttl() error");
			break;
		}

		addr.sin_port = htons(port);
	
		if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
			perror("connect() error");
		else
			printf("port[%u] is opend\n", port);
		
		close(sock);
	}
*/

int main(int argc, char ** argv)
{
	int sock;
	struct sockaddr_in addr, raddr;
	unsigned short port = 1;
	int cnt, ttl = 1;
	struct timeval timeout;
	unsigned char pkt[1024], rep[1024];
	struct tcphdr * tcp;
	int len, ret;
	int on = 0;

	struct sockaddr_in saddr;

	unsigned char * tt;
	//if (argc == 1)
		//return -1;

	sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket() error");
		return -1;
	}

	if (setsockopt(sock, IPPROTO_IP, IP_NODEFRAG, &on, sizeof(on)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = inet_addr("192.168.0.1");
	addr.sin_port = htons(80);

	/*if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
{
	perror("connect()");
	return -1;
}
else
	return 0;*/
	
	/*timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}*/

	for (port= 80; port <= 65536; port++)
	{
		memset(pkt, 0, sizeof(pkt));
		//addr.sin_port = htons(port);
	
		tcp = (struct tcphdr *)pkt;
		tcp->source = htons(51234);
		tcp->dest = htons(port);
		tcp->seq = htonl(123456);
		tcp->doff = 6;
		tcp->syn = 1;			
		tcp->window = htons(1024);

		tt = (unsigned char *)(tcp + 1);
		tt[0] = 2;
		tt[1] = 4;
		tt[2] = 0x05;
		tt[3] = 0xb4;
		tcp->check = cksum(pkt, sizeof(struct tcphdr) + 4);

		if (sendto(sock, pkt, sizeof(struct tcphdr) + 4, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		{
			perror("sendto() error");
			break;
		}

		ret = recvfrom(sock, rep, sizeof(rep), 0, NULL, NULL); 
		if (ret < 0)
		{
			perror("recvfrom() error");
			continue;
		}
		
		rep[ret] = 0;
		printf("len, %d, %u is open\n", ret, port);	
	}

	close(sock);
	return 0;
}
