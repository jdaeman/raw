#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char ** argv)
{
	int sock;
	struct sockaddr_in addr;
	unsigned short port = 1;
	int cnt, ttl = 1;
	struct timeval timeout;

	timeout.tv_sec = 7;
	timeout.tv_usec = 0;

	if (argc == 1)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);

	for (port= 443; port <= 65536; port++)
	{
		sock = socket(PF_INET, SOCK_STREAM, 0);
		if (sock < 0)
		{
			perror("socket() error");
			break;
		}

		/*if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
		{
			perror("setsockopt() error");
			break;
		}*/
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


	return 0;
}
