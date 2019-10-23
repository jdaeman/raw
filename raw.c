#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_SIZE 65536

int main(int argc, char ** argv[])
{
	int sniff_sock;
	unsigned char buf[BUF_SIZE];
	
	printf("%s\n", argv[0]);
		

	//argv[0] :
	//argv[1] :
	//argv[2] :
	//argv[3] :

	return 0;
}
