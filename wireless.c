#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>

/*#include <linux/if.h>

ifconfig -> flags

enum net_device_flags

SIOCGIFFLAGS, SIOCSIFFLAGS
-> up, down

first, down the interface
second, changed the mode managed mode(2) -> moniotor mode
third, up the interface
*/

int main(int argc, char ** argv)
{
	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	struct iwreq iwreq;

	strcpy(iwreq.ifr_ifrn.ifrn_name, "wlan0");
	iwreq.u.mode = IW_MODE_MONITOR;
	if (ioctl(sock, SIOCSIWMODE, &iwreq) < 0)
	{
		perror("ioctl error");
		return -1;
	}
	printf("%u \n", iwreq.u.mode);
	

	return 0;
}
