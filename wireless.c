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
//iwreq.u.mode = IW_MODE_MONITOR;

static const char * flags[] = {"UP", "BROADCAST", "DEBUG", "LOOPBACK",
				"POINTTOPOINT", "NOTRAILERS", "RUNNING", "NOARP",
				"PROMISC", "ALLMULTI", "MASTER", "SLAVE",
				"MULTICAST", "PORTSEL", "AUTOMEDIA", "DYNAMIC"};

static const char * modes[] = {"AUTO", "ADHOC", "INFRA", "MASTER",
				"REPEAT", "SECOND", "MONITOR", "MESH"};

static void print_if_state(struct ifreq * ifreq)
{
	int off;

	if (!ifreq)
		return;

	printf("%s flags: ", ifreq->ifr_name);
	for (off = 0; off < 16; off++)
	{
		if (ifreq->ifr_flags & (1 << off))
			printf("%s ", flags[off]);
	}
	puts("");
}

static int if_switch(int sock, struct ifreq * ifreq, int on)
{
	unsigned short flag = (IFF_UP | IFF_RUNNING); 
	
	if (!ifreq)
		return -1;
	
	if (on)
		ifreq->ifr_flags |= flag;
	else
		ifreq->ifr_flags &= ~flag;

	if (ioctl(sock, SIOCSIFFLAGS, ifreq) < 0)
		return -1;
	return 0;	
}

static int wireless_mode_change(int sock, struct ifreq * ifreq, struct iwreq * iwreq, int mode)
{
	if (!ifreq || !iwreq)
		return -1;

	if (ioctl(sock, SIOCGIFFLAGS, ifreq) < 0)
		return -1;

	if (if_switch(sock, ifreq, 0) < 0) //off
		return -1;

	(iwreq->u).mode = mode;
	if (ioctl(sock, SIOCSIWMODE, iwreq) < 0)
		return -1;

	if (if_switch(sock, ifreq, 1) < 0) //on
		return -1;

	printf("%s, [%s] mode on\n", ifreq->ifr_name, modes[mode]);
	return 0;
}

int main(int argc, char ** argv)
{
	struct iwreq iwreq;
	struct ifreq ifreq;
	int sock, off;

	if (argc == 1)
	{
		printf("there is no interface name\n");
		return -1;
	}

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		goto socket_err;
	
	strcpy(iwreq.ifr_ifrn.ifrn_name, argv[1]);
	strcpy(ifreq.ifr_name, argv[1]);

	//check whether the inteface is wireless.
	if (ioctl(sock, SIOCGIWMODE, &iwreq) < 0)
		goto ioctl_err;

	//monitor mode on
	if (wireless_mode_change(sock, &ifreq, &iwreq, IW_MODE_MONITOR) < 0)
		goto ioctl_err;
	
	//sniff code, ieee80211_hdr

	if (wireless_mode_change(sock, &ifreq, &iwreq, IW_MODE_INFRA) < 0)
		goto ioctl_err;
	
	return 0;

socket_err:
	perror("socket() error");
	return -1;
ioctl_err:
	perror("ioctl() error");
	close(sock);
	return -1;
}
