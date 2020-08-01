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
#include <sys/wait.h>
#include <signal.h>
#include "util.h"
#include "pktparse.h"

#define BUF_SIZE 4096 + 1
//adfadffadfadsf

static const char * flags[] = {"UP", "BROADCAST", "DEBUG", "LOOPBACK",
				"POINTTOPOINT", "NOTRAILERS", "RUNNING", "NOARP",
				"PROMISC", "ALLMULTI", "MASTER", "SLAVE",
				"MULTICAST", "PORTSEL", "AUTOMEDIA", "DYNAMIC"};

static const char * modes[] = {"AUTO", "ADHOC", "MANAGE", "MASTER",
				"REPEAT", "SECOND", "MONITOR", "MESH"};

static struct iwreq iwreq;
static struct ifreq ifreq;

static int cont = 1;


static void ieee80211_hdr_parse(char * pkt, int len)
{
	struct ieee80211_hdr * h = (struct ieee80211_hdr *)pkt;
}

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

static int wifi_disconnect(int sock)
{
	char buf[IW_ESSID_MAX_SIZE + 1]; //32
	char exec[] = "/bin/nmcli"; //NetworkManager Controller
	char * argv[5] = {exec, "con", "down", buf, NULL};
	int pid;
	
	iwreq.u.essid.pointer = buf;
	iwreq.u.essid.length = sizeof(buf);

	ioctl(sock, SIOCGIWESSID, &iwreq);

	if (!(pid = fork()))
	{
		//child process
		extern char ** environ;
		return execve(exec, argv, environ);
	}
	else
		return pid;
}

static int wireless_mode_change(int sock, int mode)
{
	unsigned short flag = (IFF_UP | IFF_RUNNING);

	//get interface flags
	if (ioctl(sock, SIOCGIFFLAGS, &ifreq) < 0)
		return -1;
	
	//turn off interface
	ifreq.ifr_flags &= ~flag;
	if (ioctl(sock, SIOCSIFFLAGS, &ifreq) < 0)
		return -1;

	//change operation mode
	iwreq.u.mode = mode;
	if (ioctl(sock, SIOCSIWMODE, &iwreq) < 0)
		return -1;

	//turn on interface
	ifreq.ifr_flags |= flag;
	if (ioctl(sock, SIOCSIFFLAGS, &ifreq) < 0)
		return -1;

	return 0;
}

static int init_base(int argc, char ** argv)
{
	int sock, pid, status;
	
	if (argc == 1)
	{
		printf("There is no interface name\n");
		exit(-1);
	}

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		goto socket_err;

	strcpy(iwreq.ifr_ifrn.ifrn_name, argv[1]);
	strcpy(ifreq.ifr_name, argv[1]);

	//check wireless interface	
	if (ioctl(sock, SIOCGIWMODE, &iwreq) < 0)
		goto ioctl_err;

	//step1, 
	pid = wifi_disconnect(sock);
	if (pid < 0)
		goto some_err;
	waitpid(pid, &status, 0);

	//step2, 
	if (wireless_mode_change(sock, IW_MODE_MONITOR) < 0)
		goto ioctl_err;

	//step3,
	system("service NetworkManager restart");

	return sock;

socket_err:
	perror("socket() error");
	goto finish;
ioctl_err:
	perror("ioctl() error");
	goto free_resource;
some_err:
	perror("execve() error");
free_resource:
	close(sock);
finish:
	exit(-1);
}

static void restore(int sock)
{
	wireless_mode_change(sock, IW_MODE_INFRA);

	system("service NetworkManager restart");
}

void sighandle(int sig)
{
	if (sig == SIGINT)
	{
		cont = 0;
	}
}

static void sniff(int sock)
{
	unsigned char buf[BUF_SIZE];
	unsigned char parse[BUF_SIZE];

	signal(SIGINT, sighandle);

	while (cont)
	{
		int len = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);

		if (len <= 0)
		{
			perror("recvfrom() error");
			break;
		}

		ieee80211_handle(buf, parse, len);
		printf("%s\n", parse);
	}
}

int main(int argc, char ** argv)
{
	int sock;

	sock = init_base(argc, argv);
	
	sniff(sock);

	restore(sock);

	close(sock);

	return 0;
}


