#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define BUF_SIZE 8192

static char * vendor_table[16777216]; //0xffffff

unsigned char * ether_ntoa_e(unsigned char * mac)
{
	static unsigned char hf_mac[32];

	sprintf(hf_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return hf_mac;
}

int get_vendor(unsigned char * buf, unsigned char * mac)
{
	unsigned char rev[] = {mac[2], mac[1], mac[0]}; //reverse
	int vendor_code = 0;

	memcpy(&vendor_code, rev, 3);	

	if (!vendor_table[vendor_code])
	{
		strcpy(buf, "Un-registered");
		return -1; //fail
	}

	strcpy(buf, vendor_table[vendor_code]);
	return 0; //success
}		

void vendor_init(const char * path)
{
	int transform[256];
	int offset[] = {0x00100000, 0x00010000, 0x00001000, 0x00000100, 0x00000010, 0x00000001};
	int idx, v;

	FILE * fp = fopen(path, "r");
	char buf[128];

	if (!fp)
	{
		perror("fopen() error");
		return;
	}

	for (idx = '0', v = 0; idx <= '9'; idx++)
		transform[idx] = v++;
	for (idx = 'A'; idx <= 'F'; idx++)
		transform[idx] = v++;

	while (fgets(buf, sizeof(buf), fp))
	{
		int len = strlen(buf);
		char * ptr;

		v = 0;
		buf[len - 1] = 0; //remove '\n'

		for (idx = 0; idx < 6; idx++) //ex) '112233' -> 0x112233
			v += (transform[buf[idx]] * offset[idx]);

		ptr = (char *)malloc(sizeof(char) * 32);
		if (!ptr)
		{
			perror("malloc() error");
			return;
		}

		strncpy(ptr, buf + 7, 31); //to store NULL
		vendor_table[v] = ptr;
	}

	fclose(fp);
}

static int send_request(int nl_sock, int type, int * nlseq)
{
	struct nlmsghdr * nlmsg; //Netlink message header
	unsigned char buf[BUF_SIZE];

	nlmsg = (struct nlmsghdr *)buf;
	memset(buf, 0, BUF_SIZE);
	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); //routing message
	nlmsg->nlmsg_type = type; //RTM_GETROUTE or RTM_GETNEIGH
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; //maybe default setting?
	nlmsg->nlmsg_seq = (*nlseq)++; //sequence
	nlmsg->nlmsg_pid = getpid(); //for distinguish

	return send(nl_sock, buf, nlmsg->nlmsg_len, 0);
}

static int recv_response(int nl_sock, unsigned char * buf, int nlseq)
{
	unsigned char * ptr;
	int len, tot_len = 0;
	struct nlmsghdr * nlmsg;
	pid_t pid = getpid();

	ptr = buf;
	do
	{
		//receive the response
		len = recv(nl_sock, ptr, BUF_SIZE - tot_len, 0);

		if (len < 0)
			return -1;

		nlmsg = (struct nlmsghdr *)ptr;
		if (NLMSG_OK(nlmsg, len) == 0)
			return -1;
		if (nlmsg->nlmsg_type == NLMSG_ERROR)
			return -1;
		if (nlmsg->nlmsg_type == NLMSG_DONE)
			break;

		ptr += len; //next
		tot_len += len;
		
		if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0) //??
			break; 		
	} while (nlmsg->nlmsg_seq != nlseq || nlmsg->nlmsg_pid != pid);

	return tot_len;
}

static int parse_response(unsigned char * buf, int tot_len, unsigned int * ip, unsigned char * mac, int index)
{
	struct nlmsghdr * nlmsg;
	struct rtmsg * rtmsg;
	struct ndmsg * ndmsg;
	struct rtattr * attr;
	unsigned int tmp = 0, len = 0, who = 1;

	nlmsg = (struct nlmsghdr *)buf;
	for (; NLMSG_OK(nlmsg, tot_len); nlmsg = NLMSG_NEXT(nlmsg, tot_len))
	{
		if (!mac) //pointer ip is valid
		{
			rtmsg = (struct rtmsg *)(NLMSG_DATA(nlmsg));

			if (rtmsg->rtm_family != PF_INET || rtmsg->rtm_table != RT_TABLE_MAIN)
				continue;
			attr = (struct rtattr *)(RTM_RTA(rtmsg));
		}
		else //pointer mac is valid
		{
			ndmsg = (struct ndmsg *)(NLMSG_DATA(nlmsg));
		
			if (ndmsg->ndm_family != PF_INET)
				continue;
			attr = (struct rtattr *)(RTM_RTA(ndmsg));
		}

		len = RTM_PAYLOAD(nlmsg);
		for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len))
		{
			if (!mac)
			{
				if (attr->rta_type != RTA_GATEWAY)
					continue;
				if (who++ == index)
					memcpy(ip, (unsigned int *)RTA_DATA(attr), 4);

				/*{
					unsigned int zz;
					memcpy(&zz, (unsigned int *)RTA_DATA(attr), 4);
				 	//인터페이스 번호 순서대로 디폴트 게이트웨이 주소가 출력됨.
					unsigned int i = ntohl(zz);
					printf("%d.%d.%d.%d\n", (i & 0xff000000) >> 24,
						(i & 0x00ff0000) >>16,
						(i & 0x0000ff00) >> 8,
						(i & 0x000000ff));
				}*/
			}
			else
			{
				if (tmp == *ip && attr->rta_type == NDA_LLADDR)
				{
					memcpy(mac, RTA_DATA(attr), 6);
					break;
				}
				if (attr->rta_type == NDA_DST)
					memcpy(&tmp, (unsigned int *)RTA_DATA(attr), 4);
				//printf("%x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			}
		}

	}

	return 0;
}

int get_gateway(int index, unsigned int * ip, unsigned char * mac)
{
	int nl_sock;
	unsigned char buf[BUF_SIZE], * ptr;
	int nlseq = 0, msg_len = 0;
	int len, tot_len = 0;
	struct nlmsghdr * nlmsg; //netlink message
	struct ndmsg * ndmsg; //nd? message
	struct rtattr * attr; //routing attribute

	index--;

	//Netlink socket 사용 여부 확인
	nl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_sock < 0)
		return -1; //perror
	
	//phase1, find default gateway ip address
	if (send_request(nl_sock, RTM_GETROUTE, &nlseq) < 0)
		goto err_handle;
	if ((msg_len = recv_response(nl_sock, buf, nlseq)) < 0)
		goto err_handle;
	parse_response(buf, msg_len, ip, NULL, index);	

	//phase2, find default gateway mac address
	if (send_request(nl_sock, RTM_GETNEIGH, &nlseq) < 0)
		goto err_handle;
	if ((msg_len = recv_response(nl_sock, buf, nlseq)) < 0)
		goto err_handle;
	parse_response(buf, msg_len, ip, mac, index);

	//response parsing
	/*nlmsg = (struct nlmsghdr *)buf;
	for (; NLMSG_OK(nlmsg, tot_len); nlmsg = NLMSG_NEXT(nlmsg, tot_len))
	{
		ndmsg = (struct ndmsg *)(NLMSG_DATA(nlmsg));
		
		if (ndmsg->ndm_family != PF_INET)
			continue;

		attr = (struct rtattr *)(RTM_RTA(ndmsg));
		len = RTM_PAYLOAD(nlmsg);

		for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len))
		{
			if (attr->rta_type == NDA_LLADDR)
				memcpy(mac, RTA_DATA(attr), 6);
			if (attr->rta_type == NDA_DST)
				memcpy(ip, (unsigned int *)RTA_DATA(attr), 4);
		}

	}*/
	
	close(nl_sock);
	return 0;
	
err_handle:
	close(nl_sock);
	return -1; //perror
}

unsigned short cksum(unsigned short * buf, int len)
{
	/*unsigned long sum = 0;
	for(sum = 0; n > 0; n -= 2)
	{
		sum += *(buf++);	
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);*/

	unsigned int sum = 0;
	for (; len > 0; len -= 2)
	{
		if (len == 1)
			sum += (unsigned short)(*(unsigned char *)buf);
		else
			sum += *(buf++);

		while (sum & 0xffff0000)
		{
			unsigned int carry = (sum & 0xffff0000) >> 16;
			sum &= 0x0000ffff;
			sum += carry;
		}	
	}

	return (unsigned short)~sum;

	/*unsigned long sum = 0;
	for(sum = 0; len > 1; len -= 2)
	{
		sum += *(buf++);	
	}

	if(len == 1)
	{
		unsigned short t = (unsigned short)(*((unsigned char *)buf));
		sum += t;		
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);*/
}

int find_pids(const char ** list, pid_t * plist, int len)
{
	DIR * dir;
	struct dirent * ent;
	char * endptr;
	char buf[512];
	int fd, cnt, idx = 0;

	if (!(dir = opendir("/proc")))
		return -1;

	while ((ent = readdir(dir)) != NULL)
	{
		long pid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != 0) //not numeric
			continue; 

		sprintf(buf, "/proc/%ld/comm", pid);
		fd = open(buf, O_RDONLY);
		if ((cnt =read(fd, buf, 512)) < 0)
		{
			closedir(dir);
			return -1;
		}
		buf[cnt - 1] = 0;

		for (cnt = 0; cnt < len; cnt++)
		{
			if (!strcmp(buf, list[cnt]))
			{
				plist[idx++] = pid;
				break;
			}
		}
		close(fd);
		if (idx == len)
			break;		
	}

	closedir(dir);
	if (idx < len)
		return -1;	
	return 0;
}

/*int create_icmp_packet(char * buf, int len,
			u_int8_t * eth_dest, u_int8_t * eth_src,
			u_int32_t src_ip, u_int32_t dest_ip,
			int ttl, int type, int code, void * etc)
{
	struct iphdr * ip;
	struct icmphdr * icmp;
	char * remainder;
	int etc_len = strlen(etc);

	memset(buf, 0, len);
	
	ip = (struct iphdr *)buf;
	ip->ihl = 5; //5 * 4
	ip->version = 4; //IPv4
	ip->tos = 0;
	ip->tot_len = htons(20 + 8 + etc_len); //size of iphdr + size of icmphdr
	ip->id = 5555;
	ip->frag_off = 0;
	ip->ttl = ttl;
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0;
	ip->saddr = src_ip;
	ip->daddr = dest_ip;
	
	icmp = (struct icmphdr *)(ip + 1);
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = 0;
	(icmp->un).echo.id = 1111;
	(icmp->un).echo.sequence = 15;

	remainder = (char *)(icmp + 1);
	strcpy(remainder, etc);

	icmp->checksum = cksum((unsigned short *)icmp, 8 + etc_len);	
	ip->check = cksum((unsigned short *)ip, 20 + 8 + etc_len);

	return (20 + 8 + etc_len);
}

int icmp_send(char * buf, int len, u_int32_t dest, char * cpy)
{
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	int on = 1;
	struct sockaddr_in sockaddr;
	char temp[4096];

	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
		return -1;

	sockaddr.sin_family = PF_INET;
	sockaddr.sin_addr.s_addr = dest;
	
	if(sendto(sock, buf, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
		return -1;
	
	return recvfrom(sock, cpy, 4096, 0, NULL, 0); 
}*/

