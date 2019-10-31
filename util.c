
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#define BUF_SIZE 8192

static int send_request(int nl_sock, int type, int * nlseq)
{
	struct nlmsghdr * nlmsg;
	unsigned char buf[BUF_SIZE];

	nlmsg = (struct nlmsghdr *)buf;
	memset(buf, 0, BUF_SIZE);
	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); //routing message
	nlmsg->nlmsg_type = type;
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; //maybe default?
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

static int parse_response(unsigned char * buf, int tot_len, unsigned int * ip, unsigned char * mac)
{
	struct nlmsghdr * nlmsg;
	struct rtmsg * rtmsg;
	struct ndmsg * ndmsg;
	struct rtattr * attr;
	unsigned int tmp = 0, len;

	nlmsg = (struct nlmsghdr *)buf;
	for (; NLMSG_OK(nlmsg, tot_len); nlmsg = NLMSG_NEXT(nlmsg, tot_len))
	{
		if (!mac)
		{
			rtmsg = (struct rtmsg *)(NLMSG_DATA(nlmsg));

			if (rtmsg->rtm_family != PF_INET || rtmsg->rtm_table != RT_TABLE_MAIN)
				continue;
			attr = (struct rtattr *)(RTM_RTA(rtmsg));
		}
		else
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
				memcpy(ip, (unsigned int *)RTA_DATA(attr), 4);
				break;
			}
			else
			{
				if (tmp == *ip && attr->rta_type == NDA_LLADDR)
					memcpy(mac, RTA_DATA(attr), 6);
				if (attr->rta_type == NDA_DST)
					memcpy(&tmp, (unsigned int *)RTA_DATA(attr), 4);
				//printf("%x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			}
		}

	}

	return 0;
}

int get_gateway(unsigned int * ip, unsigned char * mac)
{
	int nl_sock;
	unsigned char buf[BUF_SIZE], * ptr;
	int nlseq = 0, msg_len = 0;
	int len, tot_len = 0;
	struct nlmsghdr * nlmsg; //netlink message
	struct ndmsg * ndmsg; //nd? message
	struct rtattr * attr; //routing attribute

	nl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_sock < 0)
		return -1; //perror
	
	//phase1, find default gateway ip address
	if (send_request(nl_sock, RTM_GETROUTE, &nlseq) < 0)
		goto err_handle;
	if ((msg_len = recv_response(nl_sock, buf, nlseq)) < 0)
		goto err_handle;
	parse_response(buf, msg_len, ip, NULL);	

	//phase2, find default gateway mac address
	if (send_request(nl_sock, RTM_GETNEIGH, &nlseq) < 0)
		goto err_handle;
	if ((msg_len = recv_response(nl_sock, buf, nlseq)) < 0)
		goto err_handle;
	parse_response(buf, msg_len, ip, mac);

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

	unsigned long sum = 0;
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
	return (unsigned short)(~sum);
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

