#ifndef __UTIL_H_
#define __UTIL_H_

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

#endif
