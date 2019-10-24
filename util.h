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

#endif
