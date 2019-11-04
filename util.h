#ifndef __UTIL_H_
#define __UTIL_H_

extern int get_gateway(unsigned int * ip, unsigned char * mac);

extern unsigned short cksum(unsigned short * buf, int len);

extern int find_pids(const char ** list, int * plist, int len);

#endif
