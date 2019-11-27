#ifndef __UTIL_H_
#define __UTIL_H_

extern int get_gateway(int index, unsigned int * ip, unsigned char * mac);

extern int get_vendor(unsigned char * buf, unsigned char * mac);

extern void vendor_init(const char * path);

extern unsigned short cksum(unsigned char * buf, int len);

extern unsigned char * ether_ntoa_e(unsigned char * mac);

extern int find_pids(const char ** list, int * plist, int len);

extern int get_host_address(int sock, const char * interface, unsigned int * ip);

#endif
