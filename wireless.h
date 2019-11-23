#ifndef _WIRELESS_H_
#define _WIRELESS_H_

struct ieee80211_hdr
{
	unsigned short frame_control;
	//protocol version:2, type:2, subtype:4, ToAP:1
	//FromAP:1, morefrag: 1, Retry:1, pwrmgt: 1, moredata:1, WEP:1, Rsvd:1	
	unsigned short duration_id;
	unsigned char addr1[6]; //dest address
	unsigned char addr2[6]; //src address
	unsigned char addr3[6]; //router address
	unsigned short seq_ctrl;
	unsigned char addr4[6]; //used in adhoc

	//payload, max 2312 bytes
	//CRC, 4 bytes		
};

#endif
