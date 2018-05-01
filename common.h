#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <iostream>

struct dhcp_header {
	u_int8_t op_code;
	u_int8_t HType;
	u_int8_t HLen = 6;
	u_int8_t Hops;
	u_int32_t XID;
	u_int16_t Secs;
	u_int16_t flags;
	u_int32_t CIAddr;
	u_int32_t YIAddr;
	u_int32_t SIAddr;
	u_int32_t GIAddr;
	u_int8_t CHAddr[16];

	char SName[64];
	char File[128];
    u_int32_t MAGIC_COOKIE;
	uint8_t options[0];
};


unsigned short in_cksum(unsigned short *addr, int len);

int get_mac_addr(const char *device, u_int8_t *mac) ;