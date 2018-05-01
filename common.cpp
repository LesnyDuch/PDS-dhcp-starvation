#include "common.h"

/* A function used to calculate checksum for the packet.
 * Taken from FreeBSD
 */
unsigned short in_cksum(unsigned short *addr, int content_length)
{
    int sum = 0;
    u_short answer = 0;
    u_short *w = addr;
    int nleft = content_length;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}


/* Get MAC address of given device.
 * Reworked from "Simple DHCP Client"
 */
int get_mac_addr(const char *device, u_int8_t *mac) {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int result;


    strcpy(s.ifr_name, device);
    result = ioctl(fd, SIOCGIFHWADDR, &s);
    close(fd);
    if (result != 0)
        return -1;

    memcpy((void *)mac, s.ifr_addr.sa_data, 6);
    return 0;
}
