/* This code was inspired by "Simple DHCP Client"
 * https://github.com/samueldotj/dhcp-client/blob/master/dhcp-client.c
 * All thanks to its author Samuel Jacob (samueldotj@gmail.com)
 */

#include "dhcp_client.h"
#include <iostream>

using namespace std;

pcap_t*  ClientDhcpInterface::pcap_handle = 0;
uint32_t ClientDhcpInterface::server_ip = 0;
uint32_t ClientDhcpInterface::client_ip = 0;
uint32_t ClientDhcpInterface::xid = 0;
uint8_t ClientDhcpInterface::dev_mac[16];
int ClientDhcpInterface::state = 0;


/* Get server address from DHCP options instead of SIAddr field.
 */
u_int32_t ClientDhcpInterface::get_siaddr(dhcp_header *packet, uint8_t opt=54) {
    uint8_t option = 0;
    uint32_t address = 0;
    int pos = 0;
    while (packet->options[pos] != 255) {
        // Get the option
        option = int(packet->options[pos]);
        // cout<<"Reading option "<<int(packet->options[pos])<<endl;
        if (int(option) == opt) {
            address = ntohl(*(uint32_t *)&(packet->options[pos+2]));
            break;
        }
        else {
            pos += packet->options[pos+1];
            pos += 2;
        }
        // return 0;
    }
    return address;
}

/* Get a 1 byte-long option from DHCP options.
 */
u_int8_t ClientDhcpInterface::get_option(dhcp_header *packet, uint8_t opt) {
    uint8_t option = 0;
    uint32_t result = 0;
    int pos = 0;
    while (packet->options[pos] != 255) {
        option = int(packet->options[pos]);
        if (option == opt) {
            result = packet->options[pos+2];
            break;
        }
        else {
            pos += packet->options[pos+1];
            pos += 2;
        }
    }
    return result;
}

/* Setup DHCP options for DISCOVERY message.
 */
int ClientDhcpInterface::setup_discovery(dhcp_header *packet) {
    int len = 0;
    u_int8_t parameter_req_list[] = {1, 3, 6, 15};

    uint8_t padding[16];

    u_int8_t option = 1;
    // Discovey
    len += this->add_opt(&packet->options[len], 53,
                                  &option, sizeof(option));
    // Requirements list
    len += this->add_opt(&packet->options[len], 55,
                        (u_int8_t *)&parameter_req_list,
                        sizeof(parameter_req_list));
    option = 0;
    // Endmark
    len += this->add_opt(&packet->options[len], 255, &option, sizeof(option));

    // Padding
    len += this->add_opt(&packet->options[len], 0, (u_int8_t *)&padding,
                         sizeof(padding));
    return len;
}

/* Setup DHCP options for REQUEST message.
 */
int ClientDhcpInterface::setup_request(dhcp_header *packet) {
    int len = 0;
    u_int32_t rev_cip = htonl(ClientDhcpInterface::client_ip);
    u_int32_t rev_sip = htonl(ClientDhcpInterface::server_ip);

    uint8_t padding[16];

    u_int8_t option = 3;  // Request

    len += this->add_opt(&packet->options[len], 53, &option, sizeof(option));
    // Requested IP
    len += this->add_opt(&packet->options[len], 50, (uint8_t*)&rev_cip,
                         sizeof(uint32_t));
    // Server ID
    len += this->add_opt(&packet->options[len], 54, (uint8_t*)&rev_sip,
                         sizeof(uint32_t));
    option = 0;
    // Endmark
    len += this->add_opt(&packet->options[len], 255, &option, sizeof(option));
    // Padding
    len += this->add_opt(&packet->options[len], 0, (u_int8_t *)&padding,
                        sizeof(padding));
    return len;
}

/* Add a DHCP option into options array.
 * Taken from "Simple DHCP Client"
 */
int ClientDhcpInterface::add_opt(u_int8_t *options, u_int8_t option,
    u_int8_t *content, u_int8_t content_length) {

    options[0] = option;
    options[1] = content_length;

    memcpy(&options[2], content, content_length);

    return content_length + (sizeof(u_int8_t) * 2);
}

/* Parse a DHCP header.
 */
void ClientDhcpInterface::handle_dhcp_header(dhcp_header *packet) {
    // Check if it's an offer
    if (state == WAITING_FOR_OFFER &&
        get_option(packet, 53) == 2 &&
        packet->XID == xid) {

        // Get the ip
        client_ip = ntohl(packet->YIAddr);
        server_ip = get_siaddr(packet);
        pcap_breakloop(pcap_handle);
    }
    // Check if its an ACK, or a NAK
    else if (state == WAITING_FOR_ACK &&
            (get_option(packet, 53) == 5 || get_option(packet, 53) == 6) &&
             packet->XID == xid)  {

        if (ntohl(packet->YIAddr) == client_ip) {
            pcap_breakloop(pcap_handle);
        }
    }
}

/* Decapsulate the packet to see if its a DHCP packet. If so, pass it to the
 * DHCP header handler.
 * Reworked from "Simple DHCP Client"
 */
void ClientDhcpInterface::decapsulate_packet(
    u_char *args, const struct pcap_pkthdr *header, const u_char *frame) {

    struct ether_header * ethernet_frame = (struct ether_header *)frame;
    struct ip * ip_packet;
    struct udphdr * udp_header;

    if (htons(ethernet_frame->ether_type) == ETHERTYPE_IP) {
        ip_packet = (struct ip *)(frame + sizeof(struct ether_header));
        // Care only about UDP
        if (ip_packet->ip_p == IPPROTO_UDP) {
            udp_header = (struct udphdr *)((char *)ip_packet + sizeof(struct ip));
            // DHCP runs on port 67 client-side
            if (ntohs(udp_header->uh_sport) == 67) {
                handle_dhcp_header(
                    (dhcp_header *)((char *)udp_header +
                                        sizeof(struct udphdr)));
            }
        }
    }
}

/* Encapsulate the data with appropriate ethernet header.
 * Reworked from "Simple DHCP Client"
 */
void ClientDhcpInterface::ethernet_enc(u_char *frame, u_int8_t *mac, int len) {
    struct ether_header *eframe = (struct ether_header *)frame;

    memcpy(eframe->ether_shost, dev_mac, ETHER_ADDR_LEN);
    memset(eframe->ether_dhost, -1,  ETHER_ADDR_LEN);
    eframe->ether_type = htons(ETHERTYPE_IP);

    len = len + sizeof(struct ether_header);

    pcap_inject(this->pcap_handle, frame, len);
}

/* Encapsulate the data with appropriate IP header.
 * Reworked from "Simple DHCP Client"
 */
void ClientDhcpInterface::ip_enc(struct ip *ip_header, int *len) {
    *len += sizeof(struct ip);

    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0x10;
    ip_header->ip_len = htons(*len);
    ip_header->ip_id = htons(0xffff);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = 0;
	ip_header->ip_dst.s_addr = 0xFFFFFFFF;

    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));

}

/* Encapsulate the data with appropriate UDP header.
 * Reworked from "Simple DHCP Client"
 */
void ClientDhcpInterface::udp_enc(struct udphdr *udp_header, int *len) {
    if (*len & 1)
        *len += 1;
    *len += sizeof(struct udphdr);

    udp_header->uh_sport = htons(68);
    udp_header->uh_dport = htons(67);
    udp_header->uh_ulen = htons(*len);
    udp_header->uh_sum = 0;
}

/* Set up the DHCP header.
 * Reworked from "Simple DHCP Client"
 */
void ClientDhcpInterface::dhcp_client_output(dhcp_header *dhcp, u_int8_t *mac, int *len) {
    *len += sizeof(dhcp_header);
    memset(dhcp, 0, sizeof(dhcp_header));

    dhcp->op_code = 1;
    dhcp->HType = 1;  // Ethernet
    dhcp->HLen = 6;
    dhcp->flags = htons(1<<15);
    dhcp->SIAddr = htonl(server_ip);
    dhcp->XID = xid;
    memcpy(dhcp->CHAddr, mac, 16);
    dhcp->MAGIC_COOKIE = htonl(0x63825363);
}

/* Send a DHCP packet with correctly set-up options.
 * Inspired by "Simple DHCP Client"
 */
int ClientDhcpInterface::dhcp_send(u_int8_t *mac, uint8_t option) {
    int len = 0;
    u_char send_packet[4096];
    struct udphdr *udp_header;
    struct ip *ip_header;
    dhcp_header *packet;

    ip_header = (struct ip *)(send_packet + sizeof(struct ether_header));
    udp_header = (struct udphdr *)(((char *)ip_header) + sizeof(struct ip));
    packet = (dhcp_header *)(((char *)udp_header) + sizeof(struct udphdr));

    switch(option) {
        case DISCOVERY:
            len = this->setup_discovery(packet);
            break;

        case REQUEST:
            len = this->setup_request(packet);
            break;
    }

    this->dhcp_client_output(packet, mac, &len);
    this->udp_enc(udp_header, &len);
    this->ip_enc(ip_header, &len);
    this->ethernet_enc(send_packet, mac, len);

    return 0;
}
