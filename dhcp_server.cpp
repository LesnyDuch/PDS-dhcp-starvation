/* This code was inspired by "Simple DHCP Client"
 * https://github.com/samueldotj/dhcp-client/blob/master/dhcp-client.c
 * All thanks to its author Samuel Jacob (samueldotj@gmail.com)
 */


#include "dhcp_server.h"
#include <iostream>
using namespace std;

// If a client sent a DISCOVERY, but did not send a request, its record
// is removed from the pool table
#define DISCOVERY_TIMEOUT 600

pcap_t*  ServerDhcpInterface::pcap_handle = 0;
uint32_t ServerDhcpInterface::server_ip = 0;

uint8_t ServerDhcpInterface::client_mac = 0;
uint32_t ServerDhcpInterface::lease_time = 10;
uint32_t ServerDhcpInterface::dns_server = 0;
uint32_t ServerDhcpInterface::gateway = 0;
std::string ServerDhcpInterface::domain = "";
uint32_t ServerDhcpInterface::mask = 0;



std::vector<uint32_t> ServerDhcpInterface::unassigned_addresses = {};
std::vector<std::vector<uint64_t>> ServerDhcpInterface::pool_table = {};

/* Get server address from DHCP options instead of SIAddr field.
 */
u_int32_t ServerDhcpInterface::get_siaddr(dhcp_header *packet, uint8_t opt=54) {
    uint8_t option = 0;
    uint32_t address = 0;
    int pos = 0;
    // int size = sizeof(*packet->options);
    // cout<<"Size"<<size<<endl;
    while (packet->options[pos] != 255) {
        // Get the option
        option = int(packet->options[pos]);
        // cout<<"Reading option "<<int(packet->options[pos])<<endl;
        if (int(option) == opt) {
            address = *(uint32_t *)&(packet->options[pos+2]);
            break;
        }
        else {
            pos += packet->options[pos+1];
            pos += 2;
        }
    }
    return address;
}

/* Get a 1 byte-long option from DHCP options.
 */
u_int8_t ServerDhcpInterface::get_option(dhcp_header *packet, uint8_t opt) {
    uint8_t option = 0;
    uint32_t result = 0;
    int pos = 0;
    // int size = sizeof(*packet->options);
    while (packet->options[pos] != 255) {
        // Get the option
        option = int(packet->options[pos]);
        // cout<<"Reading option "<<int(packet->options[pos])<<endl;
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

/* Get record's id from pool table by its transaction id.
 */
uint32_t ServerDhcpInterface::get_record_by_xid(uint32_t xid) {

    for(unsigned i=0; i<pool_table.size(); i++) {
        if (pool_table[i][XID_COM] == xid) {
            return i;
        }
    }
    return -1;
}

/* Find record in pool table by its MAC address.
 */
int ServerDhcpInterface::get_record_by_mac(uint64_t mac) {
    for (unsigned i=0; i<ServerDhcpInterface::pool_table.size(); i++) {
        if (pool_table[i][MAC_ADDR] == mac) {
            return i;
        }
    }
    return -1;
}

/* Clean the pool table of:
 * - Clients that have their lease expired - lease time
 * - Clients that didn't repspond with any REQUEST after DISCOVERY - DISCOVERY
 *      timeout
 */
void ServerDhcpInterface::clean_pool_table() {
    for (unsigned i=0; i<pool_table.size(); i++) {
        // Unanswered OFFERS
        if (pool_table[i][STATUS] == OFFER &&
            (pool_table[i][TIMESTAMP] + DISCOVERY_TIMEOUT) < (unsigned)time(NULL)) {
            cout<<"DHCP - Releasing client "<<hex;
            cout<<ntohl(pool_table[i][MAC_ADDR])<<endl;

            unassigned_addresses.push_back(pool_table[i][IP_ADDR]);
            pool_table.erase(pool_table.begin()+i);

        }
        // Expired leases
        else if (pool_table[i][STATUS] == ACK &&
                (pool_table[i][TIMESTAMP] + lease_time) < (unsigned)time(NULL)) {
            cout<<"DHCP - Releasing client "<<hex;
            cout<<ntohl(pool_table[i][MAC_ADDR])<<endl;

            unassigned_addresses.push_back(pool_table[i][IP_ADDR]);
            pool_table.erase(pool_table.begin()+i);
        }
    }
}

/* Print out the contets of pool table.
 * Primarily for debugging.
 */
void ServerDhcpInterface::print_pool_table() {
    cout<<"Table size: "<<pool_table.size()<<endl;
    cout<<"MAC addr\tIP addr\tXID\tStatus\tTimestamp"<<endl;
    char buff[INET_ADDRSTRLEN];
    for (unsigned i=0; i<pool_table.size(); i++) {
        cout<<hex<<pool_table[i][MAC_ADDR]<<"\t";
        cout<<hex<<inet_ntop(AF_INET,
                             &pool_table[i][IP_ADDR],
                             buff,
                             INET_ADDRSTRLEN)<<"\t";
        cout<<hex<<ntohl(pool_table[i][XID_COM])<<"\t";
        cout<<dec<<pool_table[i][STATUS]<<"\t";
        cout<<pool_table[i][TIMESTAMP]<<endl;
    }
}

/* Fill the necessary DHCP options for OFFER.
 */
int ServerDhcpInterface::setup_offer(dhcp_header *packet, uint32_t xid) {
    int len = 0;
    int record_id = get_record_by_xid(xid);

    // Change records status to OFFER
    pool_table[record_id][STATUS] = OFFER;

    // Teke data from pool_table, or server setup
    uint32_t lease_t = htonl(ServerDhcpInterface::lease_time);
    uint32_t dns_server = htonl(ServerDhcpInterface::dns_server);
    u_int8_t option = 2;
    u_int32_t netmask = mask; // 255.255.255.0

    // Set up all necessary options
    // Offer
    len += this->add_opt(&packet->options[len], 53,
                                  &option, sizeof(option));
    // Subnet mask
    len += this->add_opt(&packet->options[len], 1,
                                  (uint8_t*)&netmask,
                                  sizeof(uint32_t));
    // Router
    len += this->add_opt(&packet->options[len], 3,
                                  (uint8_t*)&gateway,
                                  sizeof(uint32_t));
    // Lease time
    len += this->add_opt(&packet->options[len], 51,
                                  (uint8_t*)&lease_t,
                                  sizeof(uint32_t));
    // DHCP Server
    len += this->add_opt(&packet->options[len], 54,
                                  (uint8_t*)&server_ip,
                                  sizeof(uint32_t));
    // Dns server
    len += this->add_opt(&packet->options[len], 6,
                                  (uint8_t*)&dns_server,
                                  sizeof(uint32_t));
    // Endmark
    option = 0;
    len += this->add_opt(&packet->options[len], 255, &option, sizeof(option));
    return len;
}

/* Fill the necessary DHCP options for ACK.
 */
int ServerDhcpInterface::setup_ack(dhcp_header *packet,
                                               uint32_t xid) {
    int len = 0;

    int record_id = get_record_by_xid(xid);
    pool_table[record_id][STATUS] = OFFER;

    uint32_t lease_t = htonl(ServerDhcpInterface::lease_time);
    uint32_t dns_server = htonl(ServerDhcpInterface::dns_server);
    u_int8_t option;

    u_int32_t netmask = htonl(0xffffff00); // 255.255.255.0

    option = 5;  // Ack
    len += this->add_opt(&packet->options[len], 53,
                                  &option, sizeof(option));
        // Subnet mask
    len += this->add_opt(&packet->options[len], 1,
                                  (uint8_t*)&netmask,
                                  sizeof(uint32_t));
    // Router
    len += this->add_opt(&packet->options[len], 3,
                                  (uint8_t*)&gateway,
                                  sizeof(uint32_t));
    // Lease time
    len += this->add_opt(&packet->options[len], 51,
                                  (uint8_t*)&lease_t,
                                  sizeof(uint32_t));
    // DHCP Server
    len += this->add_opt(&packet->options[len], 54,
                                  (uint8_t*)&server_ip,
                                  sizeof(uint32_t));
    // Dns server
    len += this->add_opt(&packet->options[len], 6,
                                  (uint8_t*)&dns_server,
                                  sizeof(uint32_t));
    option = 0;
    len += this->add_opt(&packet->options[len], 255, &option, sizeof(option));

    return len;
}

/* Add a DHCP option into options array.
 * Taken from "Simple DHCP Client"
 */
int ServerDhcpInterface::add_opt(u_int8_t *options, u_int8_t option,
    u_int8_t *content, u_int8_t content_length) {

    options[0] = option;
    options[1] = content_length;

    memcpy(&options[2], content, content_length);

    return content_length + (sizeof(u_int8_t) * 2);
}


/* Get a new IP address from avaliable addresses. Returns -1 if there are
 * no vacant addresses.
 */
uint32_t ServerDhcpInterface::get_ip() {
    uint32_t result = -1;
    if (unassigned_addresses.empty()) {
        return result;
    }
    else {
        result = unassigned_addresses.back();
        unassigned_addresses.pop_back();
        return result;
    }
}

/* Parse DHCP header and work with pool table accordingly.
 */
void ServerDhcpInterface::handle_dhcp_header(dhcp_header *header) {
    // Clean the table before working with it
    clean_pool_table();

    // Receive a DISCOVERY
    if (ServerDhcpInterface::get_option(header, 53) == 1) {
        uint64_t client_mac = 0;
        memcpy(&client_mac, &header->CHAddr, 6);
        // Test if the device (MAC address) is already in our table
        // - in that case we remove the old record and send a new request
        int id;
        if ((id = get_record_by_mac(client_mac)) != -1) {
            cout<<"handle_dhcp_header - Resending request"<<endl;
            unassigned_addresses.push_back(pool_table[id][IP_ADDR]);
            pool_table.erase(pool_table.begin() + id);
        }

        uint32_t new_ip = ServerDhcpInterface::get_ip();
        cout << "handle_dhcp_header - Handling discovery for "<<new_ip<<endl;
        std::vector<uint64_t> new_record(5);

        // If we have an address to assign, set up a new record for request
        // and set its status to DISCOVERY
        if (new_ip != uint32_t(-1)) {
            memcpy(&new_record[MAC_ADDR], &header->CHAddr, 6);
            new_record[IP_ADDR] = new_ip;
            new_record[TIMESTAMP] = time(NULL);
            new_record[STATUS] = DISCOVERY;
            new_record[XID_COM] = header->XID;
            pool_table.push_back(new_record);
        }

        pcap_breakloop(ServerDhcpInterface::pcap_handle);
    }

    // Receive a REQUEST
    else if (get_option(header, 53) == 3) {
        int record_id = get_record_by_xid(header->XID);
        // Request from an unknown XID
        if (record_id == -1 ||
            ((get_siaddr(header) == 0)  && (get_siaddr(header) != server_ip))) {
            // It could be a REBIND
            // Check if the MAC address is already registered
            uint64_t client_mac = 0;
            memcpy(&client_mac, &header->CHAddr, 6);
            int id;
            if ((id = get_record_by_mac(client_mac)) != -1) {
                cout<<"handle_dhcp_header - Rebinding a client."<<endl;
                pool_table[id][XID_COM] = header->XID;
            }
            // No record found, ignore this
            else {
                cout << "handle_dhcp_header - No record for "<<header->XID<<endl;
                return;
            }
        }
        // The client signed to a different server
        else if (get_siaddr(header) != server_ip) {
            cout << "handle_dhcp_header -  "<<header->XID;
            cout<<" refused offer"<<endl;
            unassigned_addresses.push_back(pool_table[record_id][IP_ADDR]);
            pool_table.erase(pool_table.begin()+record_id);
        }
        pool_table[record_id][STATUS] = REQUEST;
        pcap_breakloop(ServerDhcpInterface::pcap_handle);
        print_pool_table();
    }

    // Receive a DECLINE - Given IP address could be taken
    else if (get_option(header, 53) == 4) {
        int record_id = get_record_by_xid(header->XID);
        if (record_id != -1) {
            unassigned_addresses.push_back(pool_table[record_id][IP_ADDR]);
            pool_table.erase(pool_table.begin()+record_id);
            rotate(unassigned_addresses.begin(),
                   unassigned_addresses.begin() + 1,
                   unassigned_addresses.end());
        }
    }
}

/* Decapsulate the packet to see if its a DHCP packet. If so, pass it to the
 * DHCP header handler.
 * Reworked from "Simple DHCP Client"
 */
void ServerDhcpInterface::decapsulate_packet(
    u_char *args, const struct pcap_pkthdr *header, const u_char *frame) {

    struct ether_header * ethernet_frame = (struct ether_header *)frame;
    struct ip * ip_packet;
    struct udphdr * udp_header;

    if (htons(ethernet_frame->ether_type) == ETHERTYPE_IP) {
        ip_packet = (struct ip *)(frame + sizeof(struct ether_header));
        // Care only about UDP
        if (ip_packet->ip_p == IPPROTO_UDP) {
            udp_header = (struct udphdr *)((char *)ip_packet + sizeof(struct ip));
            // DHCP runs on port 68 server-side
            if (ntohs(udp_header->uh_sport) == 68) {
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
void ServerDhcpInterface::ethernet_enc(u_char *frame, u_int8_t *mac, int len) {
    struct ether_header *eframe = (struct ether_header *)frame;

    memcpy(eframe->ether_shost, mac, ETHER_ADDR_LEN);
    memset(eframe->ether_dhost, -1,  ETHER_ADDR_LEN);

    eframe->ether_type = htons(ETHERTYPE_IP);

    len = len + sizeof(struct ether_header);

    pcap_inject(this->pcap_handle, frame, len);
}

/* Encapsulate the data with appropriate IP header.
 * Reworked from "Simple DHCP Client"
 */
void ServerDhcpInterface::ip_enc(struct ip *ip_header, int *len, int xid) {
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
    ip_header->ip_src.s_addr = server_ip;
	// ip_header->ip_dst.s_addr = pool_table[get_record_by_xid(xid)][IP_ADDR];
  	ip_header->ip_dst.s_addr = -1;


    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));

}

/* Encapsulate the data with appropriate UDP header.
 * Reworked from "Simple DHCP Client"
 */
void ServerDhcpInterface::udp_enc(struct udphdr *udp_header, int *len) {
    if (*len & 1)
        *len += 1;
    *len += sizeof(struct udphdr);

    udp_header->uh_sport = htons(67);
    udp_header->uh_dport = htons(68);
    udp_header->uh_ulen = htons(*len);
    udp_header->uh_sum = 0;
}

/* Set up the DHCP header.
* Reworked from "Simple DHCP Client"
*/
void ServerDhcpInterface::dhcp_server_output(dhcp_header *dhcp, u_int8_t *mac,
                                             int *len, uint32_t xid) {
    *len += sizeof(dhcp_header);
    memset(dhcp, 0, sizeof(dhcp_header));

    dhcp->op_code = 2;
    dhcp->HType = 1;  // Ethernet
    dhcp->HLen = 6;
    dhcp->SIAddr = server_ip;
    dhcp->GIAddr = gateway;
    memcpy(&dhcp->CHAddr, &pool_table[get_record_by_xid(xid)][MAC_ADDR], 6);
    dhcp->YIAddr = pool_table[get_record_by_xid(xid)][IP_ADDR];
    dhcp->XID=xid;
    dhcp->MAGIC_COOKIE = htonl(0x63825363);  //  99.130.83.99 v hexa

}

/* Setup up the packet and inject it onto the wire.
 * Inspired by "Simple DHCP Client"
 */
int ServerDhcpInterface::dhcp_send(u_int8_t *mac, uint8_t option,
                                   uint32_t xid) {
    int len = 0;
    u_char send_packet[4096];
    struct udphdr *udp_header;
    struct ip *ip_header;
    dhcp_header *packet;

    ip_header = (struct ip *)(send_packet + sizeof(struct ether_header));
    udp_header = (struct udphdr *)(((char *)ip_header) + sizeof(struct ip));
    packet = (dhcp_header *)(((char *)udp_header) + sizeof(struct udphdr));
    switch(option) {
        // Send an OFFER
        case OFFER:
            len = this->setup_offer(packet, xid);
            pool_table[get_record_by_xid(xid)][STATUS] = OFFER;
            break;
        // Send an ACK
        case ACK:
            len =this->setup_ack(packet, xid);
            pool_table[get_record_by_xid(xid)][STATUS] = ACK;
            break;
    }

    this->dhcp_server_output(packet, mac, &len, xid);
    this->udp_enc(udp_header, &len);
    this->ip_enc(ip_header, &len, xid);
    this->ethernet_enc(send_packet, mac, len);

    return 0;
}
