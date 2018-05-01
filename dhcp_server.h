/* Class representing DHCP server.
 */

#include <arpa/inet.h>
#include <string>
#include <vector>
#include <algorithm>

#include "common.h"

#define WAITING_FOR_DISCOVERY 202
#define WAITING_FOR_REQUEST   203

#define DISCOVERY 40
#define OFFER 41
#define REQUEST 42
#define ACK 43

#define MAC_ADDR 0
#define IP_ADDR 1
#define TIMESTAMP 2
#define STATUS 3
#define XID_COM 4


class ServerDhcpInterface {
    public:
        int dhcp_send(u_int8_t *mac, uint8_t option, uint32_t xid);
        
        static pcap_t *pcap_handle;

        static void decapsulate_packet(u_char *args, 
                                       const struct pcap_pkthdr *header, 
                                       const u_char *frame);
        // Specific parameters of the server
        static u_int32_t server_ip;
        static uint8_t client_mac;
        static uint32_t lease_time;
        static uint32_t dns_server;
        static uint32_t gateway;
        static std::string domain;
        static std::vector<uint32_t> unassigned_addresses;
        static uint32_t mask;

        static std::vector<std::vector<uint64_t>> pool_table;

    private:

        static void print_pool_table();
        static void clean_pool_table();

        static uint32_t get_ip();
        static uint32_t get_record_by_xid(uint32_t xid);
        static int get_record_by_mac(uint64_t mac);

        static uint32_t get_siaddr(dhcp_header *packet, uint8_t option);
        static uint8_t get_option(dhcp_header *packet, uint8_t option);


        static void dhcp_server_output(dhcp_header *dhcp, u_int8_t *mac, 
                                       int *len, uint32_t xid);

        int add_opt(u_int8_t *packet, u_int8_t code, u_int8_t *data, 
                    u_int8_t len);
        int setup_offer(dhcp_header *packet, uint32_t xid);  
        int setup_ack(dhcp_header *packet, uint32_t xid);

        void udp_enc(struct udphdr *udp_header, int *len);
        void ethernet_enc(u_char *frame, u_int8_t *mac, int len);
        void ip_enc(struct ip *ip_header, int *len, int xid);

        static void handle_dhcp_header(dhcp_header *packet);

};
