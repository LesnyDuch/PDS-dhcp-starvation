/* Class representing DHCP client.
 */

#include "common.h"
#include <random> 

#define WAITING_FOR_ACK 20
#define WAITING_FOR_OFFER 200

#define DISCOVERY 41
#define REQUEST 42

class ClientDhcpInterface {
    public:
        int dhcp_send(u_int8_t *mac, uint8_t option);
        static u_int8_t dev_mac[16];

        static pcap_t *pcap_handle;
        static u_int32_t client_ip;
        static u_int32_t server_ip;
        static uint32_t xid; 
        static int state;
        static void decapsulate_packet(u_char *args, 
            const struct pcap_pkthdr *header, const u_char *frame);

    private:
        // Input
        static void handle_dhcp_header(dhcp_header *packet);
        static uint32_t get_siaddr(dhcp_header *packet, uint8_t option);
        static uint8_t get_option(dhcp_header *packet, uint8_t option);


        int add_opt(u_int8_t *options, u_int8_t option, u_int8_t *content,
                    u_int8_t content_length);
        int setup_discovery(dhcp_header *packet);  

        int setup_request(dhcp_header *packet);
       
        void udp_enc(struct udphdr *udp_header, int *len);
        void ethernet_enc(u_char *frame, u_int8_t *mac, int len);
        void ip_enc(struct ip *ip_header, int *len);
        void dhcp_client_output(dhcp_header *dhcp, u_int8_t *mac, int *len);

};
