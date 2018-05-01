#include "dhcp_server.h"
#include <iostream>
#include <signal.h>
#include <algorithm>

ServerDhcpInterface *interface_ptr;

using namespace std;

/* Generate IP pool based on argument string.
 */
vector<uint32_t> generate_pool(string pool_str, uint32_t *server_ip){
    int bottom, top;
    vector<uint32_t> pool;
    inet_pton(AF_INET, 
              pool_str.substr(0, pool_str.find('-')).c_str(),
              &bottom);
    inet_pton(AF_INET, 
              pool_str.substr(pool_str.find('-')+1, pool_str.size()-1).c_str(),
              &top);
    *server_ip = bottom-1;
    bottom = ntohl(bottom);
    top = ntohl(top);

    for (auto i=bottom; i<=top; i++) {
        pool.push_back(htonl(i));
    }
    reverse(pool.begin(), pool.end());
    return pool;
}

/* Setup DHCP server interface according to cmd line arguments.
 */
ServerDhcpInterface setup_interface(int argc, char *argv[], string *device) {
    ServerDhcpInterface interface;
    string pool = "";
    int opt;
    while ((opt = getopt (argc, argv, "i:p:g:n:d:l:")) != -1) {
        cout<<optarg<<endl;
        switch (opt) {
            case 'i':
                *device = optarg; 
                break;
            case 'p':
                pool = optarg;
                interface.unassigned_addresses = generate_pool(
                    pool, &interface.server_ip);
                break;
            case 'g':
                inet_pton(AF_INET, optarg, &interface.gateway);
                break;
            case 'n':
                inet_pton(AF_INET, optarg, &interface.dns_server);
                break;
            case 'd':
                interface.domain = optarg;
                break;
            case 'l':
                interface.lease_time = stoi(string(optarg));
                break;
        }
    }
    return interface;
} 

/* Handle sigint.
 */
void sigint_handler(int signo) {
    pcap_breakloop(interface_ptr->pcap_handle);
    pcap_close(interface_ptr->pcap_handle);
    cout<<endl<<"Exiting gracefully..."<<endl;
    exit(0);
}

int main(int argc, char *argv[]) {
    int result;
    char errbuf[PCAP_ERRBUF_SIZE];
    string device;
    u_int8_t mac[6];

    ServerDhcpInterface interface;
    interface = setup_interface(argc, argv, &device);   
    interface_ptr = &interface;

    // TODO: Edit maska and edit ip

    get_mac_addr(device.c_str(), mac);

    signal(SIGINT, sigint_handler);

    // Open the device and get pcap handle for it 
    interface.pcap_handle = pcap_open_live(device.c_str(), BUFSIZ, 0, 10, 
                                           errbuf);

    pcap_lookupnet(device.c_str(), &interface.server_ip, &interface.mask,
                   errbuf);
    if (interface.pcap_handle == NULL) {
        cout<<"Failed to open pcap handle."<<endl;
        cout<<errbuf<<endl;
        return -1;
    }

    while(1) {
        cout<<"Waiting for input."<<endl;
        // Listen
        pcap_loop(interface.pcap_handle, -1, interface.decapsulate_packet, NULL);
        // Manage updated pool table
        for (unsigned i=0; i<interface.pool_table.size(); i++) {
            if (interface.pool_table[i][STATUS] == DISCOVERY) {
                interface.pool_table[i][STATUS] = OFFER;
                interface.dhcp_send(mac, OFFER, interface.pool_table[i][XID_COM]);
            }
            if (interface.pool_table[i][STATUS] == REQUEST) {
                interface.pool_table[i][STATUS] = ACK;
                interface.dhcp_send(mac, ACK, interface.pool_table[i][XID_COM]);
            }
        }
    }
    return result;
}
