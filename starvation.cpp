#include <iostream>
#include <signal.h>
#include "dhcp_client.h"

// Timeout in seconds
#define TIMEOUT 5

using namespace std;
ClientDhcpInterface * interface_ptr;

/* Setup DHCP server interface according to cmd line arguments.
 */
void get_device(int argc, char *argv[], string *device) {
    int opt;
    while ((opt = getopt (argc, argv, "i:")) != -1) {
        cout<<optarg<<endl;
        switch (opt) {
            case 'i':
                *device = optarg; 
                break;
        }
    }
} 

/* Handle sigint.
 */
void sigint_handler(int signo) {
    pcap_breakloop(interface_ptr->pcap_handle);
    pcap_close(interface_ptr->pcap_handle);
    cout<<endl<<"Exiting gracefully..."<<endl;
    exit(0);
}

/* Handle alarm.
 */
void sigalrm_handler(int signo) {
    pcap_breakloop(interface_ptr->pcap_handle);
    cout<<"TIMEOUT - Sending new DISCOVERY."<<endl;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int8_t mac[6];
    string device;

    srand(time(NULL));

    get_device(argc, argv, &device);

    ClientDhcpInterface interface;
    interface_ptr = &interface;

    // Get the mac address of given device
    get_mac_addr(device.c_str(), mac);
    get_mac_addr(device.c_str(), interface.dev_mac);

    // Respond to ctrl+c
    signal(SIGINT, sigint_handler);

    // Timeout for OFFER and ACK
    signal(SIGALRM, sigalrm_handler);

    /* Open the device and get pcap handle for it */
    interface.pcap_handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000,
                                           errbuf);
    if (interface.pcap_handle == NULL)
    {
        cout<<"Failed to open pcap handle."<<endl;
        cout<<errbuf<<endl;
        return -1;
    }

    while(1) {
        
        // Send a discovery
        interface.xid = rand()%UINT32_MAX;
        interface.server_ip = 0;
        interface.dhcp_send(mac, DISCOVERY);

        // Set the timeout for waiting for OFFER
        alarm(TIMEOUT);
        interface.state = WAITING_FOR_OFFER;
        cout<<"Waiting for DHCP_OFFER"<<endl;
        pcap_loop(interface.pcap_handle, -1, interface.decapsulate_packet, NULL);
    
        // Offer was not received
        if (interface.server_ip == 0) continue;
        cout<<"Got IP address."<<endl;

        // Send A request
        interface.dhcp_send(mac, REQUEST);
        cout<<"Sent DHCP_REQUEST."<<endl;
        
        cout<<"Waiting for DHCP_ACK."<<endl;
        // Set the timeout for waiting for ACK
        alarm(TIMEOUT);
        interface.state = WAITING_FOR_ACK;
        pcap_loop(interface.pcap_handle, -1, interface.decapsulate_packet, NULL);
        
        // Increment the MAC address
        if (mac[5] == 0xff) {
            if (mac[4] == 0xff) {
                mac[4] = mac[5] == 0;
            }
            else {
                mac[4] ++;
                mac[5] = 0;
            }
        }
        else (mac[5])++;
    }
    getchar();
    pcap_close(interface.pcap_handle);
    return 0;
}
