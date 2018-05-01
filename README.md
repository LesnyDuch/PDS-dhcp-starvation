## PDS 2017/2018 - DHCP attacks

The purpose of this project is implementation DHCP Starvation and DHCP Spoofing attacks.

### How to run
* DHCP starvation:
    ```
    $ ./pds-dhcpstarvation -i <interface>
    ```

* DHCP server:
    ```
    $ ./pds-dhcprogue -i <interface> -p <1st_ip_of_pool>-<last_ip> -g <gateway> -n <dns-server> -d <domain> -l <lease-time>
    ```
