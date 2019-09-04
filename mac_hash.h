#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <iostream>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <cstring>

struct macip{
    unsigned char ip[4];
    unsigned char mac[6];
    struct macip* next;
};

class mac_hash{
private:
    macip* known_hosts[255];
public:
    bool search(struct macip*);
    void add(struct macip*);
    bool is_same_ip(struct macip*, struct macip*);
    bool is_same_mac(struct macip*,struct macip*);
};