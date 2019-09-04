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

struct __attribute__((packed)) arpheader {
  __be16 ar_hrd;
  __be16 ar_pro;
  unsigned char ar_hln;
  unsigned char ar_pln;
  __be16 ar_op;
  unsigned char		ar_sha[6];
	unsigned char		ar_sip[4];
	unsigned char		ar_tha[6];
	unsigned char		ar_tip[4];
};

class arp_packet{
private:
  struct ethhdr* eth;
  struct arpheader* arp;
  struct in_addr ipaddr;
public:
  arp_packet(char*, int);
  unsigned char* eth_src_mac_address();
  unsigned char* arp_src_mac_address();
  unsigned char* eth_dest_mac_address();
  unsigned char* arp_dest_mac_address();
  void set_src_ip();
  bool prelim_check();
  bool secondary_check();
};
