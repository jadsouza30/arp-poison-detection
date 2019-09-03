#ifndef ICMP
#define ICMP

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
#include  <netpacket/packet.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
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


struct ping_pkt{
    struct icmphdr hdr;
    char msg[64-sizeof(struct icmphdr)];
};

class Icmp{
public:
  Icmp();
  bool process_reply(char*,int);
  unsigned short checksum(void*, int);
  void inthandler(int);
  char* dns_lookup(char*, sockaddr_in*);
  char* reverse_dns_lookup(char*);
  void send_ping(int, sockaddr_in*,char*,char*,char*);
private:
  struct ethhdr* eth;
  struct iphdr* ip;
  struct icmphdr* icmp;
};

#endif
