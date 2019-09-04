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
#include <string>

//structure of packet to be received
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
  int recieve_ping();
  int send_ping_driver(char*);
  int get_response_type(); //returnns response type in ICMP header of packet
  int main_driver(); //runs both send and recieve function
  string suspicious_ip; //stores ip address found in arp packet
  unsigned char* suspicious_mac; //stores mac address found in arp packet

private:
  struct ethhdr* eth; //headers of packet to be analyzed
  struct iphdr* ip;
  struct icmphdr* icmp;
  int response_type;
};

#endif
