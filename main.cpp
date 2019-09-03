#include "arp_packet.h"
#include <iostream>

using namespace std;
int main(int argc, char**argv){
  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if(sockfd<0){
      cout<<("Socket file descriptor not received!!\n");
      return 0;
  }
  else{
      cout<<"Socket file descriptor received";
  }
  struct sockaddr_ll addr_ll;
  addr_ll.sll_family=PF_PACKET;
  addr_ll.sll_ifindex = if_nametoindex("eth0");
  addr_ll.sll_protocol = htons(ETH_P_ARP);
  int  i = bind(sockfd, (struct sockaddr*)&addr_ll,sizeof(addr_ll));
  if(i==-1){
    cout<<"error binding"<<endl;
  }
  char buff[65536];
  memset(buff,0,65536);
  struct sockaddr s_addr;
  int len=sizeof(s_addr);
  int buflen=recvfrom(sockfd,buff,65536,0,&s_addr,(socklen_t*) &len);
  int loop=1;
  while(loop){
    int buflen=recvfrom(sockfd,buff,65536,0,&s_addr,(socklen_t*) &len);
    struct ethhdr* eth=(struct ethhdr*)buff;
    if(htons(eth->h_proto)==2054){
      cout<<"ARP Packet recieved. Processing now"<<endl;
      arp_packet suspicious_host(buff,buflen);
      if(suspicious_host.prelim_check()==true){
        suspicious_host.secondary_check;
      }
    }
  }
}
