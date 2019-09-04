#include "arp_packet.h"
#include "icmp.h"
#include "mac_hash.h"
#include <iostream>

int main(int argc, char**argv){
   //keeps track of known hosts;
   mac_hash trustedhosts;

   //create raw socket to listen on
  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

   //error handling
  if(sockfd<0){
      std::cout<<("Socket file descriptor not received!!\n");
      return 0;
  }

  //create struct for interface to listen on, in this case ethernet
  struct sockaddr_ll addr_ll;
  addr_ll.sll_family=PF_PACKET;
  addr_ll.sll_ifindex = if_nametoindex("eth0");
  addr_ll.sll_protocol = htons(ETH_P_ARP);

  //bind socket to interface
  int  i = bind(sockfd, (struct sockaddr*)&addr_ll,sizeof(addr_ll));

  //error handling
  if(i==-1){
    cout<<"error binding"<<endl;
  }

  char buff[65536];
  memset(buff,0,65536);
  struct sockaddr s_addr;
  int len=sizeof(s_addr);
  int loop=1;

  while(loop){

    //continue to listen while porgram runs
    int buflen=recvfrom(sockfd,buff,65536,0,&s_addr,(socklen_t*) &len);
    struct ethhdr* eth=(struct ethhdr*)buff;

    //process packet if it's ethernet protocol is ARP
    if(htons(eth->h_proto)==2054){
        std::cout<<"ARP Packet recieved. Processing now"<<endl;
        struct macip* host=new struct macip;
        host->ip=ip->saddr;
        host->mac=eth->h_source;

        //if known to be reliable, continue listening for packets
        if(trustedhosts,search(host)){
            continue;
        }

        //if not found in trusted hosts, perform arp poison detection
        else{

            arp_packet suspicious_host(buff,buflen);

            //perform initila check for conflicts in mac addresses
            if(suspicious_host.prelim_check()==true){

              //perform secondary check
              if(suspicious_host.secondary_check()){
                trustedhosts.add(host);
                std::cerr<<"Legitimate host added"<<endl;
              }
              else{
                std::cerr<<"Poison detected"<<endl;
              }
            }
            else{
              std::cerr<<"poison detected"<<endl;
            }
        }
      }
  }
}
