#include "arp_packet.h"

using namespace std;

arp_packet::arp_packet(char* data, int size){
  eth=(struct ethhdr*)data;
  arp=(struct arpheader*)(data+sizeof(struct ethhdr));
}

unsigned char* arp_packet::eth_src_mac_address(){
  return eth->h_source;
}

unsigned char* arp_packet::arp_src_mac_address(){
  return arp->ar_sha;
}

unsigned char* arp_packet::eth_dest_mac_address(){
  return eth->h_dest;
}

unsigned char* arp_packet::arp_dest_mac_address(){
  return arp->ar_tha;
}

bool arp_packet::prelim_check(){
  unsigned char* ether=eth_src_mac_address();
  unsigned char* arpa=arp_src_mac_address();
  unsigned char* ethd=eth_dest_mac_address();
  unsigned char* arpd=arp_dest_mac_address();
  int compare=strncmp((const char*)ether,(const char*)arpa,6);
  int compared=strncmp((const char*)ethd,(const char*)arpd,6);
  if(compare!=0){
    return false;
  }
  else{
    return true;
  }
}
