#include "arp_packet.h"
#include <string>
#include "icmp.h"
#include <sstream>
#include <iostream>

using namespace std;

arp_packet::arp_packet(char* data, int size){
  //initialize data headers
  eth=(struct ethhdr*)data;
  arp=(struct arpheader*)(data+sizeof(struct ethhdr));
}

unsigned char* arp_packet::eth_src_mac_address(){
  //return source mac address from ethernet header
  return eth->h_source;
}

unsigned char* arp_packet::arp_src_mac_address(){
  //return source mac address from arp header
  return arp->ar_sha;
}

unsigned char* arp_packet::eth_dest_mac_address(){
  //return dest mac address from ethernet ehader
  return eth->h_dest;
}

unsigned char* arp_packet::arp_dest_mac_address(){
  //return dest mac address from arp header
  return arp->ar_tha;
}

bool arp_packet::prelim_check(){
  unsigned char* ether=eth_src_mac_address();
  unsigned char* arpa=arp_src_mac_address();
  unsigned char* ethd=eth_dest_mac_address();
  unsigned char* arpd=arp_dest_mac_address();
  int compare=strncmp((const char*)ether,(const char*)arpa,6);
  int compared=strncmp((const char*)ethd,(const char*)arpd,6);

  //if conflicting source mac addresses, arp poisoning is present
  if(compare!=0){
    return false;
  }

  else{
    return true;
  }
}

bool arp_packet::secondary_check(){
  Icmp sus_host;
  unsigned long add;
  add |= ((int)arp->ar_sip[3] << 24);
  add |= ((int)arp->ar_sip[2] << 16);
  add |= ((int)arp->ar_sip[1] << 8);
  add |= ((int)arp->ar_sip[0]);

  stringstream buffer;
  for(int i=0;i<3;i++){
    buffer<<(int)arp->ar_sip[i];
    buffer<<".";
  }
  buffer<<(int)arp->ar_sip[3];
  buffer<<'\n';
  buffer>>sus_host.suspicious_ip;
  sus_host.suspicious_mac=eth->h_source;
  int response=sus_host.main_driver();
  if(response!=0){
    return false;
  }
  else{
    return false;
  }
}
