#include "icmp.h"
// Define the Ping Loop
#define PING_PKT_S 64
#define PORT_NO 0
#define PING_SLEEP_RATE 1000000
#define RECV_TIMEOUT 1
int pingloop=1;

Icmp::Icmp(){

}

//calculates checksum to be used in ICMP header
unsigned short Icmp::checksum(void *b, int len)
{
    unsigned short *buf =(unsigned short*) b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


// break fromloop upon input
void Icmp::inthandler(int dummy)
{
    pingloop=0;
}

// Performs a DNS lookup
char* Icmp::dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
    std::cout<<"Resolving DNS.."<<endl;
    struct hostent *host_entity;
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
    int i;

    if ((host_entity = gethostbyname(addr_host)) == NULL)
    {
        // No ip found for hostname
        return NULL;
    }

    //filling up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)
                          host_entity->h_addr));
    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons (PORT_NO);
    (*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr;
    return ip;
}

// Resolves the reverse lookup of the hostname
char* Icmp::reverse_dns_lookup(char *ip_addr)
{
    struct sockaddr_in temp_addr;
    socklen_t len;
    char buf[NI_MAXHOST], *ret_buf;

    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
    len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *) &temp_addr, len, buf,
                    sizeof(buf), NULL, 0, NI_NAMEREQD))
    {
        //printf("Could not resolve reverse lookup of hostname\n");
        return NULL;
    }
    ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char) );
    strcpy(ret_buf, buf);
    return ret_buf;
}

// make a ping request
int Icmp::recieve_ping()
{
  int ttl_val=64, msg_count=0, i, addr_len, flag=1,
             msg_received_count=0;
  bool returnval=0;
  struct ping_pkt pckt;
  struct sockaddr_in r_addr;
  struct timespec time_start, time_end, tfs, tfe;
  long double rtt_msec=0, total_msec=0;
  struct timeval tv_out;
  tv_out.tv_sec = RECV_TIMEOUT;
  tv_out.tv_usec = 0;

        //receive packet
        //addr_len=sizeof(r_addr);
  char buff[65535];

  //create socket to send on
  int sockr=socket(AF_PACKET,SOCK_RAW,ETH_P_IP);
  struct sockaddr_ll addr_ll;
  addr_ll.sll_family=PF_PACKET;
  addr_ll.sll_ifindex = if_nametoindex("eth0");
  addr_ll.sll_protocol = htons(ETH_P_IP);

  //bind socket to interface
  int  t = bind(sockr, (struct sockaddr*)&addr_ll,sizeof(addr_ll));

  //error handling
  if(t<0){
    std::cerr<<"fail"<<endl;
  }

  int loop=1;
  struct sockaddr s_addr;
  int len=sizeof(s_addr);

  //recieve from socket until the response packet comes in
  while(loop){
    int buflen=recvfrom(sockr,buff,65535,0,&s_addr,(socklen_t*)&len);
    struct ethhdr* ether=(struct ethhdr*)buff;
    struct iphdr* ip4=(struct iphdr*)(buff+sizeof(struct ethhdr));

    //make sure it is ICMP protocol
    if(ip4->protocol==1){
      if(process_reply(buff,(1))){
        returnval=1;
      }
      loop=0; //break loop
    }

  }

  //returns true if successfully received response, else false
  return returnval;
}

void Icmp::send_ping(int ping_sockfd, struct sockaddr_in *ping_addr,
                char *ping_dom, char *ping_ip, char *rev_host){
    int ttl_val=64, msg_count=0, i, addr_len, flag=1,
               msg_received_count=0;
    //packet used to send icmp request
    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec=0, total_msec=0;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs);


    // set socket options at ip to TTL and value to 64,
    // change to what you want by setting ttl_val
    if (setsockopt(ping_sockfd, SOL_IP, IP_TTL,
               &ttl_val, sizeof(ttl_val)) != 0)
    {
        std::cerr<<"Setting socket options to TTL failed!\n";
        return;
    }

    // setting timeout of recv setting
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   (const char*)&tv_out, sizeof tv_out);

    // send icmp, here only one but feel free to change to more
    for(int count=0;count<1;count++){

        // flag is whether packet was sent or not
        flag=1;

        //filling packet
        bzero(&pckt, sizeof(pckt));

        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = getpid();
         //fill packet as minimum size requirement by kernel, actual values are unimportant
        for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';

        pckt.msg[i] = 0;

        //used to match response with reply
        pckt.hdr.un.echo.sequence = msg_count++;

        //checksum funciton as defined above used
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));


        usleep(PING_SLEEP_RATE);

        //send packet
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0,
           (struct sockaddr*) ping_addr,
            sizeof(*ping_addr)) <= 0)
        {
            std::cerr<<"Packet Sending Failed!";
            flag=0;
        }

}
}

int Icmp::send_ping_driver(char* ipa) //helper function to set up paramters for the socket
{
    int sockfd;
    char *ip_addr, *reverse_hostname;
    struct sockaddr_in addr_con;
    int addrlen = sizeof(addr_con);
    char net_buf[NI_MAXHOST];

    //get information of host
    ip_addr = dns_lookup(ipa, &addr_con);

    //error handling
    if(ip_addr==NULL)
    {
        std::cerr<<"DNS lookup failed! Could  not resolve hostname!";
        return 0;
    }

    reverse_hostname = reverse_dns_lookup(ip_addr);

    //socket()
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    //error handling
    if(sockfd<0)
    {
        std::cerr<<"Socket file descriptor not received!!";
        return 0;
    }

    send_ping(sockfd, &addr_con, reverse_hostname,
                                 ip_addr, ipa);

    return 0;
}

bool Icmp::process_reply(char* data, int sequence){ //fully unpacks reply packet

  //checks if it is really a reply packet, as 0 is ICMP_ECHOREPLY
  if((int)(icmp->type)!=0){
    response_type=(int)(icmp->type);
    return true;
  }

  eth=(struct ethhdr*)data;
  ip=(struct iphdr*)(data+sizeof(struct ethhdr));
  int hdrlen=4*ip->ihl;

  //extracts ICMP header
  icmp=(struct icmphdr*)(data+sizeof(struct ethhdr)+hdrlen);

  //counts number of characters in ip address, this is variable depending on specific address
  int count=0;
  while(suspicious_ip[count]!='\n'){
    count++;
  }
  struct in_addr compare;compare.s_addr=ip->saddr;

  //checks if the mac address that sent the reply is the same as the one we sent to
  if(strncmp((const char*)eth->h_source,(const char*)suspicious_mac,6)!=0){
    return false;
  }

  //returns response time indicating if host responded, or if not why
  response_type=(int)(icmp->type);
  return true;
}

int Icmp::get_response_type(){
  return response_type;
}

int Icmp::main_driver(){ //runs everything, sending, receving, and processing
  int count=0;
  while(suspicious_ip[count]!='\n'){
    count++;
  }
  char* input=new char[count];

  //convert from string to cstring
  for(int i=0;i<count;i++){
    input[i]=suspicious_ip[i];
  }

  //fork so we can send and receive at the same time
  int branch=fork();

  //parent process sends
  if(branch==0){
    send_ping_driver(input);
  }

  //child process receives
  else{
    recieve_ping();
  }

  delete[] input;
  return response_type;
}
