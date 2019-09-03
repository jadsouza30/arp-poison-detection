#include "icmp.h"
// Define the Ping Loop
#define PING_PKT_S 64
#define PORT_NO 0
#define PING_SLEEP_RATE 1000000
#define RECV_TIMEOUT 1
int pingloop=1;

using namespace std;
// Calculating the Check Sum
Icmp::Icmp(){
  int a;
}

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
    printf("\nResolving DNS..\n");
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
        printf("Could not resolve reverse lookup of hostname\n");
        return NULL;
    }
    ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char) );
    strcpy(ret_buf, buf);
    return ret_buf;
}

// make a ping request
void Icmp::send_ping(int ping_sockfd, struct sockaddr_in *ping_addr,
                char *ping_dom, char *ping_ip, char *rev_host)
{
  int ttl_val=64, msg_count=0, i, addr_len, flag=1,
             msg_received_count=0;

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
      printf("\nSetting socket options to TTL failed!\n");
      return;
  }

  else
  {
      printf("\nSocket set to TTL..\n");
  }

  // setting timeout of recv setting
  setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                 (const char*)&tv_out, sizeof tv_out);
        pckt.hdr.type=ICMP_ECHO;
        pckt.hdr.un.echo.id=getpid();
        for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';
        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = msg_count++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
        usleep(PING_SLEEP_RATE);

        for(int t=0;t<5;t++){
        if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0,
           (struct sockaddr*) ping_addr,
            sizeof(*ping_addr)) <= 0){
            cout<<"Packet Sending Failed!";
            flag=0;
        }

        else{
          cout<<"success, sent"<<endl;
        }
      }

        //receive packet
        //addr_len=sizeof(r_addr);

        int loop=1;
        while(loop){
          /*
          int buflen=recvfrom(sockr,buff,65535,0,&s_addr,(socklen_t*)&len);
          struct ethhdr* ether=(struct ethhdr*)buff;

          struct iphdr* ip4=(struct iphdr*)(buff+sizeof(struct ethhdr));
          if(ip4->protocol==1){
            cout<<"source mac"<<ether_ntoa((ether_addr*)ether->h_source);
            cout<<"recieved paket"<<endl;
            if(process_reply(buff,(1))){
              loop=0;
            }
            loop=0;
          }*/
        }
}

bool Icmp::process_reply(char* data, int sequence){
  eth=(struct ethhdr*)data;
  ip=(struct iphdr*)(data+sizeof(struct ethhdr));
  struct sockaddr_in source;
  source.sin_addr.s_addr=ip->saddr;
  cout<<"source ip"<<inet_ntoa(source.sin_addr);
  int hdrlen=4*ip->ihl;
  icmp=(struct icmphdr*)(data+sizeof(struct ethhdr)+hdrlen);
  cout<<"seq"<<ntohs(icmp->un.echo.sequence)<<endl;
  if((int)(icmp->type)==0){
    cout<<"recieved a reply";
  }
  cout<<"type"<<(int)icmp->type;
  if(ntohs(icmp->un.echo.sequence==0)){
    cout<<"recieved correct packet";
    return true;
  }
  else{
    return false;
  }
}

int main(){
  Icmp test;
  int ping_sockfd; struct sockaddr_in ping;
                  char *ping_dom; char *ping_ip; char *rev_host;
  ping_sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
  struct sockaddr_in* ping_addr=&ping;
  ping_addr->sin_family=AF_INET;
  ping_addr->sin_port=0;
  inet_aton("10.26.68.207",&ping_addr->sin_addr);
  test.send_ping(ping_sockfd,ping_addr,ping_dom, ping_ip, rev_host);
}
