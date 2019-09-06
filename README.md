# arp-poison-detection

ARP Posison Detection is a command line program. While running, it verifies that every ARP packet recieved is sent from a 
legitimate host and not one attempting to poison the ARP-Cache of your machine.

# how it works

The internet was designed for efficiency, not security. It is shockingly easy to gain access to sensitive information sent out
on a network with with very basic netoworking knowledge. ARP cache poisoning is one of the most common LAN attacks. For 
those who are unacquainted, please read about it here:

https://www.veracode.com/security/arp-spoofing

Arp Poison Detetion prevents suck attacks by analyzing all arp packets sent to a computer running the program. It intercepts
such packets by utilizing raw sockets. An ARP packet consists of an ethernet header followed by an arp header, both of which contain
the source and destination mac addresses. If either the source or destination addresses differ in the two headers, it is guranteed
that such a packet came from a malicious host. An alert will be printed if this is the case.

If the ethernet and ARP headers are consistent, the program moves on to its next and final line of defense. Using the source 
mac and ip addresses found in the ARP packet, it will construct an ICMP packet with its destintion set to that MAC IP pair.
If the attacker has IP routing disabled, his kernel will drop the packet as his IP address does not match that of the one he 
is trying to impersonate, aka the one the ICMP packet is addressed to. If the program does not receive a reply packet, 
it will alert the user immediately. 

If a reply packet is received, the reply packet will be analyzed. Because the malicious host who has IP routing enabled forwarded 
the packet to the real machine with the IP address the ICMP packet was addressed to, that machine will reply to the packet, and
the malicious host will forward its response to our machine. If the MAC and IP pair in the ICMP response packet differ from those
in the original ARP Packet, there is once again evidence of ARP spoofing. 

If the ARP Packet passes both lines of defense, then the MAC and IP pair will be added to the hash table of known hosts. All future
ARP packets, or more specifically their IP MAC pair, will be compared to the known hosts stored in this table. If there is a 
match, we will regard that ARP packet as legitimate and continue scanning. If not, it will enter the two tests outlined above. 

#usage

After downloading the files, open terminal and enter the directory in which you downloaded the program. In the shell enter the
following:

g++ main.cpp arp_packet.cpp icmp_packet.cpp mac_hash.cpp

I hope to add a makefile in the near future to avoid typing this out. To run the program, tyoe the following:

sudo ./a.out

It is critical that you run the program as root as Linux requires root access in order to open some of the sockets used in this
program.

# future additions

In the near future I would like to flesh out the program by perhaps creating a gui rather than it jsut being a command line prompt. 
ARP-Poisoning has the potential to be catastrophic and it is all too easy for users to forget about the terminal window in which
the program is running, allowing the attacker to intercept valuable information despite the program detecting malicious behavior.

Furthermore, my program can simply detect arp poisoning instead of being able to drop such packets. Dropping packets, however, 
requires a kernel space module whereas mine is a user space one. Perhaps time permitting I will be able to program a 
more powerful kernel module.

