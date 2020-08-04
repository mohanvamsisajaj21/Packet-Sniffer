#include <stdio.h>                      
#include <stdlib.h>                     
#include <errno.h>                      
#include <stdbool.h>                    
#include <string.h>                     
#include <sys/socket.h>                 
#include <arpa/inet.h>                  
#include </usr/include/netinet/ip.h>    
#include </usr/include/netinet/ip6.h>   
#include </usr/include/pcap/pcap.h>     
#include <net/ethernet.h>               
#include <netinet/in.h>                 
#include <netinet/if_ether.h>           
#include <netinet/ether.h>              
#include <netinet/tcp.h>                
#include <netinet/udp.h>               
#include <netinet/ip_icmp.h>            
#include <netinet/icmp6.h>              

void handle_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void handle_ipv6(int, int, const u_char*, char*);
void print_tcp (const u_char*, int*);
void print_udp (const u_char*, int*);
void print_payload (const u_char *, int);
void print_ipv4(char*, char*);
void print_icmp6(const u_char*, int*);
void print_ipv6();

bool ipv4_bool = false;
bool ipv6_bool = false;
bool tcp_bool = false;
bool udp_bool = false;
bool icmp_bool = false;
bool other_traffic_bool = false;
bool unknown_protocol_bool = false;

int packet_counter = 0; 
int headerLength = 0;   

char sourIP6[INET_ADDRSTRLEN];  
char destIP6[INET_ADDRSTRLEN];  

int main(int argc, char *argv[]) 
{
    const char *fname = argv[1];   
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *handle;                
        
    if(argc == 1){
	printf("Error: pcap file is missing! \n");
	printf("Please use following format command: $./eps [captured_file_name] \n");
	exit(EXIT_FAILURE);
    }
    
    for(int i = 2; i < argc; i++){
	if(strcasecmp("IPV4", argv[i]) == 0){
	    ipv4_bool = true;
	}
	else if(strcasecmp("IPV6", argv[i]) == 0){
	    ipv6_bool = true;
	}
	else if(strcasecmp("TCP", argv[i]) == 0){
	    tcp_bool = true;
	}
	else if(strcasecmp("UDP", argv[i]) == 0){
	    udp_bool = true;
	}
	else if(strcasecmp("ICMP", argv[i]) == 0){
	    icmp_bool = true;
	}
	else if(strcasecmp("UNKNOWN", argv[i]) == 0){
	    unknown_protocol_bool = true;
	}
    }

    if(argc == 2){
	ipv4_bool = true;
	ipv6_bool = true;
	other_traffic_bool = true;
    }
    
    if((ipv4_bool == true || ipv6_bool == true) && tcp_bool == false && udp_bool == false && icmp_bool == false && unknown_protocol_bool == false){
	tcp_bool = true;
	udp_bool = true;
	icmp_bool = true;
	unknown_protocol_bool = true;
    }

    if(argc > 2){
	printf("Error: unrecognized command! \n");
	printf("Please use following format command: $./eps [captured_file_name] \n");
	exit(EXIT_FAILURE);
    }

    handle = pcap_open_offline(fname, errbuf);

    if(handle == NULL){
	printf("pcap file [%s] with error %s \n", fname, errbuf);
	exit(EXIT_FAILURE);
    }

    pcap_loop(handle, 0, handle_packet, NULL);
    
    return 1;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header *ethernet_header; 
    const struct ip *ipv4_header;               
    const struct ip6_hdr *ipv6_header;          
    const struct tcphdr *tcp_header;            
    const struct udphdr *udp_header;            
    const struct icmphdr *icmp_header;          
    
    char sourIP4[INET_ADDRSTRLEN];  
    char destIP4[INET_ADDRSTRLEN];  

    headerLength = header->len;
    ++packet_counter;
    ethernet_header = (struct ether_header*)(packet);
    int size = 0;
    size += sizeof(struct ether_header);
    switch(ntohs(ethernet_header->ether_type)){
	case ETHERTYPE_IP:
		if(ipv4_bool == false){
		    return;
		}

		ipv4_header = (struct ip*)(packet + size);
		inet_ntop(AF_INET, &(ipv4_header->ip_src), sourIP4, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipv4_header->ip_dst), destIP4, INET_ADDRSTRLEN);
		size += sizeof(struct ip);
		u_char *payload;
		int dataLength = 0;
		switch(ipv4_header->ip_p){
		    case IPPROTO_TCP:
			if(tcp_bool == false){
			    return;
			}
			print_ipv4(sourIP4, destIP4);
			print_tcp(packet, &size);
			break;
		    
		    case IPPROTO_UDP:
			if(udp_bool == false){
			    return;
			}
			print_ipv4(sourIP4, destIP4);
			print_udp(packet, &size);
			break;

		    case IPPROTO_ICMP:  
			if(icmp_bool == false){
			    return;
			}
			print_ipv4(sourIP4, destIP4);
			printf("Protocol: ICMP \n"); 
			icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			u_int type = icmp_header->type;
			if(type == 11){
			    printf("TTL Expired! \n");
			}
			else if(type == ICMP_ECHOREPLY){
			    printf("ICMP Echo Reply! \n");
			}

			payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr));
			dataLength = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr)); 
			printf("Payload: (%d bytes) \n", dataLength);
			printf("\n");
			print_payload(payload, dataLength);

			break;
		     default:
			if(unknown_protocol_bool == false){
			    return;
			}
			printf("Protocol: Unknown \n");
			break;
		}
		break;

	case ETHERTYPE_IPV6:
		if(ipv6_bool == false){
		    return;
		}
		ipv6_header = (struct ip6_hdr*)(packet + size); 
		inet_ntop(AF_INET6, &(ipv6_header->ip6_src), sourIP6, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);
		int nextheader = ipv6_header->ip6_nxt;
		size += sizeof(struct ip6_hdr);
		char string[100] = " ";
		handle_ipv6(nextheader, size, packet, string);
		break;
	
	default:
		if(other_traffic_bool == false){
		    return;
		}
		printf("Ether Type: Other \n");
		break;
    }
}

void handle_ipv6(int header, int size, const u_char *packet, char *string)
{
    switch(header){
	case IPPROTO_ROUTING:
		strcat(string, "ROUTING, ");
		struct ip6_rthdr* header = (struct ip6_rthdr*)(packet + size); 
		size+=sizeof(struct ip6_rthdr);
		print_ipv6(header->ip6r_nxt, size, packet, string);
		break;
	
	case IPPROTO_HOPOPTS:
		strcat(string, "HOP-BY_HOP, ");
		struct ip6_hbh* header_hop = (struct ip6_hbh*)(packet + size); 
		size+=sizeof(struct ip6_hbh);
		print_ipv6(header_hop->ip6h_nxt, size, packet, string);
		break;

	case IPPROTO_FRAGMENT:
		strcat(string, "FRAGMENTATION, ");
		struct ip6_frag* header_frag = (struct ip6_frag*)(packet + size); 
		size+=sizeof(struct ip6_frag);
		print_ipv6(header_frag->ip6f_nxt, size, packet, string);
		break;

	case IPPROTO_DSTOPTS:
		strcat(string, "Destination options, ");
		struct ip6_dest* header_dest = (struct ip6_dest*)(packet + size); 
		size+=sizeof(struct ip6_dest);
		print_ipv6(header_dest->ip6d_nxt, size, packet, string);
		break;

	case IPPROTO_TCP:
		if(tcp_bool == false){
		    return;
		}
		print_ipv6();
		printf("%s \n", string);
		print_tcp(packet, &size);
		break;

	case IPPROTO_UDP:
		if(udp_bool == false){
		    return;
		}
		print_ipv6();
		printf("%s \n", string);
		print_udp(packet, &size);
		break;

	case IPPROTO_ICMPV6:
		if(icmp_bool == false){
		    return;
		}
		print_ipv6();
		printf("%s \n", string);
		print_icmp6(packet, &size);
		break;

	default:
		if(unknown_protocol_bool == false){
		    return;
		}
		print_ipv6();
		printf("Protocol: Unknown \n");
		break;
    }
}

void print_ipv6()
{
    printf("\n");
    printf("********************************************************* \n");
    printf("Packet #: %d \n", packet_counter);
    printf("Ether Type: IPv6 \n");
    printf("From: %s \n", sourIP6);
    printf("To: %s \n", destIP6);
    printf("Extension Headers:");
}

void print_icmp6(const u_char *packet, int *size)
{
    printf("Protocol: ICMPv6 \n");
    u_char *payload;
    int dataLength = 0;
    struct icmp6_hdr* header_icmp6 = (struct icmp6_hdr*)(packet+*size);
    payload = (u_char*)(packet + *size + sizeof(struct icmp6_hdr));
    dataLength = headerLength - *size + sizeof(struct icmp6_hdr);    
    printf("Payload: (%d bytes) \n", dataLength);
    print_payload(payload, dataLength);
}

void print_tcp(const u_char *packet, int *size)
{    
    const struct tcphdr* tcp_header;    
    u_int sourPort, destPort;  
    u_char *payload;           
    int dataLength = 0;
    tcp_header = (struct tcphdr*)(packet + *size);
    sourPort = ntohs(tcp_header->source);
    destPort = ntohs(tcp_header->dest);
    *size += tcp_header->doff*4;
    payload = (u_char*)(packet + *size);
    dataLength = headerLength - *size;
    printf("Protocol: TCP \n");
    printf("Source port: %d\n", sourPort);
    printf("Destination port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("\n");
    print_payload(payload, dataLength);
}

void print_udp(const u_char *packet, int *size)
{     
    const struct udphdr* udp_header;
    u_int sourPort, destPort;  
    u_char *payload;           
    int dataLength = 0;
    udp_header = (struct udphdr*)(packet + *size);
    sourPort = ntohs(udp_header->source);
    destPort = ntohs(udp_header->dest);
    *size+=sizeof(struct udphdr);
    payload = (u_char*)(packet + *size);
    dataLength = headerLength - *size;
    printf("Protocol: UDP \n");
    printf("Source port: %d\n", sourPort);
    printf("Destination port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("\n");
    print_payload(payload, dataLength);
}

void print_ipv4(char *source, char *dest)
{
    printf("\n");
    printf("********************************************************* \n");
    printf("Packet #: %d \n", packet_counter);
    printf("Ether Type: IPv4 \n");
    printf("From: %s \n", source);
    printf("To: %s \n", dest);
}

void print_payload(const u_char *payload, int Size)
{
    int i , j;
    for(i = 0; i < Size; i++){
        if( i!=0 && i%16==0){  
            printf("         ");            
	    for(j = i - 16; j < i; j++){
                if(payload[j] >= 32 && payload[j] <= 128){
                    printf("%c",(unsigned char)payload[j]); 
		}
                else{
		    printf("."); 
		}
            }
            printf("\n");
        }
         
        if(i%16 == 0) printf("   ");
            printf(" %02X",(unsigned int)payload[i]);
                 
        if(i == Size - 1){  
            for(j = 0; j < 15 - i%16; j++){
		printf("   "); 
            }
             
            printf("         ");
             
            for(j = i - i%16; j <= i; j++){
                if(payload[j] >= 32 && payload[j] <= 128){
		    printf("%c",(unsigned char)payload[j]);
                }
                else{
		    printf(".");
                }
            }
            printf("\n" );
        }
    }
}