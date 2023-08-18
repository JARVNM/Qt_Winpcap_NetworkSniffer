#ifndef PROTOCOL_H
#define PROTOCOL_H
#define HAVE_REMOTE
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#include <iostream>
#include <QObject>
#include "_bsd_types.h"
#include "pcap.h"
using namespace std;
//IPV4
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

typedef struct ipv6_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
    u_char byte7;
    u_char byte8;
}ipv6_address;

typedef struct ipv4_header{
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short Identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    ip_address srcaddr;
    ip_address dstaddr;
    u_int op_pad;
}ipv4_header;

typedef struct ipv6_header{
    u_int ver:4,
        flowtype:8,
        flowtip:20;
    u_short len;
    u_char pnext;
    u_char lim;
    ipv6_address srcaddr;
    ipv6_address dstaddr;
}ipv6_header;

typedef struct tcp_header{
    u_short srcport;
    u_short dstport;
    u_int seq;
    u_int ack_seq;
    u_short resl:4,
        doff:4,
        fin:1,
        syn:1,
        pst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
    u_short window;
    u_short check;
    u_short urg_ptr;
    u_int opt;
}tcp_header;

typedef struct udp_header{
    u_short srcport;
    u_short dstport;
    u_short tlen;
    u_short crc;
}udp_header;

typedef struct icmp_header{
    u_char type;
    u_char code;
    u_char seq;
    u_char crc;
}icmp_header;

typedef struct icmp6_header{
    u_char type;
    u_char code;
    u_char seq;
    u_char crc;
    u_char op_type;
    u_char op_len;
    u_char op_ethaddr[6];
}icmp6_header;

typedef struct pkg_count{
    int n_tcp;
    int n_udp;
    int n_icmp;
    int n_icmp6;
    int n_http;
    int n_arp;
    int n_ipv4;
    int n_ipv6;
    int n_other;
    int n_ttl;
}pkg_count;

typedef struct arp_header{
    u_short hardware;
    u_short proto;
    u_char ml;
    u_char ipl;
    u_short opt;
    u_char sm[6];
    ip_address sip;
    u_char dm[6];
    ip_address dip;
}arp_hearder;

typedef struct eth_header{
    u_char smac[6];
    u_char dmac[6];
    u_short type;
}eth_header;

typedef struct pkg_data
{
    QString pkgtype;
    int time[6];
    int len;
    
    eth_header *ethh;
    
    ipv4_header *ipv4h;
    ipv6_header *ipv6h;
    arp_header *arph;
    
    udp_header *udph;
    tcp_header *tcph;
    icmp_header *icmph;
    icmp6_header *icmp6;

    void *apph;
    
}pkg_data;




#endif // PROTOCOL_H
