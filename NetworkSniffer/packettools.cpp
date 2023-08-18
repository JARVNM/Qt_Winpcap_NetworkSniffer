#include "packettools.h"
#include <QDebug>


int PacketTools::unpcak_Frame(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    eth_header *ethh = (eth_header *)pkg;
    data->ethh = new eth_header;
    if(data->ethh == NULL)
        return -1;
    for(int i = 1; i < 6; i++)
    {
        data->ethh->dmac[i] = ethh->dmac[i];
        data->ethh->smac[i] = ethh->smac[i];
    }
    pkgCnts->n_ttl++;
    data->ethh->type = ntohs(ethh->type);
    switch(data->ethh->type)
    {
        case 0x0806:
            return PacketTools::unpcak_Arp((u_char*)pkg+14, data, pkgCnts);
            break;
        case 0x0800:
            return PacketTools::unpack_Ip((u_char*)pkg+14, data, pkgCnts);
            break;
        case 0x86dd:
            return PacketTools::unpack_Ipv6((u_char*)pkg+14, data, pkgCnts);
            break;
        default:
            pkgCnts->n_other++;
            return -1;
            break;
    }
    return 1;
}

int PacketTools::unpcak_Arp(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    arp_header *arph = (arp_header*)pkg;
    data->arph = new arp_header;
    if(NULL == data->arph)
        return -1;

    for(int i = 0; i < 6; i++)
    {
        data->arph->dm[i] = arph->dm[i];
        data->arph->sm[i] = arph->sm[i];
    }
    data->arph->dip = arph->dip;
    data->arph->sip = arph->sip;
    data->arph->ml = arph->ml;
    data->arph->ipl = arph->ipl;
    data->arph->hardware = ntohs(arph->hardware);
    data->arph->opt = ntohs(arph->opt);
    data->arph->proto = ntohs(arph->proto);
    data->pkgtype = QString("ARP");
    pkgCnts->n_arp++;
    return 1;
}

int PacketTools::unpack_Ip(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    ipv4_header *iph = (ipv4_header *)pkg;
    data->ipv4h = new ipv4_header;
    if(NULL == data->ipv4h)
        return -1;
    pkgCnts->n_ipv4++;
    data->ipv4h->crc = iph->crc;
    data->ipv4h->dstaddr = iph->dstaddr;
    data->ipv4h->srcaddr = iph->srcaddr;
    data->ipv4h->flags_fo = iph->flags_fo;
    data->ipv4h->Identification = iph->Identification;
    data->ipv4h->proto = iph->proto;
    data->ipv4h->tlen = ntohs(iph->tlen);
    data->ipv4h->tos = iph->tos;
    data->ipv4h->ttl = iph->ttl;
    data->ipv4h->ver_ihl = iph->ver_ihl;
    data->ipv4h->op_pad = iph->op_pad;

    int ipLen = (iph->ver_ihl&0xf)*4;
    switch(iph->proto)
    {
        case PROTO_ICMP:
            return PacketTools::unpack_Icmp((u_char*)pkg+ipLen, data, pkgCnts);
            break;
        case PROTO_TCP:
            return PacketTools::unpack_Tcp((u_char*)pkg+ipLen, data, pkgCnts);
            break;
        case PROTO_UDP:
            return  PacketTools::unpack_Udp((u_char*)pkg+ipLen, data, pkgCnts);
            break;
        default:
            return -1;
            break;
    }
    return 1;
}

int PacketTools::unpack_Ipv6(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    ipv6_header *ip6h = (ipv6_header *)pkg;
    data->ipv6h = new ipv6_header;

    if(NULL == data->ipv6h)
        return -1;

    pkgCnts->n_ipv6++;

    data->ipv6h->ver = ip6h->ver;
    data->ipv6h->flowtype = ip6h->flowtype;
    data->ipv6h->flowtip = ip6h->flowtip;
    data->ipv6h->lim = ip6h->lim;
    data->ipv6h->pnext = ip6h->pnext;
    data->ipv6h->len = ntohs(ip6h->len);
    data->ipv6h->srcaddr = ip6h->srcaddr;
    data->ipv6h->dstaddr = ip6h->dstaddr;

    switch (ip6h->pnext) {
    case 0x3a:
        return PacketTools::unpack_Icmp6((u_char *)ip6h+40, data, pkgCnts);
        break;
    case 0x06:
        return PacketTools::unpack_Tcp((u_char *)ip6h+40, data, pkgCnts);
        break;
    case 0x11:
        return PacketTools::unpack_Udp((u_char *)ip6h+40, data, pkgCnts);
        break;
    default:
        return -1;
        break;
    }

    return 1;
}

int PacketTools::unpack_Icmp(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    icmp_header *icmph = (icmp_header *)pkg;
    data->icmph = new icmp_header;

    if(NULL == data->icmph)
        return -1;
    pkgCnts->n_icmp++;

    data->icmph->code = icmph->code;
    data->icmph->crc = icmph->crc;
    data->icmph->seq = icmph->seq;
    data->icmph->type = icmph->type;
    data->pkgtype = "ICMP";

    return 1;
}

int PacketTools::unpack_Icmp6(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    icmp6_header *icmph6 = (icmp6_header *)pkg;
    data->icmp6 = new icmp6_header;

    if(NULL == data->icmp6)
        return -1;
    pkgCnts->n_ipv6++;

    data->icmp6->code = icmph6->code;
    data->icmp6->crc = icmph6->crc;
    data->icmp6->op_len = icmph6->op_len;
    data->icmp6->op_type = icmph6->op_type;
    data->icmp6->seq = icmph6->seq;
    data->icmp6->type = icmph6->type;
    for(int i = 0; i < 6; i++)
    {
        data->icmp6->op_ethaddr[i] = icmph6->op_ethaddr[i];
    }
    data->pkgtype = "ICMP6";

    return 1;
}

int PacketTools::unpack_Tcp(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    tcp_header *tcph = (tcp_header *)pkg;
    data->tcph = new tcp_header;

    if(NULL == data->tcph)
        return -1;

    data->tcph->ack = tcph->ack;
    data->tcph->ack_seq = tcph->ack_seq;
    data->tcph->check = tcph->check;
    data->tcph->cwr = tcph->cwr;
    data->tcph->doff = tcph->doff;
    data->tcph->dstport = tcph->dstport;
    data->tcph->ece = tcph->ece;
    data->tcph->fin = tcph->fin;
    data->tcph->opt = tcph->opt;
    data->tcph->psh = tcph->psh;
    data->tcph->pst = tcph->psh;
    data->tcph->resl = tcph->resl;
    data->tcph->seq = tcph->seq;
    data->tcph->srcport = tcph->srcport;
    data->tcph->syn = tcph->syn;
    data->tcph->urg = tcph->urg;
    data->tcph->urg_ptr = tcph->urg_ptr;
    data->tcph->window = tcph->window;

    if(ntohs(tcph->dstport) == 80 || ntohs(tcph->srcport) == 80)
    {
        data->pkgtype = QString("HTTP");
        pkgCnts->n_http++;
    }
    else
    {
        data->pkgtype = QString("TCP");
        pkgCnts->n_tcp++;
    }

    return 1;
}

int PacketTools::unpack_Udp(const u_char *pkg, pkg_data *data, pkg_count *pkgCnts)
{
    udp_header *udph = (udp_header *)pkg;
    data->udph = new udp_header;

    if(NULL == data->udph)
        return -1;

    data->udph->crc = udph->crc;
    data->udph->dstport = ntohs(udph->dstport);
    data->udph->srcport = ntohs(udph->srcport);
    data->udph->tlen = ntohs(udph->tlen);
    data->pkgtype = QString("UDP");
    pkgCnts->n_udp++;
    return 1;
}

int PacketTools::pack_Print(u_char *pkg, int size, QTextEdit *edit)
{
    int rowCnt;
    QString buf = "";
    for(int i = 0; i < size; i+=16)
    {

        buf.append(QString("%1  ").arg(i, 4, 16));
        rowCnt = (size - i)>16 ? 16 : (size - i);
        for(int j = 0; j < rowCnt; j++)
        {
            buf.append(QString("%1  ").arg(pkg[i+j], 2, 16));
        }
        if(rowCnt < 16)
        {
            for(int j = rowCnt; j < 16; j++)
                buf.append("    ");
        }

        for(int j = 0; j < rowCnt; j++)
        {
            char ch = pkg[i+j];
            ch = isprint(ch) ? ch : '.';
            buf.append(QString(ch));
        }

        buf.append("\r\n");

        if(rowCnt < 16)
            break;
    }

    edit->clear();
    edit->insertPlainText(buf);
    return 1;
}


