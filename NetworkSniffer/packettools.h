#ifndef PACKETTOOLS_H
#define PACKETTOOLS_H
#include <QObject>
#include <QTextEdit>
#include "protocol.h"
#include "iostream"

using namespace std;

class PacketTools
{
public:
    static int unpcak_Frame(const u_char *pkg,
                             pkg_data *data,
                             pkg_count *pkgCnts);


    static int unpcak_Arp(const u_char *pkg,
                           pkg_data *data,
                           pkg_count *pkgCnts);

    static int unpack_Ip(const u_char *pkg,
                          pkg_data *data,
                          pkg_count *pkgCnts);

    static int unpack_Ipv6(const u_char *pkg,
                           pkg_data *data,
                           pkg_count *pkgCnts);

    static int unpack_Icmp(const u_char *pkg,
                            pkg_data *data,
                            pkg_count *pkgCnts);

    static int unpack_Icmp6(const u_char *pkg,
                            pkg_data *data,
                            pkg_count *pkgCnts);

    static int unpack_Tcp(const u_char *pkg,
                           pkg_data *data,
                           pkg_count *pkgCnts);

    static int unpack_Udp(const u_char *pkg,
                           pkg_data *data,
                           pkg_count *pkgCnts);

    static int pack_Print(u_char *pkg,
                           int size,
                          QTextEdit *edit);
};

#endif // PACKETTOOLS_H
