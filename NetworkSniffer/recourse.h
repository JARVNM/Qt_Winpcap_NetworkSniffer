#ifndef RECOURSE_H
#define RECOURSE_H
#define HAVE_REMOT
#include "pcap.h"
#include "protocol.h"
#include <QObject>
extern pcap_if_t *alldevs;
extern pcap_if_t *d;
extern bool isRun;
extern pkg_count *pkgCnt;
extern QList<u_char *> netpkgList;

#endif // RECOURSE_H
