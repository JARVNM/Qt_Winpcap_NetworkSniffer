#include "recourse.h"

pcap_if_t *alldevs = NULL;
pcap_if_t *d = NULL;
bool isRun = false;
pkg_count *pkgCnt = NULL;
QList<u_char *> netpkgList;
