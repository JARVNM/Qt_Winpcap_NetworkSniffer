#include "listenthread.h"

void ListenThread::setCurrentDev(pcap_if_t *currentDev)
{
    this->currentDev = currentDev;
    qDebug()<<currentDev->description;
}

void ListenThread::run()
{
    isRun = true;
    pcap_t *adhandle;
    int res;
    char errBuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    struct bpf_program fcode;
    char packet_filter[] = "";
    u_int netmask;
    if((adhandle = pcap_open(currentDev->name,
                             65536,
                             PCAP_OPENFLAG_PROMISCUOUS,
                             1000,
                             NULL,
                             errBuf)) == NULL)
    {

        emit errSendSignal(QString(errBuf));
       return;
    }
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        emit errSendSignal("Only for ethernet");
        return;
    }
    if(currentDev->addresses != NULL)
    {
        netmask = ((struct sockaddr_in *)(currentDev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        netmask = 0xffffff;
    }
    if(pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        emit errSendSignal("Unable to compile packet");
        return;
    }
    if(pcap_setfilter(adhandle, &fcode) < 0)
    {
        emit errSendSignal("Error setting the filter");
        return;
    }
    while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        mutex.lock();
        if(!isRun)
            return;
        mutex.unlock();
        pkg_data *data = new pkg_data;
        if(NULL == data)
        {
            emit errSendSignal("Cant't accept more packet");
            return;
        }
        if(res == 0)
            continue;
        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        PacketTools::unpcak_Frame(pkt_data, data, pkgCnt);
        data->len = header->len;
        u_char *netData = const_cast<unsigned char *>(pkt_data);
        netpkgList.append(netData);
        emit pkmsgSendSignal(QString(timestr), data);
        QThread::sleep(1);
        if(res == -1)
        {
            emit errSendSignal("Error reading the packets");
        }

    }
}

