#ifndef LISTENTHREAD_H
#define LISTENTHREAD_H
#define HAVE_REMOTE
#include <QObject>
#include "pcap.h"
#include "recourse.h"
#include <QMessageBox>
#include <QThread>
#include <QDebug>
#include <QMutex>
#include "protocol.h"
#include <winsock2.h>
#include <windows.h>
#include <winsock.h>
#include "packettools.h"


class ListenThread : public QThread
{
    Q_OBJECT
public:
    void setCurrentDev(pcap_if_t *currentDev);

private:
    pcap_if_t *currentDev;
    QMutex mutex;
signals:
    void pkmsgSendSignal(QString, pkg_data*);
    void errSendSignal(QString);

protected:
    virtual void run();
};

#endif // LISTENTHREAD_H
