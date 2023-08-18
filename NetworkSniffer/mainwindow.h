#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#define HAVE_REMOTE
#include <QMainWindow>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTreeWidget>
#include <QTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QSpacerItem>
#include <QStyleFactory>
#include <QMenu>
#include <QAction>
#include <QHostInfo>
#include <QNetworkInterface>
#include "pcap.h"
#include "process.h"
#include <windows.h>
#include <winsock2.h>
#include <QMessageBox>
#include "recourse.h"
#include <QVector>
#include "listenthread.h"
#include <QThread>
#include <winsock.h>
#include <QSocketNotifier>
#include <iphlpapi.h>
#include <QWidget>
#include <QList>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
private:
    Ui::MainWindow *ui;
    void pInit();
    void uiInit();
    void hardwareInfoInit();
    void cntListUpdate(pkg_count *pkgCnts);
private:
    QLabel *labNetworkCard;
    QComboBox *cmbNetworkCard;
    QLabel *labCaptureRule;
    QComboBox *cmbCaptureRule;

    QPushButton *btnBeginCapture;
    QPushButton *btnEndCapture;

    QTableWidget *captureTableWidget;
    QTreeWidget *unpackTreeWidget;
    QTextEdit *captureTextEdit;

    QLabel *labPackCount;

    QLabel *labTcpPack;
    QLineEdit *editTcpPack;
    QLabel *labUdpPack;
    QLineEdit *editUdpPack;
    QLabel *labIcmpPack;
    QLineEdit *editIcmpPack;
    QLabel *labHttpPack;
    QLineEdit *editHttpPack;
    QLabel *labArpPack;
    QLineEdit *editArpPack;
    QLabel *labIpv4Pack;
    QLineEdit *editIpv4Pack;
    QLabel *labOther;
    QLineEdit *editOtherPack;
    QLabel *labCount;
    QLineEdit *editCount;
private:
    ListenThread *thread;
    QVector<pcap_if_t *> devList;
    pcap_if_t *currentDev;
    QList<pkg_data *> pkgList;
    int pkgSeq;
    bool ifSet;
public slots:
    void pkmsgAcpSlot(QString time, pkg_data *data);
    void errAcpSlot(QString errBuf);
private slots:
    void cmbNetworkIndexChangeSlot(int newIndex);
    void btnBeginClickedSlot(bool isClicked);
    void btnEndClickedSlot(bool isClicked);
    void tabWidgetDoubleClickItemSlot(int row, int col);
    void exit();
    void reset();
    void aboutmker();
    void aboutsniffer();
private:
    QMenu *fileMenu;
    QMenu *aboutMenu;
    QAction *resetAct;
    QAction *exitAct;
    QAction *aboutmkerAct;
    QAction *aboutsnifferAct;
    void menuBarInit();
};

#endif // MAINWINDOW_H
