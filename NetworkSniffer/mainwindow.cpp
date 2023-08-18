#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "flatui.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    pInit();
    uiInit();
    menuBarInit();
    hardwareInfoInit();
    cntListUpdate(pkgCnt);
    ifSet = true;
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::pInit()
{
    pkgCnt = new pkg_count;
    this->currentDev = NULL;
    this->devList.clear();
    this->pkgList.clear();
    netpkgList.clear();
    this->pkgSeq = 0;
    pkgCnt->n_arp = 0;
    pkgCnt->n_http = 0;
    pkgCnt->n_icmp = 0;
    pkgCnt->n_icmp6 = 0;
    pkgCnt->n_ipv4 = 0;
    pkgCnt->n_other = 0;
    pkgCnt->n_tcp = 0;
    pkgCnt->n_ttl = 0;
    pkgCnt->n_udp = 0;
    pkgCnt->n_ipv6 = 0;
}

void MainWindow::uiInit()
{
    QWidget *newWidget = new QWidget(this);
    this->setCentralWidget(newWidget);
    this->setFixedSize(1600, 900);
    this->setWindowIcon(QIcon(QPixmap(":/icon.jpeg")));
    this->setWindowTitle("Network Sniffer");
    QFont font;
    font.setPixelSize(30);
    this->labNetworkCard = new QLabel(this);
    this->cmbNetworkCard = new QComboBox(this);
    this->cmbNetworkCard->setFixedWidth(800);
    FlatUI::setComboBoxQss(cmbNetworkCard);
    this->labNetworkCard->setText("Netword Card");
    this->labNetworkCard->setFixedSize(200, 36);
    this->labNetworkCard->setFont(font);
    this->labCaptureRule = new QLabel(this);
    this->labCaptureRule->setText("Capture Type");
    this->labCaptureRule->setFixedSize(200, 36);
    this->labCaptureRule->setFont(font);
    this->cmbCaptureRule = new QComboBox(this);
    FlatUI::setComboBoxQss(cmbCaptureRule);
    font.setPixelSize(25);
    QStringList typeList;
    typeList<< "All"<< "Tcp"<< "Udp"<< "Icmp"<< "Http"<< "Arp"<< "Ipv4"<< "Other";
    this->cmbCaptureRule->addItems(typeList);
    this->btnBeginCapture = new QPushButton(this);
    this->btnEndCapture = new QPushButton(this);
    this->cmbCaptureRule->setFont(font);
    this->cmbCaptureRule->setFixedSize(700, 36);
    this->cmbNetworkCard->setFont(font);
    this->cmbNetworkCard->setFixedSize(1300, 36);
    QHBoxLayout *hbNetworkCard = new QHBoxLayout(this);
    QHBoxLayout *hbCaptureRule = new QHBoxLayout(this);
    hbCaptureRule->layout()->setAlignment(Qt::AlignLeft);
    hbNetworkCard->layout()->setAlignment(Qt::AlignLeft);
    hbNetworkCard->addWidget(labNetworkCard);
    hbNetworkCard->addWidget(cmbNetworkCard);
    hbCaptureRule->addWidget(labCaptureRule);
    hbCaptureRule->addWidget(cmbCaptureRule);
    hbCaptureRule->addWidget(btnBeginCapture);
    hbCaptureRule->addWidget(btnEndCapture);
    FlatUI::setPushButtonQss(btnBeginCapture);
    FlatUI::setPushButtonQss(btnEndCapture);
    font.setPixelSize(20);
    this->btnBeginCapture->setFixedSize(200, 36);
    this->btnBeginCapture->setText("Begin");
    this->btnBeginCapture->setFont(font);
    this->btnEndCapture->setFixedSize(200, 36);
    this->btnEndCapture->setText("End");
    this->btnEndCapture->setFont(font);
    this->btnEndCapture->setEnabled(false);
    this->captureTableWidget = new QTableWidget(this);
    captureTableWidget->setAutoScroll(true);
    captureTableWidget->verticalHeader()->setHidden(true);
    captureTableWidget->setRowCount(60);
    captureTableWidget->setFixedWidth(1570);
    captureTableWidget->setFixedHeight(300);
    captureTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    captureTableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    captureTableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    captureTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    captureTableWidget->insertRow(0);
    captureTableWidget->insertColumn(0);
    captureTableWidget->insertColumn(1);
    captureTableWidget->insertColumn(2);
    captureTableWidget->insertColumn(3);
    captureTableWidget->insertColumn(4);
    captureTableWidget->insertColumn(5);
    captureTableWidget->insertColumn(6);
    captureTableWidget->insertColumn(7);
    captureTableWidget->setHorizontalHeaderItem(0, new QTableWidgetItem("Num"));
    captureTableWidget->setHorizontalHeaderItem(1, new QTableWidgetItem("Time"));
    captureTableWidget->setHorizontalHeaderItem(2, new QTableWidgetItem("Src Mac"));
    captureTableWidget->setHorizontalHeaderItem(3, new QTableWidgetItem("Dest Mac"));
    captureTableWidget->setHorizontalHeaderItem(4, new QTableWidgetItem("Length"));
    captureTableWidget->setHorizontalHeaderItem(5, new QTableWidgetItem("Protocol"));
    captureTableWidget->setHorizontalHeaderItem(6, new QTableWidgetItem("Src IP"));
    captureTableWidget->setHorizontalHeaderItem(7, new QTableWidgetItem("Dest IP"));
    QGridLayout *gridLayout = new QGridLayout(this);
    QVBoxLayout *Layout = new QVBoxLayout(this);
    this->labTcpPack = new QLabel(this);
    this->labTcpPack->setText("Tcp");
    this->editTcpPack = new QLineEdit(this);
    this->labUdpPack = new QLabel(this);
    this->labUdpPack->setText("Udp");
    this->editUdpPack = new QLineEdit(this);
    this->labIcmpPack = new QLabel(this);
    this->labIcmpPack->setText("Icmp4/6");
    this->editIcmpPack = new QLineEdit(this);
    this->labHttpPack = new QLabel(this);
    this->labHttpPack->setText("Http");
    this->editHttpPack = new QLineEdit(this);
    this->labIpv4Pack = new QLabel(this);
    this->labIpv4Pack->setText("Ipv4/6");
    this->editIpv4Pack = new QLineEdit(this);
    this->labOther = new QLabel(this);
    this->labOther->setText("Other");
    this->editOtherPack = new QLineEdit(this);
    this->labCount = new QLabel(this);
    this->labCount->setText("Count");
    this->editCount = new QLineEdit(this);
    this->labArpPack = new QLabel(this);
    this->labArpPack->setText("Arp");
    this->editArpPack = new QLineEdit(this);
    QList<QLineEdit *> editList= this->findChildren<QLineEdit *>();
    foreach (QLineEdit *edit, editList) {
        FlatUI::setLineEditQss(edit);
        edit->setReadOnly(true);
    }
    gridLayout->addWidget(labTcpPack, 0, 0);
    gridLayout->addWidget(editTcpPack, 0, 1);
    gridLayout->addWidget(labUdpPack, 0, 2);
    gridLayout->addWidget(editUdpPack, 0, 3);
    gridLayout->addWidget(labIcmpPack, 0, 4);
    gridLayout->addWidget(editIcmpPack, 0, 5);
    gridLayout->addWidget(labHttpPack, 1, 0);
    gridLayout->addWidget(editHttpPack, 1, 1);
    gridLayout->addWidget(labArpPack, 1, 2);
    gridLayout->addWidget(editArpPack, 1, 3);
    gridLayout->addWidget(labIpv4Pack, 1, 4);
    gridLayout->addWidget(editIpv4Pack, 1, 5);
    gridLayout->addWidget(labOther, 2, 0);
    gridLayout->addWidget(editOtherPack, 2, 1);
    gridLayout->addWidget(labCount, 2, 2);
    gridLayout->addWidget(editCount, 2, 3);
    font.setPixelSize(25);
    this->captureTextEdit = new QTextEdit(this);
    this->captureTextEdit->setFont(font);
    captureTextEdit->setReadOnly(true);
    font.setPixelSize(20);
    this->unpackTreeWidget = new QTreeWidget(this);
    this->unpackTreeWidget->setFont(font);
    this->unpackTreeWidget->setFixedWidth(400);
    unpackTreeWidget->header()->setHidden(true);
    unpackTreeWidget->setStyle(QStyleFactory::create("Macintosh"));
    unpackTreeWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    unpackTreeWidget->header()->setStretchLastSection(false);
    QVBoxLayout *vbLayout = new QVBoxLayout(this);
    QHBoxLayout *hbLayout = new QHBoxLayout(this);
    vbLayout->addWidget(captureTextEdit);
    vbLayout->addLayout(gridLayout);
    hbLayout->addWidget(unpackTreeWidget);
    hbLayout->addLayout(vbLayout);
    Layout->addLayout(hbNetworkCard);
    Layout->addLayout(hbCaptureRule);
    Layout->addWidget(captureTableWidget);
    Layout->addLayout(hbLayout);
    centralWidget()->setLayout(Layout);
}

void MainWindow::hardwareInfoInit()
{
    int cnt = 0;
    this->captureTextEdit->append("Localhost Name:");
    this->captureTextEdit->append(QHostInfo::localHostName());
    QList<QNetworkInterface> nets = QNetworkInterface::allInterfaces();
    foreach (QNetworkInterface net, nets) {
        if(net.flags().testFlag(QNetworkInterface::IsUp)
                &&net.flags().testFlag(QNetworkInterface::IsRunning)
                &&!net.flags().testFlag(QNetworkInterface::IsLoopBack))
        {
            for(int i=0;i<net.addressEntries().size();i++)
            {
                if(net.addressEntries().at(i).ip() != QHostAddress::LocalHost
                        &&net.addressEntries().at(i).ip().protocol() == QAbstractSocket::IPv4Protocol)
                {

                    this->captureTextEdit->append(QString("Devive %1\nIP:%2\nHardWare:%3%4\n%5").arg(QString::number(cnt),
                                                                                          net.addressEntries().at(i).ip().toString(),
                                                                                          net.humanReadableName(),
                                                                                          net.hardwareAddress(),
                                                                                          net.name()));
                    cnt++;
                }
            }
        }
    }
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        QMessageBox::warning(this, "No Device", "There are no device in your PC!");
    }
    for(d = alldevs; d; d = d->next)
    {

        if(d->description)
        {
            this->cmbNetworkCard->addItem(QString::fromStdString(d->description));
            this->devList.append(d);
        }
    }
    this->currentDev = alldevs;
    connect(this->captureTableWidget, &QTableWidget::cellDoubleClicked, this, &MainWindow::tabWidgetDoubleClickItemSlot);
    connect(cmbNetworkCard, SIGNAL(currentIndexChanged(int)), this, SLOT(cmbNetworkIndexChangeSlot(int)));
    connect(this->btnBeginCapture, SIGNAL(clicked(bool)), this, SLOT(btnBeginClickedSlot(bool)));
    connect(this->btnEndCapture, SIGNAL(clicked(bool)), this, SLOT(btnEndClickedSlot(bool)));
}

void MainWindow::cntListUpdate(pkg_count *pkgCnts)
{
    this->editArpPack->setText(QString::number(pkgCnts->n_arp));
    this->editCount->setText(QString::number(pkgCnts->n_ttl));
    this->editHttpPack->setText(QString::number(pkgCnts->n_http));
    this->editIcmpPack->setText(QString::number(pkgCnts->n_icmp)
                                +"/"
                                +QString::number(pkgCnts->n_icmp6));
    this->editIpv4Pack->setText(QString::number(pkgCnts->n_ipv4)
                                +"/"
                                +QString::number(pkgCnts->n_ipv6));
    this->editOtherPack->setText(QString::number(pkgCnts->n_other));
    this->editTcpPack->setText(QString::number(pkgCnts->n_tcp));
    this->editUdpPack->setText(QString::number(pkgCnts->n_udp));
}

void MainWindow::pkmsgAcpSlot(QString time, pkg_data *data)
{
    this->pkgList.append(data);
    char dmac[18];
    char smac[18];
    QString sip, dip;
    sprintf(dmac, "%02X-%02X-%02X-%02X", data->ethh->dmac[0],data->ethh->dmac[1],data->ethh->dmac[2],
            data->ethh->dmac[3]);
    sprintf(smac, "%02X-%02X-%02X-%02X", data->ethh->smac[0],data->ethh->smac[1],data->ethh->smac[2],
            data->ethh->smac[3]);
    if(0x0806 == data->ethh->type)
    {
        dip = QString::number(int(data->arph->dip.byte1))+"."+
                              QString::number(int(data->arph->dip.byte2))+"."+
                              QString::number(int(data->arph->dip.byte3))+"."+
                              QString::number(int(data->arph->dip.byte4));
        sip = QString::number(int(data->arph->sip.byte1))+"."+
                              QString::number(int(data->arph->sip.byte2))+"."+
                              QString::number(int(data->arph->sip.byte3))+"."+
                              QString::number(int(data->arph->sip.byte4));
    }
    else if(0x0800 == data->ethh->type)
    {
        sip = QString::number(int(data->ipv4h->srcaddr.byte1))+"."+
                QString::number(int(data->ipv4h->srcaddr.byte2))+"."+
                QString::number(int(data->ipv4h->srcaddr.byte3))+"."+
                QString::number(int(data->ipv4h->srcaddr.byte4));

        dip =  QString::number(int(data->ipv4h->dstaddr.byte1))+"."+
                QString::number(int(data->ipv4h->dstaddr.byte2))+"."+
                QString::number(int(data->ipv4h->dstaddr.byte3))+"."+
                QString::number(int(data->ipv4h->dstaddr.byte4));
    }
    else if(0x86dd == data->ethh->type)
    {
        sip = QString::number(int(data->ipv6h->srcaddr.byte1))+"."+
                QString::number(int(data->ipv6h->srcaddr.byte2))+"."+
                QString::number(int(data->ipv6h->srcaddr.byte3))+"."+
                QString::number(int(data->ipv6h->srcaddr.byte4))+"."+
                QString::number(int(data->ipv6h->srcaddr.byte5))+"."+
                QString::number(int(data->ipv6h->srcaddr.byte6))+"."+
                QString::number(int(data->ipv6h->srcaddr.byte7))+"."+
                QString::number(int(data->ipv6h->srcaddr.byte8));

        dip = QString::number(int(data->ipv6h->dstaddr.byte1))+"."+
                QString::number(int(data->ipv6h->dstaddr.byte2))+"."+
                QString::number(int(data->ipv6h->dstaddr.byte3))+"."+
                QString::number(int(data->ipv6h->dstaddr.byte4))+"."+
                QString::number(int(data->ipv6h->dstaddr.byte5))+"."+
                QString::number(int(data->ipv6h->dstaddr.byte6))+"."+
                QString::number(int(data->ipv6h->dstaddr.byte7))+"."+
                QString::number(int(data->ipv6h->dstaddr.byte8));
    }
    this->captureTableWidget->insertRow(this->pkgSeq);
    this->captureTableWidget->setItem(this->pkgSeq, 0, new QTableWidgetItem(QString::number(this->pkgSeq)));
    this->captureTableWidget->setItem(this->pkgSeq, 1, new QTableWidgetItem(time));
    this->captureTableWidget->setItem(this->pkgSeq, 2, new QTableWidgetItem(QString(smac)));
    this->captureTableWidget->setItem(this->pkgSeq, 3, new QTableWidgetItem(QString(dmac)));
    this->captureTableWidget->setItem(this->pkgSeq, 4, new QTableWidgetItem(QString::number(data->len)));
    this->captureTableWidget->setItem(this->pkgSeq, 5, new QTableWidgetItem(data->pkgtype));
    this->captureTableWidget->setItem(this->pkgSeq, 6, new QTableWidgetItem(sip));
    this->captureTableWidget->setItem(this->pkgSeq, 7, new QTableWidgetItem(dip));

    cntListUpdate(pkgCnt);
    this->pkgSeq++;
}

void MainWindow::errAcpSlot(QString errBuf)
{
    QMessageBox::warning(this, "Warning", errBuf);
}

void MainWindow::cmbNetworkIndexChangeSlot(int newIndex)
{
    int i;
    for(this->currentDev = alldevs, i = 0; i < newIndex; currentDev = currentDev->next, i++);
}

void MainWindow::btnBeginClickedSlot(bool isClicked)
{
    if(this->currentDev)
    {
        this->thread = new ListenThread;
        connect(thread, SIGNAL(pkmsgSendSignal(QString,pkg_data*)), this,
                SLOT(pkmsgAcpSlot(QString,pkg_data*)));
        connect(thread, SIGNAL(errSendSignal(QString)), this, SLOT(errAcpSlot(QString)));
        thread->setCurrentDev(this->currentDev);
        thread->start();
        this->btnEndCapture->setEnabled(true);
        this->btnBeginCapture->setEnabled(false);
        this->cmbNetworkCard->setEnabled(false);
        ifSet = false;
    }
    else
    {
        QMessageBox::warning(this, "Warning", "No current device");
        return;
    }
}

void MainWindow::btnEndClickedSlot(bool isClicked)
{
    qDebug()<<isClicked;
    isRun = false;
    this->btnBeginCapture->setEnabled(true);
    this->btnEndCapture->setEnabled(false);
    this->cmbNetworkCard->setEnabled(true);
}

void MainWindow::tabWidgetDoubleClickItemSlot(int row, int col)
{
    if(row >= this->pkgSeq)
        return;
    this->unpackTreeWidget->clear();
    pkg_data *pk = (pkg_data*)(pkgList.at(row));
    u_char *npk = (u_char*)(netpkgList.at(row));
    QTreeWidgetItem *rootItem = new QTreeWidgetItem(unpackTreeWidget);
    QTreeWidgetItem *seqItem = new QTreeWidgetItem(rootItem);
    QTreeWidgetItem *linkItem = new QTreeWidgetItem(seqItem);
    QTreeWidgetItem *smacItem = new QTreeWidgetItem(linkItem);
    QTreeWidgetItem *dmacItem = new QTreeWidgetItem(linkItem);
    QTreeWidgetItem *proItem = new QTreeWidgetItem(linkItem);
    rootItem->setText(0, "packet analyze");
    rootItem->addChild(seqItem);
    seqItem->setText(0, QString::number(row)+"th packet");
    seqItem->addChild(linkItem);
    linkItem->setText(0, "Link layer");
    QList<QTreeWidgetItem *> linkList;
    linkList<< smacItem<< dmacItem<< proItem;
    linkItem->addChildren(linkList);
    smacItem->setText(0, "SrcMac:"+captureTableWidget->item(row, 2)->text());
    dmacItem->setText(0, "DstMac:"+captureTableWidget->item(row, 3)->text());
    if(this->pkgList.at(row)->ethh->type == 0x0800)
    {
        proItem->setText(0, "Protocol: 0x0800"); 
        QTreeWidgetItem *ipItem = new QTreeWidgetItem(seqItem);
        ipItem->setText(0, "Network layer");
        QTreeWidgetItem *verItem = new QTreeWidgetItem(ipItem);
        verItem->setText(0, "Version: " + QString::number((pk->ipv4h->ver_ihl & 0xf0)>>4));
        QTreeWidgetItem *hlenItem = new QTreeWidgetItem(ipItem);
        hlenItem->setText(0, "IPH len: " + QString::number(pk->ipv4h->ver_ihl & 0xf));
        QTreeWidgetItem *tosItem = new QTreeWidgetItem(ipItem);
        tosItem->setText(0, "Tos:" + QString::number(int(pk->ipv4h->tos)));
        QTreeWidgetItem *tlenItem = new QTreeWidgetItem(ipItem);
        tlenItem->setText(0, "Sum len: " + QString::number(int(pk->ipv4h->tlen)));
        QTreeWidgetItem *idItem = new QTreeWidgetItem(ipItem);
        idItem->setText(0, "Id:" + QString::number(int(pk->ipv4h->Identification)));
        QTreeWidgetItem *fragItem = new QTreeWidgetItem(ipItem);
        fragItem->setText(0, "Frag off: " + QString::number(int(pk->ipv4h->flags_fo)));
        QTreeWidgetItem *ttlItem = new QTreeWidgetItem(ipItem);
        ttlItem->setText(0, "Ttl: " + QString::number(int(pk->ipv4h->ttl)));
        QTreeWidgetItem *protoItem = new QTreeWidgetItem(ipItem);
        switch(pk->ipv4h->proto)
        {
        case 6:
        {
            if(ntohs(pk->tcph->dstport) == 80 || ntohs(pk->tcph->srcport) == 80)
                protoItem->setText(0, "Protocol: " + QString("HTTP"));
            else
                protoItem->setText(0, "Protocol: " + QString("TCP"));
            QTreeWidgetItem *tcpItem = new QTreeWidgetItem(seqItem);
            tcpItem->setText(0, "Transport layer");
            QTreeWidgetItem *seqItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *ackseqItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *reslItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *doffItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *finItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *synItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *pstItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *pshItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *ackItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *urgItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *eceItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *cwrItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *windowItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *checkItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *urgpItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *optItem = new QTreeWidgetItem(tcpItem);
            ipItem->setText(0, "IP Header");
            seqItem->setText(0, "Seq" + QString::number(pk->tcph->seq));
            ackseqItem->setText(0, "Ack_seq: " + QString::number(pk->tcph->ack_seq));
            reslItem->setText(0, "Resl: " + QString::number(pk->tcph->resl));
            doffItem->setText(0, "Doff: " + QString::number(pk->tcph->doff));
            finItem->setText(0, "Fin: " + QString::number(pk->tcph->fin));
            synItem->setText(0, "Syn: " + QString::number(pk->tcph->syn));
            pstItem->setText(0, "Pst: " + QString::number(pk->tcph->pst));
            pshItem->setText(0, "Psh: " + QString::number(pk->tcph->psh));
            ackItem->setText(0, "Ack: " + QString::number(pk->tcph->ack));
            urgItem->setText(0, "Urg: " + QString::number(pk->tcph->urg));
            eceItem->setText(0, "Ece: " + QString::number(pk->tcph->ece));
            cwrItem->setText(0, "Cwr: " + QString::number(pk->tcph->cwr));
            windowItem->setText(0, "Window: " + QString::number(pk->tcph->window));
            checkItem->setText(0, "Cre: " + QString::number(pk->tcph->check));
            urgpItem->setText(0, "Urg_ptr: " + QString::number(pk->tcph->urg_ptr));
            optItem->setText(0, "opt: " + QString::number(pk->tcph->opt));
            break;
        }
        case 17:
        {
            protoItem->setText(0, "Protocol: " + QString("UDP"));
            QTreeWidgetItem *udpItem = new QTreeWidgetItem(seqItem);
            udpItem->setText(0, "Transport layer");
            QTreeWidgetItem *sportItem = new QTreeWidgetItem(udpItem);
            QTreeWidgetItem *dportItem = new QTreeWidgetItem(udpItem);
            QTreeWidgetItem *len = new QTreeWidgetItem(udpItem);
            QTreeWidgetItem *crc = new QTreeWidgetItem(udpItem);
            sportItem->setText(0, "Src port: " + QString::number(pk->udph->srcport));
            dportItem->setText(0, "Dst port" + QString::number(pk->udph->dstport));
            len->setText(0, "Len: " + QString::number(pk->udph->tlen));
            crc->setText(0, "Cre: " + QString::number(pk->udph->crc));;
            break;
        }

        case 1:
        {
            protoItem->setText(0, "Protocol: " + QString("ICMP"));
            QTreeWidgetItem *icmpItem = new QTreeWidgetItem(seqItem);
            icmpItem->setText(0, "Transport layer");
            QTreeWidgetItem *type = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *code = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *seq = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *crc = new QTreeWidgetItem(icmpItem);
            type->setText(0, "Type: " + QString::number(pk->icmph->type));
            code->setText(0, "Code: " + QString::number(pk->icmph->code));
            seq->setText(0, "Seq: " + QString::number(pk->icmph->seq));
            crc->setText(0, "Crc: " + QString::number(pk->icmph->crc));
            break;
        }
        }
        QTreeWidgetItem *ckItem = new QTreeWidgetItem(ipItem);
        ckItem->setText(0, "Crc: " + QString::number(int(pk->ipv4h->crc)));
        QTreeWidgetItem *optItem = new QTreeWidgetItem(ipItem);
        optItem->setText(0, "Opt: " + QString::number(int(pk->ipv4h->op_pad)));
    }
    if(this->pkgList.at(row)->ethh->type == 0x0806)
    {
        proItem->setText(0, "Protocol: 0x0806");
        QTreeWidgetItem *arpItem = new QTreeWidgetItem(seqItem);
        QTreeWidgetItem *hardItem = new QTreeWidgetItem(arpItem);
        QTreeWidgetItem *protoItem = new QTreeWidgetItem(arpItem);
        QTreeWidgetItem *hlenItem = new QTreeWidgetItem(arpItem);
        QTreeWidgetItem *plenItem = new QTreeWidgetItem(arpItem);
        QTreeWidgetItem *optItem = new QTreeWidgetItem(arpItem);
        arpItem->setText(0, "Network layer");
        hardItem->setText(0, "Hardware: " + QString::number(pk->arph->hardware));
        protoItem->setText(0, "Protocol: ARP" );
        hlenItem->setText(0, "Hardware len: " + QString::number(pk->arph->ml));
        plenItem->setText(0, "IP len: " + QString::number(pk->arph->ipl));
        optItem->setText(0, "Option: " + QString::number(pk->arph->opt));
    }
    else if(this->pkgList.at(row)->ethh->type == 0x86dd)
    {
        proItem->setText(0, "Protocol: 0x86dd");
        QTreeWidgetItem *ipv6Item = new QTreeWidgetItem(seqItem);
        QTreeWidgetItem *verItem = new QTreeWidgetItem(ipv6Item);
        QTreeWidgetItem *ftypeItem = new QTreeWidgetItem(ipv6Item);
        QTreeWidgetItem *fidItem = new QTreeWidgetItem(ipv6Item);
        QTreeWidgetItem *plenItem = new QTreeWidgetItem(ipv6Item);
        QTreeWidgetItem *nhItem = new QTreeWidgetItem(ipv6Item);
        QTreeWidgetItem *hlimItem = new QTreeWidgetItem(ipv6Item);
        verItem->setText(0, "Version: " + QString::number(pk->ipv6h->ver));
        ftypeItem->setText(0, "Flow type: " + QString::number(pk->ipv6h->flowtype));
        fidItem->setText(0, "Flow id: " + QString::number(pk->ipv6h->flowtip));
        plenItem->setText(0, "Payload length: " + QString::number(pk->ipv6h->len));
        nhItem->setText(0, "Next header: " + QString::number(pk->ipv6h->pnext));
        hlimItem->setText(0, "Hop limit: " + QString::number(pk->ipv6h->lim));
        QTreeWidgetItem *protoItem = new QTreeWidgetItem(ipv6Item);
        switch(pk->ipv6h->pnext)
        {
        case 0x3a:
        {
            protoItem->setText(0, "Protocol: " + QString("ICMPv6"));
            QTreeWidgetItem *icmpItem = new QTreeWidgetItem(seqItem);
            icmpItem->setText(0, "Transport layer");
            QTreeWidgetItem *type = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *code = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *seq = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *crc = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *optype = new QTreeWidgetItem(icmpItem);
            QTreeWidgetItem *oplen = new QTreeWidgetItem(icmpItem);
            type->setText(0, "Type: " + QString::number(pk->icmp6->type));
            code->setText(0, "Code: " + QString::number(pk->icmph->code));
            seq->setText(0, "Seq: " + QString::number(pk->icmp6->seq));
            crc->setText(0, "Crc: " + QString::number(pk->icmp6->crc));
            optype->setText(0, "Opt type: " + QString::number(pk->icmp6->op_type));
            oplen->setText(0, "Opt len: " + QString::number(pk->icmp6->op_len));
            break;
        }

        case 0x06:
        {
            if(ntohs(pk->tcph->dstport) == 80 || ntohs(pk->tcph->srcport) == 80)
                protoItem->setText(0, "Protocol: " + QString("HTTP"));
            else
                protoItem->setText(0, "Protocol: " + QString("TCP"));
            QTreeWidgetItem *tcpItem = new QTreeWidgetItem(seqItem);
            tcpItem->setText(0, "Transport layer");
            QTreeWidgetItem *seqItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *ackseqItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *reslItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *doffItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *finItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *synItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *pstItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *pshItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *ackItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *urgItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *eceItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *cwrItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *windowItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *checkItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *urgpItem = new QTreeWidgetItem(tcpItem);
            QTreeWidgetItem *optItem = new QTreeWidgetItem(tcpItem);
            ipv6Item->setText(0, "IPv6 Header");
            seqItem->setText(0, "Seq" + QString::number(pk->tcph->seq));
            ackseqItem->setText(0, "Ack_seq: " + QString::number(pk->tcph->ack_seq));
            reslItem->setText(0, "Resl: " + QString::number(pk->tcph->resl));
            doffItem->setText(0, "Doff: " + QString::number(pk->tcph->doff));
            finItem->setText(0, "Fin: " + QString::number(pk->tcph->fin));
            synItem->setText(0, "Syn: " + QString::number(pk->tcph->syn));
            pstItem->setText(0, "Pst: " + QString::number(pk->tcph->pst));
            pshItem->setText(0, "Psh: " + QString::number(pk->tcph->psh));
            ackItem->setText(0, "Ack: " + QString::number(pk->tcph->ack));
            urgItem->setText(0, "Urg: " + QString::number(pk->tcph->urg));
            eceItem->setText(0, "Ece: " + QString::number(pk->tcph->ece));
            cwrItem->setText(0, "Cwr: " + QString::number(pk->tcph->cwr));
            windowItem->setText(0, "Window: " + QString::number(pk->tcph->window));
            checkItem->setText(0, "Cre: " + QString::number(pk->tcph->check));
            urgpItem->setText(0, "Urg_ptr: " + QString::number(pk->tcph->urg_ptr));
            optItem->setText(0, "opt: " + QString::number(pk->tcph->opt));
            break;
        }
        case 0x11:
        {
            protoItem->setText(0, "Protocol: " + QString("UDP"));
            QTreeWidgetItem *udpItem = new QTreeWidgetItem(seqItem);
            udpItem->setText(0, "Transport layer");
            QTreeWidgetItem *sportItem = new QTreeWidgetItem(udpItem);
            QTreeWidgetItem *dportItem = new QTreeWidgetItem(udpItem);
            QTreeWidgetItem *len = new QTreeWidgetItem(udpItem);
            QTreeWidgetItem *crc = new QTreeWidgetItem(udpItem);
            sportItem->setText(0, "Src port: " + QString::number(pk->udph->srcport));
            dportItem->setText(0, "Dst port" + QString::number(pk->udph->dstport));
            len->setText(0, "Len: " + QString::number(pk->udph->tlen));
            crc->setText(0, "Cre: " + QString::number(pk->udph->crc));;
            break;
        }
        }
    }
    PacketTools::pack_Print(npk, pk->len, this->captureTextEdit);
}

void MainWindow::exit()
{
    if(this->thread != nullptr)
    {
        if(this->thread->isRunning())
        {
            isRun = false;
            Sleep(1);
        }
        delete thread;
    }
    close();

}

void MainWindow::reset()
{
    if(ifSet)
        return;
    if(this->thread != nullptr)
    {
        while(this->thread->isRunning())
        {
            isRun = false;
            Sleep(1);
        }
        delete thread;
    }
    this->currentDev = nullptr;
    delete this->currentDev;
    pkgCnt = nullptr;
    delete pkgCnt;
    d = nullptr;
    delete d;
    pcap_freealldevs(alldevs);
    this->captureTableWidget->clear();
    this->captureTextEdit->clear();
    while(this->cmbNetworkCard->count())
        this->cmbNetworkCard->removeItem(0);
    pInit();
    hardwareInfoInit();
    this->btnBeginCapture->setEnabled(true);
    this->btnEndCapture->setEnabled(false);
    this->cmbNetworkCard->setEnabled(true);
    this->unpackTreeWidget->clear();
    cntListUpdate(pkgCnt);
    this->captureTextEdit->append("Network Sniffer has been resetted over.");
}

void MainWindow::aboutmker()
{
    QMessageBox::about(this, "About Maker", tr("<p>电信214杨晓通</p>"));
}

void MainWindow::aboutsniffer()
{
    QMessageBox::about(this, "About Sniffer", tr("<p>Network Sniffer 1.0 for ethernet</p>"));
}

void MainWindow::menuBarInit()
{
    this->fileMenu = new QMenu(tr("&File"));
    this->aboutMenu = new QMenu(tr("&About"));
    this->resetAct = new QAction(tr("&Reset"));
    connect(resetAct, &QAction::triggered, this, &MainWindow::reset);
    this->resetAct->setShortcut(QKeySequence::Refresh);
    this->exitAct = new QAction(tr("&Exit"));
    connect(exitAct, &QAction::triggered, this, &MainWindow::exit);
    this->exitAct->setShortcut(QKeySequence::Close);
    this->aboutmkerAct = new QAction(tr("&About Maker"));
    connect(aboutmkerAct, &QAction::triggered, this, &MainWindow::aboutmker);
    this->aboutsnifferAct = new QAction(tr("&About"));
    connect(aboutsnifferAct, &QAction::triggered, this, &MainWindow::aboutsniffer);
    
    QList<QAction *> fileActList;
    fileActList<< this->resetAct<< this->exitAct;
    QList<QAction *> aboutActList;
    aboutActList<< aboutsnifferAct<< aboutmkerAct;
    this->fileMenu->addActions(fileActList);
    this->aboutMenu->addActions(aboutActList);
    
    ui->menuBar->addMenu(fileMenu);
    ui->menuBar->addMenu(aboutMenu);
}

