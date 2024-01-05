#include "MyNetDump.h"


TimerCounter MyNetDump::tCounter;

MyNetDump::MyNetDump(QWidget *parent)
    : QMainWindow(parent),
    hr_Packet(new PacketHandler())

{
    ui.setupUi(this);
    this->setWindowIcon(QIcon(":/MyNetDump/images/icon.png"));
    initConnect();
    initDevices();
    initWidget();
    ui.le_FilterInput->setText("udp and dst port 5513");
    ui.le_FilterInput->setPlaceholderText(QString::fromLocal8Bit("��������Чɸѡfilter"));
}

void MyNetDump::test()
{   
 /*   QString info = "this is a test info";
    for (size_t i = 0; i < 10; i++)
    {
        QStringList pinfo;
        pinfo << "123" << "192.168.1.1" << "192.168.0.1" << "icmp" << tr("%1").arg(64) << info;
        this->showTable(pinfo);
        info += info;
    }*/
}

void MyNetDump::initDevices()
{
    if (allDevices.size() == 0)
    {
        getDeviceList();
    }
    std::vector<pcpp::PcapLiveDevice*>::iterator it;

    QStringList nics;
    QString desc;
    for (it = this->allDevices.begin(); it < this->allDevices.end(); it++)
    { 
        pcpp::PcapLiveDevice* dev = *it;
        if (!dev->getDesc().empty())
        {
            desc= QString(dev->getDesc().c_str());
        }
        else
        {
            desc = QString(dev->getName().c_str());
        }
       
        nics.append(desc);
    }
    ui.cb_NicList->addItems(nics);
}

void MyNetDump::initMenu()
{

}

void MyNetDump::initWidget()
{
    //����table_view
    ui.wTable_data->setSelectionBehavior(QAbstractItemView::SelectRows);//����ѡ�еķ�ʽ
    ui.wTable_data->setEditTriggers(QAbstractItemView::NoEditTriggers);//��ֹ�޸�
    ui.wTable_data->setSelectionMode(QAbstractItemView::SingleSelection);//����ѡ�е���
    ui.wTable_data->horizontalHeader()->setSectionResizeMode(5,QHeaderView::Stretch); //�������Ӧ
    
     //ui.wTable_data->resizeColumnsToContents();

    //����tree_view
    QStandardItemModel* model = new QStandardItemModel(this);

    //���ñ�ͷ����
    //ui->treeView->setHeaderHidden(true);

    //���ñ�ͷ
    model->setHorizontalHeaderLabels(QStringList() << QString::fromLocal8Bit("Э���") << QString::fromLocal8Bit("��Ϣ"));

    //����model 
    ui.wTree_data->setModel(model);

    //����չ��
    ui.wTree_data->expandAll();


    
}

void MyNetDump::initConnect()
{
    //����widgetTable ѡ��ʱ�Ĵ���
    connect(ui.wTable_data, static_cast<void(QTableWidget::*)(int,int)>(&QTableWidget::cellClicked), this,&MyNetDump::analysisPacket);
    connect(ui.wTable_data, static_cast<void(QTableWidget::*)(QTableWidgetItem*, QTableWidgetItem*)>(&QTableWidget::currentItemChanged), this, [=](QTableWidgetItem* c, QTableWidgetItem* p){
        //���õ�ǰItem�����ԣ����÷�������
        if (c!= nullptr)
            analysisPacket(c->row(), c->column());
        
        });
    //��������ӿ�ѡ����ʵ�ֺ��� 
    connect(ui.cb_NicList, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &MyNetDump::selectNIC);

    //���� ��ʼץ������ʵ��
    connect(ui.actionstartPcap, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::startPcap);

    //���� ֹͣץ������ʵ��
    connect(ui.actionstopPcap, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::stopPcap);
    //
    connect(hr_Packet, static_cast<void(PacketHandler::*)(QStringList)>(&PacketHandler::PackInfo),this,&MyNetDump::showTable,Qt::QueuedConnection);

    //���ݱ��湦��
    connect(ui.actionSaveFile, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::savePacket);
    
    //�����������
    connect(ui.actionClear, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::clearData);
    //�ļ��رչ���
    connect(ui.actionCloseFile, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::clearData);
    //�ļ��򿪹���
    connect(ui.actionOpenFile, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::openFile);

    connect(ui.wTree_data, static_cast<void(QTreeView::*)(const QModelIndex&)>(&QTreeView::expanded), this, [=](QModelIndex mi) {
        if (mi.isValid())
        {
            std::cout << mi.row() << std::endl;
            QStandardItemModel* model = (QStandardItemModel*)mi.model();
            QList<QStandardItem*> items =  model->findItems(QString("Data:"));
            for each (auto  item in items)
            {
                std::cout << item->text().toStdString();
            }
        }
        });
}

void MyNetDump::selectNIC(int index)
{
    if (index >= 0 && index < allDevices.size())
    {
        SelectedDevices = allDevices[index];
    }
    if (SelectedDevices != nullptr)
    {
        printf("Dev %s is selected. ", SelectedDevices->getDesc().c_str());
    }
    
}

void MyNetDump::startPcap()
{
    //���list�е����� 
    //��ǰ���������ݵ�ʱ��
    if (!isStop)
    {
        QMessageBox::StandardButton result = QMessageBox::question(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("����ץ�����Ƿ����¿�ʼ��"));
        if (result == QMessageBox::Yes)
        {
            this->stopPcap();
        }
        else
        {
            return;
        }
    }
    isStop = false;
    clearData();
    //���û��ѡ����������Ĭ��ʹ�õ�1��
    if (SelectedDevices == nullptr)
    {
        selectNIC(0);
    }
    std::cout << "Listening on Devices : " << SelectedDevices->getDesc() << std::endl;

    //�� ѡ��Ľӿ�
    if (!SelectedDevices->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        exit(1);
    }
   
    std::cout << std::endl << "Starting async capture..." << std::endl;
    
    //��ʼ��ʱ
    tCounter.tic();
    //��ʼ�첽ץ�� 
    QString filter = ui.le_FilterInput->text();
    bool ret = SelectedDevices->setFilter(filter.toStdString()/*"udp and dst port 5513"*/);
    SelectedDevices->startCapture(onPacketArrives, hr_Packet);
   

    // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
    //pcpp::multiPlatformSleep(10);

    // print results
    std::cout << "Results:" << std::endl;
    //stats.printToConsole();

    // clear stats
    //stats.clear();
}

void MyNetDump::stopPcap()
{
    isStop = true;
    // stop capturing packets
    if (SelectedDevices != nullptr && SelectedDevices->captureActive())
    {
        SelectedDevices->stopCapture();
    }
    
    
}

void MyNetDump::analysisPacket(int row, int col)
{
    //���ȴӱ�������ݰ��л��ѡ���д�������ݰ�
   /* std::cout << "��ǰѡ�е���Ϊ ��" << row << "/" << ui.wTable_data->rowCount()<< std::endl;
    std::cout << "�ܱ������ݰ�Ϊ��" << hr_Packet->packetCount() << std::endl;*/
    if (row == -1)
    {
        return;
    }
    sPacket spacket= hr_Packet->getPacket(row);

    //��ʾ���ݰ���16������Ϣ������Ϣд�뵽PlainText�ؼ��� 
    displayHexString(pcpp::byteArrayToHexString(spacket.rawPacket.getRawData(), spacket.rawPacket.getRawDataLen()).c_str());
    
    //std::vector<std::string> infos;
    //ȡ�����е����ݰ���Ϣ
    pcpp::Packet _packet(&spacket.rawPacket);

    QStandardItemModel* model = new QStandardItemModel(ui.wTree_data);

    model->setHorizontalHeaderLabels(QStringList() << QString::fromLocal8Bit("Э���") << QString::fromLocal8Bit("��Ϣ"));
    pcpp::Layer *_layer = _packet.getFirstLayer();
    //��ζ����ݰ������н���
    do
    {   
        QList<QStandardItem*> Items;
        //�˴�����Ƚϳ�һʱ��û�����ô��
        pcpp::ProtocolType p = _layer->getProtocol();
        switch (p)
        {
        case pcpp::Ethernet:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::EthLayer>(p), &Items);
            break;
        case pcpp::ARP:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::ArpLayer>(p), &Items);
            break;
        case pcpp::IPv4:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::IPv4Layer>(p), &Items);
            break;
        case pcpp::IPv6:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::IPv6Layer>(p), &Items);
            break;
        case pcpp::ICMP:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::IcmpLayer>(p), &Items);
            break;
        case pcpp::TCP:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::TcpLayer>(p), &Items);
            break;
        case pcpp::UDP:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::UdpLayer>(p), &Items);
            break;
        case pcpp::HTTPRequest:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::HttpRequestLayer>(p), &Items);
            break;
        case pcpp::HTTPResponse:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::HttpResponseLayer>(p), &Items);
            break;
        case pcpp::SSL:
            hr_Packet->LayerHandler(_packet.getLayerOfType<pcpp::SSLLayer>(p), &Items);
            break;
        default:
            hr_Packet->LayerHandler(_layer, &Items);
            break;
        }
        
        model->appendRow(Items);
    } while ((_layer = _layer->getNextLayer())!=NULL); 
    
    
    ui.wTree_data->setModel(model);

}

void MyNetDump::savePacket()
{
    //��һ���ļ��Ի�����
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save File"),"output",tr("Pacp (*.pcap *.pcapng)"));

    if (fileName.isEmpty())
    {
        std::cout << "������һ���ļ���!!!!" << std::endl;
        return;
    }
    
    std::cout << fileName.toStdString();

    hr_Packet->savePacketToFile(fileName);
}

void MyNetDump::clearData()
{
    if (ui.wTable_data->rowCount() > 0)
    {
        QMessageBox::StandardButton result = QMessageBox::question(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("�Ƿ񱣴����ݣ�"));
        if (result == QMessageBox::Yes)
        {
            std::cout << "yes";
            savePacket();
        }
        else
        {
            std::cout << "no";
        }
    }
    hr_Packet->clearPacket();
    ui.wTable_data->clearContents();
    ui.wTable_data->setRowCount(0);
    ui.pte_data->clear();

    //��������һ���յ�model�ķ�ʽ��ɾ�����е�����
    //����tree_view
    QStandardItemModel* model = new QStandardItemModel(this);

    //���ñ�ͷ
    model->setHorizontalHeaderLabels(QStringList() << QString::fromLocal8Bit("Э���") << QString::fromLocal8Bit("��Ϣ"));

    //����model 
    ui.wTree_data->setModel(model);
}

void MyNetDump::openFile()
{
    //����һ���ļ��򿪴���
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("Pacp (*.pcap *.pcapng)"));
    if (fileName.isEmpty())
    {
        std::cout << "δѡ���κ��ļ�!!!" << std::endl;
    }
    std::cout << fileName.toStdString() << std::endl;

    hr_Packet->openPcapFile(fileName);

}

void MyNetDump::displayHexString(QString hexStr)
{
    QString strDis;
    hexStr = hexStr.toUpper();//ת��Ϊ��д
    for (int i = 0; i < hexStr.length(); i += 2)//��ӿո�
    {
        QString st = hexStr.mid(i, 2);
        strDis += st;
        strDis += "  ";
        
    }
    ui.pte_data->setPlainText(strDis);
}

void MyNetDump::closeEvent(QCloseEvent* event)
{
    clearData();
}

void MyNetDump::showTable(QStringList PackInfo)
{
    int RowCont;
    QBrush brush(QColor("#000000"));
    RowCont = ui.wTable_data->rowCount();
    ui.wTable_data->insertRow(RowCont);//����һ��
    if (isColorful)
    {
        brush.setColor(QColor("#0000ee"));
    }
    else
    {
        ui.wTable_data->setAlternatingRowColors(true); // ���б�ɫ
        ui.wTable_data->setPalette(QPalette("#87CEFA")); // ���ø��б�ɫ����ɫ  gray��ɫ
    }
    int i = 0;
    for each (QString strItem in PackInfo)
    {
        //����Ԫ��
        QTableWidgetItem* item = new QTableWidgetItem(strItem);
        if (isColorful)
        {
            item->setBackground(brush);
        }
        
        ui.wTable_data->setItem(RowCont, i++, item);
        ui.wTable_data->scrollToBottom();
    }
    

   /* ui.wTable_data->setItem(RowCont, 1, item2);

    QTableWidgetItem* item3 = new QTableWidgetItem(dIP);
    ui.wTable_data->setItem(RowCont, 2, item3);

    QTableWidgetItem* item4 = new QTableWidgetItem(protocol);
    ui.wTable_data->setItem(RowCont, 3, item4);

    QTableWidgetItem* item5 = new QTableWidgetItem(tr("%1").arg(nLen));
    ui.wTable_data->setItem(RowCont, 4, item5);
    QTableWidgetItem* item6 = new QTableWidgetItem(info);
    ui.wTable_data->setItem(RowCont, 5, item6);*/

}

void MyNetDump::onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    // extract the stats object form the cookie
    PacketHandler* pcHander = (PacketHandler*)cookie;
    
    pcHander->savePacket(packet, tCounter.toc());
}

QString MyNetDump::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
   
    return QString(hr_Packet->getStrProtocolType(protocolType).c_str());
}


void MyNetDump::getDeviceList()
{
    std::vector<pcpp::PcapLiveDevice*> tmpList(pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList());
    this->allDevices.assign(tmpList.begin(), tmpList.end());
}
