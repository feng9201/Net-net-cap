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
    ui.le_FilterInput->setPlaceholderText(QString::fromLocal8Bit("请输入有效筛选filter"));
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
    //设置table_view
    ui.wTable_data->setSelectionBehavior(QAbstractItemView::SelectRows);//整行选中的方式
    ui.wTable_data->setEditTriggers(QAbstractItemView::NoEditTriggers);//禁止修改
    ui.wTable_data->setSelectionMode(QAbstractItemView::SingleSelection);//可以选中单个
    ui.wTable_data->horizontalHeader()->setSectionResizeMode(5,QHeaderView::Stretch); //宽度自适应
    
     //ui.wTable_data->resizeColumnsToContents();

    //设置tree_view
    QStandardItemModel* model = new QStandardItemModel(this);

    //设置表头隐藏
    //ui->treeView->setHeaderHidden(true);

    //设置表头
    model->setHorizontalHeaderLabels(QStringList() << QString::fromLocal8Bit("协议层") << QString::fromLocal8Bit("信息"));

    //设置model 
    ui.wTree_data->setModel(model);

    //设置展开
    ui.wTree_data->expandAll();


    
}

void MyNetDump::initConnect()
{
    //连接widgetTable 选择时的处理
    connect(ui.wTable_data, static_cast<void(QTableWidget::*)(int,int)>(&QTableWidget::cellClicked), this,&MyNetDump::analysisPacket);
    connect(ui.wTable_data, static_cast<void(QTableWidget::*)(QTableWidgetItem*, QTableWidgetItem*)>(&QTableWidget::currentItemChanged), this, [=](QTableWidgetItem* c, QTableWidgetItem* p){
        //利用当前Item的属性，调用分析函数
        if (c!= nullptr)
            analysisPacket(c->row(), c->column());
        
        });
    //连接网络接口选择器实现函数 
    connect(ui.cb_NicList, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &MyNetDump::selectNIC);

    //连接 开始抓包功能实现
    connect(ui.actionstartPcap, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::startPcap);

    //连接 停止抓包功能实现
    connect(ui.actionstopPcap, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::stopPcap);
    //
    connect(hr_Packet, static_cast<void(PacketHandler::*)(QStringList)>(&PacketHandler::PackInfo),this,&MyNetDump::showTable,Qt::QueuedConnection);

    //数据保存功能
    connect(ui.actionSaveFile, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::savePacket);
    
    //数据清除功能
    connect(ui.actionClear, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::clearData);
    //文件关闭功能
    connect(ui.actionCloseFile, static_cast<void(QAction::*)(bool)>(&QAction::triggered), this, &MyNetDump::clearData);
    //文件打开功能
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
    //清空list中的数据 
    //当前表中有数据的时候
    if (!isStop)
    {
        QMessageBox::StandardButton result = QMessageBox::question(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("正在抓包，是否重新开始？"));
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
    //如果没有选择网卡，就默认使用第1块
    if (SelectedDevices == nullptr)
    {
        selectNIC(0);
    }
    std::cout << "Listening on Devices : " << SelectedDevices->getDesc() << std::endl;

    //打开 选择的接口
    if (!SelectedDevices->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        exit(1);
    }
   
    std::cout << std::endl << "Starting async capture..." << std::endl;
    
    //开始计时
    tCounter.tic();
    //开始异步抓包 
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
    //首先从保存的数据包中获得选中行代表的数据包
   /* std::cout << "当前选中的行为 ：" << row << "/" << ui.wTable_data->rowCount()<< std::endl;
    std::cout << "总保存数据包为：" << hr_Packet->packetCount() << std::endl;*/
    if (row == -1)
    {
        return;
    }
    sPacket spacket= hr_Packet->getPacket(row);

    //显示数据包的16进制信息，将信息写入到PlainText控件中 
    displayHexString(pcpp::byteArrayToHexString(spacket.rawPacket.getRawData(), spacket.rawPacket.getRawDataLen()).c_str());
    
    //std::vector<std::string> infos;
    //取出所有的数据包信息
    pcpp::Packet _packet(&spacket.rawPacket);

    QStandardItemModel* model = new QStandardItemModel(ui.wTree_data);

    model->setHorizontalHeaderLabels(QStringList() << QString::fromLocal8Bit("协议层") << QString::fromLocal8Bit("信息"));
    pcpp::Layer *_layer = _packet.getFirstLayer();
    //其次对数据包表层进行解析
    do
    {   
        QList<QStandardItem*> Items;
        //此处代码比较丑，一时间没想好怎么做
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
    //打开一个文件对话窗口
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save File"),"output",tr("Pacp (*.pcap *.pcapng)"));

    if (fileName.isEmpty())
    {
        std::cout << "请输入一个文件名!!!!" << std::endl;
        return;
    }
    
    std::cout << fileName.toStdString();

    hr_Packet->savePacketToFile(fileName);
}

void MyNetDump::clearData()
{
    if (ui.wTable_data->rowCount() > 0)
    {
        QMessageBox::StandardButton result = QMessageBox::question(this, QString::fromLocal8Bit("提示"), QString::fromLocal8Bit("是否保存数据？"));
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

    //利用设置一个空的model的方式，删除所有的数据
    //设置tree_view
    QStandardItemModel* model = new QStandardItemModel(this);

    //设置表头
    model->setHorizontalHeaderLabels(QStringList() << QString::fromLocal8Bit("协议层") << QString::fromLocal8Bit("信息"));

    //设置model 
    ui.wTree_data->setModel(model);
}

void MyNetDump::openFile()
{
    //弹出一个文件打开窗口
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("Pacp (*.pcap *.pcapng)"));
    if (fileName.isEmpty())
    {
        std::cout << "未选中任何文件!!!" << std::endl;
    }
    std::cout << fileName.toStdString() << std::endl;

    hr_Packet->openPcapFile(fileName);

}

void MyNetDump::displayHexString(QString hexStr)
{
    QString strDis;
    hexStr = hexStr.toUpper();//转换为大写
    for (int i = 0; i < hexStr.length(); i += 2)//填加空格
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
    ui.wTable_data->insertRow(RowCont);//增加一行
    if (isColorful)
    {
        brush.setColor(QColor("#0000ee"));
    }
    else
    {
        ui.wTable_data->setAlternatingRowColors(true); // 隔行变色
        ui.wTable_data->setPalette(QPalette("#87CEFA")); // 设置隔行变色的颜色  gray灰色
    }
    int i = 0;
    for each (QString strItem in PackInfo)
    {
        //插入元素
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
