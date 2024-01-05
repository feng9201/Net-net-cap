#include "PacketHandler.h"
#include <ArpLayer.h>
#include <EthLayer.h>
#include <IcmpLayer.h>
#include <IPv4Layer.h>
#include <EthLayer.h>

//处理arp数据包

void PacketHandler::savePacket(pcpp::RawPacket* packet, long long time)
{
    sPacket tmpS = {};
    tmpS.rawPacket = *packet;
    tmpS.time = time;
    svPackets.push_back(tmpS);
    getPacketInfo(packet,time);
}

bool PacketHandler::savePacketToFile(QString fileName)
{
    // 新建一个Pcap文件写入器
     pcpp::PcapFileWriterDevice pcapWriter(fileName.toStdString(), pcpp::LINKTYPE_ETHERNET);
    // 打开文件写入器
    if (!pcapWriter.open())
    {
        std::cerr << "Cannot open output.pcap for writing" << std::endl;
        return false;
    }

    //开始写包
    if (svPackets.size() == 0)
    {
        std::cerr << "packet is null." << std::endl;
        pcapWriter.close();
        return false;
    }
    //循环写入数据包
    for (auto iter = svPackets.begin(); iter != svPackets.end(); iter++)
    {
        pcapWriter.writePacket(iter->rawPacket);
    }

    // 创建一个状态对象
    pcpp::IPcapDevice::PcapStats stats;

    //获取写入的状态
    pcapWriter.getStatistics(stats);

    //输出状态信息
    QString statsInfo = QString("\nWrite:%1 Packets \nDrop:%2 Pakcets").arg(stats.packetsRecv).arg(stats.packetsDrop);
    std::cout << statsInfo.toStdString();

    pcapWriter.close();
    return true;
}

void PacketHandler::clearPacket()
{
    this->svPackets.clear();
}

int PacketHandler::packetCount()
{
    return this->svPackets.size();
}



void PacketHandler::openPcapFile(QString fileName)
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(fileName.toStdString());
    if (reader == NULL)
    {
        std::cout << "File Open failed..";
        return;
    }
    // open the reader for reading
    if (!reader->open())
    {
        std::cout << "Cannot open input.pcap for reading" << std::endl;
        return ;
    }
    // the packet container
    pcpp::RawPacket rawPacket;

    // a while loop that will continue as long as there are packets in the input file
    // matching the BPF filter
    while (reader->getNextPacket(rawPacket))
    {
        savePacket(&rawPacket, 0);
    }
    delete reader;
}

sPacket PacketHandler::getPacket(int index)
{
    if (index > -1 && index < svPackets.size())
    {
        return svPackets[index];
    }
    return sPacket();
}

void PacketHandler::getRawPacketVector(pcpp::RawPacketVector *rpv)
{
    for (auto iter = svPackets.begin(); iter != svPackets.end(); iter++)
    {
        pcpp::RawPacket rawPacket(iter->rawPacket);
        rpv->pushBack(&rawPacket);
    }
}

void PacketHandler::getPacketInfo(pcpp::RawPacket* packet,long long time)
{
    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    pcpp::Layer* lastLayer = parsedPacket.getLastLayer();
    pcpp::EthLayer* ETHLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ETHLayer == nullptr)
    {
        std::cout << "ETH handler error!!!" <<std::endl;
        return;
    }

    /*bool ret = false;
    pcpp::Layer* _first_layer = parsedPacket.getFirstLayer();
    do {
        pcpp::ProtocolType p = _first_layer->getProtocol();
        if (pcpp::UDP == p) {
            ret = true;
        }
    } while ((_first_layer = _first_layer->getNextLayer()) != NULL);
    if (!ret) {
        return;
    }*/
    

    //获取数据的长度
    QStringList pinfo;

    //添加时间信息
    pinfo << QString::number(time) + "ms";

    pcpp::IPv4Layer* _IPLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    if (_IPLayer != nullptr)
    {
        //添加发送IP地址
        pinfo << QString(_IPLayer->getSrcIPv4Address().toString().c_str());

        //添加接收IP地址 
        pinfo << QString(_IPLayer->getDstIPv4Address().toString().c_str());
    }
    else
    {
        //添加发送IP地址
        pinfo << QString(ETHLayer->getSourceMac().toString().c_str());

        //添加接收IP地址 
        pinfo << QString(ETHLayer->getDestMac().toString().c_str());
    }


    //添加包长度
    //pcpp::Layer* LastLayer = packet.getLastLayer();
    //添加协议类型
    pinfo << QString(getStrProtocolType(lastLayer->getProtocol()).c_str());

    //添加包长度
    //pcpp::Layer* LastLayer = packet.getLastLayer();

    pinfo << QString::number(ETHLayer->getDataLen());

    //添加基本的信息
    pinfo << QString(lastLayer->toString().c_str());
    //<< "192.168.1.1" << "192.168.0.1" << "arp" << QString::number(64) << "this is a test info";
    emit PackInfo(pinfo);

}



std::string PacketHandler::getStrProtocolType(pcpp::ProtocolType p)
{
    std::string strProtocal;
    switch (p)
    {
        case pcpp::UnknownProtocol:
            strProtocal = "UnknownProtocol";
            break;
        case pcpp::Ethernet:
            strProtocal = "Ethernet";
            break;
        case pcpp::IPv4:
            strProtocal = "IPv4";
            break;
        case pcpp::IPv6:
            strProtocal = "IPv6";
            break;
        case pcpp::IP:
            strProtocal = "IP";
            break;
        case pcpp::TCP:
            strProtocal = "TCP";
            break;
        case pcpp::UDP:
            strProtocal = "UDP";
            break;
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
        case pcpp::HTTP:
            strProtocal = "HTTP";
            break;
        case pcpp::ARP:
            strProtocal = "ARP";
            break;
        case pcpp::VLAN:
            strProtocal = "VLAN";
            break;
        case pcpp::ICMP:
            strProtocal = "ICMP";
            break;
        case pcpp::PPPoESession:
            strProtocal = "PPPoESession";
            break;
        case pcpp::PPPoEDiscovery:
            strProtocal = "PPPoEDiscovery";
            break;
        case pcpp::PPPoE:
            strProtocal = "PPPoE";
            break;
        case pcpp::DNS:
            strProtocal = "DNS";
            break;
        case pcpp::MPLS:
            strProtocal = "MPLS";
            break;
        case pcpp::GREv0:
            strProtocal = "GREv0";
            break;
        case pcpp::GREv1:
            strProtocal = "GREv1";
            break;
        case pcpp::GRE:
            strProtocal = "GRE";
            break;
        case pcpp::PPP_PPTP:
            strProtocal = "PPP_PPTP";
            break;
        case pcpp::SSL:
            strProtocal = "SSL";
            break;
        case pcpp::SLL:
            strProtocal = "SLL";
            break;
        case pcpp::DHCP:
            strProtocal = "DHCP";
            break;
        case pcpp::NULL_LOOPBACK:
            strProtocal = "NULL_LOOPBACK";
            break;
        case pcpp::IGMP:
            strProtocal = "IGMP";
            break;
        case pcpp::IGMPv1:
            strProtocal = "IGMPv1";
            break;
        case pcpp::IGMPv2:
            strProtocal = "IGMPv2";
            break;
        case pcpp::IGMPv3:
            strProtocal = "IGMPv3";
            break;
        case pcpp::GenericPayload:
            strProtocal = "GenericPayload";
            break;
        case pcpp::VXLAN:
            strProtocal = "VXLAN";
            break;
        case pcpp::SIPRequest:
            strProtocal = "SIPRequest";
            break;
        case pcpp::SIPResponse:
            strProtocal = "SIPResponse";
            break;
        case pcpp::SIP:
            strProtocal = "SIP";
            break;
        case pcpp::SDP:
            strProtocal = "SDP";
            break;
        case pcpp::PacketTrailer:
            strProtocal = "PacketTrailer";
            break;
        case pcpp::Radius:
            strProtocal = "Radius";
            break;
        case pcpp::GTPv1:
            strProtocal = "GTPv1";
            break;
        case pcpp::EthernetDot3:
            strProtocal = "EthernetDot3";
            break;
        case pcpp::BGP:
            strProtocal = "BGP";
            break;
        case pcpp::SSH:
            strProtocal = "SSH";
            break;
        case pcpp::AuthenticationHeader:
            strProtocal = "AuthenticationHeader";
            break;
        case pcpp::ESP:
            strProtocal = "ESP";
            break;
        case pcpp::IPSec:
            strProtocal = "IPSec";
            break;
        case pcpp::DHCPv6:
            strProtocal = "DHCPv6";
            break;
        default:
            strProtocal = "UnknownProtocol";
            break;
    }
    return strProtocal;
}

QString PacketHandler::getIPProtocolTypes(pcpp::IPProtocolTypes p)
{
    std::string serviceTypeInfo;
    switch (p)
    {
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOPOPTS:
            serviceTypeInfo = "Dummy protocol for TCP IPv6 Hop-by-Hop options		";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_ICMP:
            serviceTypeInfo = " Internet Control Message Protocol	";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_IGMP:
            serviceTypeInfo = " Internet Gateway Management Protocol ";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_IPIP:
            serviceTypeInfo = " IPIP tunnels (older KA9Q tunnels use 94) ";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP:
            serviceTypeInfo = " Transmission Control Protocol	";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_EGP:
            serviceTypeInfo = " Exterior Gateway Protocol		";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_PUP:
            serviceTypeInfo = " PUP protocol";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP:
            serviceTypeInfo = " User Datagram Protocol		";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_IDP:
            serviceTypeInfo = " XNS IDP protocol			";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_IPV6:
            serviceTypeInfo = " IPv6 header";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_ROUTING:
            serviceTypeInfo = " IPv6 Routing header			";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_FRAGMENT:
            serviceTypeInfo = " IPv6 fragmentation header		";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_GRE:
            serviceTypeInfo = " GRE protocol ";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_ESP:
            serviceTypeInfo = " encapsulating security payload	";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_AH:
            serviceTypeInfo = " authentication header		";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_ICMPV6:
            serviceTypeInfo = " ICMPv6";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NONE:
            serviceTypeInfo = " IPv6 no next header			";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_DSTOPTS:
            serviceTypeInfo = " IPv6 Destination options		";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_RAW:
            serviceTypeInfo = " Raw IP packets			";
            break;
        case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_MAX:
            serviceTypeInfo = " Maximum value ";
            break;
        default:
            break;
    }
    		
    return QString(serviceTypeInfo.c_str());
}

void PacketHandler::addSubItems(QStandardItem* parentItem, const QString ItemTips, const QString ItemData)
{
    if (parentItem == nullptr)
    {
        return;
    }
    QStandardItem* siTips = new QStandardItem(ItemTips);
    QStandardItem* siData = new QStandardItem(ItemData);
    parentItem->appendRow(QList<QStandardItem*>() << siTips << siData);
}

void PacketHandler::LayerHandler(const pcpp::ArpLayer* pARPLayer, QList<QStandardItem*>* Items)
{
    //  ARP包的处理顺序
   //  ARP包是最底层的包，直接解析就可以了。
   //  获取当前层，直接获取ARP层

    // 显示基本的信息
    pcpp::ProtocolType pType = pARPLayer->getProtocol();
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pType).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pARPLayer->toString().c_str()));

    addSubItems(siLayerType, QString("Header Length:"), QString("%1").arg(pARPLayer->getHeaderLen()));

    //todo:ARP包头的十六进制数据 
    //构造包头十六进制字符串,将包头中的数据取出，构造一个十六进制字符串进行显示
    // 
    // 
    // ARP包的类型
    QString arpType = "";
    if (ntohs(pARPLayer->getArpHeader()->opcode) == pcpp::ARP_REQUEST)
    {
        arpType = QString("ARP request");
    }
    else
    {
        arpType = QString("ARP replay");

    }

    addSubItems(siLayerType, QString("ARPType:"), arpType);
    // ARP包源MAC地址
    addSubItems(siLayerType, QString("src mac:"), QString("%1").arg(pARPLayer->getSenderMacAddress().toString().c_str()));
    
    addSubItems(siLayerType, QString("target mac:"), QString("%1").arg(pARPLayer->getTargetMacAddress().toString().c_str()));

    // ARP要解析的IP地址

    addSubItems(siLayerType, QString("src IP:"), QString("%1").arg(pARPLayer->getSenderIpAddr().toString().c_str()));
    addSubItems(siLayerType, QString("target IP:"), QString("%1").arg(QString("%1").arg(pARPLayer->getTargetIpAddr().toString().c_str())));

    // ARP 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pARPLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pARPLayer->getData(), pARPLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::IcmpLayer* pIcmpLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pIcmpLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pIcmpLayer->toString().c_str()));
    
    //icmp头消息
    pcpp::icmphdr* pIcmpHdr = pIcmpLayer->getIcmpHeader();
    addSubItems(siLayerType, QString("Message Type:"), QString("%1").arg(ntohs(pIcmpHdr->type)));
    addSubItems(siLayerType, QString("Message Code:"), QString("%1").arg(ntohs(pIcmpHdr->code)));
    addSubItems(siLayerType, QString("Message checksum:"), QString("0x%1").arg(QString::number(ntohs(pIcmpHdr->checksum),16).toUpper()));

    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pIcmpLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pIcmpLayer->getData(), pIcmpLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::DnsLayer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));


    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::TcpLayer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));
    /*
    uint16_t portSrc;// Source TCP port
    uint16_t portDst;// Destination TCP port 
    uint32_t sequenceNumber;// Sequence number 
    uint32_t ackNumber;// Acknowledgment number 
    uint16_t reserved : 4,
    dataOffset : 4,// Specifies the size of the TCP header in 32-bit words 
    finFlag : 1,// FIN flag 
    synFlag : 1,// SYN flag 
    rstFlag : 1,// RST flag 
    pshFlag : 1,// PSH flag 
    ackFlag : 1,// ACK flag 
    urgFlag : 1,// URG flag 
    eceFlag : 1,// ECE flag 
    cwrFlag : 1;// CWR flag
    uint16_t	windowSize;// The size of the receive window, which specifies the number of window size units (by default, bytes) 
    uint16_t	headerChecksum;// The 16-bit checksum field is used for error-checking of the header and data 
    uint16_t	urgentPointer;// If the URG flag (@ref tcphdr#urgFlag) is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte 
    */

    pcpp::tcphdr* tcpHeader = pLayer->getTcpHeader();
    addSubItems(siLayerType, QString("Source TCP port:"), QString("%1").arg(ntohs(tcpHeader->portSrc)));
    addSubItems(siLayerType, QString("Destination TCP port:"), QString("%1").arg(ntohs(tcpHeader->portDst)));
    addSubItems(siLayerType, QString("Sequence number :"), QString("%1").arg(ntohs(tcpHeader->sequenceNumber)));
    addSubItems(siLayerType, QString("Acknowledgment number :"), QString("%1").arg(ntohs(tcpHeader->ackNumber)));
    
    addSubItems(siLayerType, QString("Flags:"), QString("SYN:%1,SYN:%2,RST:%3,PSH:%4,ACK:%5,URG:%6,ECE:%7,CWR:%8")
                                                        .arg(ntohs(tcpHeader->finFlag))
                                                        .arg(ntohs(tcpHeader->synFlag))
                                                        .arg(ntohs(tcpHeader->rstFlag))
                                                        .arg(ntohs(tcpHeader->pshFlag))
                                                        .arg(ntohs(tcpHeader->ackFlag))
                                                        .arg(ntohs(tcpHeader->urgFlag))
                                                        .arg(ntohs(tcpHeader->eceFlag))
                                                        .arg(ntohs(tcpHeader->cwrFlag))
                                                        );
    addSubItems(siLayerType, QString("receive window size:"), QString("%1").arg(ntohs(tcpHeader->windowSize)));
    addSubItems(siLayerType, QString("header Checksum:"), QString("0x%1").arg(QString::number(ntohs(tcpHeader->headerChecksum),16).toUpper()));



    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()));
    
    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::UdpLayer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));

    /*		
    uint16_t portSrc;// Source port
    uint16_t portDst;// Destination port
    uint16_t length;// Length of header and payload in bytes
    uint16_t headerChecksum;//  Error-checking of the header and data
*/
    pcpp::udphdr* udpHeader = pLayer->getUdpHeader();
    addSubItems(siLayerType, QString("Source UDP port:"), QString("%1").arg(ntohs(udpHeader->portSrc)));
    addSubItems(siLayerType, QString("Destination UDP port:"), QString("%1").arg(ntohs(udpHeader->portDst)));
    addSubItems(siLayerType, QString("Length:"), QString("%1").arg(ntohs(udpHeader->length)));
    addSubItems(siLayerType, QString("headerChecksum:"), QString("0x%1").arg(QString::number(ntohs(udpHeader->headerChecksum),16).toUpper()));

    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::HttpRequestLayer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));
    


    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(std::string((char*)pLayer->getData(), pLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::HttpResponseLayer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));

    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
   // addSubItems(siLayerType, QString("Data:"), QString("0x%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(std::string((char*)pLayer->getData(), pLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::SSLLayer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));

    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::IPv4Layer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));

    // ip头处理
    /*  uint8_t 	internetHeaderLength : 4
        uint8_t 	ipVersion : 4
        uint8_t 	typeOfService
        uint16_t 	totalLength
        uint16_t 	ipId
        uint16_t 	fragmentOffset
        uint8_t 	timeToLive
        uint8_t 	protocol
        uint16_t 	headerChecksum
        uint32_t 	ipSrc
        uint32_t 	ipDst
       */
    pcpp::iphdr* ipHeader = pLayer->getIPv4Header();
    addSubItems(siLayerType, QString("internetHeaderLength:"),QString("%1").arg(ipHeader->internetHeaderLength));
    addSubItems(siLayerType, QString("IpVersion:"),QString("%1").arg(ipHeader->ipVersion));
    addSubItems(siLayerType, QString("typeOfService:"),QString("0x%1").arg(pcpp::byteArrayToHexString(&ipHeader->typeOfService, 1).c_str()).toUpper());
    addSubItems(siLayerType, QString("TotalLength:"),QString("%1").arg(ipHeader->totalLength));
    addSubItems(siLayerType, QString("IP Identification Field:"),QString("0X%1").arg(QString::number(ipHeader->ipId, 16)).toUpper());
   /* addSubItems(siLayerType, QString("fragmentOffset:"),QString("0x%1").arg(QString::number(be16toh(ipHeader->fragmentOffset & (uint16_t)0xFF1F) * 8, 16).toUpper()));*/
    addSubItems(siLayerType, QString("timeToLive:"),QString("%1").arg(QString::number(ipHeader->timeToLive)));
    addSubItems(siLayerType, QString("protocol:"), QString("%1").arg(getIPProtocolTypes(pcpp::IPProtocolTypes(ipHeader->protocol))));
    addSubItems(siLayerType, QString("headerChecksum:"),QString("%1").arg(QString::number(ipHeader->headerChecksum, 16)));

    // 数据的处理

    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));

    addSubItems(siLayerType, QString("Data:"), QString("0x%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()).toUpper());

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::IPv6Layer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));

    /*
    *   uint8_t trafficClass:4, 			// Traffic class 
    *   ipVersion:4; 			// IP version number, has the value of 6 for IPv6 
        uint8_t flowLabel[3]; 			// Flow label 
        uint16_t payloadLength; 			// The size of the payload in octets, including any extension headers 
        uint8_t nextHeader; 			// Specifies the type of the next header (protocol). Must be one of ::IPProtocolTypes 
        uint8_t hopLimit; 			// Replaces the time to live field of IPv4 
        uint8_t ipSrc[16]; 			// Source address 
        uint8_t ipDst[16]; 			// Destination address 
    */
    pcpp::ip6_hdr* ip6Header = pLayer->getIPv6Header();
    addSubItems(siLayerType, QString("Traffic class :"), QString("%1").arg(ip6Header->trafficClass));
    addSubItems(siLayerType, QString("IP version :"), QString("%1").arg(ip6Header->ipVersion));
    addSubItems(siLayerType, QString("Flow label :"), QString("0x%1").arg(pcpp::byteArrayToHexString(ip6Header->flowLabel,3).c_str()).toUpper());
    addSubItems(siLayerType, QString("Payload length :"), QString("%1").arg(ip6Header->payloadLength));
    addSubItems(siLayerType, QString("Next header(protocol):"), QString("0x%1").arg(getIPProtocolTypes(pcpp::IPProtocolTypes(ip6Header->nextHeader))));
    addSubItems(siLayerType, QString("Hop Limit :"), QString("%1").arg(ip6Header->hopLimit));


        // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("0x%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()).toUpper());

    Items->append(siLayerType);
    Items->append(siLayerInfo);
}

void PacketHandler::LayerHandler(const pcpp::EthLayer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));



    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);
    
}
void PacketHandler::LayerHandler(const pcpp::Layer* pLayer, QList<QStandardItem*>* Items)
{
    // 显示基本的信息
    QStandardItem* siLayerType = new QStandardItem(QString(getStrProtocolType(pLayer->getProtocol()).c_str()));
    QStandardItem* siLayerInfo = new QStandardItem(QString(pLayer->toString().c_str()));

    // 数据的处理
    addSubItems(siLayerType, QString("Data Length:"), QString("%1").arg(pLayer->getDataLen()));
    addSubItems(siLayerType, QString("Data:"), QString("%1").arg(pcpp::byteArrayToHexString(pLayer->getData(), pLayer->getDataLen()).c_str()));

    Items->append(siLayerType);
    Items->append(siLayerInfo);

}
