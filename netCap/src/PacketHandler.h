#ifndef PACKET_HANDLER
#define PACKET_HANDLER

#include <sstream>
#include <iostream>
#include <string>
#include "Packet.h"
#include "DnsLayer.h"
#include "ArpLayer.h"
#include "IcmpLayer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "HttpLayer.h"
#include "SslLayer.h"
#include "IPv6Layer.h"
#include "EthLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
//#include "EndianPortable.h"
#include <QtWidgets/QMainWindow>
#include <QStandardItem>
#include <QList>
#include <qobject.h>
#include "common.h"


class PacketHandler :public QObject
{ 
	Q_OBJECT

signals:
	void PackInfo(QStringList info);

public:
	//处理arp数据包
	void LayerHandler(const pcpp::ArpLayer* pLayer, QList<QStandardItem*>* Items);

	//处理ICMP数据包
	void LayerHandler(const pcpp::IcmpLayer* pLayer, QList<QStandardItem*>* Items);

	//处理DNS数据包
	void LayerHandler(const pcpp::DnsLayer* pLayer, QList<QStandardItem*>* Items);

	//处理TCP数据包
	void LayerHandler(const pcpp::TcpLayer* pLayer, QList<QStandardItem*>* Items);

	//处理UDP数据包
	void LayerHandler(const pcpp::UdpLayer* pLayer, QList<QStandardItem*>* Items);

	//处理HTTP数据包
	void LayerHandler(const pcpp::HttpRequestLayer* pLayer, QList<QStandardItem*>* Items);
	//处理HTTP数据包
	void LayerHandler(const pcpp::HttpResponseLayer* pLayer, QList<QStandardItem*>* Items);

	//处理SSL数据包
	void LayerHandler(const pcpp::SSLLayer* pLayer, QList<QStandardItem*>* Items);

	//处理IPv4数据包
	void LayerHandler(const pcpp::IPv4Layer* pLayer, QList<QStandardItem*>* Items);

	//处理IPv6数据包
	void LayerHandler(const pcpp::IPv6Layer* pLayer, QList<QStandardItem*>* Items);

	//处理Ethnet数据包
	void LayerHandler(const pcpp::EthLayer* pLayer, QList<QStandardItem*>* Items);

	//处理未知的数据
	void LayerHandler(const pcpp::Layer* pLayer, QList<QStandardItem*>* Items);
	

	//保存原始数据包
	void savePacket(pcpp::RawPacket* packet,long long time);

	//保存到一个文件 
	bool savePacketToFile(QString fileName);

	//清空原始数据包
	void clearPacket();

	//获取保存数据包的数量 
	int packetCount();
	
	//打开一个文件
	void openPcapFile(QString fileName);
	//获取当前保存的数据包
	sPacket getPacket(int index);

	void getRawPacketVector(pcpp::RawPacketVector *rpv);
	//获取基本的信息
	void getPacketInfo(pcpp::RawPacket* packet,long long time);

	//获取字符串类型的协议
	std::string getStrProtocolType(pcpp::ProtocolType p);

private:
	QString getIPProtocolTypes(pcpp::IPProtocolTypes p);

	//给一个节点添加一个子节点
	void addSubItems(QStandardItem* parentItem,const QString ItemTips,const QString ItemData);
private:
	std::vector<sPacket> svPackets;
};

#endif // !PACKET_HANDLER