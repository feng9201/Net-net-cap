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
	//����arp���ݰ�
	void LayerHandler(const pcpp::ArpLayer* pLayer, QList<QStandardItem*>* Items);

	//����ICMP���ݰ�
	void LayerHandler(const pcpp::IcmpLayer* pLayer, QList<QStandardItem*>* Items);

	//����DNS���ݰ�
	void LayerHandler(const pcpp::DnsLayer* pLayer, QList<QStandardItem*>* Items);

	//����TCP���ݰ�
	void LayerHandler(const pcpp::TcpLayer* pLayer, QList<QStandardItem*>* Items);

	//����UDP���ݰ�
	void LayerHandler(const pcpp::UdpLayer* pLayer, QList<QStandardItem*>* Items);

	//����HTTP���ݰ�
	void LayerHandler(const pcpp::HttpRequestLayer* pLayer, QList<QStandardItem*>* Items);
	//����HTTP���ݰ�
	void LayerHandler(const pcpp::HttpResponseLayer* pLayer, QList<QStandardItem*>* Items);

	//����SSL���ݰ�
	void LayerHandler(const pcpp::SSLLayer* pLayer, QList<QStandardItem*>* Items);

	//����IPv4���ݰ�
	void LayerHandler(const pcpp::IPv4Layer* pLayer, QList<QStandardItem*>* Items);

	//����IPv6���ݰ�
	void LayerHandler(const pcpp::IPv6Layer* pLayer, QList<QStandardItem*>* Items);

	//����Ethnet���ݰ�
	void LayerHandler(const pcpp::EthLayer* pLayer, QList<QStandardItem*>* Items);

	//����δ֪������
	void LayerHandler(const pcpp::Layer* pLayer, QList<QStandardItem*>* Items);
	

	//����ԭʼ���ݰ�
	void savePacket(pcpp::RawPacket* packet,long long time);

	//���浽һ���ļ� 
	bool savePacketToFile(QString fileName);

	//���ԭʼ���ݰ�
	void clearPacket();

	//��ȡ�������ݰ������� 
	int packetCount();
	
	//��һ���ļ�
	void openPcapFile(QString fileName);
	//��ȡ��ǰ��������ݰ�
	sPacket getPacket(int index);

	void getRawPacketVector(pcpp::RawPacketVector *rpv);
	//��ȡ��������Ϣ
	void getPacketInfo(pcpp::RawPacket* packet,long long time);

	//��ȡ�ַ������͵�Э��
	std::string getStrProtocolType(pcpp::ProtocolType p);

private:
	QString getIPProtocolTypes(pcpp::IPProtocolTypes p);

	//��һ���ڵ����һ���ӽڵ�
	void addSubItems(QStandardItem* parentItem,const QString ItemTips,const QString ItemData);
private:
	std::vector<sPacket> svPackets;
};

#endif // !PACKET_HANDLER