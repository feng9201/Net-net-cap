#pragma once

#include <vector>
#include <iostream>
#include <mutex>
#include <ctime>
#include <QtWidgets/QMainWindow>
#include <QMap>
#include <QColor>
#include <QFileDialog>
#include <QBrush>
#include <QTreeWidgetItem> 
#include <QStandardItemModel>
#include <qmessagebox.h>
#include "ui_MyNetDump.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"
#include "PcapFileDevice.h"

#include "PacketHandler.h"
#include "TimerCounter.h"
#include "common.h"

struct PacketStats
{
	int ethPacketCount;
	int ipv4PacketCount;
	int ipv6PacketCount;
	int tcpPacketCount;
	int udpPacketCount;
	int dnsPacketCount;
	int httpPacketCount;
	int sslPacketCount;


	/**
	 * Clear all stats
	 */
	void clear() { ethPacketCount = 0; ipv4PacketCount = 0; ipv6PacketCount = 0; tcpPacketCount = 0; udpPacketCount = 0; tcpPacketCount = 0; dnsPacketCount = 0; httpPacketCount = 0; sslPacketCount = 0; }

	/**
	 * C'tor
	 */
	PacketStats() { clear(); }

	/**
	 * Collect stats from a packet
	 */
	void consumePacket(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethPacketCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipv4PacketCount++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ipv6PacketCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpPacketCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpPacketCount++;
		if (packet.isPacketOfType(pcpp::DNS))
			dnsPacketCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL))
			sslPacketCount++;
	}

	/**
	 * Print stats to console
	 */
	void printToConsole()
	{
		std::cout
			<< "Ethernet packet count: " << ethPacketCount << std::endl
			<< "IPv4 packet count:     " << ipv4PacketCount << std::endl
			<< "IPv6 packet count:     " << ipv6PacketCount << std::endl
			<< "TCP packet count:      " << tcpPacketCount << std::endl
			<< "UDP packet count:      " << udpPacketCount << std::endl
			<< "DNS packet count:      " << dnsPacketCount << std::endl
			<< "HTTP packet count:     " << httpPacketCount << std::endl
			<< "SSL packet count:      " << sslPacketCount << std::endl;
	}
};




class MyNetDump : public QMainWindow
{
    Q_OBJECT

public:
    MyNetDump(QWidget *parent = Q_NULLPTR);

    void test();

    //��ʼ���豸�б�
    void initDevices();

    //��ʼ���˵�
    void initMenu();

    //��ʼ�����н���
    void initWidget();

    //��ʼ�����Ӻ���
    void initConnect();

	//��ʼ����Ӧ����ɫ����
	void initColors();

    //ѡ������
    void selectNIC(int index = 0);

    //��ʼץ��
    void startPcap();

	//ֹͣץ��
	void stopPcap();

	//���ݰ����� 
	void analysisPacket(int,int);

	//�������ݰ�
	void savePacket();

	//�������
	//����ؼ��뱣������ݰ�
	void clearData();

	void openFile();

	//��ʾʮ�������ַ���
	void displayHexString(QString hexStr);

	//���ڹر��¼�
	void closeEvent(QCloseEvent* event);

	//�������Ϣ
	static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);


	//ʶ��Э��
	QString getProtocolTypeAsString(pcpp::ProtocolType protocolType);

	
	//��ʱ������
	static TimerCounter tCounter;

public slots:
	void showTable(QStringList PackInfo);	//������Ϣ

private:
    void getDeviceList();

private:
    Ui::MyNetDumpClass ui;
    std::vector<pcpp::PcapLiveDevice* > allDevices;
    pcpp::PcapLiveDevice*  SelectedDevices;
	bool isColorful = false;
	QMap<QString, QColor> mapColors;
	// ����һ�����������
	PacketHandler* hr_Packet;

	//ֹͣ��־ 
	bool isStop = true;

	//���̲߳�����
	std::mutex mtx;

	//���濪ʼʱ��
	time_t startTime;

	

};
