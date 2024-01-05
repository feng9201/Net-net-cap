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

    //初始化设备列表
    void initDevices();

    //初始化菜单
    void initMenu();

    //初始化运行界面
    void initWidget();

    //初始化连接函数
    void initConnect();

	//初始化对应的颜色属性
	void initColors();

    //选择网卡
    void selectNIC(int index = 0);

    //开始抓包
    void startPcap();

	//停止抓包
	void stopPcap();

	//数据包分析 
	void analysisPacket(int,int);

	//保存数据包
	void savePacket();

	//清除数据
	//清除控件与保存的数据包
	void clearData();

	void openFile();

	//显示十六进制字符串
	void displayHexString(QString hexStr);

	//窗口关闭事件
	void closeEvent(QCloseEvent* event);

	//处理包信息
	static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);


	//识别协议
	QString getProtocolTypeAsString(pcpp::ProtocolType protocolType);

	
	//计时器对象
	static TimerCounter tCounter;

public slots:
	void showTable(QStringList PackInfo);	//数据信息

private:
    void getDeviceList();

private:
    Ui::MyNetDumpClass ui;
    std::vector<pcpp::PcapLiveDevice* > allDevices;
    pcpp::PcapLiveDevice*  SelectedDevices;
	bool isColorful = false;
	QMap<QString, QColor> mapColors;
	// 创建一个包处理对象
	PacketHandler* hr_Packet;

	//停止标志 
	bool isStop = true;

	//多线程操作锁
	std::mutex mtx;

	//保存开始时间
	time_t startTime;

	

};
