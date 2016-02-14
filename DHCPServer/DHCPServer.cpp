// DHCPServer.cpp : 定義主控台應用程式的進入點。
//

#include "stdafx.h"
#include <conio.h>
#include <winsock2.h>
#include <thread>
#include <unordered_map>
#include <iphlpapi.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")

#define DHCP_MAGIC_COOKIE 0x63825363
#define Nomal_Debug 1
#define Super_Debug 2


// struct define
enum DHCPOptionEnum {
	SUBNETMASK = 1,
	TIMEOFFSET = 2,
	ROUTER = 3,
	TIMESERVER = 4,
	NAMESERVER = 5,
	DOMAINNAMESERVER = 6,
	LOGSERVER = 7,
	COOKIESERVER = 8,
	LPRSERVER = 9,
	IMPRESSSERVER = 10,
	RESOURCELOCSERVER = 11,
	HOSTNAME = 12,
	BOOTFILESIZE = 13,
	MERITDUMP = 14,
	DOMAINNAME = 15,
	SWAPSERVER = 16,
	ROOTPATH = 17,
	EXTENSIONSPATH = 18,
	IPFORWARDING = 19,
	NONLOCALSOURCEROUTING = 20,
	POLICYFILTER = 21,
	MAXIMUMDATAGRAMREASSEMBLYSIZE = 22,
	DEFAULTIPTIMETOLIVE = 23,
	PATHMTUAGINGTIMEOUT = 24,
	PATHMTUPLATEAUTABLE = 25,
	INTERFACEMTU = 26,
	ALLSUBNETSARELOCAL = 27,
	BROADCASTADDRESS = 28,
	PERFORMMASKDISCOVERY = 29,
	MASKSUPPLIER = 30,
	PERFORMROUTERDISCOVERY = 31,
	ROUTERSOLICITATIONADDRESS = 32,
	STATICROUTE = 33,
	TRAILERENCAPSULATION = 34,
	ARPCACHETIMEOUT = 35,
	ETHERNETENCAPSULATION = 36,
	TCPDEFAULTTTL = 37,
	TCPKEEPALIVEINTERVAL = 38,
	TCPKEEPALIVEGARBAGE = 39,
	NETWORKINFORMATIONSERVICEDOMAIN = 40,
	NETWORKINFORMATIONSERVERS = 41,
	NETWORKTIMEPROTOCOLSERVERS = 42,
	VENDORSPECIFICINFORMATION = 43,
	NETBIOSOVERTCPIPNAMESERVER = 44,
	NETBIOSOVERTCPIPDATAGRAMDISTRIBUTIONSERVER = 45,
	NETBIOSOVERTCPIPNODETYPE = 46,
	NETBIOSOVERTCPIPSCOPE = 47,
	XWINDOWSYSTEMFONTSERVER = 48,
	XWINDOWSYSTEMDISPLAYMANAGER = 49,
	REQUESTEDIPADDRESS = 50,
	IPADDRESSLEASETIME = 51,
	OPTIONOVERLOAD = 52,
	DHCPMESSAGETYPE = 53,
	SERVERIDENTIFIER = 54,
	PARAMETERREQUESTLIST = 55,
	MESSAGE = 56,
	MAXIMUMDHCPMESSAGESIZE = 57,
	RENEWALTIMEVALUE_T1 = 58,
	REBINDINGTIMEVALUE_T2 = 59,
	VENDORCLASSIDENTIFIER = 60,
	CLIENTIDENTIFIER = 61,
	NETWORKINFORMATIONSERVICEPLUSDOMAIN = 64,
	NETWORKINFORMATIONSERVICEPLUSSERVERS = 65,
	TFTPSERVERNAME = 66,
	BOOTFILENAME = 67,
	MOBILEIPHOMEAGENT = 68,
	SMTPSERVER = 69,
	POP3SERVER = 70,
	NNTPSERVER = 71,
	DEFAULTWWWSERVER = 72,
	DEFAULTFINGERSERVER = 73,
	DEFAULTIRCSERVER = 74,
	STREETTALKSERVER = 75,
	STDASERVER = 76,
	END_OPTION = 255
};
enum DHCPMessageType {
	DHCPDISCOVER=1,
	DHCPOFFER=2,
	DHCPREQUEST=3,
	DHCPDECLINE=4,
	DHCPACK=5,
	DHCPNAK=6,
	DHCPRELEASE=7,
	DHCPINFORM=8
};
struct DHCP_PACKET { // Max 548Byte
	byte OP;
	byte HTYPE;
	byte HLEN;
	byte HOPS;
	UINT32 TRANSACTION_ID;
	UINT16 SECONDS;
	UINT16 FLAGS;
	byte ciaddr[4];
	byte yiaddr[4];
	byte siaddr[4];
	byte giaddr[4];
	byte chaddr[16];
	byte sname[64];
	byte file[128];
	UINT32 magicCode;
	byte Options[308];
};
struct Packet_Information{
	char HostName[256];
	USHORT BootFileSize;
	char MeritDumpFile[256];
	byte DHCPMessageType;
	int IPLeaseTime; // for client
	byte ServerIdentifier[4]; // for client
	byte ClientIdentifier[4]; 
	byte ParameterRequestList[256];
	byte VendorClassIdentifier[256];
	byte RequestedIPAddress[4];
	byte Unsupport[256];
	bool OptionToReplay[256];
};

// function define
bool DHCP( DHCP_PACKET dhcp);
void OptionParser( byte * optionarray, Packet_Information * packInfo );
void prettyDebug(DHCP_PACKET dhcp);
void ClientListen( ULONG zz123 );
int OptionMaker( byte * ReplayOption, Packet_Information * packInfo );
void ParserAnsiTypeOption(byte opt, byte * OptionArray, int len, const char * name,  void * retarray) ;
void ParserByteTypeOption(byte opt, byte * OptionArray, int len, const char * name, byte * retarray) ;
void ParserAddressTypeOption(byte opt, byte * OptionArray, int len, const char * name, byte * retarray) ;
void ParserIntTypeOption(byte opt, byte * OptionArray, int len, const char * name, void * retarray) ;
void byteToHexStr( byte * in, char * out, int size  ){
	int current = 0;
	out[0] = 0;
	while ( current < size ){
		sprintf(out, "%s%02X ",out, in[current++]);
	}
}
int ChangeEndian( int var) {
	return (var&0xFF)<<24 | (var&0xFF00)<<8 | (var&0xFF0000)>>8 | (var&0xFF000000)>>24;
}
int ByteOptionWriter(byte opt, byte * retOptionArray, int len, void * inputarray);

int AnsiOptionWriter(byte opt, byte * retOptionArray, int len, void * inputarray);

int AddressOptionWriter(byte opt, byte * retOptionArray, int len, byte * inputarray);

// gobal define
int gDebug = 0;
byte gSubMask[4] = {255,255,255,0};
byte gRouter[4] = {192,168,1,254};
byte gDomainName[] = "www.darkautism.com";
byte gDomainNameServer[4] = {8,8,8,8};
byte gMyIP[4] = {192,168,56,101};
int gLeaseTime = 7200; // 預設2hr
std::tr1::unordered_map<int,int> gIPList;
std::tr1::unordered_map<int,int> gSessionList;


int GetIpFromTable( int session ) {
	if ( gSessionList.find(session) == gSessionList.end() ) { // no find key, it is new session
		for ( int i = 0 ; i < 256 ; i++  ) {
			if ( gIPList.find(session) == gIPList.end() ) { // no find key, it is new IP can use
				gSessionList[session] = i;
				gIPList[i] = session;
				return i;
			}
		}
	} else {
		return gSessionList[session];
	}
	return -1;
}


int _tmain(int argc, _TCHAR* argv[]) {
	// =================取得網路卡資訊=========================
	// 取得網路卡資訊要多長的大小存放
	ULONG outBufLen = 0; 
	GetAdaptersInfo(NULL,&outBufLen);

	PIP_ADAPTER_INFO gPIpAdapterInfo = (PIP_ADAPTER_INFO) malloc(outBufLen); 
	GetAdaptersInfo( gPIpAdapterInfo,&outBufLen);
	PIP_ADAPTER_INFO AdapterWalker = gPIpAdapterInfo;

	for ( int i = 1 ; AdapterWalker ; i++) {
		printf ("(%d) %s %s\n", i, AdapterWalker->AdapterName, AdapterWalker->Description);
		printf (" *MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", AdapterWalker->Address[0], AdapterWalker->Address[1], AdapterWalker->Address[2],
			AdapterWalker->Address[3], AdapterWalker->Address[4], AdapterWalker->Address[5]);
		IP_ADDR_STRING *pIpAddrString =&(AdapterWalker->IpAddressList);
		do  {
			printf (" *IP: %s\n *Subnet Mask: %s\n *Gateway: %s\n", 
				pIpAddrString->IpAddress.String, pIpAddrString->IpMask.String, AdapterWalker->GatewayList.IpAddress.String);
			pIpAddrString=pIpAddrString->Next;
		} while (pIpAddrString);
		AdapterWalker = AdapterWalker->Next;
	}

	ULONG bindInterfaceAddress = 0;
	do {
		printf("Choose which network interface you wanna to bind:");
		byte num = _getch() - '0';
		printf("Choose which network interface you wanna to bind:\n");
		AdapterWalker = gPIpAdapterInfo;
		for ( int i = 1 ; AdapterWalker && (!bindInterfaceAddress) ; i++ ) {
			if ( num == i ) {
				bindInterfaceAddress = inet_addr( AdapterWalker->IpAddressList.IpAddress.String );
			}
			AdapterWalker = AdapterWalker->Next;
		}
	} while ( !bindInterfaceAddress ) ;

	memcpy(gMyIP, &bindInterfaceAddress, 4);
	memcpy(gRouter, &bindInterfaceAddress, 4); // 設一樣

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		printf("Socket init failed.\n");
		return WSAGetLastError();
	}

	SOCKET m_socket;
	m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (m_socket == INVALID_SOCKET) {
		printf("Connect error : %ld\n", WSAGetLastError());
		WSACleanup();
		return WSAGetLastError();
	}

	bool optval=true; 
	if ( setsockopt(m_socket,SOL_SOCKET,SO_BROADCAST,(char*)&optval,sizeof(bool)) == -1 )  
		printf("Can't broadcast.");


	SOCKADDR_IN broadcast; 
	broadcast.sin_family=AF_INET; 
	broadcast.sin_port=htons(68); 
	inet_pton(AF_INET, "255.255.255.255", &broadcast.sin_addr); // Set the broadcast IP address
	// broadcast.sin_addr.s_addr=INADDR_BROADCAST ;

	SOCKADDR_IN reciver; 
	int senferAddSize=sizeof(reciver); 
	reciver.sin_family=AF_INET; 
	reciver.sin_port=htons(67); 
	reciver.sin_addr.s_addr= bindInterfaceAddress; // htonl(INADDR_ANY);
	bind(m_socket,(SOCKADDR*)&reciver,sizeof(reciver));


	printf("Waiting...\n");


	std::thread mThread( ClientListen, bindInterfaceAddress );

	Packet_Information pakInfo;
	byte ReplayOption[308];
	char strbuf[1645]; // 548*3+1
	int getbytes, id;
	char * tmp;
	while (true) {
		DHCP_PACKET dhcp;
		memset(&dhcp, 0, 548);
		getbytes = recvfrom(m_socket, (char*)&dhcp, 548, 0, (struct sockaddr*) &reciver, &senferAddSize) ;
		if (getbytes >=0) {
			printf("[%s/%d] Connected.\n", inet_ntoa(reciver.sin_addr), htons(reciver.sin_port));
			byte * optionarray = dhcp.Options;
			memset(ReplayOption, 0, 308);
			// prettyDebug( dhcp);
			// ========================== Init ===========================
			bool end = false;
			int ReplayOptionWalker = 0;
			memset( &pakInfo, 0, sizeof(pakInfo));
			printf( "OP:%d\n", dhcp.OP );
			printf( "ciaddr:%d.%d.%d.%d\n", dhcp.ciaddr[0], dhcp.ciaddr[1], dhcp.ciaddr[2], dhcp.ciaddr[3] );
			printf( "yiaddr:%d.%d.%d.%d\n", dhcp.yiaddr[0], dhcp.yiaddr[1], dhcp.yiaddr[2], dhcp.yiaddr[3] );
			printf( "siaddr:%d.%d.%d.%d\n", dhcp.siaddr[0], dhcp.siaddr[1], dhcp.siaddr[2], dhcp.siaddr[3] );
			printf( "giaddr:%d.%d.%d.%d\n", dhcp.giaddr[0], dhcp.giaddr[1], dhcp.giaddr[2], dhcp.giaddr[3] );
			// ===================== parser Option =======================
			OptionParser( dhcp.Options, &pakInfo );

			// 製作Option
			for (int i = 0 ; pakInfo.ParameterRequestList[i] ; i++) {
				pakInfo.OptionToReplay[pakInfo.ParameterRequestList[i]] = true;
			}
			// default Server Option
			pakInfo.OptionToReplay[DHCPMESSAGETYPE] = true;
			pakInfo.OptionToReplay[SERVERIDENTIFIER] = true;
			pakInfo.OptionToReplay[IPADDRESSLEASETIME] = true;
			pakInfo.OptionToReplay[DOMAINNAME] = true;
			pakInfo.OptionToReplay[SUBNETMASK] = true;
			pakInfo.OptionToReplay[ROUTER] = true;
			pakInfo.OptionToReplay[DOMAINNAMESERVER] = true;

			ReplayOptionWalker += OptionMaker( ReplayOption+ReplayOptionWalker, &pakInfo);

			// END
			ReplayOption[ReplayOptionWalker++] = 0xFF;

			// 製作封包
			dhcp.OP = 2;
			memset( dhcp.ciaddr, 0, 4); // 設為0
			memcpy( dhcp.yiaddr, gMyIP, 3);
			dhcp.yiaddr[3] = GetIpFromTable( dhcp.TRANSACTION_ID );
			dhcp.FLAGS = 0;
			dhcp.SECONDS = 0;
			memcpy( dhcp.Options, ReplayOption, ReplayOptionWalker);

			if ( sendto(m_socket,(char*)&dhcp, 548, 0, (SOCKADDR*)&broadcast,sizeof(SOCKADDR)) <0) {
				printf(" *Error to Send:%d\n", GetLastError());
			}

			if(gDebug) {
				byteToHexStr((byte*) &dhcp, strbuf, getbytes  );
				printf("[Chunk Debug]\n%s/%d\n", strbuf, getbytes);
			} 
			printf("\n");
		} 
	} 
	free(gPIpAdapterInfo);
	WSACleanup();
	return 0;
}

void OptionParser( byte * optionarray, Packet_Information * packInfo ){
	bool end = false;
	while (optionarray[0] && !end) {
		short len = optionarray[1];
		switch ( optionarray[0] ) {
		case 0:
			len = -1; // 只去除該padding
			break;
		case SUBNETMASK : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Subnet Mask", packInfo->Unsupport);
			break;
		case TIMEOFFSET : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Time Offset", packInfo->Unsupport);
			break;
		case ROUTER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Router", packInfo->Unsupport);
			break;
		case TIMESERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Time Server", packInfo->Unsupport);
			break;
		case NAMESERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Name Server", packInfo->Unsupport);
			break;
		case DOMAINNAMESERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Domain Name Server", packInfo->Unsupport);
			break;
		case LOGSERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Log Server", packInfo->Unsupport);
			break;
		case COOKIESERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Cookie Server", packInfo->Unsupport);
			break;
		case LPRSERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "LPR Server", packInfo->Unsupport);
			break;
		case IMPRESSSERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Impress Server", packInfo->Unsupport);
			break;
		case RESOURCELOCSERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Resource Location Server", packInfo->Unsupport);
			break;
		case HOSTNAME : 
			ParserAnsiTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Host Name", packInfo->HostName);
			break;
		case BOOTFILESIZE : 
			ParserIntTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Boot File Size", &packInfo->BootFileSize);
			break;
		case MERITDUMP : 
			ParserAnsiTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Merit Dump File", packInfo->MeritDumpFile);
			break;
		case DOMAINNAME : 
			ParserAnsiTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Domain Name", (char *)packInfo->Unsupport);
			break;
		case SWAPSERVER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Swap Server", packInfo->Unsupport);
			break;
		case ROOTPATH : 
			ParserAnsiTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Root Path", packInfo->Unsupport);
			break;
		case EXTENSIONSPATH : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Extensions Path", packInfo->Unsupport);
			break;
		case IPFORWARDING : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "IP Forwarding", packInfo->Unsupport);
			break;
		case NONLOCALSOURCEROUTING : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Non-Local Source Routing", packInfo->Unsupport);
			break;
		case POLICYFILTER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Policy Filter", packInfo->Unsupport);
			break;
		case MAXIMUMDATAGRAMREASSEMBLYSIZE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Maximum Datagram Reassembly Size", packInfo->Unsupport);
			break;
		case DEFAULTIPTIMETOLIVE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Default IP Time-to-live", packInfo->Unsupport);
			break;
		case PATHMTUAGINGTIMEOUT : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Path MTU Aging Timeout", packInfo->Unsupport);
			break;
		case PATHMTUPLATEAUTABLE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Path MTU Plateau Table", packInfo->Unsupport);
			break;
		case INTERFACEMTU : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Interface MTU", packInfo->Unsupport);
			break;
		case ALLSUBNETSARELOCAL : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "All Subnets are Local", packInfo->Unsupport);
			break;
		case BROADCASTADDRESS : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Broadcast Address", packInfo->Unsupport);
			break;
		case PERFORMMASKDISCOVERY : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Perform Mask Discovery", packInfo->Unsupport);
			break;
		case MASKSUPPLIER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Mask Supplier", packInfo->Unsupport);
			break;
		case PERFORMROUTERDISCOVERY : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Perform Router Discovery", packInfo->Unsupport);
			break;
		case ROUTERSOLICITATIONADDRESS : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Router Solicitation Address", packInfo->Unsupport);
			break;
		case STATICROUTE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Static Route", packInfo->Unsupport);
			break;
		case TRAILERENCAPSULATION : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Trailer Encapsulation", packInfo->Unsupport);
			break;
		case ARPCACHETIMEOUT : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "ARP Cache Timeout", packInfo->Unsupport);
			break;
		case ETHERNETENCAPSULATION : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Ethernet Encapsulation", packInfo->Unsupport);
			break;
		case TCPDEFAULTTTL : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "TCP Default TTL", packInfo->Unsupport);
			break;
		case TCPKEEPALIVEINTERVAL : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "TCP Keepalive Interval", packInfo->Unsupport);
			break;
		case TCPKEEPALIVEGARBAGE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "TCP Keepalive Garbage", packInfo->Unsupport);
			break;
		case NETWORKINFORMATIONSERVICEDOMAIN : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Network Information Service Domain", packInfo->Unsupport);
			break;
		case NETWORKINFORMATIONSERVERS : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Network Information Servers", packInfo->Unsupport);
			break;
		case NETWORKTIMEPROTOCOLSERVERS : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Network Time Protocol Servers", packInfo->Unsupport);
			break;
		case VENDORSPECIFICINFORMATION : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Vendor Specific Information", packInfo->Unsupport);
			break;
		case NETBIOSOVERTCPIPNAMESERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "NetBIOS over TCP/IP Name Server", packInfo->Unsupport);
			break;
		case NETBIOSOVERTCPIPDATAGRAMDISTRIBUTIONSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "NetBIOS over TCP/IP Datagram Distribution Server", packInfo->Unsupport);
			break;
		case NETBIOSOVERTCPIPNODETYPE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "NetBIOS over TCP/IP Node Type", packInfo->Unsupport);
			break;
		case NETBIOSOVERTCPIPSCOPE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "NetBIOS over TCP/IP Scope", packInfo->Unsupport);
			break;
		case XWINDOWSYSTEMFONTSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "X Window System Font Server", packInfo->Unsupport);
			break;
		case XWINDOWSYSTEMDISPLAYMANAGER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "X Window System Display Manager", packInfo->Unsupport);
			break;
		case REQUESTEDIPADDRESS : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Requested IP Address", packInfo->Unsupport);
			break;
		case IPADDRESSLEASETIME : 
			ParserIntTypeOption(optionarray[0],  optionarray+2, optionarray[1], "IP Address Lease Time", (void *)&packInfo->IPLeaseTime);
			break;
		case OPTIONOVERLOAD : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Option Overload", packInfo->Unsupport);
			break;
		case DHCPMESSAGETYPE : 
			ParserIntTypeOption(optionarray[0],  optionarray+2, optionarray[1], "DHCP Message Type", &packInfo->DHCPMessageType);
			break;
		case SERVERIDENTIFIER : 
			ParserAddressTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Server Identifier", packInfo->ServerIdentifier);
			break;
		case PARAMETERREQUESTLIST : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case MESSAGE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case MAXIMUMDHCPMESSAGESIZE : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case RENEWALTIMEVALUE_T1 : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case REBINDINGTIMEVALUE_T2 : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case VENDORCLASSIDENTIFIER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case CLIENTIDENTIFIER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Client-identifier", packInfo->ClientIdentifier);
			break;
		case NETWORKINFORMATIONSERVICEPLUSDOMAIN : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case NETWORKINFORMATIONSERVICEPLUSSERVERS : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case TFTPSERVERNAME : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case BOOTFILENAME : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case MOBILEIPHOMEAGENT : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case SMTPSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case POP3SERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case NNTPSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case DEFAULTWWWSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case DEFAULTFINGERSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case DEFAULTIRCSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case STREETTALKSERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case STDASERVER : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "UnSupportOption", packInfo->Unsupport);
			break;
		case END_OPTION : 
			end = true;
			break;
		default : 
			ParserByteTypeOption(optionarray[0],  optionarray+2, optionarray[1], "Unknow Option", packInfo->Unsupport);
			break;
		}
		optionarray += len +2; // 下一個option
	}
}

void prettyDebug(DHCP_PACKET dhcp) {

	if(gDebug==Super_Debug) {
		printf("┌───┬───┬───┬───┐\n");
		printf("│  OP  │HTYPE │ HLEN │ HOPS │\n");
		printf("├───┼───┼───┼───┤\n");
	} else {
		printf("┌───┬───┬───┬───┐\n");
	}
	printf("│ 0x%02X │ 0x%02X │ 0x%02X │ 0x%02X │\n", dhcp.OP, dhcp.HTYPE, dhcp.HLEN, dhcp.HOPS );

	if(gDebug==Super_Debug) {
		printf("├───┴───┴───┴───┤\n");
		printf("│             XID              │\n");
		printf("├───────────────┤\n");
	} else {
		printf("├───┴───┴───┴───┤\n");
	}
	printf("│         0x%08X           │\n", dhcp.TRANSACTION_ID);

	if(gDebug==Super_Debug) {
		printf("├───────┬───────┤\n");
		printf("│    SECS      │    FLAGS     │\n");
		printf("├───────┼───────┤\n");
	} else {
		printf("├───────┬───────┤\n");
	}
	printf("│    0x%04X    │    0x%04X    │\n", dhcp.SECONDS, dhcp.FLAGS);

	if(gDebug==Super_Debug) {
		printf("├───────┴───────┤\n");
		printf("│           CIADDR             │\n");
		printf("├───────────────┤\n");
	} else {
		printf("├───────┴───────┤\n");
	}
	printf("│       %03d.%03d.%03d.%03d        │\n", dhcp.ciaddr[0], dhcp.ciaddr[1], dhcp.ciaddr[2], dhcp.ciaddr[3]);

	if(gDebug==Super_Debug) {
		printf("├───────────────┤\n");
		printf("│           YIADDR             │\n");
	} 
	printf("├───────────────┤\n");
	printf("│       %03d.%03d.%03d.%03d        │\n", dhcp.yiaddr[0], dhcp.yiaddr[1], dhcp.yiaddr[2], dhcp.yiaddr[3]);

	if(gDebug==Super_Debug) {
		printf("├───────────────┤\n");
		printf("│           SIADDR             │\n");
	} 
	printf("├───────────────┤\n");
	printf("│       %03d.%03d.%03d.%03d        │\n", dhcp.siaddr[0], dhcp.siaddr[1], dhcp.siaddr[2], dhcp.siaddr[3]);

	if(gDebug==Super_Debug) {
		printf("├───────────────┤\n");
		printf("│           GIADDR             │\n");
	} 
	printf("├───────────────┤\n");
	printf("│       %03d.%03d.%03d.%03d        │\n", dhcp.giaddr[0], dhcp.giaddr[1], dhcp.giaddr[2], dhcp.giaddr[3]);

	if(gDebug==Super_Debug) {
		printf("├───────────────┤\n");
		printf("│           CHADDR             │\n");
	} 
	printf("├───────────────┤\n");
	printf("│      %02X:%02X:%02X:%02X:%02X:%02X       │\n", dhcp.chaddr[0], dhcp.chaddr[1], dhcp.chaddr[2], dhcp.chaddr[3], dhcp.chaddr[4], dhcp.chaddr[5]);
	printf("├───────────────┤\n");
	printf("│%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X │\n", dhcp.chaddr[6], dhcp.chaddr[7], dhcp.chaddr[8], dhcp.chaddr[9], dhcp.chaddr[10], dhcp.chaddr[11], dhcp.chaddr[12], dhcp.chaddr[13], dhcp.chaddr[14], dhcp.chaddr[15]);


	if(gDebug==Super_Debug) {
		printf("├───────────────┤\n");
		printf("│        Magic Cookie          │\n");
	} 
	printf("├───────────────┤\n");
	printf("│         0x%08X           │\n", dhcp.magicCode);
	printf("└───────────────┘\n");
}

void ClientListen( ULONG bindInterfaceAddress ) {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		printf("Socket init failed\n");
		return ;
	}

	SOCKET m_socket;
	m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (m_socket == INVALID_SOCKET) {
		printf("Connection failed. Error no : %ld\n", WSAGetLastError());
		WSACleanup();
		return ;
	}
	bool opt = true;

	SOCKADDR_IN reciver;
	int senferAddSize=sizeof(reciver); 
	reciver.sin_family=AF_INET; 
	reciver.sin_port=htons(68); 
	reciver.sin_addr.s_addr=bindInterfaceAddress; 

	if ( bind(m_socket,(SOCKADDR*)&reciver,sizeof(reciver)) == -1) {
		printf("Socket bind error. (%d)\n", WSAGetLastError());
	}

	Packet_Information pakInfo;
	char strbuf[1645]; // 548*3+1
	int len, getbytes;
	while (true) {
		DHCP_PACKET dhcp;
		memset(&dhcp, 0, 548);
		getbytes = recvfrom(m_socket, (char*)&dhcp, 548, 0, (struct sockaddr*) &reciver, &senferAddSize) ;
		if (getbytes >0) {
			printf("[%s/%d] Connected.\n", inet_ntoa(reciver.sin_addr), htons(reciver.sin_port));
			// prettyDebug( dhcp);
			printf( "OP:%d\n", dhcp.OP );
			printf( "ciaddr:%d.%d.%d.%d\n", dhcp.ciaddr[0], dhcp.ciaddr[1], dhcp.ciaddr[2], dhcp.ciaddr[3] );
			printf( "yiaddr:%d.%d.%d.%d\n", dhcp.yiaddr[0], dhcp.yiaddr[1], dhcp.yiaddr[2], dhcp.yiaddr[3] );
			printf( "siaddr:%d.%d.%d.%d\n", dhcp.siaddr[0], dhcp.siaddr[1], dhcp.siaddr[2], dhcp.siaddr[3] );
			printf( "giaddr:%d.%d.%d.%d\n", dhcp.giaddr[0], dhcp.giaddr[1], dhcp.giaddr[2], dhcp.giaddr[3] );
			memset( &pakInfo, 0, sizeof(pakInfo));
			OptionParser(  dhcp.Options, &pakInfo );
			if(gDebug) {
				byteToHexStr((byte*) &dhcp, strbuf, getbytes  );
				printf("[Chunk Debug]\n%s/%d\n", strbuf, getbytes);
			}

			printf("\n");
		}
	} 
}

int OptionMaker( byte * ReplayOption, Packet_Information * packInfo ) {
	int ReplayOptionWalker= 0;
	if (packInfo->OptionToReplay[DHCPMESSAGETYPE]) { // 最優先回
		switch (packInfo->DHCPMessageType) {
		case DHCPDISCOVER : 
			ReplayOption[2] = DHCPOFFER;
			break;
		case DHCPOFFER : break;
		case DHCPREQUEST :
			ReplayOption[2] = DHCPACK;
			break;
		case DHCPDECLINE : break;
		case DHCPACK : break;
		case DHCPNAK : break;
		case DHCPRELEASE : break;
		case DHCPINFORM : break;
		}
		ReplayOption[0] = DHCPMESSAGETYPE;
		ReplayOption[1] = 1;
		ReplayOptionWalker+=3;
	}
	if (packInfo->OptionToReplay[SERVERIDENTIFIER]) {
		ReplayOptionWalker+=AddressOptionWriter(SERVERIDENTIFIER, ReplayOption+ReplayOptionWalker, 4,  gMyIP);
	}
	if (packInfo->OptionToReplay[IPADDRESSLEASETIME]) {
		ReplayOption[ReplayOptionWalker] = IPADDRESSLEASETIME;
		ReplayOption[ReplayOptionWalker+1] = 4;
		int tmpTime = ChangeEndian(gLeaseTime);
		memcpy( ReplayOption +ReplayOptionWalker+2, & tmpTime, 4 );
		ReplayOptionWalker+=6;
	}
	if (packInfo->OptionToReplay[SUBNETMASK]) {
		ReplayOptionWalker+=AddressOptionWriter(SUBNETMASK, ReplayOption+ReplayOptionWalker, 4,  gSubMask);
	}
	if (packInfo->OptionToReplay[TIMEOFFSET]) {
	}
	if (packInfo->OptionToReplay[ROUTER]) {
		ReplayOptionWalker+=AddressOptionWriter(ROUTER, ReplayOption+ReplayOptionWalker, 4,  gRouter);
	}
	if (packInfo->OptionToReplay[TIMESERVER]) {
	}
	if (packInfo->OptionToReplay[NAMESERVER]) {
	}
	if (packInfo->OptionToReplay[DOMAINNAMESERVER]) {
		ReplayOptionWalker+=AddressOptionWriter(DOMAINNAMESERVER, ReplayOption+ReplayOptionWalker, 4,  gDomainNameServer);
	}
	if (packInfo->OptionToReplay[LOGSERVER]) {
	}
	if (packInfo->OptionToReplay[COOKIESERVER]) {
	}
	if (packInfo->OptionToReplay[LPRSERVER]) {
	}
	if (packInfo->OptionToReplay[IMPRESSSERVER]) {
	}
	if (packInfo->OptionToReplay[RESOURCELOCSERVER]) {
	}
	if (packInfo->OptionToReplay[HOSTNAME]) {
	}
	if (packInfo->OptionToReplay[BOOTFILESIZE]) {
	}
	if (packInfo->OptionToReplay[MERITDUMP]) {
	}
	if (packInfo->OptionToReplay[DOMAINNAME]) {
		ReplayOptionWalker+=AnsiOptionWriter(DOMAINNAME, ReplayOption+ReplayOptionWalker, sizeof(gDomainName), gDomainName);
	}
	if (packInfo->OptionToReplay[SWAPSERVER]) {
	}
	if (packInfo->OptionToReplay[ROOTPATH]) {
	}
	if (packInfo->OptionToReplay[EXTENSIONSPATH]) {
	}
	if (packInfo->OptionToReplay[IPFORWARDING]) {
	}
	if (packInfo->OptionToReplay[NONLOCALSOURCEROUTING]) {
	}
	if (packInfo->OptionToReplay[POLICYFILTER]) {
	}
	if (packInfo->OptionToReplay[MAXIMUMDATAGRAMREASSEMBLYSIZE]) {
	}
	if (packInfo->OptionToReplay[DEFAULTIPTIMETOLIVE]) {
	}
	if (packInfo->OptionToReplay[PATHMTUAGINGTIMEOUT]) {
	}
	if (packInfo->OptionToReplay[PATHMTUPLATEAUTABLE]) {
	}
	if (packInfo->OptionToReplay[INTERFACEMTU]) {
	}
	if (packInfo->OptionToReplay[ALLSUBNETSARELOCAL]) {
	}
	if (packInfo->OptionToReplay[BROADCASTADDRESS]) {
	}
	if (packInfo->OptionToReplay[PERFORMMASKDISCOVERY]) {
	}
	if (packInfo->OptionToReplay[MASKSUPPLIER]) {
	}
	if (packInfo->OptionToReplay[PERFORMROUTERDISCOVERY]) {
	}
	if (packInfo->OptionToReplay[ROUTERSOLICITATIONADDRESS]) {
	}
	if (packInfo->OptionToReplay[STATICROUTE]) {
	}
	if (packInfo->OptionToReplay[TRAILERENCAPSULATION]) {
	}
	if (packInfo->OptionToReplay[ARPCACHETIMEOUT]) {
	}
	if (packInfo->OptionToReplay[ETHERNETENCAPSULATION]) {
	}
	if (packInfo->OptionToReplay[TCPDEFAULTTTL]) {
	}
	if (packInfo->OptionToReplay[TCPKEEPALIVEINTERVAL]) {
	}
	if (packInfo->OptionToReplay[TCPKEEPALIVEGARBAGE]) {
	}
	if (packInfo->OptionToReplay[NETWORKINFORMATIONSERVICEDOMAIN]) {
	}
	if (packInfo->OptionToReplay[NETWORKINFORMATIONSERVERS]) {
	}
	if (packInfo->OptionToReplay[NETWORKTIMEPROTOCOLSERVERS]) {
	}
	if (packInfo->OptionToReplay[VENDORSPECIFICINFORMATION]) {
	}
	if (packInfo->OptionToReplay[NETBIOSOVERTCPIPNAMESERVER]) {
	}
	if (packInfo->OptionToReplay[NETBIOSOVERTCPIPDATAGRAMDISTRIBUTIONSERVER]) {
	}
	if (packInfo->OptionToReplay[NETBIOSOVERTCPIPNODETYPE]) {
	}
	if (packInfo->OptionToReplay[NETBIOSOVERTCPIPSCOPE]) {
	}
	if (packInfo->OptionToReplay[XWINDOWSYSTEMFONTSERVER]) {
	}
	if (packInfo->OptionToReplay[XWINDOWSYSTEMDISPLAYMANAGER]) {
	}
	if (packInfo->OptionToReplay[REQUESTEDIPADDRESS]) {
	}
	if (packInfo->OptionToReplay[OPTIONOVERLOAD]) {
	}

	if (packInfo->OptionToReplay[PARAMETERREQUESTLIST]) {
	}
	if (packInfo->OptionToReplay[MESSAGE]) {
	}
	if (packInfo->OptionToReplay[MAXIMUMDHCPMESSAGESIZE]) {
	}
	if (packInfo->OptionToReplay[RENEWALTIMEVALUE_T1]) {
	}
	if (packInfo->OptionToReplay[REBINDINGTIMEVALUE_T2]) {
	}
	if (packInfo->OptionToReplay[VENDORCLASSIDENTIFIER]) {
	}
	if (packInfo->OptionToReplay[CLIENTIDENTIFIER]) {
	}
	if (packInfo->OptionToReplay[NETWORKINFORMATIONSERVICEPLUSDOMAIN]) {
	}
	if (packInfo->OptionToReplay[NETWORKINFORMATIONSERVICEPLUSSERVERS]) {
	}
	if (packInfo->OptionToReplay[TFTPSERVERNAME]) {
	}
	if (packInfo->OptionToReplay[BOOTFILENAME]) {
	}
	if (packInfo->OptionToReplay[MOBILEIPHOMEAGENT]) {
	}
	if (packInfo->OptionToReplay[SMTPSERVER]) {
	}
	if (packInfo->OptionToReplay[POP3SERVER]) {
	}
	if (packInfo->OptionToReplay[NNTPSERVER]) {
	}
	if (packInfo->OptionToReplay[DEFAULTWWWSERVER]) {
	}
	if (packInfo->OptionToReplay[DEFAULTFINGERSERVER]) {
	}
	if (packInfo->OptionToReplay[DEFAULTIRCSERVER]) {
	}
	if (packInfo->OptionToReplay[STREETTALKSERVER]) {
	}
	if (packInfo->OptionToReplay[STDASERVER]) {
	}
	return ReplayOptionWalker;
}

void ParserAnsiTypeOption(byte opt, byte * OptionArray, int len, const char * name,  void * retarray) {
	memcpy( retarray, OptionArray, len);
	((char *)retarray)[len] = 0;
	printf(" *%s(%d) : %s\n", name, opt,  retarray );
}

void ParserByteTypeOption(byte opt, byte * OptionArray, int len, const char * name, byte * retarray) {
	memcpy( retarray, OptionArray, len);
	char * tmp = new char[len*3+1];
	byteToHexStr( OptionArray, tmp, len);
	printf(" *%s(%d) : %s\n",name, opt, tmp );
	delete tmp;
}

void ParserAddressTypeOption(byte opt, byte * OptionArray, int len, const char * name, byte * retarray) {
	memcpy( retarray, OptionArray, len);
	for ( int i = 0 ; i < len/4 ; i++) {
		printf(" *%s(%d) : %d.%d.%d.%d\n",name, opt, OptionArray[i*4], OptionArray[i*4+1], OptionArray[i*4+2], OptionArray[i*4+3] );
	}
}

void ParserIntTypeOption(byte opt, byte * OptionArray, int len, const char * name, void * retarray) {
	for ( int i = 0 ; i < len ; i++) {
		((byte *)retarray)[len-i-1] = OptionArray[i] ;
	}
	switch ( len ) {
	case 4:
		printf(" *%s(%d) : %d\n",name, opt, ((UINT *)retarray)[0] ); break;
	case 2:printf(" *%s(%d) : %d\n",name, opt, ((USHORT *)retarray)[0] ); break;
	case 1:printf(" *%s(%d) : %d\n",name, opt, ((byte *)retarray)[0] ); break;
	default: break;
	}
}

int ByteOptionWriter(byte opt, byte * retOptionArray, int len, void * inputarray) {
	return 0;
}

int AnsiOptionWriter(byte opt, byte * retOptionArray, int len, void * inputarray) {
	retOptionArray[0] = opt;
	retOptionArray[1] = len;
	memcpy( retOptionArray +2, inputarray, len );
	return len+2;
}

int AddressOptionWriter(byte opt, byte * retOptionArray, int len, byte * inputarray) {
	retOptionArray[0] = opt;
	retOptionArray[1] = len;
	int ReplayOptionWalker = 2;
	for ( int i = 0 ; i < len/4 ; i++ ) {
		memcpy( retOptionArray +ReplayOptionWalker, &inputarray[i*4], 4 );
		ReplayOptionWalker+=4;
	}
	return ReplayOptionWalker;
}
