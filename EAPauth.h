#include "EapHelper.h"
#include "IpHelper.h"
#include "const.h"
#include "packet32.h"
#include <conio.h>
#include <ntddndis.h>
#include<string>
#pragma comment(lib,"ws2_32.lib")
//using namespace std;

class EAPauth :public EapHelper{

private :
	pcap_t* EAPstar;
	char* DeviceName;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char* LocalMacAddr ;
	std::string EthernetHeader ;
	char* packet_filter ;
	u_int netmask;
	struct bpf_program fcode;
	std::string version;
	std::string username ;
	std::string password;

public:
	IpHelper* IPstar ;
	EAPauth();
	void setDeviceName(char *DeviceName);
	std::string pack_eapol(int type, const std::string data = "");
	std::string pack_eth(int code,int id, int type = 0 ,std::string data="");
	bool openDevice();
	void closeDevice();
	bool sendStart();
	bool sendLoginOff();
	char* GetErrorMes();
	unsigned char* getMacAddr(char* AdapterName);
	const u_char* StringToU_char(std::string a);
	void ServerForever();
	void EAPHandler(u_char* message);
	bool SendResponseID(int id);
	bool SendResponseH3c(int id);
	bool SendResponseMd5(int id,char* MD5Value);
	bool SendData(int id,std::string content,int type);
};