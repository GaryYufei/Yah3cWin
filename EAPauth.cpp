#include "EAPauth.h"
#include <conio.h>


EAPauth::EAPauth(){
	this->DeviceName = NULL;
	this->IPstar = new IpHelper;
	memset(this->errbuf,0,PCAP_ERRBUF_SIZE);
	this->EAPstar = NULL;
	this->netmask = 0xffffff ;
	this->password = "your password";
	this->username = "your sysu NetID";
	this->version = "\x15\x04\xac\x12\x9c\62\x06\x07PDBqTUxRYyd+GkgyfgMpLir45Yk=  ";
}

void EAPauth::setDeviceName(char *DeviceName){

	this->DeviceName = (char *)malloc( strlen(PCAPHEAD) + strlen(DeviceName) + 1 );
	strcpy(this->DeviceName,PCAPHEAD);
	this->DeviceName = strcat(this->DeviceName,DeviceName);
	this->LocalMacAddr = this->getMacAddr(this->DeviceName);
	this->EthernetHeader = GetEthernetHeader(ServerMacAddr,this->LocalMacAddr,AuthenticationType);

	char* macSTR = MacToStr(this->LocalMacAddr);
	this->packet_filter = (char *)malloc( strlen(NETDATAFILTER) + strlen(macSTR) + 1 );
	strcpy(this->packet_filter,NETDATAFILTER);
	this->packet_filter = strcat(this->packet_filter,macSTR);
}

bool EAPauth::openDevice(){
	EAPstar= pcap_open(this->DeviceName,            
                  100,               
                  PCAP_OPENFLAG_PROMISCUOUS,  
                  1000,               
                  NULL,              
                  this->errbuf             
                  );
	if(EAPstar != NULL){
		if(pcap_compile(this->EAPstar, &fcode, packet_filter, 1, netmask) < 0 ){
			return false;
		}
		if( pcap_setfilter(this->EAPstar, &fcode) < 0){
			return false ;
		}
		return true;
	}
	return false;
}

void EAPauth::closeDevice(){
	pcap_close(this->EAPstar); 
	this->EAPstar = NULL;
}

char* EAPauth::GetErrorMes(){
	return this->errbuf;
}

std::string EAPauth::pack_eapol(int type, const std::string data){
    std::string packet;
    packet.assign(4, 0);
    *(unsigned char*)&packet[0] = EAPOL_VERSION;
    *(unsigned char*)&packet[1] = type;
    *(unsigned short*)&packet[2] = htons(data.length());
    packet.append(data);
    return packet;
}

std::string EAPauth::pack_eth(int code,int id, int type ,std::string data){
	std::string EAP ;
	int TotaLength = data.length() + 5 ;
	EAP.assign(5,0);
	EAP[0] = (unsigned char)code;
	EAP[1] = (unsigned char)id;
	EAP[2] = (unsigned char)(TotaLength / 256) ;
	EAP[3] = (unsigned char)(TotaLength % 256) ;
	EAP[4] = (unsigned char)type ;
	return EAP + data;
}

unsigned char*  EAPauth::getMacAddr(char* AdapterName){
	LPADAPTER lp = PacketOpenAdapter(AdapterName); 
	PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);
	PacketRequest(lp, FALSE, OidData);
	unsigned char* mac = new unsigned char[6];
	for(int i = 0 ; i < 6 ; i++){
		mac[i] = (OidData->Data)[i];
	}
	return mac;
}

const u_char*  EAPauth::StringToU_char(std::string a){
	u_char* result = new u_char[a.size()];
	for(int i = 0 ; i < a.size() ; i++){
		result[i] = a[i];
	}
	return result ;
}

bool EAPauth::sendStart(){
	std::string content = this->pack_eapol(EAPOL_START);
	std::string EAPOL = this->EthernetHeader + content;
	printf("Send Start\n");
	return  pcap_sendpacket(this->EAPstar,this->StringToU_char(EAPOL) , EAPOL.size() ) == 0 ;
}

bool EAPauth::sendLoginOff(){
	std::string content = this->pack_eapol(EAPOL_LOGOFF);
	std::string EAPOL = this->EthernetHeader + content;
	return  pcap_sendpacket(this->EAPstar,this->StringToU_char(EAPOL) , EAPOL.size() ) == 0 ;
}

bool EAPauth::SendData(int id,std::string content,int type){
	std::string EAPOL = this->EthernetHeader + this->pack_eapol(EAPOL_EAPPACKET,
													this->pack_eth(
														EAP_RESPONSE,
														id,
														type,
														content
													));
	int ResultFlag = pcap_sendpacket(this->EAPstar,this->StringToU_char(EAPOL) , EAPOL.size() );
	return ResultFlag == 0 ;
}


bool EAPauth::SendResponseID(int id){
	std::string content = this->version + this->username;
	return this->SendData(id,content,EAP_TYPE_ID);
}

bool EAPauth::SendResponseH3c(int id){
	char temp[5];
	itoa(this->password.size(),temp,5);
	std::string content = temp;
	content = content + this->password + this->username;
	return this->SendData(id,content,EAP_TYPE_H3C);
}

bool EAPauth::SendResponseMd5(int id,char* MD5Value){
	std::string FullPas ;
	FullPas.assign(16,0);
	for(int i = 0 ; i < this->password.length();i++){
		FullPas[i] = this->password[i];
	}
	std::string MD5 = "",content;
	for(int i = 0 ; i < 16 ; i++){
		MD5 = MD5 + (char)(FullPas[i] ^ MD5Value[i]);
	}
	content = (char)'0x10' + MD5 + this->username;
	return this->SendData(id,content,EAP_TYPE_MD5);
}

void EAPauth::EAPHandler(u_char* message){	
	this->SetEtherMessage(message);
	Radius* radius = this->GetRadius();
	if(radius->Eap->code == EAP_SUCCESS){
		printf("get on line!\nSet IP.......\n");
		if(this->IPstar->RenewDHCP()){
			this->OnSuccessLogIn();
		}
	}else if(radius->Eap->code == EAP_FAILURE){
		this->OnFailureLogin(radius->Eap->Content);
	}else if(radius->Eap->code == EAP_RESPONSE){
		printf("Got Unknown EAP Response\n");
	}else if(radius->Eap->code == EAP_REQUEST){

		if(radius->Eap->ReqType == EAP_TYPE_ID){
			printf("send username\n");
			this->SendResponseID(radius->Eap->id);
		}else if(radius->Eap->ReqType == EAP_TYPE_H3C){
			printf("Request for Allocation\n");
			this->SendResponseH3c(radius->Eap->id);
		}else if(radius->Eap->ReqType == EAP_TYPE_MD5){
			printf("Request for MD5-Challenge\n");
			this->SendResponseMd5(radius->Eap->id,radius->Eap->Content);
		}else{
			printf("Got unknown EAP code");
		}
	}
	this->CleanEtherMessage();
}

void EAPauth::ServerForever(){

	int res ;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	if(!this->openDevice()){
		this->OnFailureOpenDevice();
	}
	this->sendStart();
	
	while((res = pcap_next_ex(this->EAPstar , &header, &pkt_data)) >= 0){

		if(res == 0){
			continue;
		}

		unsigned char *p = new unsigned char[MacLength];
		memcpy(p,pkt_data+MacLength,MacLength);
		if(!isFromServer(p)){
			continue ;
		}
		this->EAPHandler((u_char*)(pkt_data+HeaderLength));
	}
	this->closeDevice();
}

