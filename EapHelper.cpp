#include "EapHelper.h"

EapHelper::EapHelper(){
	this->EtherMessage = NULL;
	this->Authen_ = NULL;
	this->EAP_ = NULL;
}

void EapHelper::CleanEtherMessage(){
	if(this->Authen_ != NULL){
		delete this->Authen_ ;
	}
	if(this->EAP_ != NULL){
		delete this->EAP_;
	}
}

void EapHelper::SetEtherMessage(u_char* message){
	this->EtherMessage = message;
	this->Authen_ = new u_char[this->AuthenLen];
	this->EAP_ = new u_char[this->EAPLen];
	memcpy( this->Authen_ , message , AuthenLen );
	memcpy( this->EAP_ , message + AuthenLen , EAPLen );
}


Radius* EapHelper::GetRadius(){
	Radius* radius = NULL;
	if(this->Authen_ == NULL || this->EAP_ == NULL){
		return NULL;
	}
	radius = new Radius();
	radius->Eap = new EAP();

	radius->version = (int)this->Authen_[0];
	radius->type = (int)this->Authen_[1];
	radius->EapoLength = ((int)this->Authen_[2]) * 256 + (int)this->Authen_[3];

	radius->Eap->code = (int)this->EAP_[0];
	radius->Eap->id = (int)this->EAP_[1];
	radius->Eap->EapLength = ((int)this->EAP_[2]) * 256 + (int)this->EAP_[3];

	if(radius->Eap->code == EAP_REQUEST){
		radius->Eap->ReqType = (int)this->EtherMessage[this->AuthenLen + this->EAPLen];
		if(radius->Eap->ReqType == EAP_TYPE_MD5){
			radius->Eap->Content = this->GetMD5Value();
		}
	}
	
	if(radius->Eap->code == EAP_FAILURE){
		radius->Eap->Content = this->GetError();
	}

	return radius;
}

void EapHelper::OnSuccessLogIn(){
	printf("Success Login\n");
}
void EapHelper::OnFailureLogin(char* ErrorMessage){
	printf("Error : %s\n",ErrorMessage);
}
void EapHelper::OnSuccessLogOff(){
	printf("Success LogOff\n");
}
void EapHelper::OnFailureOpenDevice(){
	printf("Fail to Open netWork Device\n");
}

std::string  EapHelper::GetEthernetHeader(const unsigned char dst[6], const unsigned char src[6], unsigned short type){
	std::string packet;
    packet.assign(14, 0);
    memcpy(&packet[0], dst, 6);
    memcpy(&packet[6], src, 6);
    *(unsigned short*)&packet[12] = htons(type);
	return packet;
}

bool  EapHelper::isFromServer(const unsigned char mac[6]){
	static const unsigned char ServerMacAddr[6] = {0x80,0xf6,0x2e,0xfe,0x31,0x5e};
	for(int i = 0 ; i < 6 ; i++){
		if(mac[i] != ServerMacAddr[i]){
			return false ;
		}
	}
	return true;
}

char  EapHelper::GetLetter(int a){
	if( a <= 9 ){
		return '0' + a ;
	}
	return 'a' + a - 10 ;
}

char*  EapHelper::MacToStr(const unsigned char mac[6]){
	char* result = new char[18];
	for(int i = 0 ; i < 6 ; i++){
		int a = mac[i];
		result[i*3] = this->GetLetter(a / 16);
		result[i*3+1] = this->GetLetter(a % 16);
		result[i*3+2] = '-';
	}
	result[17] = '\0';
	return result;
}





