#include <stdio.h>
#include <pcap.h>
#include <string>

#define EAP_REQUEST   1
#define EAP_TYPE_MD5  4 
#define EAP_FAILURE   4

struct EAP{
	int code ;
	int id ;
	int EapLength;
	int ReqType;
	char* Content;

	EAP(){
		Content = NULL;
	}

	~EAP(){
		free(Content);
	}
};

struct Radius{
	int version;
	int type ;
	int EapoLength;
	struct EAP* Eap;

	Radius(){
		Eap = NULL;
	}

	~Radius(){
		free(Eap);
	}
};


class EapHelper{
private:
	u_char* EtherMessage;
	u_char* Authen_ ;
	u_char* EAP_ ;
	const static int AuthenLen = 4 ;
	const static int EAPLen = 4 ;
	const static int ErrorLen = 6 ;
	char* GetError(){
		char* content = NULL;
		if( this->EtherMessage == NULL ){
			return NULL;
		}
		content = new char[this->ErrorLen + 1];
		memcpy(content,this->EtherMessage+10,this->ErrorLen);
		content[this->ErrorLen] = '\0';
		return content;
	}
	char* GetMD5Value(){
		int MD5Len = (int)this->EtherMessage[AuthenLen + EAPLen + 1];
		char* MD5Value = new char[MD5Len];
		memcpy(MD5Value,this->EtherMessage+(AuthenLen+EAPLen+2),MD5Len);
		return MD5Value;
	}
public:
	EapHelper();
	void SetEtherMessage(u_char* message);
	void CleanEtherMessage();
	Radius* GetRadius();
	std::string GetEthernetHeader(const unsigned char dst[6], const unsigned char src[6], unsigned short type);
	bool isFromServer(const unsigned char mac[6]);
	char* MacToStr(const unsigned char mac[6]);
	char GetLetter(int a);
	void OnSuccessLogIn();
	void OnFailureLogin(char* ErrorMessage);
	void OnSuccessLogOff();
	void OnFailureOpenDevice();
};