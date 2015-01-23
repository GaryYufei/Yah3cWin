#include "IpHelper.h"

IpHelper::IpHelper(){
	this->ulOutBufLen = 0;
	this->dwRetVal = 0;
	this->AdapterInfo = NULL;
	this->pInfo = NULL;
}

bool IpHelper::GetAdapterInfo(){
	this->dwRetVal = GetAdaptersInfo(NULL, &(this->ulOutBufLen));
    if (this->dwRetVal == ERROR_BUFFER_OVERFLOW) {
        this->AdapterInfo = (PIP_ADAPTER_INFO) MALLOC(ulOutBufLen);
        if (this->AdapterInfo == NULL) {
            return false;
        }
    }
    this->dwRetVal = GetAdaptersInfo(this->AdapterInfo, &(this->ulOutBufLen));
	return this->dwRetVal == NO_ERROR;
}

std::vector<char*>* IpHelper::GetAdapterDescription(){
	std::vector<char*>* result = NULL;
	if(!this->GetAdapterInfo() || !this->GetInterFaceInfo()){
		return result;
	}
	result = new std::vector<char*>();
	PIP_ADAPTER_INFO tempShow = this->AdapterInfo;
	while(tempShow){
		result->push_back(tempShow->Description);
		tempShow = tempShow->Next;
	}
	return result;
}

char* IpHelper::GetCorespondingAdapterName(char* description){
	PIP_ADAPTER_INFO tempShow = this->AdapterInfo;
	while(tempShow){
		if( strcmp(tempShow->Description,description) == WORD_THE_SAME ){
			return tempShow->AdapterName;
		}
		tempShow = tempShow->Next;
	}
	return NULL;
}



bool IpHelper::GetInterFaceInfo(){
	this->dwRetVal = GetInterfaceInfo(NULL, &this->ulOutBufLen);
    if (this->dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        this->pInfo = (IP_INTERFACE_INFO *) MALLOC(this->ulOutBufLen);
        if (this->pInfo == NULL) {
			return false;
        }
    }
    this->dwRetVal = GetInterfaceInfo(this->pInfo, &this->ulOutBufLen);
	return this->dwRetVal == NO_ERROR;
}

bool IpHelper::RenewDHCP(){
	this->dwRetVal =IpRenewAddress(this->pInfo->Adapter);
	return this->dwRetVal ==  NO_ERROR ;
}