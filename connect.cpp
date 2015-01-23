#include "EAPauth.h"

int main(){
	EAPauth EAPer;
	std::vector<char *> *a = EAPer.IPstar->GetAdapterDescription();
	char *name = EAPer.IPstar->GetCorespondingAdapterName(a->at(2));
	EAPer.setDeviceName(name);
	EAPer.ServerForever();
	return 0 ;
}