#include <tchar.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <vector>
#include <string.h>
#pragma comment(lib, "iphlpapi.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x)) 
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define WORD_THE_SAME 0

class IpHelper{

private:
	ULONG ulOutBufLen;
	DWORD dwRetVal;
	PIP_ADAPTER_INFO AdapterInfo;
	PIP_INTERFACE_INFO pInfo ;

public:
	IpHelper();
	bool GetAdapterInfo();
	bool GetInterFaceInfo();
	std::vector<char *>* GetAdapterDescription();
	char* GetCorespondingAdapterName(char* description);
	bool RenewDHCP();
};
