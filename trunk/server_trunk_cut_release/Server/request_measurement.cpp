//© 2009-2012 The MITRE Corporation. ALL RIGHTS RESERVED.
//Permission to use, copy, modify, and distribute this software for any
//purpose with or without fee is hereby granted, provided that the above
//copyright notice and this permission notice appear in all copies.
//THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//This will be for sending each of the measurement request type packets

//Some code taken from the raw packet generation example:
//http://www.codeproject.com/KB/IP/UDPandWPCAP.aspx
//Copyright Emmanuel Herrera 2008, may be used in accordance with http://www.opensource.org/licenses/ms-pl.html
//Modified by Xeno Kovah - 4/5/2009

#include <math.h>
#include <queue>

#include "raw_packet.h"
#include "thread_pcap.h"
#include "request_measurement.h"
#include "server_client_protocol.h"
#include "database_mysql2.h"
extern "C"{
	#include "database_mysql.h"
} 

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
//For manually testing the self-checksumming
unsigned int gUserSpecifiedNonce;

//EXTERNS

//In database_mysql.c
extern "C" MYSQL mysqlMeasurements;
extern "C" HANDLE mysqlMutex;

extern string gffDefaultSrcIPStr;
extern int gVerbose, gQuiet;

//in thread_pcap.cpp
extern char gUseBroadcastMAC;

//in main.cpp
extern DeviceInfo * globDeviceInfoPtr;
extern pcap_if_t * globDevice;
//For getting random numbers
extern HCRYPTPROV gCryptoContext;

////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

//TODO: If you put this in request_measurement.h you get a nasty tangle
//of redefinitions and such. Don't feel like fixing it now, so do later :)
DeviceInfo * GetAdapterInfo(pcap_if_t* Device);

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//nameW can be used for binary name or device name
int RequestMeasurementByType(msgType t, wstring * nameW, unsigned int hostID){
	int ret;
	//get dst IP and hostname
	char dstHostname[128];
	char dstIP[16];

	ret = SelectHostNameByID(hostID, dstHostname);
	if(ret != GENERIC_SUCCESS){
		printf("RequestMeasurementByType: SelectHostNameByID failed\n");
		return ret;
	}
	ret = SelectHostIPByID(hostID, dstIP);
	if(ret != GENERIC_SUCCESS){
		printf("RequestMeasurementByType: SelectHostIPByID failed\n");
		return ret;
	}

	switch(t){
		case TICKSTAMP_ATTESTATION:
			ret = BuildTickStampAttestationRequestPacket((char *)gffDefaultSrcIPStr.c_str(),dstIP, dstHostname, 2500000);
			if(ret != GENERIC_SUCCESS){printf("BuildTickStampAttestationRequestPacket failed\n");}
			break;
		case TOGGLE_ATTACK:
			ret = ToggleAttackRequestPacket((char *)gffDefaultSrcIPStr.c_str(),
								dstIP,
								dstHostname);
	}

	return ret;
}

//This is the function to use exclusivly with the timing_test version of the client code.
//It allows you to specify the number of iterations which you want the self-check to use.
int BuildTimingTestRequestPacket(char * sourceIP, char * destinationIP, char * dstHostName, unsigned int numIterations)
{
	int ret;
	request_hdr_t * requestHeader;
	unsigned int requestSize = 0;
	unsigned int hostID;
	bool alphaCharDetected = false;

	requestSize = sizeof(request_hdr_t);
	requestHeader = (request_hdr_t *)malloc(requestSize);
	if(requestHeader == NULL){
		cout << "BuildTimingTestRequestPacket: malloc() failed\n";
		return GENERIC_ERROR;
	}

	requestHeader->rand = numIterations; //just because we don't want to add a field
	requestHeader->type = TIMING_TEST;
	requestHeader->wcharArraySize = 0;
	requestHeader->wcharArray = NULL;

	//Need to look up the hostID before we InsertPendingME()
	if(SelectHostIDByNetorderIP(inet_addr(destinationIP), &hostID) != GENERIC_SUCCESS){
		printf("BuildTimingTestRequestPacket: SelectHostIDByNetorderIP failed\n");
		return GENERIC_ERROR;
	}

	//We now put the entry into the PendingMeasurementEvents table *before* we send it
	//and then when the outbound packet is seen, the time is just updated so it's no
	//longer the placeholder value of 0
	me_t tmpME;
	memset(&tmpME, 0, sizeof(me_t));
	tmpME.type = requestHeader->type;
	tmpME.nonce = requestHeader->rand;
	tmpME.hostID = hostID;
	ret = InsertPendingME(&tmpME, 0);
	if(ret != GENERIC_SUCCESS){
		printf("BuildTimingTestRequestPacket: InsertPendingME failed for ip = %s, type = %#x, nonce = %#x\n", destinationIP, tmpME.type, tmpME.nonce);
		return GENERIC_ERROR;
	}

	//Set the pendingID of the request equal to the ID of the successful
	//insert into the PendingMeasurementEvents table (returned in the me_t
	//which was passed by reference to InsertPendingME)
	requestHeader->pendingID = tmpME.id;

	////Get ready to insert a pending measurement
	//me_t outboundPendingME;
	//memset(&outboundPendingME, 0, sizeof(me_t));
	////Any me_t fields specific to this measurement type go here:

	ret = RequestCommon(sourceIP, destinationIP, dstHostName, requestHeader, requestSize, &tmpME, "BuildTimingTestRequestPacket");
	if(ret != GENERIC_SUCCESS){
		printf("BuildTimingTestRequestPacket: RequestCommon failed\n");
	}

	free(requestHeader);

	return GENERIC_SUCCESS;
}



int BuildTickStampAttestationRequestPacket(char * sourceIP, char * destinationIP, char * dstHostName, unsigned int numIterations)
{
	int ret;
	request_hdr_t * requestHeader;
	unsigned int requestSize = 0;

	// then proceed to build the normal self request packet
	requestSize = sizeof(request_hdr_t);
	requestHeader = (request_hdr_t *)malloc(requestSize);
	if(requestHeader == NULL){
		cout << "BuildTickStampAttestationRequestPacket: malloc() failed\n";
		return GENERIC_ERROR;
	}

	requestHeader->type = TICKSTAMP_ATTESTATION;
	requestHeader->wcharArraySize = 0;
	requestHeader->wcharArray = NULL;
	requestHeader->rand = numIterations; //just because we don't want to add a field


	//Get ready to insert a pending measurement
	me_t outboundPendingME;
	memset(&outboundPendingME, 0, sizeof(me_t));
	//Any me_t fields specific to this measurement type go here:

	ret = RequestCommon(sourceIP, destinationIP, dstHostName, requestHeader, requestSize, &outboundPendingME, "BuildTickStampAttestationRequestPacket");
	if(ret != GENERIC_SUCCESS){
		printf("BuildTickStampAttestationRequestPacket: RequestCommon failed\n");
	}

	free(requestHeader);	

	return ret;
}

int ToggleAttackRequestPacket(char * sourceIP, char * destinationIP, char * dstHostName)
{
	int ret;
	request_hdr_t * requestHeader;
	unsigned int requestSize = 0;

	// then proceed to build the normal self request packet
	requestSize = sizeof(request_hdr_t);
	requestHeader = (request_hdr_t *)malloc(requestSize);
	if(requestHeader == NULL){
		cout << "ToggleAttackRequestPacket: malloc() failed\n";
		return GENERIC_ERROR;
	}

	requestHeader->type = TOGGLE_ATTACK;
	requestHeader->wcharArraySize = 0;
	requestHeader->wcharArray = NULL;
	requestHeader->rand = 0;
	requestHeader->pendingID = 0;


	//Get ready to insert a pending measurement
	me_t outboundPendingME;
	memset(&outboundPendingME, 0, sizeof(me_t));
	//Any me_t fields specific to this measurement type go here:

	ret = RequestCommon(sourceIP, destinationIP, dstHostName, requestHeader, requestSize, &outboundPendingME, "ToggleAttackRequestPacket");
	if(ret != GENERIC_SUCCESS){
		printf("ToggleAttackRequestPacket: RequestCommon failed\n");
	}

	free(requestHeader);	

	return ret;
}

int CheckHostIPValues(string & ipString, string & hostName, bool * ipExists, bool * nameExists){
	char hostNameBuffer[128];
	char ipStrBuffer[16];
	int ret;
	bool result = false;

	memset(ipStrBuffer,0,16);
	memset(hostNameBuffer,0,128);

	ret = IsHostName((char *)ipString.c_str(), &result);
	if(ret != GENERIC_SUCCESS){
		printf("CheckHostIPValues(): IsHostName() failed\n");
		return GENERIC_ERROR;
	}

	// The IP address is actually a host name, so try to fix it
	if(result == true){
		hostName = ipString;
		ipString = "";

		ret = GetIpByHostName((char *)hostName.c_str(), ipStrBuffer);
		if(ret != GENERIC_SUCCESS){
			printf("CheckHostIPValues(): GetIpByHostName() failed\n");
		}else{
			ipString = ipStrBuffer;
		}
	}

	if(!hostName.empty()){
		*nameExists = true;
	}
	if(!ipString.empty()){
		*ipExists = true;
	}

	// if neither exists, error out
	if(*nameExists == false && *ipExists == false){
		printf("CheckHostIPValues(): Both host name and ip string passed were null\n");
		return GENERIC_ERROR;
	}
	else if(*nameExists == true && *ipExists == false){
		ret = GetIpByHostName((char *)hostName.c_str(), ipStrBuffer);
		if(ret != GENERIC_SUCCESS || ipStrBuffer == NULL){
			printf("CheckHostIPValues(): GetIpByHostName() failed\n");
			return GENERIC_ERROR;
		}
		else{
			//sprintf_s(ipString,16,"%s",ipStrBuffer);
			ipString = ipStrBuffer;
			*ipExists = true;
		}
	}
	else if(*nameExists == false && *ipExists == true){
		ret = GetHostNameByIP((char *)ipString.c_str(), hostNameBuffer);
		if(ret != GENERIC_SUCCESS || hostNameBuffer == NULL){	
			printf("CheckHostIPValues(): GetHostNameByIP() failed\n");
			return NO_RESULTS_FOUND;
		}
		else{
			//sprintf_s(hostName,128,"%s",hostNameBuffer);
			hostName = hostNameBuffer;
			*nameExists = true;
		}
	}

	return GENERIC_SUCCESS;
}


int GetHostNameByIP(const char * ipAddress, char * hostName){
	int err;
	sockaddr_in tAddr;
	memset(&tAddr, 0, sizeof(sockaddr_in));
	tAddr.sin_family=AF_INET;
	tAddr.sin_addr.S_un.S_addr=inet_addr(ipAddress);

	char szHostName[128];
	memset(szHostName,0,128);
	if(err = getnameinfo((const struct sockaddr *)&tAddr, sizeof(sockaddr_in), szHostName, 128, 0, 0, NI_NAMEREQD) != 0){
		printf("GetHostNameByIP: getnameinfo failed with error: %d\n", err);
		sprintf_s(hostName,128,"%s","");
		return GENERIC_ERROR;
	}	

	if(szHostName != NULL){
		sprintf_s(hostName,128,"%s",szHostName);
	}else{
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int GetIpByHostName(const char * hostName, char * ipAddress){
	struct addrinfo hints, *res;
	struct in_addr addr;
	int err;
	
	memset(ipAddress,0,16);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	if((err = getaddrinfo(hostName, NULL, &hints, &res)) != 0){
		printf("GetIpByHostName: error %d\n", err);
		sprintf_s(ipAddress,16,"%s","");
		return GENERIC_ERROR;
	}

	addr.S_un = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.S_un;
	sprintf_s(ipAddress,16,"%s",inet_ntoa(addr));
	
    freeaddrinfo(res);
	return GENERIC_SUCCESS;
}

int ResolveIPsAndNames(string * srcIP, string * dstIP, string * srcHostName, string * dstHostName){
	int ret;

	// if the srcIP is defined and valid
	if(srcIP->length() >= 7 && srcHostName->empty()){
	
		// if the source host is blank, try to get the host name from the ip

			const char * tempIP = srcIP->c_str();
			char tempHostName[128];
			ret = GetHostNameByIP(tempIP, tempHostName);
			if(ret != GENERIC_SUCCESS){
				printf("ResolveIPsAndNames: GetHostNameByIP failed\n");
				return GENERIC_ERROR;
			}

			if(tempHostName != NULL){
				*srcHostName = tempHostName;
			}else{
				printf("ResolveIPsAndNames: GetHostNameByIP returned a null host name\n");
				return GENERIC_ERROR;
			}
		
		// else if the host name is defined and not blank
	}else if(! srcHostName->empty() && srcIP->empty()){

		const char * tempHostName = srcHostName->c_str();
		char tempIP[128];
		ret = GetIpByHostName(tempHostName, tempIP);
		if(ret != GENERIC_SUCCESS){
			printf("ResolveIPsAndNames: getIPByHostName failed\n");
			return GENERIC_ERROR;
		}

		if(tempIP != NULL){
			*srcIP = tempIP;
		}else{
			printf("ResolveIPsAndNames: getIPByHostName returned a null ip address\n");
			return GENERIC_ERROR;
		}
	}

	// Now doing the same for the destination IP and HostName
	// if the dstIP is defined and valid
	if(dstIP->length() >= 7 && dstHostName->empty()){
	
		// if the dst host is blank, try to get the host name from the ip
	
			const char * tempIP = dstIP->c_str();
			char tempHostName[128];
			ret = GetHostNameByIP(tempIP, tempHostName);
			if(ret != GENERIC_SUCCESS){
				printf("ResolveIPsAndNames: GetHostNameByIP failed\n");
				return GENERIC_ERROR;
			}

			if(tempHostName != NULL){
				*dstHostName = tempHostName;
			}else{
				printf("ResolveIPsAndNames: GetHostNameByIP returned a null host name\n");
				return GENERIC_ERROR;
			}
		
		// else if the host name is defined and not blank
	}else if(! dstHostName->empty() && dstIP->empty()){

		// if the dst ip is blank, try to get the ip from the hostname
		const char * tempHostName = dstHostName->c_str();
		char tempIP[128];
		ret = GetIpByHostName(tempHostName, tempIP);
		if(ret != GENERIC_SUCCESS){
			printf("ResolveIPsAndNames: getIPByHostName failed\n");
			return GENERIC_ERROR;
		}

		if(tempIP != NULL){
			*dstIP = tempIP;
		}else{
			printf("ResolveIPsAndNames: getIPByHostName returned a null ip address\n");
			return GENERIC_ERROR;
		}
	}
	
	return GENERIC_SUCCESS;
}

int IsHostName(char * str, bool * result){
	bool alphaCharDetected = false;
	char charTemp;

	if(str == NULL){
		return GENERIC_ERROR;
	}

	if(strlen(str) == 0 || strcmp(str,"") == 0){
		*result = false;
		return GENERIC_SUCCESS;
	}
	

	for(unsigned int j = 0; j < strlen(str); j++){
		charTemp = str[j];
		// if character is not a number (ASCII value of char) or a period
		if(!((charTemp >= 48 && charTemp <= 57) || charTemp == 46)){
			alphaCharDetected = true;
		}
	}

	if(alphaCharDetected){
		*result = true;
	}else{
		*result = false;
	}

	return GENERIC_SUCCESS;
}

//This copies the data at requestHeader, so you can free the memory after this has been called
int RequestCommon(char * sourceIP, char * destinationIP, char * dstHostName, request_hdr_t * requestHeader, unsigned int requestSize, me_t * outboundPendingME, char * parentFuncName){
	int ret;
	unsigned short sourcePort = 0xDEAD;
	unsigned short destinationPort = 0xBEEF;
	unsigned char dstMac[6] = {0,0,0,0,0,0};
	ULONG dstMacLong[2] = {0,0};
	ULONG MACSize = 6;
	RawPacket RP;
	IPAddr srcIPAddr, dstIPAddr;

	srcIPAddr = inet_addr(sourceIP);
	dstIPAddr = inet_addr(destinationIP);

	//This is a quick hack to make it server be a bit smarter 
	//about what dst MAC is uses - gateway if the dst IP is non-local, 
	//otherwise the MAC specifically for the dst host
	//ASSUMPTION: that all hosts on the same /24 are on the same ethernet segment
	if(memcmp(&srcIPAddr, &dstIPAddr, 3) == 0){
		//send to a local host on the same ethernet segment directly
		ret = SendARP(dstIPAddr, srcIPAddr, &dstMacLong, &MACSize);
		if(ret != NO_ERROR){
			if(gUseBroadcastMAC){
				printf("%s: RequestCommon: Failed to get the MAC address for the destination host on the same local network. Defaulting to broadcast MAC\n", parentFuncName);
				memset(&dstMac, 0xFF, 6);
			}
			else{
				printf("%s: RequestCommon: Failed to get the MAC address for the destination host on the same local network. Broadcast MAC disabled, erroring out\n", parentFuncName);
				//UpdateReadinessByHostID(hostID, ARP_FAIL);
				//If we're going to error out and not send the packet, we need to delete the pending events
				//We will not delete the null measurement because it will have actually been sent
				if(strcmp("BuildNullSelfMeasurementRequestPacket", parentFuncName) != 0){
					if(strcmp("BuildSelfMeasurementRequestPacket", parentFuncName) != 0){
						ret = SelectPreviousPendingIDFromPendingME(outboundPendingME->id,outboundPendingME->nonce, &outboundPendingME->previousPendingID);
						if(ret != GENERIC_SUCCESS){
							printf("RequestCommon: SelectPreviousPendingIDFromPendingMEByID failed\n");
							return ret;
						}
						if(!gQuiet) printf("Deleting PendingMeasurementEvent id = %u\n", outboundPendingME->previousPendingID);
						DeleteFromTableByID("PendingMeasurementEvents", outboundPendingME->previousPendingID);
					}
					if(!gQuiet) printf("Deleting PendingMeasurementEvent id = %u\n", outboundPendingME->id);
					DeleteFromTableByID("PendingMeasurementEvents", outboundPendingME->id);
				
					return GENERIC_ERROR;
				}
			}
		}
		else{
			memcpy(&dstMac, &dstMacLong, 6);
		}
		RP.CreatePacket(globDeviceInfoPtr->PhysicalAddress, dstMac,
						inet_addr(sourceIP),inet_addr(destinationIP),sourcePort,destinationPort,
						(UCHAR*)requestHeader, requestSize);
	}
	else{
		//send to a non-local host, by way of the gateway
		RP.CreatePacket(globDeviceInfoPtr->PhysicalAddress, globDeviceInfoPtr->GatewayPhysicalAddress,
						inet_addr(sourceIP),inet_addr(destinationIP),sourcePort,destinationPort,
						(UCHAR*)requestHeader, requestSize);
	}

	RP.SendPacket(globDevice);

	return GENERIC_SUCCESS;
}
