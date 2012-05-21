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

//This code is a modified version of the winpcap udpdump.c example code
//included with the winpcap developers pack 4.0.2
//Xeno Kovah - 4/5/09


/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#define WIN32

#include "pcap.h"
#include "thread_pcap.h"
#include "global_includes.h"
#include "server_client_protocol.h"
#include "IPTypes.h" // for IP_ADAPTER_INFO etc
#include "IPHlpApi.h" //for GetAdaptersInfo etc
#include <queue>
#include "database_mysql2.h" //only for MsgTypeToString which had to be moved there as a gross hack

//From raw_packet.h but don't want to include raw_packet.h
//because it screws up includes and such
unsigned int BytesTo32(unsigned char W,unsigned char X,unsigned char Y,unsigned char Z);


extern "C"{
	#include "database_mysql.h"
}

using namespace std;

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////


////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

char gUseBroadcastMAC;
//EXTERNS

extern int gVerbose, gQuiet;

extern "C" MYSQL mysqlMeasurements;
extern "C" HANDLE mysqlMutex;

extern pcap_if_t * globDevice;

//The pcap portion just queues up the relevant information so that
//it can pass it off to the measurement
extern queue<me_t *> measurementEventQueue; //from thread_parse_measurements.cpp
//For the pcap thread to wake the measurement parsing thread
extern HANDLE measurementEvent; //from thread_parse_measurements.cpp
//To prevent the pcap and measurement parsing thread from stomping on the queue
extern HANDLE measurementEventQueueMutex; //from thread_parse_measurements.cpp
////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

DWORD WINAPI PcapThread(LPVOID lpParam)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *adhandle;
	u_int netmask;
	char packet_filter[] = "udp port 0xDEAD";
	struct bpf_program fcode;

	/* Open the adapter */
	if ((adhandle = pcap_open_live(globDevice->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter.\n");
		return GENERIC_ERROR;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		return GENERIC_ERROR;
	}
	
	if(globDevice->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(globDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		return GENERIC_ERROR;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		return GENERIC_ERROR;
	}
	
	printf("\nlistening on %s...\n", globDevice->description);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	time_t local_tv_sec;
	unsigned int ret, holder;
	unsigned int showPacketArrivalTimes = 0;

	//tmpME is dealloced either on error or when it is consumed by
	//the MeasurementParsingThread
	me_t * tmpME = (me_t *)malloc(sizeof(me_t));
	memset(tmpME, 0, sizeof(me_t));
	if(showPacketArrivalTimes){
		// convert the timestamp to readable format
		local_tv_sec = header->ts.tv_sec;
		ltime=localtime(&local_tv_sec);
		
		strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
		//print timestamp and length of the packet
		printf("%s.%.6d len:%d ", timestr, (int)header->ts.tv_usec, (int)header->len);
	}

	// retrieve the position of the ip header
	ih = (ip_header *) (pkt_data + ETH_HDR_SIZE);

	// retrieve the position of the udp header
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((unsigned char*)ih + ip_len);

	//If the IPID + fragment offset is 0x1337 it's outbound
	//Do something based on that :)
	short ipid = ntohs(ih->identification);
	short df = ih->flags_fo >> 6; //Only want the DF flag, 2nd to most significant bit, 
					//but allow the endianness to be backwards so that flags_fo
					//should look like 0x0040 (assuming fragment offset = 0)
	if((ipid + df) == (0x1336 + 1)){ //TODO: when this settles down make it more streamlined

		request_hdr_t * req = (request_hdr_t *)((char *)uh + sizeof(udp_header));

		if(gVerbose){
			printf("Measurement type %s request packet seen from ip = %#x at time %u seconds %u microseconds\n", MsgTypeToString(req->type), ih->saddr, (unsigned int)header->ts.tv_sec, (unsigned int)header->ts.tv_usec);
		}
		else{
			if(!gQuiet) printf("\nMeasurement type %s request packet seen\n\n", (char *)MsgTypeToString(req->type));
		}

		//Lookup the existing entry
		ret = UpdatePendingMETime(req->pendingID, header->ts.tv_sec, header->ts.tv_usec);
		if(ret != GENERIC_SUCCESS){
			printf("packet_handler: UpdatePendingMETime failed for id = %u, ip = %#x, type = %#x, nonce = %#x\n", req->pendingID, tmpME->ip, tmpME->type, tmpME->nonce);
			free(tmpME);	
			return;
		}
		//We need to update the placeholder self-attestation entry in the
		//PendingMeasurementEvents table too
		ret = SelectPreviousPendingIDFromPendingME(req->pendingID, req->rand, &holder);
		if(ret != GENERIC_SUCCESS){
			printf("packet_handler: SelectPreviousPendingIDFromPendingMEByID failed\n");
			return;
		}

		ret = UpdatePendingMETime(holder, header->ts.tv_sec, header->ts.tv_usec);
		if(ret != GENERIC_SUCCESS){
			printf("packet_handler: UpdatePendingMETime failed for id = %u, ip = %#x, type = %#x, nonce = %#x\n", holder, tmpME->ip, tmpME->type, tmpME->nonce);
			free(tmpME);	
			return;
		}

		//The measurement event won't be used by MeasurementParsingThread. 
		//So we should dealloc it now.
		free(tmpME);	
		return;
	}

	//if the IPID is 0x1338 it's inbound
	if(ipid == 0x1338){
		//Queue up 'me_t's for the MeasurementParsingThread
		response_hdr_t * msg = (response_hdr_t *)((char *)uh + sizeof(udp_header));
		tmpME->type = msg->type;
		tmpME->nonce = msg->rand;
		tmpME->id = msg->pendingID;
		tmpME->timeInSeconds = header->ts.tv_sec;
		tmpME->timeInMicroseconds = header->ts.tv_usec;
		tmpME->ip = *(unsigned int *)&(ih->saddr);
		
		if(gVerbose){
			printf("Measurement type %s response packet seen from ip = %#x at time %u seconds %u microseconds\n", MsgTypeToString((msgType)(tmpME->type)), ih->saddr, (int)header->ts.tv_sec, (int)header->ts.tv_usec);
		}
		else{
			if(!gQuiet) printf("\nMeasurement type %s response packet seen\n\n", MsgTypeToString((msgType)(tmpME->type)));
		}

		ret = SelectHostIDByNetorderIP(tmpME->ip, &(tmpME->hostID));
		if(ret != GENERIC_SUCCESS){
			printf("packet_handler: SelectHostIDByNetorderIP failed");
			free(tmpME);	
			return;
		}

		//Make a copy of the packet, but don't include the headers
		tmpME->pktLen = header->len - ETH_HDR_SIZE - ip_len - sizeof(udp_header);
		tmpME->pktData = (unsigned char *)malloc(tmpME->pktLen);
		memcpy(tmpME->pktData, msg, tmpME->pktLen);
		if(WaitForSingleObject(measurementEventQueueMutex, INFINITE) != WAIT_OBJECT_0){
			printf("packet_handler: Couldn't acquire mutex. Returning\n");
			__asm{int 3};
			free(tmpME->pktData);
			free(tmpME);
			return;
		}

		measurementEventQueue.push(tmpME);
		if(!ReleaseMutex(measurementEventQueueMutex)){
			printf("packet_handler: Couldn't release mutex. Returning\n");
			__asm{int 3};
			free(tmpME->pktData);
			free(tmpME);
			return;
		}

		//Notify the measurement parsing thread 
		SetEvent(measurementEvent);

	}
}
//
////Just for watching simple example of a handler, and it's memory usage pattern
/////* Callback function invoked by libpcap for every incoming packet */
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
//{
//	struct tm *ltime;
//	char timestr[16];
//	time_t local_tv_sec;
//
//	/*
//	 * unused parameters
//	 */
//	(VOID)(param);
//	(VOID)(pkt_data);
//
//	/* convert the timestamp to readable format */
//	local_tv_sec = header->ts.tv_sec;
//	ltime=localtime(&local_tv_sec);
//	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
//	
//	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
//	
//}


//Xeno changed this to return a pointer
//it was returning its own locally allocated struct for use
//in the calling function which is obviously bad mojo
//NOTE: CALLER MUST FREE THE RETURNED DeviceInfo!
DeviceInfo * GetAdapterInfo(pcap_if_t* Device)
{
	//NOTE: DevInfo will be transfered to a global and used for the lifetime
	//of the program, so this should only be dealloced on error
	DeviceInfo * DevInfo = (DeviceInfo *)malloc(sizeof(DeviceInfo));
	memset(DevInfo,0,sizeof(DeviceInfo));

	IP_ADAPTER_INFO* AdapterInfo = new IP_ADAPTER_INFO [48];
	ULONG AIS = sizeof(IP_ADAPTER_INFO) * 48;

	GetAdaptersInfo(AdapterInfo,&AIS);

	for(IP_ADAPTER_INFO* Current = AdapterInfo;Current != NULL;Current = Current->Next)
	{
		if(strstr(Device->name,Current->AdapterName)!=0)
		
		{	
			DevInfo->IP = BytesTo32(Device->addresses->addr->sa_data[2],Device->addresses->addr->sa_data[3],
			Device->addresses->addr->sa_data[4],Device->addresses->addr->sa_data[5]);

			DevInfo->DefaultGateway = inet_addr(Current->GatewayList.IpAddress.String);	// DevInfo->DefaultGateway
			DevInfo->IP = inet_addr(Current->IpAddressList.IpAddress.String); //DevInfo->IP
			memcpy((void*)DevInfo->PhysicalAddress,(void*)(Current->Address),6); //DevInfo->PhysicalAddress
			ULONG MACSize = 6;
			if(gUseBroadcastMAC || SendARP(DevInfo->DefaultGateway,NULL,(void*)DevInfo->GatewayPhysicalAddress,&MACSize)!=NO_ERROR){
				printf("SendARP Failed. No default gateway. Defaulting to broadcast.\n");
				memset(DevInfo->GatewayPhysicalAddress, 0xFF, 6);
			}
			DevInfo->Exists = true;
			//IMPORTANT! Otherwise it leaks 31k! (Emmanuel Herrera code FTL)
			delete AdapterInfo;
			return DevInfo;
		}
	}
	DevInfo->Exists = false;
	//IMPORTANT! Otherwise it leaks 31k! (Emmanuel Herrera code FTL)
	delete AdapterInfo;
	return DevInfo;
}