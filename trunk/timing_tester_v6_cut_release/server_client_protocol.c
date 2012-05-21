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

//Structures and functions which support communication between
//server and client

#include "precomp.h"
#include "misc.h"
#include "server_client_protocol.h"
#include "PktHdr.h"
//Next two in lieu of a UtilRtns.h
USHORT GetIPChecksum(PUSHORT pIPH, USHORT usIPHdr); 
USHORT GetUDPChecksum(IPHdr * iph, UDPHeader * udph, unsigned char * data, unsigned int len);

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

NDIS_HANDLE     gPacketPoolH;
NDIS_HANDLE		gBufferPoolH;

//EXTERNS
extern NDIS_HANDLE DriverHandle;
extern NDIS_HANDLE ProtHandle;
extern ULONG gDstIP; //In PktHdr.h
extern ULONG gSrcIP; //In PktHdr.h
extern ULONG gSetInfoIP;

////////////////////////////////////////////////////////
//BEGIN CODE
////////////////////////////////////////////////////////


//SendPacket:
//Prepends the IP/UDP headers and then sends the packet.
//Now supports IP fragmentation
//Should not know anything about any of the message types

//Inputs:
//pktBuffer: char array where packet data is stored
//len: length of the pktBuffer array
//fragOffsetAndFlags: 
//	If fragOffsetAndFlags != 0, then the packet to be sent will be a fragment.
//	fragOffsetAndFlags should also contain the correct IP flags embedded in it, and it 
//	SHOULD NOT be passed in already in network byte ordering.
NTSTATUS
SendPacket(PADAPT pAdapt, unsigned char * pktBuffer, unsigned int len, unsigned short fragOffsetAndFlags){
	NDIS_STATUS aStat;
	PNDIS_PACKET ndisPktPtr;
	PNDIS_BUFFER ndisBufPtr;
	PVOID ndisMemPtr;
	KIRQL aIrqL;
	EthHdr myEth;
	IPHdr myIP;
	UDPHeader myUDP;
	unsigned char * pktWithHeaders;
	unsigned int pktWithHeadersLen;
	unsigned int offset;
	PNDIS_PACKET_STACK        pStack;
	BOOLEAN                   Remaining;
	char eSrc[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	char eDst[6] = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44};

	KdPrint(("In SendPacket\n"));
	pktWithHeadersLen = sizeof(EthHdr) + sizeof(IPHdr) + sizeof(UDPHeader) + len;
	//Before we do anything else, we need to wrap our packet data in network protocol headers
	memcpy(myEth.DestMAC, gDstMAC, 6);
	memcpy(myEth.SrcMAC, gSrcMAC, 6);
	myEth.Type = htons(EthHTypeIP);

	memset(&myIP, 0, sizeof(IPHdr));
	myIP.DestinationAddress = gDstIP;
	if(gSetInfoIP == 0){
		myIP.SourceAddress = gSrcIP;
	}else{
		myIP.SourceAddress = gSetInfoIP;
	}
	myIP.Identification = htons(0x1338);
	myIP.IPHdrLen = 5; //size is 20 bytes, which is 5 four-byte-dwords
	myIP.IPVer = 4;
	myIP.Protocol = IPPROTO_UDP;
	myIP.TotalLength = htons(sizeof(IPHdr) + sizeof(UDPHeader) + (USHORT)len); //Size of datagram (sans header)
	myIP.TTL = 64;
	myIP.TypeOfService = 0xFF; //This gets filtered on our internal network
	myIP.FragmentationSummary = htons(fragOffsetAndFlags);
	myIP.Checksum = GetIPChecksum((PUSHORT)&myIP, sizeof(IPHdr));

	memset(&myUDP, 0, sizeof(UDPHeader));
	myUDP.Dest = htons(0xDEAD);
	myUDP.Source = htons(0xBEEF);
	myUDP.Length = htons(sizeof(UDPHeader) + (USHORT)len); //Size of data
	myUDP.Checksum = GetUDPChecksum(&myIP, &myUDP, pktBuffer, len);

	//Headers created, now start to create an NDIS_PACKET
	NdisAllocatePacket( &aStat,	&ndisPktPtr, gPacketPoolH);			
	if(aStat != NDIS_STATUS_SUCCESS)
	{
		KdPrint(("SendPacket: NdisAllocatePacket failed\n"));
		return GENERIC_ERROR;
	}

	//KdPrint(("&ndisPktPtr = %#x, ndisPktPtr = %#x\n", &ndisPktPtr, ndisPktPtr));

	// grab some contiguous memory in which to build the packet
	//Uses default memory tag
	if(NdisAllocateMemoryWithTag( &ndisMemPtr, pktWithHeadersLen, 0) != NDIS_STATUS_SUCCESS){	
		KdPrint(("SendPacket: NdisAllocateMemory failed\n"));
		NdisFreePacket(ndisPktPtr);																
		return GENERIC_ERROR;
	}


	//Now copy in all the headers and data into our contiguous memory block

	KdPrint(("ndisMemPtr = %#x, pktWithHeadersLen = %#x\n", ndisMemPtr, pktWithHeadersLen));
	memcpy(ndisMemPtr, &myEth, sizeof(EthHdr));
	offset = sizeof(EthHdr);
	memcpy(((char *)ndisMemPtr)+offset, &myIP, sizeof(IPHdr));
	offset += sizeof(IPHdr);
	memcpy(((char *)ndisMemPtr)+offset, &myUDP, sizeof(UDPHeader));
	offset += sizeof(UDPHeader);
	memcpy(((char *)ndisMemPtr)+offset, pktBuffer, len);

	// Create a Buffer Descriptor for contiguous our memory buffer
	NdisAllocateBuffer(&aStat, &ndisBufPtr, gBufferPoolH, ndisMemPtr, pktWithHeadersLen);		
	if(aStat != NDIS_STATUS_SUCCESS)
	{
		KdPrint(("SendPacket: NdisAllocateBuffer failed\n"));
		NdisFreeMemory(ndisMemPtr, pktWithHeadersLen, 0);										
		NdisFreePacket(ndisPktPtr);																
		return GENERIC_ERROR;
	}
	//KdPrint(("&ndisBufPtr = %#x, ndisBufPtr = %#x\n", &ndisBufPtr, ndisBufPtr));

	// hook (chain) our Buffer at the end of the packet (actually should be the only block but ..)
	NdisChainBufferAtBack(ndisPktPtr, ndisBufPtr);

	KdPrint(("X: Before NdisSend: pAdapt = %#x\n", pAdapt));
	NdisSend( &aStat, pAdapt->BindingHandle, ndisPktPtr );		// Send it down to the NIC - will we ever see it again? Maybe
	KdPrint(("X: NdisSend returned status:0x%x\n", aStat));
	///__asm { int 3 }

	// We have to free the packet in all cases except for NDIS_STATUS_PENDING
	// Everything else means we're done with the packet.

	switch(aStat){
		case NDIS_STATUS_SUCCESS:
			KdPrint(("NdisSend NDIS_STATUS_SUCCESS\n"));
			//DbgPrint("a\n");
			break;
		case NDIS_STATUS_PENDING:
			//It will go to PtSendComplete
			KdPrint(("NdisSend NDIS_STATUS_PENDING\n"));
			//DbgPrint("b\n");
			break;
		case NDIS_STATUS_FAILURE:
			KdPrint(("NDIS_STATUS_FAILURE"));
			//DbgPrint("c\n");
			break;
		case NDIS_STATUS_NOT_RECOGNIZED:
			KdPrint(("NdisSend NDIS_STATUS_NOT_RECOGNIZED\n"));
			break;
		case NDIS_STATUS_NOT_ACCEPTED:
			KdPrint(("NdisSend NDIS_STATUS_NOT_ACCEPTED\n"));
			break;
		case NDIS_STATUS_RESOURCES:
			KdPrint(("NdisSend NDIS_STATUS_RESOURCES\n"));
			break;
		case NDIS_STATUS_NOT_SUPPORTED:
			KdPrint(("NdisSend NDIS_STATUS_NOT_SUPPORTED\n"));
			break;
		case NDIS_STATUS_CLOSING_INDICATING:
			KdPrint(("NdisSend NDIS_STATUS_CLOSING_INDICATING\n"));
			break;
		case NDIS_STATUS_INVALID_LENGTH:
			KdPrint(("NdisSend NDIS_STATUS_INVALID_LENGTH\n"));
			break;
		case NDIS_STATUS_BUFFER_TOO_SHORT:
			KdPrint(("NdisSend NDIS_STATUS_BUFFER_TOO_SHORT\n"));
			break;
		case NDIS_STATUS_INVALID_DATA:
			KdPrint(("NdisSend NDIS_STATUS_INVALID_DATA\n"));
			break;
		case NDIS_STATUS_INVALID_OID:
			KdPrint(("NdisSend NDIS_STATUS_INVALID_OID\n"));
			break;
		case NDIS_STATUS_INVALID_PACKET:
			KdPrint(("NDIS_STATUS_INVALID_PACKET"));
			break;
		case NDIS_STATUS_CLOSING:
			KdPrint(("NDIS_STATUS_CLOSING"));
			break;
		case NDIS_STATUS_RESET_IN_PROGRESS:
			KdPrint(("NDIS_STATUS_RESET_IN_PROGRESS"));
			break;
		default:
			KdPrint((" was error in SendRaw\n")); //This way it will be obvious if it's some other error
			//DbgPrint("d\n");
	}
	if (aStat != NDIS_STATUS_PENDING)
	{
		KdPrint(("Freeing Packet memory"));
		PtFreePacket(ndisPktPtr);														
	}

	KdPrint(("Returned from NdisSend, and now exiting SendPacket\n"));
	return STATUS_SUCCESS;
}

//TODO: document this somewhere real:
//The format of the error packet is response_hdr_t followed by a char array
//of size errMsgLenWithNull. The response_hdr_t.numElements holds the string length
//including the null character
void SendErrorPacket(PADAPT pAdapt, char * errMsg, unsigned int errMsgLenWithNull, unsigned int randFromServer, unsigned int pendingIDFromServer){
	unsigned char * pktBuffer;
	response_hdr_t responseHdr;
	unsigned int currentPacketSize = 0, errorPacketDataSize = 0;

	//Sanity check our error message.
	if(errMsg == 0 || strlen(errMsg) != (errMsgLenWithNull-1)){
		KdPrint(("SendErrorPacket: inconsistent error message length. No msg sent.\n"));
		return;
	}

	errorPacketDataSize = sizeof(response_hdr_t) + errMsgLenWithNull;

	//We will never send more than an ethernet packet's worth of data at a time
	//so we can just reuse the same buffer over and over
	pktBuffer = ExAllocatePool(NonPagedPool, errorPacketDataSize);			
	if(pktBuffer == NULL){
		KdPrint(("SendErrorPacket: ExAllocatePool failed\n"));
		return;
	}
	memset(pktBuffer, 0xCC, errorPacketDataSize);

	memset(&responseHdr, 0, sizeof(response_hdr_t));
	responseHdr.rand = randFromServer;
	responseHdr.type = ERROR_MSG;
	responseHdr.numElements = errMsgLenWithNull;
	responseHdr.pendingID = pendingIDFromServer;

	memcpy(pktBuffer, &responseHdr, sizeof(response_hdr_t));
	currentPacketSize = sizeof(responseHdr);

	memcpy(pktBuffer+currentPacketSize, errMsg, errMsgLenWithNull);
	currentPacketSize += errMsgLenWithNull;

	//Sanity check against dev error if and when this gets more complicated
	if(errorPacketDataSize != currentPacketSize){
		KdPrint(("You modified SendErrorPacket such that it's now broken or you need to update the sanity check.\n"));
		ExFreePool(pktBuffer);												
		return;
	}

	//If it fails we're basically mute except for DbgPrints
	if(SendPacket(pAdapt, pktBuffer, errorPacketDataSize, 0) != STATUS_SUCCESS){
		KdPrint(("SendErrorPacket: SendPacket failed\n"));
	}
	else{
		KdPrint(("SendErrorPacket: SendPacket succeeded\n"));
	}

	ExFreePool(pktBuffer);													
}
