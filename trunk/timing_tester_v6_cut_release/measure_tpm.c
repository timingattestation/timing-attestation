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

#include <ntddk.h>
#include "precomp.h"
#include "misc.h"
#include "measure_tpm.h"
#include "tpm.h"
#include "server_client_protocol.h"
#include "measure_self.h"
#include "sha1.h"
#include "Ntstrsafe.h"

extern PDRIVER_OBJECT gDriverObject;


NTSTATUS
SendTickStampAttestationPacket(PDRIVER_OBJECT driverObject, 
							PADAPT pAdapt, 
							unsigned int randFromServer, 
							unsigned int pendingIDFromServer,
							unsigned int numIterations){
	unsigned int currentPacketSize = 0;
	int ret = 0;
	NTSTATUS ntStatus;
	response_hdr_t responseHdr;
	self_check_t * pSelfCheck;
	unsigned char * pktBuffer;
	char errorMsgBuf[100];
	unsigned int selfMeasurementPacketSize = sizeof(response_hdr_t) + sizeof(self_check_t);

	KdPrint(("In SendTickStampAttestationPacket\n"));

	if (!gTPMEnabled)
	{
		KdPrint(("SendTickStampAttestationPacket: TPM Not enabled!\n"));
		return STATUS_INTERNAL_ERROR;
	}
	
	//We will never send more than an ethernet packet's worth of data at a time
	//so we can just reuse the same buffer over and over
	pktBuffer = ExAllocatePool(NonPagedPool, selfMeasurementPacketSize);			
	if(pktBuffer == NULL){
		return STATUS_NO_MEMORY;
	}

	//This packet can only be binary section measurements since now the type is on a per-function basis
	// memset(&responseHdr, 0xCC, sizeof(response_hdr_t));	// redundant
	responseHdr.rand = randFromServer; //Use the same number in the reply to make it 
								//easier to sync up the request and the response
	responseHdr.pendingID = pendingIDFromServer;
	responseHdr.type = TICKSTAMP_ATTESTATION;
	responseHdr.numElements = SELF_CHECKSUM_SIZE; //should be set to the number of 4 byte checksum pieces
	responseHdr.fragmentNumber = 0;

	currentPacketSize = 0;
	//Start with the header
	memcpy(pktBuffer+currentPacketSize, &responseHdr, sizeof(responseHdr));			
	currentPacketSize = sizeof(responseHdr);
	
	pSelfCheck = (self_check_t *)(pktBuffer+currentPacketSize);

	//ASSUMPTION: the below line assumes that the SelfCheck function
	//occurs no more than 4kb from the beginning of where the binary
	//is mapped into memory. If this changes, the below will need to change
	pSelfCheck->baseVA = driverObject->DriverStart;
	if(!gTimeDateStamp){ //First time we go get it
		gTimeDateStamp = FindSelfTimeDateStamp(pSelfCheck->baseVA);
	}
	pSelfCheck->timeDateStamp = gTimeDateStamp;
	pSelfCheck->nonce = randFromServer;
	
	KdPrint(("nonce = %#x\n", randFromServer));
	KdPrint(("baseVA = %#x\n", pSelfCheck->baseVA));
	KdPrint(("timeDateStamp = %#x\n", pSelfCheck->timeDateStamp));
	//If the nonce == 0, then this is a "null measurement", which is 
	//just being sent to determine the network RTT + overhead from
	//the networking code and misc in this client.
	//In which case it sets all the self_check_t values except the
	//self-checksum
	if(randFromServer != 0){
		//Copy in the checksum pieces
		SHA1String(pSelfCheck->startTickStamp.nonce, (unsigned char*)&(pSelfCheck->nonce),sizeof(unsigned int));
		memcpy(pSelfCheck->startTickStamp.digest, pSelfCheck->startTickStamp.nonce, TCG_HASH_SIZE);
		ret = TPM_TickStampBlob(&(pSelfCheck->startTickStamp));
		if (ret != GENERIC_SUCCESS)
		{
			KdPrint(("SendTickStampAttestationPacket: TPM_TickStampBlob of startTIckStamp failed\n"));
			ExFreePool(pktBuffer);
			return GENERIC_ERROR;
		}
		//use the signature of the starting tickstamp as the nonce to the self attestation
		//this way we know for sure that the start tick stamp occured BEFORE the self attestation began
		ret = SelfCheck_v6(driverObject, *((unsigned int *)(&pSelfCheck->startTickStamp.signature)), numIterations, pSelfCheck->baseVA, &(pSelfCheck->moduleInfo), &pSelfCheck->upperCycleCount, &pSelfCheck->lowerCycleCount, (unsigned int *)pSelfCheck->checksum);
tpmparent:
		if(ret != GENERIC_SUCCESS) return ret;
		SHA1String(pSelfCheck->endTickStamp.nonce, pSelfCheck->startTickStamp.signature, TCG_SIGNATURE_SIZE);
		SHA1String(pSelfCheck->endTickStamp.digest, (unsigned char *)(&pSelfCheck->checksum[0]),SELF_CHECKSUM_SIZE*sizeof(unsigned int));
		ret = TPM_TickStampBlob(&(pSelfCheck->endTickStamp));
		if (ret != GENERIC_SUCCESS)
		{
			KdPrint(("SendTickStampAttestationPacket: TPM_TickStampBlob of endTIckStamp failed\n"));
			ExFreePool(pktBuffer);
			return GENERIC_ERROR;
		}

		///gBaseVA = pSelfCheck->baseVA;
		if (gAttackActivated == 1)
			pSelfCheck->baseVA = gCheckmateCleanImage;
		//Automatically set gHookOffset, by using a label to the call to SelfCheck_v6
		/*__asm{
			lea edi, hookLabel;
			sub edi, 4;
			sub edi, gBaseVA;
			mov gHookOffset, edi;
		}*/

	}
	KdPrint(("ndisBase = %#x\n", pSelfCheck->moduleInfo.ndisInfo.base));
	KdPrint(("ndisTimeDateStamp = %#x\n", pSelfCheck->moduleInfo.ndisInfo.timeDateStamp));
	KdPrint(("ndisSizeOfImage = %#x\n", pSelfCheck->moduleInfo.ndisInfo.sizeOfImage));
	currentPacketSize += sizeof(self_check_t);

	//An entire self-measurement checksum buffer + headers should easily fit
	//into a single packet
	ret = SendPacket(pAdapt, pktBuffer, currentPacketSize, 0);

	//KdPrint(("Freeing pktBuffer %#x\n", pktBuffer));
	ExFreePool(pktBuffer); //No longer freed in a different function than its allocated		
	return STATUS_SUCCESS;
}



