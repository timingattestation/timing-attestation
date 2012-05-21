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

//The single function in this file, FilterPacket(), is called for every packet
//seen incoming or outgoing. We use this to hide the measurement requests
//and responces from the OS and tools like Wireshark/MS netmon

//Formerly FiltrRtns.cpp
/**************************************************************************************************/      
/*                                                                                                */      
/* Copyright (C) 2003, James Antognini, antognini@mindspring.com.                                 */
/*                                                                                                */      
/**************************************************************************************************/      
//http://www.wd-3.com/archive/ExtendingPassthru2.htm
//Companion Sample Code for the Article
//"Extending the Microsoft PassThru NDIS Intermediate Driver"
//
//Portions Copyright ©1992-2000 Microsoft Corporation; used by permission.
//Portions Copyright © 2003 Printing Communications Associates, Inc. (PCAUSA)
//
//The right to use this code in your own derivative works is granted so long as
//
//Your own derivative works include significant modifications of your own.
//You retain the above copyright notices and this paragraph in its entirety within sources derived from this code.
//This product includes software developed by PCAUSA. The name of PCAUSA may not be used to endorse or promote products derived from this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

extern "C"
{
#include <ndis.h>
#include "misc.h"
#include "passthru.h"
#include "PktHdr.h"
#include "WMIFunc.h"
#include "measure_self.h"
#include "measure_tpm.h"
//#include "exclusivity.h"
#include "Ntstrsafe.h"
#include "pe.h"
}

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

//EXTERNS

//Imported from measure_binary.c - quick and dirty since it didn't like being in the .h file
extern "C" NDIS_STATUS ReceivedBinaryMeasurementRequest(request_hdr_t * pReqHdr);

//from exclusivity.c
extern "C" PKDPC gDPC;

//from passthru.c
extern "C" PDRIVER_OBJECT gDriverObject;

//from measure_self.c
extern "C" unsigned int gRelativeMinicheckEnd;

/**************************************************************************************************/      
/*                                                                                                */      
/**************************************************************************************************/      
extern "C"
NDIS_STATUS
FilterPacket(
             PADAPT               pAdapt,             // Address of adapter structure.
             PNDIS_PACKET         pPktDesc,           // Address of NDIS_PACKET, if available.  NULL if not.
             PUCHAR               pPayload,           // Address of packet payload if NDIS_PACKET is NULL.  Must contain at least the ethernet header and, 
                                                      //   if the type is IP, the IP header or, if the type is ARP or RARP, the ARP or RARP structure.
             BOOLEAN              bSend,              // TRUE if Send, FALSE if Receive.
             PBOOLEAN             pBDecision          // Address of boolean variable, whose value will be:  TRUE => drop packet and FALSE => do not drop.
                                                      //   But this is meaningful only if returned status is NDIS_STATUS_SUCCESS.
            )
{
#define                 szPayloadCopy ETH_MAX_PACKET_SIZE
UCHAR                   PayloadCopy[szPayloadCopy];  // Area to receive packet payload if NDIS_PACKET provided.
pEthHdr                 pETH;
pIPHdr                  pIPH;
pUDPHeader				 pUDPH;
ULONG const             LoopLim = 5;
ULONG					IPAddr, ulOrigPayload;
char donePrinting = 0;
BOOLEAN                 bGotStorage = FALSE;

*pBDecision = FALSE;                                 // Default action is not to drop the packet.
request_hdr_t * pReqHdr;
NTSTATUS ntStatus;
KIRQL oldIRQL;
char errorMsgBuf[100];
//for the attacker
unsigned int displacement;
char hookBytes[5];
char origBytes[5];
//KdPrint(("In FilterPacket\n"));

 
if (NULL!=pPktDesc)                               // NDIS_PACKET provided?
  GetPktPayload(pPktDesc,                         // Copy payload
                PayloadCopy,                      //   to area.
                szPayloadCopy,                    // Amount of space in area.
                &ulOrigPayload                    // Return number of bytes in packet.
               );

else
  NdisMoveMemory(PayloadCopy,                     // An IP packet (on ethernet) comprises the ethernet header + the IP header/body.  An ARP or RARP packet
                 pPayload,                        // similarly comprises the ethernet header and the ARP or RARP body.  Since the mapped IP header is 20
                 sizeof(EthHdr)+sizeof(IPHdr)     // bytes and an ARP or RARP is 28 bytes, an amount = sizeof(EthHdr)+sizeof(IPHdr) is safely copied.
                );

pETH = (pEthHdr)PayloadCopy;                      // Point to ethernet header.

if (EthHTypeIP!=RtlUshortByteSwap(pETH->Type)){    // No IP header?
	KdPrint(("Non-IP abort\n"));
	return NDIS_STATUS_SUCCESS;
}

//Copy the incoming packet's source MAC to use as the outgoing packet's destination MAC
memcpy(gDstMAC, pETH->SrcMAC, 6);
memcpy(gSrcMAC, pETH->DestMAC, 6);

pIPH = (pIPHdr)(PayloadCopy + sizeof(EthHdr));    // Point to IP header in copy of payload.

if (TRUE==bSend){                                  // Packet being sent
	if(pIPH->Identification == 0x3813){
		KdPrint(("\nOUTBOUND FILTERED PACKET\n\n"));
		//*pBDecision = TRUE; //Don't pass the packet to lower layers, only if we're hiding the packets
	}
}
else{
	pUDPH = (pUDPHeader)((char *)pIPH + sizeof(IPHdr));

	//Need a better CC, but this is my lazy solution for now
	//this should minimize false positives
	if(pIPH->DoNotFragment != 0 && (pIPH->Identification + pIPH->DoNotFragment) == (0x3613 + 1)){
		//*pBDecision = TRUE; //Don't pass the packet to higher layers, only if we're hiding the packets
		//TODO: need to determine if this will ever exceed the amount that has been
		//safely copied above
		pReqHdr = (request_hdr_t *)((char *)pIPH + sizeof(IPHdr) + sizeof(UDPHeader));
		if (gCrashed == FALSE && gPFNFound == TRUE)
		{
			switch(pReqHdr->type){

			case TIMING_TEST:
				KdPrint(("\nSAW THE TIMING TEST CONTROL PACKET\n\n"));
				__asm { cli };
				KeRaiseIrql(HIGH_LEVEL, &oldIRQL);
				gDstIP = pIPH->SourceAddress;
				gSrcIP = pIPH->DestinationAddress;
				//we're using pReqHdr->rand as the requested number of iterations
				//that way it can be varied easily for testing different number of iterations
				ntStatus = SendSelfMeasurementsPackets(gDriverObject, pAdapt, pReqHdr->rand, pReqHdr->pendingID, pReqHdr->rand);
//the label is to make sure I don't accidentally grab the offset to the call to SendSelfMeasurementPackets
//in a different case statement when hardcoding in the offset in tiresias (also makes it easier to find in IDA)
timegrandparent:
				if(ntStatus != STATUS_SUCCESS){
					KdPrint(("SendBinaryMeasurementsPackets failed with ntStatus = %#x\n", ntStatus));
					RtlStringCbPrintfA(errorMsgBuf, 100, "SendBinaryMeasurementsPackets failed with ntStatus = %#x", ntStatus);
					SendErrorPacket(pAdapt, errorMsgBuf, strlen(errorMsgBuf)+1, pReqHdr->rand, pReqHdr->pendingID);
				}
				KeLowerIrql(oldIRQL);
				__asm { sti };
				break;

			case TOGGLE_ATTACK:
				if (!gAttackActivated)
				{
					DisableWP();
					//determine the relative displacement from the start of SelfCheck_v6+5
					displacement = ((unsigned int)SelfCheck_Attack - ((unsigned int)SelfCheck_v6 + 5));
					hookBytes[0] = 0xE9; //jmp near relative
					hookBytes[1] = (char)(displacement & 0x000000FF); //little endian order
					hookBytes[2] = (char)((displacement >> 8) & 0x000000FF); 
					hookBytes[3] = (char)((displacement >> 16) & 0x000000FF); 
					hookBytes[4] = (char)((displacement >> 24) & 0x000000FF);
					memcpy(SelfCheck_v6, hookBytes, 5);
					EnableWP();
					gAttackActivated = 1;
					DbgPrint("ATTACK CODE ACTIVATED\n");					
				} else {
					origBytes[0] = 0x8B;
					origBytes[1] = 0xFF;//mov edi, edi
					origBytes[2] = 0x55;//push ebp
					origBytes[3] = 0x8B;
					origBytes[4] = 0xEC;//mov ebp, esp

					DisableWP();
					memcpy(SelfCheck_v6, origBytes, 5);
					EnableWP();
					gAttackActivated = 0;
					DbgPrint("ATTACK CODE TURNED OFF\n");
					//attack stuff
					//gBaseVA = (unsigned int)gDriverObject->DriverStart;
					//gHookLocation = gBaseVA + gHookOffset;
					//end attack stuff
				}
				break;
			case TICKSTAMP_ATTESTATION:
				KdPrint(("\nSAW THE TICKSTAMP ATTESTATION CONTROL PACKET\n\n"));
				__asm { cli };
				KeRaiseIrql(HIGH_LEVEL, &oldIRQL);
				gDstIP = pIPH->SourceAddress;
				gSrcIP = pIPH->DestinationAddress;
				//we're using pReqHdr->rand as the requested number of iterations
				//that way it can be varied easily for testing different number of iterations
				//NOTE: can't handle this in the current tiresias. Can't have two different parent/grandparents for a single type of measurement
				//so this one will just go unverified for now
				ntStatus = SendSelfMeasurementsPackets(gDriverObject, pAdapt, pReqHdr->rand, pReqHdr->pendingID, pReqHdr->rand);
				if(ntStatus != STATUS_SUCCESS){
					KdPrint(("SendBinaryMeasurementsPackets failed with ntStatus = %#x\n", ntStatus));
					RtlStringCbPrintfA(errorMsgBuf, 100, "SendBinaryMeasurementsPackets failed with ntStatus = %#x", ntStatus);
					SendErrorPacket(pAdapt, errorMsgBuf, strlen(errorMsgBuf)+1, pReqHdr->rand, pReqHdr->pendingID);
				}

				//IMPORTANT NOTE! We overload the use of the nonce as the parameter for the numIterations
				//only for experimentation, allowing us to easily modify the numIterations without
				//adding a new parameter for the server to send. In practice numIterations should be
				//hardcoded to an appropriate count for the hardware
				ntStatus = SendTickStampAttestationPacket(gDriverObject, pAdapt, pReqHdr->rand, pReqHdr->pendingID, pReqHdr->rand);
//the label is to make sure I don't accidentally grab the offset to the call to SendSelfMeasurementPackets
//in a different case statement when hardcoding in the offset in tiresias (also makes it easier to find in IDA)
tpmgrandparent:
				if(ntStatus != STATUS_SUCCESS){
					KdPrint(("SendBinaryMeasurementsPackets failed with ntStatus = %#x\n", ntStatus));
					RtlStringCbPrintfA(errorMsgBuf, 100, "SendBinaryMeasurementsPackets failed with ntStatus = %#x", ntStatus);
					SendErrorPacket(pAdapt, errorMsgBuf, strlen(errorMsgBuf)+1, pReqHdr->rand, pReqHdr->pendingID);
				}


				KeLowerIrql(oldIRQL);
				__asm { sti };
				break;
			default:
				//for now this means the packet is corrupt
				return NDIS_STATUS_NOT_RECOGNIZED;
			}//end switch for type of request
		} else {
			if (gCrashed == TRUE)
			{
				KdPrint(("gCrashed = TRUE so ignoring Checkmate server packets\n"));
				DbgPrint("gCrashed = TRUE so ignoring Checkmate server packets\n");
				SendErrorPacket(pAdapt, "gCrashed = TRUE so ignoring Checkmate server packets", strlen("gCrashed = TRUE so ignoring Checkmate server packets")+1, pReqHdr->rand, pReqHdr->pendingID);
			}

			if (gPFNFound == FALSE)
			{
				KdPrint(("gPFNFound = FALSE so ignoring Checkmate server packets\n"));
				DbgPrint("gPFNFound = FALSE so ignoring Checkmate server packets\n");
				SendErrorPacket(pAdapt, "gPFNFound = FALSE so ignoring Checkmate server packets", strlen("gPFNFound = FALSE so ignoring Checkmate server packets")+1, pReqHdr->rand, pReqHdr->pendingID);
			}

		}//end if/else gCrashed eq FALSE AND gPFNFound eq TRUE 
	}//end if matches the covert channel
}//end else (TRUE!=bSend)

 return NDIS_STATUS_SUCCESS;
}





