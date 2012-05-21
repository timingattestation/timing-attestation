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

//Taken from example code and unmodified
//Some code like GetPktPayload is used by the FilterRtns.cpp

#include "precomp.h"
#pragma hdrstop

#include "PktHdr.h"
#include "pe.h"
#include "safe_mem_access.h"
#include "misc.h"
#include "measure_self.h"

/**************************************************************************************************/      
/*                                                                                                */      
/* Copy the payload of the specified packet into the specified buffer.                            */      
/*                                                                                                */      
/* Adapted from http://www.ndis.com/papers/ndispacket/readonpacket.htm, 12 May 2003.              */      
/*                                                                                                */      
/**************************************************************************************************/      

VOID
GetPktPayload(
              PNDIS_PACKET     pPacket,               // Address of packet descriptor.
              PUCHAR           pOutBfr,               // Address of output buffer, to get copied packet payload.
              ULONG            ulOutBfrAvail,         // Size of output buffer.
              PULONG           pUlBytesCopied         // Output variable for number of bytes copied.
             )
{
   PNDIS_BUFFER    pNdisBfr;
   ULONG           ulBfrCnt,
                   ulTotPktLen,
                   ulCurrBfr,
                   ulAmtToMove;
   PUCHAR          pCurrBfr;

   *pUlBytesCopied = 0;                               // Set 0 bytes copied.

   if (0==ulOutBfrAvail)                              // Is output buffer 0 bytes in length?
     goto Done;

   NdisQueryPacket(pPacket,                           // Get information from packet descriptor.
                   NULL,                      
                   NULL,
                   &pNdisBfr,                         // Output variable for address of first buffer descriptor.
                   &ulTotPktLen                       // Output variable for number of bytes in packet payload.
                  );

   NdisQueryBuffer(pNdisBfr,                          // Get information from first buffer descriptor.
                   &pCurrBfr,                         // Output variable for address of described virtual area.
                   &ulCurrBfr                         // Output variable for size of virtual area.
                  );

   while (ulOutBfrAvail>0)                            // Space remaining in output buffer?
     {
      while (0==ulCurrBfr)                            // While the current buffer has zero length.
        {
         NdisGetNextBuffer(pNdisBfr,                  // Get next buffer descriptor.
                           &pNdisBfr
                          );

         if (NULL==pNdisBfr)                          // None?
           goto Done;

         NdisQueryBuffer(pNdisBfr,                    // Get information from next buffer descriptor.
                         &pCurrBfr,                   // Output variable for address of current buffer.
                         &ulCurrBfr                   // Output variable for size of current buffer.
                        );
        }

      if (ulCurrBfr>ulOutBfrAvail)                    // Does current buffer's usable size exceed space remaining in output buffer?
        ulAmtToMove = ulOutBfrAvail;                  // Use only amount remaining in output buffer.
      else
        ulAmtToMove = ulCurrBfr;                      // Use full size of current buffer.

      NdisMoveMemory(pOutBfr,                         // Copy packet data to output buffer.
                     pCurrBfr,
                     ulAmtToMove
                    );

      *pUlBytesCopied += ulAmtToMove;                 // Update output variable of bytes copied.
      pOutBfr += ulAmtToMove;                         // Update pointer to output buffer.
      ulOutBfrAvail -= ulAmtToMove;                   // Update number of bytes available in output buffer.

      ulCurrBfr = 0;                                  // Force search for next buffer.
     }                                                // End 'while' copy bytes to output buffer.

Done:
  ;
}


//****************************************************************************//
//*                                                                           //
//* Copyright (C) 2003, James Antognini, antognini@mindspring.com.            //
//*                                                                           //
//****************************************************************************//
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

/**************************************************************************************************/      
/*                                                                                                */      
/* Calculate TCP checksum, based on TCP datagram (TCP header + data) and pseudo-header.           */      
/*                                                                                                */      
/* Derived in part from from RFC 1071, section 4.1, p 7, and in part from DDK \e100bex\offload.h. */      
/*                                                                                                */      
/* Notes:                                                                                         */      
/*                                                                                                */      
/*     1) This routine is written for a little-endian environment (eg, x86).  It has been tested  */      
/*        and used in WinXP user- and kernel-space environments.                                  */      
/*                                                                                                */      
/*     2) This routine assumes the checksum field in the TCP header has been set to 0, in order   */      
/*        to compute the checksum.                                                                */      
/*                                                                                                */      
/*     3) This routine, as is, cannot be used to check a checksum, because checking a checksum    */      
/*        involves getting the one's complement sum over the TCP datagram, with the checksum      */      
/*        included (see RFC 1071, p 1), but this routine does that summing and then returns the   */      
/*        one's complement of that sum.  That is, this routine will, if a checksum is correct,    */      
/*        yield 0xffff in the folding statement below but then will return the one's complement   */      
/*        of 0xffff, which is 0.                                                                  */      
/*                                                                                                */      
/**************************************************************************************************/      
USHORT
GetTCPChecksum(
               PUSHORT pTCPFd,                        // Pointer to TCP datagram (header + data).
               PUSHORT pSrcAddr,                      // Address of source IP address (in network format).
               PUSHORT pDestAddr,                     // Address of destination IP address (in network format).
               USHORT  usTCPFd                        // Length of TCP datagram (header + data).
              )
{
 #define JADrvRtnsVer    "1.01"   

 #define lnPseudoHdr 12                               // Size of pseudo-header.
 char    PseudoHdrArr[lnPseudoHdr];                   // Pseudo-header.
 USHORT  usPsHdr = lnPseudoHdr;                       // Length of pseudo-header.
 PUSHORT pPseudoHdr = (PUSHORT)PseudoHdrArr;          // Pointer to pseudo-header.
 ULONG   sum = 0; 

 // Note:  The one's complement addition done for the TCP datagram and for the pseudo-header is effected
 //        with little-endian PUSHORT variables.  Because of the associativity of addition, that produces
 //        a good result except that the bytes have to be swapped in the return statement.  (The data
 //        being checked-summed are, as always, in network (big-endian) order; eg, if the length of the
 //        TCP datagram used in the pseudo-header is 0x95, the value is stored as 0x0095 in memory, not
 //        as 0x9500.)

 // Build the pseudo-header field. 

 memcpy(PseudoHdrArr, pSrcAddr, 4);                   // Copy source IP address.
 memcpy(PseudoHdrArr+4, pDestAddr, 4);                // Copy destination IP address.
 PseudoHdrArr[8] = 0;                                 // Set to 0.
 PseudoHdrArr[9] = IPPROTO_TCP;                       // Set to TCP protocol constant.
 pPseudoHdr[5] =                                      // Put length of entire TCP datagram into pseudo-header.
   (USHORT)(((usTCPFd&0xFF00)>>8) + ((usTCPFd&0x00FF)<<8));

 // Do one's complement addition of pseudo-header.

 while(usPsHdr > 0)
   {
    sum += *pPseudoHdr++;
    usPsHdr -= 2;
   }

 // Do one's complement addition of TCP field, except for the last byte if the field length is odd. 

 while(usTCPFd > 1)
   {
    sum += *pTCPFd++;
    usTCPFd -= 2;
   }

 // Add left-over byte, if any.

 if(usTCPFd > 0)
   sum += *(PUCHAR)pTCPFd;

 // Fold 32-bit sum to 16 bits (form per offload.h in DDK \e100bex).

 sum = (((sum >> 16) | (sum << 16)) + sum) >> 16;

 // Return one's complement (in little-endian form, by the way).

 return (USHORT)~sum;
}                                                     // End GetTCPChecksum().

//****************************************************************************//
//*                                                                           //
//* Derived from Ping.cpp in SDK Samples\netds\WinSock\Ping.                  //
//*                                                                           //
//****************************************************************************//
//Modified by Xeno to match the RFC

USHORT
GetIPChecksum(PUSHORT pIPH, USHORT usIPHdr)
{
 ULONG cksum = 0;

 while (usIPHdr > 1)
 {
  cksum += *pIPH++;
  usIPHdr -= sizeof(USHORT);
 }

 if(usIPHdr > 0){
	cksum += * (unsigned char *)pIPH;
 }

 while (cksum>>16)
  cksum = (cksum & 0xFFFF)+(cksum >> 16);

 return (USHORT)~cksum;
}

//By Xeno
USHORT
GetUDPChecksum(IPHdr * iph, UDPHeader * udph, unsigned char * data, unsigned int len){
	unsigned int checksum = 0;
	unsigned int tmp = 0;
	unsigned int i = 0;

	//Pseudo header contains source and destination IP addresses
	checksum += (iph->SourceAddress & 0xFFFF) + (iph->SourceAddress >> 16) + 
				(iph->DestinationAddress & 0xFFFF) + (iph->DestinationAddress >> 16);

	//Pseudo header contains length of UDP header and data (in number of bytes)
	//Also includes the protocol (UDP = 17 = 0x11)
	checksum += htons(len + sizeof(UDPHeader) + iph->Protocol);

	//Include the UDP header
	for(i = 0; i < 4; i++){
		checksum += *((USHORT *)udph+i);
	}

	//Include the data
	//If there's an odd number of bytes in the data, need to pretend there's a padding byte at the end
	if((len & 1) == 1){
		checksum += htons((data[len-1]) << 8);
	}

	for(i = 0; i < (len-1); i+=2){
		checksum += *(USHORT *)(data+i);
	}

	//Only give a 16 bit checksum
	while (checksum>>16)
		checksum = (checksum & 0xFFFF)+(checksum >> 16);


	//Return the ones complement
	return ~(USHORT)checksum;
}

//The below had to be moved here due to some code reorganization for public release

//Returns the dateTimeStamp PE header field for this kernel module we're
//currently in (i.e. it's the client's version)
unsigned int FindSelfTimeDateStamp(unsigned int myBaseVA){
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;

	if(CheckPageForSafeAccess((unsigned int)myBaseVA) != GENERIC_SUCCESS){
		KdPrint(("Cannot access our own baseVA!\n"));
		return STATUS_INTERNAL_ERROR;
	}
	pDosH = (PIMAGE_DOS_HEADER)(myBaseVA);
	pNtH = (PIMAGE_NT_HEADERS)((char *)pDosH + pDosH->e_lfanew);
	return pNtH->FileHeader.TimeDateStamp;
}

void DisableWP(){
	__asm{
		push eax;
		mov eax, cr0;
		and eax, 0xFFFEFFFF;
		mov cr0, eax;
		pop eax;
	};
}

void EnableWP(){
	__asm{
		push eax;
		mov eax, cr0;
		or eax, NOT 0xFFFEFFFF;
		mov cr0, eax;
		pop eax;
	};
}

//Currently, this function returns a driverBase which can be used for ParseHeadersToFindSections.
unsigned char *
SearchForDriver(PDRIVER_OBJECT theDriverObject, wchar_t * searchedDriverName){
	unsigned int i = 0;
	unsigned char * driverBase;
	NTSTATUS ntStatus;
	PLDR_DATA_TABLE_ENTRY module;

	//TODO NOTE: to get version use RtlGetVersion, and then assign the right type of struct for module
	//based on that
	PLDR_DATA_TABLE_ENTRY start = (PLDR_DATA_TABLE_ENTRY)(theDriverObject->DriverSection);
	
	KdPrint(("Search For Driver Begin Irql=%d\n", KeGetCurrentIrql()));
	
	//module = (PLDR_DATA_TABLE_ENTRY)start->InLoadOrderLinks.Blink; //The first entry will always be this driver, so we don't need to check it
	module = start;

	if(start == NULL /*|| module == NULL*/ || start->InLoadOrderLinks.Blink == NULL){
		KdPrint(("Unanticipated memory layout. Exiting SearchForDriver for safety\n"));
		return NULL;
	}


	//From looking at the module list in WinDbg, I have determined that it is a circular, doubly-linked
	//list. However it has one malformed entry in it. It is malformed in the sense that the MODULE_ENTRY
	//values *except* the module_list linked list entries, have unexpected values. However, because
	//the module_list entries still allow the list to remain circular, we will simply step past this 
	//entry, rather than have to have forward searching and backward searching loops.

	//Backward searching loop
	while(TRUE){

		if(module == NULL){
			break;
		}

		//Check for the weird MODULE_ENTRY
		if(module->Base == 0 || module->BaseName.Buffer == NULL){ 
			module = (PLDR_DATA_TABLE_ENTRY)module->InLoadOrderLinks.Blink;
			if (module == start){ //this needed to be added otherwise it could infinite loop
				break;
			}
			continue;
		}
		//changed to case insensitive compare
		if(_wcsicmp(module->BaseName.Buffer, searchedDriverName) == 0){
			KdPrint(("%ws found at %#x\n", searchedDriverName, module->Base));
			return (unsigned char *)module->Base;
		}
		else{
			//KdPrint(("module->driver_Name = %ws wasn't what we were looking for\n", module->driver_Name.Buffer));
			module = (PLDR_DATA_TABLE_ENTRY)module->InLoadOrderLinks.Blink;
		}

		if (module == start){
			break;
		}
	}
	KdPrint(("%ws not found\n", searchedDriverName));
	return NULL;
}


int getHalpRealModeStartAndEnd(unsigned int baseVA, unsigned int timeDateStamp, unsigned int sizeOfImage, unsigned int *halpRealModeStart, unsigned int *halpRealModeEnd) {
	int ret;
	unsigned int sizeOfHalpDataToZero;
	unsigned int offsetToHalpRealModeStart = 0;

	//Fixed: This should actually be 0x80A which is the distance, not 0x7FE. 
	//The 0x7FE is because we skip the first 0xC bytes when zeroing out, so
	//as not to delete the little snippet of code at HalpRealModeStart
	sizeOfHalpDataToZero = 0x80A; //the + 0xC is because 

	if(timeDateStamp == 0x48E20EE2){
		//0x20D80 is from halmacpi.dll as determined from debug string
		if(sizeOfImage == 0x20D80){
			offsetToHalpRealModeStart = 0x318A;
		}
		//TODO: find value for halaacpi.dll
	}
	else if(timeDateStamp == 0x4802517F){
		//0x20D00 is from halamcpi.dll as determined from debug string
		if(sizeOfImage == 0x20D00){
			offsetToHalpRealModeStart = 0x318A;
		}
		//0x20300 is from halaacpi.dll as determined from debug string
		else if(sizeOfImage == 0x20300){
			offsetToHalpRealModeStart = 0x2ec6;
		}
	}
	else if(timeDateStamp == 0x42B9FCE0){
		//0x20C80 is from halmacpi.dll as determined from debug string
		if(sizeOfImage == 0x20C80){
			offsetToHalpRealModeStart = 0x318A;
		}
		//TODO: find value for halaacpi.dll
	}
	else if(timeDateStamp == 0x41107B29){
		//0x20380 is from halaacpi.dll as determined from debug string
		if(sizeOfImage == 0x20380){
			offsetToHalpRealModeStart = 0x2ec6;
		}
		//TODO: find value for halmacpi.dll
	}
	else if(offsetToHalpRealModeStart == 0){
		//If we hit this case it means we hit one of those TODOs above
		KdPrint(("getHalpRealModeStartAndEnd: failed to find timeDateStamp's that match this one\n"));
		return GENERIC_ERROR;
	}else {
		KdPrint(("getHalpRealModeStartAndEnd: failed to find timeDateStamp's that match this one\n"));
		return GENERIC_ERROR;
	}
	*halpRealModeStart = baseVA + offsetToHalpRealModeStart;
	*halpRealModeEnd = *halpRealModeStart + sizeOfHalpDataToZero;
	KdPrint(("getHalpRealModeStart: 0x%x\n", *halpRealModeStart));
	KdPrint(("getHalpRealModeEnd: 0x%x\n", *halpRealModeEnd));

	return GENERIC_SUCCESS;
}

//Both the base, start, and end are absolute virtual addresses
//We also bring back the timeDateStamp and sizeOfImage so we know which version of files we're dealing with
int FindTextSectionStartAndEnd(wchar_t * name, unsigned char * baseVA, unsigned int * start, unsigned int * end, unsigned int * timeDateStamp, unsigned int * sizeOfImage){
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSectH;
	char errorMsgBuf[100];

	pDosH = (PIMAGE_DOS_HEADER)(baseVA);
	if(CheckPageForSafeAccess((unsigned int)baseVA) != GENERIC_SUCCESS){
		KdPrint(("Cannot access base virtual address for %ws\n", name));
		return STATUS_INTERNAL_ERROR;
	}
	pNtH = (PIMAGE_NT_HEADERS)((char *)pDosH + pDosH->e_lfanew);
	//ASSUMPTION: first section is the .text
	pSectH = (PIMAGE_SECTION_HEADER)((char *)pNtH + sizeof(IMAGE_NT_HEADERS));
	if(CheckPageForSafeAccess((unsigned int)pSectH) != GENERIC_SUCCESS){
		KdPrint(("Cannot access base virtual address for %ws\n", name));
		return STATUS_INTERNAL_ERROR;
	}

	*timeDateStamp = pNtH->FileHeader.TimeDateStamp;
	*sizeOfImage = pNtH->OptionalHeader.SizeOfImage;
	*start = (unsigned int)(baseVA+pSectH->VirtualAddress);
	*end = (unsigned int)(*start+pSectH->Misc.VirtualSize);
	
	return STATUS_SUCCESS;
}