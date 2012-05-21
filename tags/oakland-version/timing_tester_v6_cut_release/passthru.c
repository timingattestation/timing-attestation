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

//This is functionally main.c
//DriverEntry() is main(), and is the first function which is called upon 
//the driver being loaded
//Passthru is an NDIS intermediate driver, which means that it
//glues together an NDIS miniport driver and NDIS protocol driver

//Some code derived from Microsoft NDIS Passthru IM driver example code, used by permission
/*++

Copyright (c) 1992-2000  Microsoft Corporation
 
Module Name:
 
    passthru.c

Abstract:

    Ndis Intermediate Miniport driver sample. This is a passthru driver.

Author:

Environment:


Revision History:


--*/


#include "precomp.h"
#include "misc.h"
#include "measure_self.h"
#include "server_client_protocol.h"
#include "safe_mem_access.h" //for FindPFNBase
#include "tpm.h"
#pragma hdrstop

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////
#define TRANSMIT_PACKETS    128
#define ETHERNET_HEADER_LENGTH   14

#pragma NDIS_INIT_FUNCTION(DriverEntry)

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
BOOL gCrashed;
BOOL gPFNFound;

//attack stuff
HANDLE gDriverBinaryFile;
IO_STATUS_BLOCK gIoStatusBlock;
unsigned int gBaseVA = 0x00;
unsigned int gHookLocation = 0x00;

typedef struct _PACKET_RESERVED {
    LIST_ENTRY     ListElement;
    PIRP           Irp;
	PVOID		   pBuffer; /* used for buffers built in kernel mode */
	ULONG		   bufferLen;
	PVOID		   pHeaderBufferP;
	ULONG		   pHeaderBufferLen;
    PMDL           pMdl;
}  PACKET_RESERVED, *PPACKET_RESERVED;

NDIS_HANDLE         ProtHandle = NULL;
NDIS_HANDLE         DriverHandle = NULL;
NDIS_MEDIUM         MediumArray[4] =
                    {
                        NdisMedium802_3,    // Ethernet
                        NdisMedium802_5,    // Token-ring
                        NdisMediumFddi,     // Fddi
                        NdisMediumWan       // NDISWAN
                    };

NDIS_SPIN_LOCK     GlobalLock;

PADAPT             pAdaptList = NULL;
LONG               MiniportCount = 0;

NDIS_HANDLE        NdisWrapperHandle;


NDIS_HANDLE     NdisDeviceHandle = NULL;
PDEVICE_OBJECT  ControlDeviceObject = NULL;

enum _DEVICE_STATE
{
    PS_DEVICE_STATE_READY = 0,    // ready for create/delete
    PS_DEVICE_STATE_CREATING,    // create operation in progress
    PS_DEVICE_STATE_DELETING    // delete operation in progress
} ControlDeviceState = PS_DEVICE_STATE_READY;

//To be used in place of the one which would have been given to threads
PDRIVER_OBJECT gDriverObject;

//EXTERNS
extern NDIS_HANDLE     gPacketPoolH;
extern NDIS_HANDLE		gBufferPoolH;

//In lieu of having prototypes in measure_binary.h
extern NTSTATUS MeasureBinaryThread(IN PVOID pContext);

extern ULONG gSetInfoIP;
extern unsigned char gDstMAC[6];

extern unsigned int gOSDependent_pfnBase;

void LoadAndRelocateCleanImage();
unsigned int ParsePEHeaders(PIMAGE_DOS_HEADER * pDosH, PIMAGE_NT_HEADERS * pNtH, PIMAGE_SECTION_HEADER * pFirstSectH);
char * FindRelocs(PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH);
PIMAGE_SECTION_HEADER rvaToSectH(unsigned int rva, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH);
char * AllocBufForSect(PIMAGE_SECTION_HEADER pDesiredSect);
void bogusFunction(char *buf);
int GetRelocatedSection(PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pSectH, unsigned int baseVADiff, char * relocBuf, char **outputBuffer, unsigned int * outputBufLen);


////////////////////////////////////////////////////////
//BEGIN CODE
////////////////////////////////////////////////////////

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT        DriverObject,
    IN PUNICODE_STRING       RegistryPath
    )
/*++

Routine Description:

    First entry point to be called, when this driver is loaded.
    Register with NDIS as an intermediate driver.

Arguments:

    DriverObject - pointer to the system's driver object structure
        for this driver
    
    RegistryPath - system's registry path for this driver
    
Return Value:

    STATUS_SUCCESS if all initialization is successful, STATUS_XXX
    error code if not.

--*/
{
	NTSTATUS ntStatus;
    NDIS_STATUS                        Status;
    NDIS_PROTOCOL_CHARACTERISTICS      PChars;
    NDIS_MINIPORT_CHARACTERISTICS      MChars;
    NDIS_STRING                        Name;


    //tpm initilization data
    PHYSICAL_ADDRESS tpmPhysicalAddress;

	//these vars are just for checking whether a memory dump file is on the
	//filesystem so we can bail out early if necessary

	gCrashed = FALSE;

	//tpm initialization code
	tpmPhysicalAddress.QuadPart = 0xfed40000;
	gTPMRegisterSize = 0x5000;
	gTPMLinearAddress = 0;
	gTPMEnabled = 0;
	gTPMLinearAddress = MmMapIoSpace(tpmPhysicalAddress, gTPMRegisterSize,MmNonCached); 
	if (gTPMLinearAddress == 0)
	{
		KdPrint(("DriverEntry: MmMapIOSpace for TPM failed\n"));
	}

	if (gTPMLinearAddress)
	{
		gTPMEnabled = TIS_Init();
	}

	DbgPrint("gTPMEnabled = %d\n", gTPMEnabled);


	LoadAndRelocateCleanImage();

	//Orphans from previous code organization
	//TODO: anywhere better to put these?
	gDriverObject = DriverObject;
	FindPFNBase();

	gSetInfoIP = 0;
	memset(&gDstMAC, 0, 6);

	//Initalize global packet and buffer pools for the threads to use
	//TODO: do I now need a mutex for them? How would I know if the
	//functions which use them internally maintain mutual exclusion?
	NdisAllocatePacketPool(&ntStatus, &gPacketPoolH, TRANSMIT_PACKETS, sizeof(PACKET_RESERVED));	
	if (ntStatus != NDIS_STATUS_SUCCESS) 
	{
		KdPrint(("NdisAllocatePacketPool failed, MeasureBinaryThread exiting\n"));
		//PsTerminateSystemThread(STATUS_SUCCESS);
		return STATUS_INTERNAL_ERROR; //Ahhh, nice and generic
	}

	NdisAllocateBufferPool(&ntStatus, &gBufferPoolH, TRANSMIT_PACKETS );							
	if (ntStatus != NDIS_STATUS_SUCCESS) 
	{
		KdPrint(("NdisAllocateBufferPool failed, MeasureBinaryThread exiting\n"));
		//PsTerminateSystemThread(STATUS_SUCCESS);

		NdisFreePacketPool(gPacketPoolH);															

		return STATUS_INTERNAL_ERROR; //Ahhh, nice and generic
	}

    Status = NDIS_STATUS_SUCCESS;
    NdisAllocateSpinLock(&GlobalLock);																

    NdisMInitializeWrapper(&NdisWrapperHandle, DriverObject, RegistryPath, NULL);

    do
    {
        //
        // Register the miniport with NDIS. Note that it is the miniport
        // which was started as a driver and not the protocol. Also the miniport
        // must be registered prior to the protocol since the protocol's BindAdapter
        // handler can be initiated anytime and when it is, it must be ready to
        // start driver instances.
        //

        NdisZeroMemory(&MChars, sizeof(NDIS_MINIPORT_CHARACTERISTICS));

        MChars.MajorNdisVersion = PASSTHRU_MAJOR_NDIS_VERSION;
        MChars.MinorNdisVersion = PASSTHRU_MINOR_NDIS_VERSION;

        MChars.InitializeHandler = MPInitialize;
        MChars.QueryInformationHandler = MPQueryInformation;
        MChars.SetInformationHandler = MPSetInformation;
        MChars.ResetHandler = NULL;
        MChars.TransferDataHandler = MPTransferData;
        MChars.HaltHandler = MPHalt;
#ifdef NDIS51_MINIPORT
        MChars.CancelSendPacketsHandler = MPCancelSendPackets;
        MChars.PnPEventNotifyHandler = MPDevicePnPEvent;
        MChars.AdapterShutdownHandler = MPAdapterShutdown;
#endif // NDIS51_MINIPORT

        //
        // We will disable the check for hang timeout so we do not
        // need a check for hang handler!
        //
        MChars.CheckForHangHandler = NULL;
        MChars.ReturnPacketHandler = MPReturnPacket;

        //
        // Either the Send or the SendPackets handler should be specified.
        // If SendPackets handler is specified, SendHandler is ignored
        //
        MChars.SendHandler = NULL;    // MPSend;
        MChars.SendPacketsHandler = MPSendPackets;

        Status = NdisIMRegisterLayeredMiniport(NdisWrapperHandle,
                                                  &MChars,
                                                  sizeof(MChars),
                                                  &DriverHandle);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }

		//DELETEME
		KdPrint(("__--__-___-___--___----_-_-_-DriverHandle = %#x\n", DriverHandle));

        NdisMRegisterUnloadHandler(NdisWrapperHandle, PtUnload);

        //
        // Now register the protocol.
        //
        NdisZeroMemory(&PChars, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
        PChars.MajorNdisVersion = PASSTHRU_PROT_MAJOR_NDIS_VERSION;
        PChars.MinorNdisVersion = PASSTHRU_PROT_MINOR_NDIS_VERSION;

        //
        // Make sure the protocol-name matches the service-name
        // (from the INF) under which this protocol is installed.
        // This is needed to ensure that NDIS can correctly determine
        // the binding and call us to bind to miniports below.
        //
        NdisInitUnicodeString(&Name, L"Checkmate");    // Protocol name
        PChars.Name = Name;
        PChars.OpenAdapterCompleteHandler = PtOpenAdapterComplete;
        PChars.CloseAdapterCompleteHandler = PtCloseAdapterComplete;
        PChars.SendCompleteHandler = PtSendComplete;
        PChars.TransferDataCompleteHandler = PtTransferDataComplete;
    
        PChars.ResetCompleteHandler = PtResetComplete;
        PChars.RequestCompleteHandler = PtRequestComplete;
		PChars.ReceiveHandler = PtReceive;
        PChars.ReceiveCompleteHandler = PtReceiveComplete;
        PChars.StatusHandler = PtStatus;
        PChars.StatusCompleteHandler = PtStatusComplete;
        PChars.BindAdapterHandler = PtBindAdapter;
        PChars.UnbindAdapterHandler = PtUnbindAdapter;
        PChars.UnloadHandler = PtUnloadProtocol;

		
        PChars.ReceivePacketHandler = PtReceivePacket;
        PChars.PnPEventHandler= PtPNPHandler;

        NdisRegisterProtocol(&Status,
                             &ProtHandle,
                             &PChars,
                             sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisIMDeregisterLayeredMiniport(DriverHandle);
            break;
        }

		///DELETEME
		KdPrint(("__--__-___-___--___----_-_-_-ProtHandle = %#x\n", ProtHandle));

        NdisIMAssociateMiniport(DriverHandle, ProtHandle);
    }
    while (FALSE);

    if (Status != NDIS_STATUS_SUCCESS)
    {
        NdisTerminateWrapper(NdisWrapperHandle, NULL);
    }

    return(Status);
}

NTSTATUS
PtDispatch(
    IN PDEVICE_OBJECT    DeviceObject,
    IN PIRP              Irp
    )
/*++
Routine Description:

    Process IRPs sent to this device.

Arguments:

    DeviceObject - pointer to a device object
    Irp      - pointer to an I/O Request Packet

Return Value:

    NTSTATUS - STATUS_SUCCESS always - change this when adding
    real code to handle ioctls.

--*/
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);
    
    KdPrint(("==>Pt Dispatch\n"));
    irpStack = IoGetCurrentIrpStackLocation(Irp);
      

    switch (irpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;
            
        case IRP_MJ_CLEANUP:
            break;
            
        case IRP_MJ_CLOSE:
            break;        
            
        case IRP_MJ_DEVICE_CONTROL:
            //
            // Add code here to handle ioctl commands sent to passthru.
            //
            break;        
        default:
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    KdPrint(("<== Pt Dispatch\n"));

    return status;

} 

VOID
PtUnload(
    IN PDRIVER_OBJECT        DriverObject
    )
//
// PassThru driver unload function
//
{
    UNREFERENCED_PARAMETER(DriverObject);

    KdPrint(("PtUnload: entered\n"));
    PtUnloadProtocol();
    NdisIMDeregisterLayeredMiniport(DriverHandle);
	//Some deallocates that didn't previously exist
	NdisFreePacketPool(gPacketPoolH);							
	NdisFreeBufferPool(gBufferPoolH);							
//Why isn't this defined? It's an empty macro!
	NdisFreeSpinLock(&GlobalLock);								
    KdPrint(("PtUnload: done!\n"));
}

void LoadAndRelocateCleanImage() {
	UNICODE_STRING fileName;
	OBJECT_ATTRIBUTES objAttr;
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pFirstSectH;
	NTSTATUS status;
	int ret;
	char *relocBuf;
	unsigned int outputBufLen;

	//SystemRoot is C:\WINDOWS and is mounted earlier than other stuff rooted at C:\
	//So make sure the file is copied to C:\WINDOWS\Checkmate.sys for the attack to work
	RtlInitUnicodeString(&fileName, L"\\SystemRoot\\Checkmate.sys");
	//RtlInitUnicodeString(&fileName, L"\\??\\C:\\WINDOWS\\System32\\drivers\\Checkmate.sys");
	//RtlInitUnicodeString(&fileName, L"\\??\\C:\\mordor\\branches\\timing_tester_v6\\i386\\Checkmate.sys");
	
	InitializeObjectAttributes(&objAttr, &fileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);
	
//	status = ZwOpenFile(&gDriverBinaryFile, FILE_READ_DATA, &objAttr, &gIoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
	status = ZwOpenFile(&gDriverBinaryFile, FILE_READ_DATA | SYNCHRONIZE, &objAttr, &gIoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT);

	///ret = 0;

	if(ParsePEHeaders(&pDosH, &pNtH, &pFirstSectH) == GENERIC_ERROR){
		KdPrint(("LoadAndRelocateCleanImage: ParsePEHeaders failed\n"));
		return;
	}

	//unsigned int baseVADiff = FindBaseVADiff(stm->baseVA, pNtH);
	relocBuf = FindRelocs(pNtH, pFirstSectH);
	if(relocBuf == NULL){
		KdPrint(("LoadAndRelocateCleanImage: FindRelocs failed\n"));
		return;
	}

	GetRelocatedSection(pNtH, pFirstSectH, 0, relocBuf, &gCheckmateCleanImage, &outputBufLen);
	//No point in checking return value, we do the same thing either way

	ExFreePool(relocBuf);

	ZwClose(gDriverBinaryFile);
	
}

unsigned int ParsePEHeaders(PIMAGE_DOS_HEADER * pDosH, PIMAGE_NT_HEADERS * pNtH, PIMAGE_SECTION_HEADER * pFirstSectH){
	char * tmpBuf;
	unsigned int bytesRead;
	LARGE_INTEGER byteOffset;
	NTSTATUS status;

	tmpBuf = (char *)ExAllocatePool(NonPagedPool, PAGE_SIZE);

	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;

	status = ZwReadFile(gDriverBinaryFile, NULL, NULL, NULL, &gIoStatusBlock, tmpBuf, PAGE_SIZE, &byteOffset, NULL);
	
	//Find the base VA, find the offset between base VA and real VA
	*pDosH = (PIMAGE_DOS_HEADER)tmpBuf;
	*pNtH = (PIMAGE_NT_HEADERS)(tmpBuf + (*pDosH)->e_lfanew);
	*pFirstSectH = (PIMAGE_SECTION_HEADER)((char *)(*pNtH) + sizeof(IMAGE_NT_HEADERS));

	return GENERIC_SUCCESS;
}

char * FindRelocs(PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH){
	unsigned int relocRVA;
	PIMAGE_SECTION_HEADER pRelocSect;
	char *relocBuf;

	relocRVA = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	pRelocSect = rvaToSectH(relocRVA, pNtH, pFirstSectH);
	if(pRelocSect == NULL){
		return NULL;
	}

	relocBuf = AllocBufForSect(pRelocSect);

	return relocBuf;
}

PIMAGE_SECTION_HEADER rvaToSectH(unsigned int rva, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH){
	PIMAGE_SECTION_HEADER pSectH;
	PIMAGE_SECTION_HEADER pDesiredSect;
	int i;

	pSectH = pFirstSectH;
	pDesiredSect = 0;
	
	for(i = 0; i < pNtH->FileHeader.NumberOfSections; i++){
		//Keep the relocation section pointer by itself
		if(pSectH->VirtualAddress <= rva && rva < (pSectH->VirtualAddress + pSectH->SizeOfRawData)){
			pDesiredSect = pSectH;
			break;
		}
		pSectH++;
	}

	//Will either be a valid ptr or 0
	return pDesiredSect;
}

char * AllocBufForSect(PIMAGE_SECTION_HEADER pDesiredSect){
	char *buf;
	LARGE_INTEGER byteOffset;

	buf = (char *)ExAllocatePool(NonPagedPool, pDesiredSect->SizeOfRawData);
	if(buf == NULL){
		return NULL;
	}

	byteOffset.HighPart = 0;
	byteOffset.LowPart = pDesiredSect->PointerToRawData;

	ZwReadFile(gDriverBinaryFile, NULL, NULL, NULL, &gIoStatusBlock, buf, pDesiredSect->SizeOfRawData, &byteOffset, NULL);

///print bytes to sanity check opened file
///	bogusFunction(buf);

	return buf;
}

void bogusFunction(char *buf) {
	int i;
	for (i=0;i<12;i++)
		DbgPrint(" buf[%d] = 0x%x\n", i, buf[i]);
}

int GetRelocatedSection(PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pSectH, unsigned int baseVADiff, char * relocBuf, char **outputBuffer, unsigned int * outputBufLen){
	unsigned int offset;
	unsigned int totalRelocsProcessed;
	unsigned int sectSize;
	unsigned int totalRelocSize;
	unsigned int sectionStart;
	unsigned int sectionEnd;
	unsigned int numPagesInSect;
	LARGE_INTEGER fileOffset;
	IMAGE_BASE_RELOCATION * pCurrentRelocBlock;
	unsigned int currentRVA; 
	char * currentFileOffset;
	unsigned int i;
	unsigned int relocOffset; //Used as an offset to step through reloc entries
	unsigned short * relocEntry;
	unsigned short offsetIntoPage;
	int * relocPtr;
	int vaDiff;

	offset = 0;
	totalRelocsProcessed = 0;
	sectSize = 0;

	totalRelocSize = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	//The size is whichever is smaller
	if(pSectH->SizeOfRawData > pSectH->Misc.VirtualSize){
		sectSize = pSectH->Misc.VirtualSize;
	}
	else{
		sectSize = pSectH->SizeOfRawData;
	}
	//Read the section data into a buffer
	//Have to over-allocate the buffer along page boundaries to start with
	//because the relocation list can have things which point to page 0
	sectionStart = PA_DOWN_INT(pSectH->VirtualAddress);
	sectionEnd = PA_UP_INT(pSectH->VirtualAddress + sectSize);
	numPagesInSect = (sectionEnd - sectionStart) / PAGE_SIZE;

	fileOffset.HighPart = 0;
	fileOffset.LowPart = 0;
	//Overall, the size of data to be read in from file should be
	//(pSectH->PointerToRawData & 0xFFF) + sectSize
	*outputBufLen = 0;

	//If the VirtualAddress is aligned then the data beginning at 
	//that file offset will be the data beginning at the page boundary.
	//NOTE: I found with ntoskrnl.exe timeDateStamp 0x4A784394 that 
	//it has aligned virtual and raw data addresses, but they were not the
	//same, and for that case, doing the below was also the valid thing
	//so I changed up the condition to make this only depend on
	//alignment of the virtual address (since the previous version also
	//had a check for unaligned raw data address, but that version of
	//ntoskrnl.exe showed that it's not dependent on the characteristics
	//of the raw data address)
	if(((pSectH->VirtualAddress & 0xFFF) == 0)){
		fileOffset.LowPart = pSectH->PointerToRawData;
	}
	else if(pSectH->PointerToRawData == pSectH->VirtualAddress && 
			((pSectH->PointerToRawData & 0xFFF) != 0)){
		//If the VirtualAddress == PointerToRawData (and are both unaligned)
		//then the virtual address *for relocations purposes*
		//will be the address aligned down (since relocation chunks start
		//on aligned boundaries)
		//Since it's aligned down, we need to read in the information before
		fileOffset.LowPart = PA_DOWN_INT(pSectH->PointerToRawData);
	}
	*outputBufLen += (pSectH->PointerToRawData & 0xFFF) + sectSize;

	//*outputBuffer = (char *)malloc(*outputBufLen);//xkovah 1 alloc
	*outputBuffer = (char *)ExAllocatePool(NonPagedPool, *outputBufLen);
	vaDiff = (*outputBuffer - pNtH->OptionalHeader.ImageBase);
	/*
	if(fseek(gStream, fileOffset, 0) != 0){
		printf("GetRelocatedSection: fseek failed\n");
		return GENERIC_ERROR;
	}

	unsigned int bytesRead = fread(*outputBuffer, sizeof(char), *outputBufLen, gStream);
	if(bytesRead != *outputBufLen){
		printf("GetRelocatedSection: file was not read, or didn't contain %d bytes\n", (numPagesInSect * PAGE_SIZE));
		return GENERIC_ERROR;
	}
	*/

	ZwReadFile(gDriverBinaryFile, NULL, NULL, NULL, &gIoStatusBlock, *outputBuffer, *outputBufLen, &fileOffset, NULL);

	//Apply relocations
	
	//This should point at the page which we want to find relocations for.
	//Should be given as a page-aligned RVA
	currentRVA = 0; 

	//Used as the offset into the buffer we've just allocated
	currentFileOffset = *outputBuffer;
	
	//Here's the important fact about relocations: because we page align down section addresses
	//(so that they match potential relocations block virtual addresses, which can start at 0)
	//it is possible for a single page's relocations block to actually apply to multiple SECTIONS
	//worth of addresses. Therefore, it is legitimate for us to apply the relocations in a single
	//sections block multiple times to a chunk of memory (which maybe the first time the hash
	//only cares about the bottom part of, and the second time maybe it only cares about the top
	//part of). Therefore, the best way to do it is NOT to keep a running total of the relocations
	//we've applied (as we used to do), but rather, to just find and apply relocations starting
	//at the beginning of the relocations for each section.
	for(i = 0; i < numPagesInSect; i++){
		currentRVA = sectionStart + (i * PAGE_SIZE);
		if(i != 0){
			currentFileOffset += PAGE_SIZE;
		}
		if(currentFileOffset > (*outputBuffer + *outputBufLen)){
			__asm{int 3};
		}

		pCurrentRelocBlock = (IMAGE_BASE_RELOCATION *)(relocBuf);
		offset = 0;

		//First make sure the relocation is not less than the section we're currently looking at
		while(pCurrentRelocBlock->VirtualAddress < currentRVA){
			offset += pCurrentRelocBlock->SizeOfBlock;
			//Sanity check:
			//Before we set the next pointer, ensure that the offset is not greater than the size of
			//the relocations buffer, lest we generate addresses outside of it
			if(offset >= totalRelocSize){
				break;
			}
			pCurrentRelocBlock = (IMAGE_BASE_RELOCATION *)(relocBuf+offset);
		}

		//Have to check one more time, so we can break one more time
		//incase we broke in the while due to the sanity check
		if(offset >= totalRelocSize){
			//Continue rather than break, incase there's more sections which somehow could be covered
			continue;
		}
		//If this case happens it means we stepped through the relocs, and there were none
		//which applied to the current page
		//TODO: Find out if it be possible though for there to be some for a subsequent page, and thus
		//we would be skipping them? (e.g. .text page 0 has no relocs but .text page 1 does...)
		if(pCurrentRelocBlock->VirtualAddress > currentRVA){
			continue;
		}

		//Therefore, at this point pCurrentRelocBlock->VirtualAddress == currentRVA
		//and there must be relocations for this page
		relocOffset = sizeof(IMAGE_BASE_RELOCATION); //Used as an offset to step through reloc entries
		offsetIntoPage = 0;

		while(relocOffset < pCurrentRelocBlock->SizeOfBlock && pCurrentRelocBlock->SizeOfBlock != 0){
			relocEntry = (unsigned short *)((char *)pCurrentRelocBlock + relocOffset);
			if(*relocEntry == 0){ //when they're 0, it's just for padding at the end
				break;
			}
			offsetIntoPage = (unsigned short)(*relocEntry & 0x0FFF);
			relocPtr = (int *)(currentFileOffset + offsetIntoPage);
			//We can get into a case where because we align down the start of sections
			//therefore a given block of relocations may seem like they apply (based on its
			//virtual address), but in reality we may not have read in enough data from 
			//file in order to safely apply every last relocation. Therefore we need to
			//bounds check that we're not generating addresses for relocations which
			//exist beyond the bounds of the memory we malloc()ed
			//Importantly (as I found out) we need to be checking the *final* address
			//which is being written to, not just the first address ;) (cause I saw a case
			//of relocOffset = 0xFFD on a 0x1000 byte buffer, which would mean the initial
			//address was in bounds, but the final was out)
			if((unsigned int)relocPtr + sizeof(unsigned int) > (unsigned int)(*outputBuffer + *outputBufLen)){
				break;
			}

			//*relocPtr += baseVADiff; //AT LAST! Perform the relocation!
			*relocPtr += vaDiff;
			relocOffset += sizeof(short);
		}

		//reminder: offset is used to make sure the next pCurrentRelocBlock gets set
		totalRelocsProcessed += pCurrentRelocBlock->SizeOfBlock;
	}

	return GENERIC_SUCCESS;
}
