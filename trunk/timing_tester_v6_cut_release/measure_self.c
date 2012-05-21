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

//Self-checksumming code based on the techniques laid out by Pioneer
//
#include "precomp.h"	// this must be first otherwise "misc.h" isn't found in the current dir
#include "misc.h"
#include "server_client_protocol.h"
#include "measure_self.h"
#include "PktHdr.h"
#ifndef WORD
#error WORD Should be defined
#endif

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

extern PKDPC gDPC;

typedef struct ServiceDescriptorEntry
{
  unsigned int *ServiceTableBase;
  unsigned int *ServiceCounterTableBase;	//Used only in Checked build
  unsigned int NumberOfServices;
  unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

__declspec (dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

//So that when we find it once we don't have to look it up again
unsigned int gTimeDateStamp;

//ATTACK SPECIFIC STUFF
unsigned int gAttackActivated;
char * gCheckmateCleanImage = NULL;
//END ATTACK SPECIFIC STUFF

//Just an end memory address to get a memory address range
//This was found in IDA to be basically the last code in the .text section
extern void __stdcall NdisRequest(PNDIS_STATUS Status, NDIS_HANDLE NdisBindingHandle, PNDIS_REQUEST NdisRequest);

////////////////////////////////////////////////////////
//BEGIN CODE
////////////////////////////////////////////////////////

int SelfCheck_v6(PDRIVER_OBJECT theDriverObject,
					unsigned int nonce,
					unsigned int numIterations,
					unsigned int baseVA, 
					api_module_info_t * moduleInfo, 
					unsigned int * upperCycleCount,
					unsigned int * lowerCycleCount,
					unsigned int * outputChecksum)
{
	unsigned int beforeUpperTime, beforeLowerTime;	//Used to store the halves of the timestamp counter
	unsigned int afterUpperTime, afterLowerTime;	//Used to store the halves of the timestamp counter
	unsigned char * codeStart, * codeEnd;
	unsigned int memRange; //codeEnd - codeStart, for use in keeping memory reads in bounds
	unsigned int blockZeroAddress;
	unsigned int i;
	unsigned int tmp;
	int ret;
	unsigned int rangeCtr;		//used to determine which memory range the minichecksum should be operating on next
	unsigned int ndisStart, halStart, ntStart, ndisEnd, halEnd, ntEnd;
	unsigned int halpRealModeStart, halpRealModeEnd;
	unsigned int ntSSDTStart, ntSSDTEnd;
	unsigned int blockAddressTable[NUM_BLOCKS];


	/*INITIALIZATION*/
	rangeCtr = -1;
	codeStart = (unsigned char *) SelfCheck_v6;
	//codeEnd need to be set to the function after SelfCheck_v6 
	//in the binary. This is because v6 only checks its own function, and then
	//the minichecksum checks the rest. The function after the v6 function
	//can only be found by disassembling, because apparently the linker doesn't
	//seem to be being consistent and use either the order in the measure_self.h 
	//or the lexicographical order
	
	//Want to get the address of selfCheckFunctionEnd into a variable
	__asm lea edi, selfCheckV6End;
	__asm add edi, 0x10;	//We add enough so that we make sure we cover the function asm epilog
	__asm mov codeEnd, edi;

		//Want to get the address of blockZero into a variable
	__asm	lea edi, blockZero;		// blockZero is text (code) address declared below
	__asm	mov blockZeroAddress, edi;

	for (i=0;i<NUM_BLOCKS;i++)
	{
		blockAddressTable[i] = blockZeroAddress + (i*BLOCK_SIZE);
	}

	//The memory range should cover all of SelfCheck_v6, the prolog (this code), blocks, and epilog
	memRange = (unsigned int)codeEnd - (unsigned int)codeStart;

	KdPrint(("INITIAL VALUES BEFORE LOOP\n"));
	KdPrint(("codeStart = %#x\n", codeStart));
	KdPrint(("codeEnd = %#x\n", codeEnd));
	KdPrint(("memRange = %#x\n", memRange));

	//Set the control debug register (DR7) to a value based on the nonce
	//because we will then read that value through the checksum
	__asm	mov eax, nonce;
	__asm	shl eax, 16;
	__asm	mov dr7, eax;

	//Serializing instruction
	__asm xor eax,eax;
	__asm cpuid;
	//Optional - Just for doing a total time determination
	__asm rdtsc;
	__asm mov beforeUpperTime, edx;
	__asm mov beforeLowerTime, eax;

	//REGISTER CONVENTIONS FOR THE BELOW CODE:
	//---long lived registers---
	//ecx = occasionally accumulates values read and holds EIP_DST right before inter-block transitions
	//ebx = long lived counter to determine how many blocks to execute
	//edi = data pointer, points at self memory to read and check
	//esi = x for PRNG
	//esp = checksum[1] for a memory layout of checksum[0],gap,[1],[2],[3],[4],[5]
	//---scratch registers---
	//eax = scratch register, occasionally accumulates values read
	//edx = scratch register, general purpose

		//initializations for long-lived register values
	__asm	mov edi, codeStart;			//Data Pointer
	__asm	mov ebx, numIterations;		//Number of times to loop
	__asm	mov esi, nonce;				//Pseudo Random Number (PRN)
	__asm	mov ecx, blockZeroAddress;	//The new code wants ecx to hold the EIP_DST
	__asm	sub esp, 0x14;					//memory is like checksum[0],gap,[1],[2],[3],[4],[5] so +8 to get to checksum[1]
		//now esp points at checksum[1]
	__asm	mov dword ptr [esp-8], 0xdeadbeef;
	__asm	mov dword ptr [esp-4], 0;
	__asm	mov dword ptr [esp], 0xcafebabe;
	__asm	mov dword ptr [esp+4], 0xf005ba11;
	__asm	mov dword ptr [esp+8], 0xca55e77e;
	__asm	mov dword ptr [esp+0xC], 0xf01dab1e;
	__asm	mov dword ptr [esp+0x10], 0xb01dface;
	__asm	push ecx;

//BLOCKS AND SUBBLOCKS
//Each block will be divided into multiple sub-blocks. These are:
//1) PRN Update
//2) Memory Read
//3) State Read
//4) Checksum Update
//5) Inter-block Jump
//NOTE! There can be multiple instances of 1-4 in a given block, and only one instance of 5

blockZero:
	//////////////////////////////////
	//ONE TIME EIP MIX IN
	//////////////////////////////////
	__asm	add ecx, [esp];	//ecx = EIP_DST + EIP_SRC
	__asm	add esp, 4;	//to make it point back at checksum[1] instead of the tmp storage gap

	//////////////////////////////////
	//UPDATE PRN SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx. UPDATES: esi(PRN), ecx(accumulator)
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN

	//////////////////////////////////
	//MEMORY READING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx, UPDATES:edi(DP), ecx(accumulator)
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP

	//Extra subblocks to pad out size to have all blocks be the same size but
	//still have room to remove these to make space for the minichecksums
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(codeStart, memRange);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP

	//////////////////////////////////
	//ADDITIONAL STATE READING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx, [esp-4] UPDATES: ecx(accumulator)
	READ_UEE_STATE_WITH_XOR_DR7_ADD_EFLAGS;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP XOR DR7 + EFLAGS

	//Incoporates either the return address into SendSelfMeasurementPackets or
	//the return address into FilterPackets into the accumulator.
	//CLOBBERS: eax, edx UPDATES: ecx(accumulator)
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP XOR DR7 + EFLAGS + ret XOR PRN

	//////////////////////////////////
	//CHECKSUM MIXING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx UPDATES:checksum[numIterations%5]
	SUBBLOCK_CHECKSUM_UPDATE;

	//////////////////////////////////
	//JUMP SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: ecx, eax.
	SUBBLOCK_INTERBLOCK_TRANSFER(blockAddressTable);
blockOne:
	COMPLETE_V6_BLOCK_VAR1(codeStart, memRange, blockAddressTable);
	COMPLETE_V6_BLOCK_VAR2(codeStart, memRange, blockAddressTable);
	COMPLETE_V6_BLOCK_VAR3(codeStart, memRange, blockAddressTable);
	COMPLETE_V6_BLOCK_VAR4(codeStart, memRange, blockAddressTable);
blockNminus2:
	COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR1(codeStart, memRange, blockAddressTable);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so that
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect to see 64 byte cache lines, but am using 32 for backwards compat)
miniFrag1:
	//This is like SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D without random order traversal
	__asm add ecx, edi;		//ecx = PRN + DP
	__asm xor ecx, [edi];	//ecx = PRN + DP XOR [DP]
	__asm add edi, 4;		//Move the data pointer forward in memory

	__asm and eax, 3;
	__asm xor [esp + eax*4], ecx;
	__asm sub eax, 1;

	__asm bt dword ptr [esp+0x10], 1;

	__asm jmp miniFrag2;
	__asm nop;
	__asm nop;
	__asm nop;
blockNminus1:
	COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR2(codeStart, memRange, blockAddressTable);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so that
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect to see 64 byte cache lines, but am using 32 for backwards compat)
miniFrag2:
	//This is the first part of SUBBLOCK_CHECKSUM_UPDATE
	__asm rcr dword ptr [esp-0x08], 1;
	__asm rcr dword ptr [esp], 1;
	__asm rcr dword ptr [esp+0x04], 1;
	__asm rcr dword ptr [esp+0x08], 1;
	__asm rcr dword ptr [esp+0x0C], 1;
	__asm rcr dword ptr [esp+0x10], 1;
	__asm jmp miniFrag3;
	__asm nop;
	__asm nop;
blockN:
	COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR3(codeStart, memRange, blockAddressTable);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so thatto
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect 64 byte cache lines, but am using 32 for backwards compat)'
miniFrag3:

	__asm cmp edi, esi;	//Check to see if we've covered all of memory yet
	__asm jb miniFrag1;		//Exit the loop if done (jump above = unsigned)
	
setRange:
	__asm add rangeCtr, 1;
	__asm sub esp, 8;//protect esp-8 value. Can delete when no more functions in the switch
	__asm push eax;//protect eax value. Can delete when no more functions in the switch
	switch(rangeCtr){
		//First we cover our own driver, as normal
		case 0:
			KdPrint(("Output checksum before minichecksum\n"));
			KdPrint(("(eax,ignore = %#x)\n [0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n"));
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, SelfCheck_v6; //This is the first function in our .text section
			__asm	and di, 0xF000;	//Aligned down so that we include the headers
			__asm	mov esi, NdisRequest; //This is the last function in our .text section
			__asm	add esi, 6; //because NdisRequest is a 6 byte jump
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	mov eax, ebx;	//First time only, set up eax to be decrementing counter starting at known value (0 at this point)
			__asm	jmp miniFrag1;
		//Then we cover ndis
		case 1:
			KdPrint(("Output checksum after minichecksum\n"));
			KdPrint(("(eax,ignore = %#x)\n [0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n"));
			//Find the ndis range
			moduleInfo->ndisInfo.base = SearchForDriver(theDriverObject, L"ndis.sys");
			if(moduleInfo->ndisInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"ndis.sys", moduleInfo->ndisInfo.base, &ndisStart, &ndisEnd, &(moduleInfo->ndisInfo.timeDateStamp), &(moduleInfo->ndisInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			__asm pop eax;
			__asm add esp, 8;

			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, ndisStart;
			__asm	mov esi, ndisEnd;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp miniFrag1; 
		case 2:
			KdPrint(("Output checksum after ndis minichecksum\n"));
			KdPrint(("(eax,ignore = %#x)\n [0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n"));

			//Find the nt range
			moduleInfo->ntInfo.base = SearchForDriver(theDriverObject, L"ntoskrnl.exe");
			if(moduleInfo->ntInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"ntoskrnl.exe", moduleInfo->ntInfo.base, &ntStart, &ntEnd, &(moduleInfo->ntInfo.timeDateStamp), &(moduleInfo->ntInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			KdPrint(("ntStart = %#x\n", ntStart));
			KdPrint(("ntEnd = %#x\n", ntEnd));
			//This is theoretically equivalent to KiServiceTable (unexported symbol)
			ntSSDTStart = (unsigned int) (KeServiceDescriptorTable.ServiceTableBase);
			KdPrint(("ntSSDTStart = %#x\n", ntSSDTStart));
			//This is theoretically equivalent to KiServiceLimit (unexported symbol)
			ntSSDTEnd = ntSSDTStart + ( KeServiceDescriptorTable.NumberOfServices * sizeof(int));
			KdPrint(("ntSSDTEnd = %#x\n", ntSSDTEnd));
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, ntStart;
			__asm	mov esi, ntSSDTStart;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp miniFrag1; 
		case 3:
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, ntSSDTEnd;
			__asm	mov esi, ntEnd;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp miniFrag1; 
		case 4:
			//Find the hal range
			moduleInfo->halInfo.base = SearchForDriver(theDriverObject, L"hal.dll");
			if(moduleInfo->halInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"hal.sys", moduleInfo->halInfo.base, &halStart, &halEnd, &(moduleInfo->halInfo.timeDateStamp), &(moduleInfo->halInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			ret = getHalpRealModeStartAndEnd(moduleInfo->halInfo.base, moduleInfo->halInfo.timeDateStamp, moduleInfo->halInfo.sizeOfImage, &halpRealModeStart, &halpRealModeEnd);
			if (ret != GENERIC_SUCCESS) return NDIS_FAILURE;
			__asm pop eax;
			__asm add esp, 8;

			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, halStart;
			__asm	mov esi, halpRealModeStart;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp miniFrag1;
		case 5:
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, halpRealModeEnd;
			__asm	mov esi, halEnd;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp miniFrag1;

		default:
			//The halStart and halEnd don't matter since I'm not going to use it.
			//Just setting the base, timeDateStamp, and sizeOfImage for these modules
			moduleInfo->bootvidInfo.base = SearchForDriver(theDriverObject, L"bootvid.dll");
			if(moduleInfo->bootvidInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"bootvid.dll", moduleInfo->bootvidInfo.base, &halStart, &halEnd, &(moduleInfo->bootvidInfo.timeDateStamp), &(moduleInfo->bootvidInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			moduleInfo->kdcomInfo.base = SearchForDriver(theDriverObject, L"kdcom.dll");
			if(moduleInfo->kdcomInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"kdcom.dll", moduleInfo->kdcomInfo.base, &halStart, &halEnd, &(moduleInfo->kdcomInfo.timeDateStamp), &(moduleInfo->kdcomInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			__asm pop eax;
			__asm add esp, 8;
			break;
	}

//This label is used as the boundary of the self-check function checking itself
selfCheckFunctionEnd:

	//Set the checksum values to send back
	__asm	mov eax, outputChecksum;
	__asm	mov ebx, [esp-8];
	__asm	mov [eax], ebx;
		//check out my wicked sweet memory to memory move ;)
	__asm	pop dword ptr [eax+4];
	__asm	pop dword ptr [eax+8];
	__asm	pop dword ptr [eax+0xC];
	__asm	pop dword ptr [eax+0x10];
	__asm	pop dword ptr [eax+0x14];
		//At this point esp should hopefully be pointing at the caller-save registers

	//Serializing instruction
	__asm xor eax,eax ;
	__asm cpuid ;
	__asm rdtsc ;
	__asm mov afterUpperTime, edx ;
	__asm mov afterLowerTime, eax ;
	*upperCycleCount = afterUpperTime - beforeUpperTime;
	*lowerCycleCount = afterLowerTime - beforeLowerTime;

	KdPrint(("outputChecksum[0] = 0x%08x\n",outputChecksum[0]));
	KdPrint(("outputChecksum[1] = 0x%08x\n",outputChecksum[1]));
	KdPrint(("outputChecksum[2] = 0x%08x\n",outputChecksum[2]));
	KdPrint(("outputChecksum[3] = 0x%08x\n",outputChecksum[3]));
	KdPrint(("outputChecksum[4] = 0x%08x\n",outputChecksum[4]));
	KdPrint(("outputChecksum[5] = 0x%08x\n",outputChecksum[5]));

selfCheckV6End:
	return GENERIC_SUCCESS;
}

//This is the version of the attack which maps a clean copy of the client into memory and then lies 
//about the base address sent back in the measurement, so that tiresias reconstructs based on that
//base address. In this way the attacker only needs to forge EIP, not DP
//NOTE: this can probably be optimized by padding out the location of the tiresias code so that the
//EIP_SRC and EIP_DST are some power of 2 difference from the expected, so that it can use shifts
int SelfCheck_Attack(	PDRIVER_OBJECT theDriverObject,
						unsigned int nonce,
						unsigned int numIterations,
						unsigned int baseVA, 
						api_module_info_t * moduleInfo, 
						unsigned int * upperCycleCount,
						unsigned int * lowerCycleCount,
						unsigned int * outputChecksum)
{
	unsigned int beforeUpperTime, beforeLowerTime;	//Used to store the halves of the timestamp counter
	unsigned int afterUpperTime, afterLowerTime;	//Used to store the halves of the timestamp counter
	char * memToCheck; //the clean copy of the client mapped and relocated by the attacker, so he doesn't have to forge DP
	unsigned int memRange; //codeEnd - codeStart, for use in keeping memory reads in bounds
	unsigned int cleanMemBlockZeroAddress; //address that blockZero would be in the clean memory range 
	//The absolute address where the client SelfCheck_vX function starts
	unsigned int clientAbsoluteSelfCheckAddress;
	//The place in the client's memory where the minichecksum should stop checksumming
	unsigned int clientAbsoluteMinichecksumEndAddress;
	//used to determine which memory range the minichecksum should be operating on next
	unsigned int rangeCtr;
	//This is used by the code to keep track of which index block of the 
	//tiresias/original code would be executing
	unsigned int currentIndex;
	//This holds the EIP_SRC which would have been pushed onto the stack by
	//the inter-block call
	unsigned int origEipSrcArray[NUM_BLOCKS];
	//This holds the addresses of the starts of the blocks used by the variant tiresias blocks
	unsigned int tiresiasEipDstArray[NUM_BLOCKS];
	//variables to hold memory ranges over which successive minichecksums will scan
	unsigned int ndisStart, ndisEnd, ntStart, ntEnd, ntSSDTStart, ntSSDTEnd, halStart, halEnd, halpRealModeStart, halpRealModeEnd;
	unsigned int tmp;
	int ret;
	//Used to save the original stack return addresses for parent and grandparent function
	//so the attacker can modify them and not have to fix them in the loops, but then
	//set them back when done.
	unsigned int origRetParent, origRetGrandparent;

	/*INITIALIZATION*/
	//the clean copy of the client mapped and relocated by the attacker, so he doesn't have to forge DP
	memToCheck = gCheckmateCleanImage;
	rangeCtr = -1; //Set this to the 1+number of ranges we set in setRange:
	///unsigned int numIterations = nonce;
	currentIndex = 0;

	//Because blockZeroAddress is used in SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS to recreate the EIP_DST 
	//as it would appear in the clean memory range, this should be set to the address in the clean memory range
	cleanMemBlockZeroAddress = memToCheck + CLIENT_RELATIVE_BLOCKZERO;
	clientAbsoluteSelfCheckAddress = memToCheck + CLIENT_RELATIVE_CHECKSUM_START; //Data Pointer pointing at attacker's clean copy
	clientAbsoluteMinichecksumEndAddress = memToCheck + CLIENT_RELATIVE_MINICHECK_END;
	memRange = (unsigned int)(CLIENT_RELATIVE_CHECKSUM_END - CLIENT_RELATIVE_CHECKSUM_START + 0x10);

		//Want to get the address of blockZero into a variable
	__asm	lea edi, attack_blockZero;		// blockZero is text (code) address declared below
	__asm	mov tmp, edi;

	tiresiasEipDstArray[0] = tmp;
	tiresiasEipDstArray[1] = tiresiasEipDstArray[0] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[2] = tiresiasEipDstArray[1] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[3] = tiresiasEipDstArray[2] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[4] = tiresiasEipDstArray[3] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[5] = tiresiasEipDstArray[4] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[6] = tiresiasEipDstArray[5] + TIRESIAS_BLOCK_SIZE; //NOTE: this attack offset differs from tiresias, because tiresias doesn't inline the minichecksum
	tiresiasEipDstArray[7] = tiresiasEipDstArray[6] + TIRESIAS_BLOCK_SIZE; //NOTE: this attack offset differs from tiresias, because tiresias doesn't inline the minichecksum

	origEipSrcArray[0] = memToCheck+CLIENT_RELATIVE_BLOCKZERO+BLOCK_SIZE;
	origEipSrcArray[1] = origEipSrcArray[0] + BLOCK_SIZE;
	origEipSrcArray[2] = origEipSrcArray[1] + BLOCK_SIZE;
	origEipSrcArray[3] = origEipSrcArray[2] + BLOCK_SIZE;
	origEipSrcArray[4] = origEipSrcArray[3] + BLOCK_SIZE;
	origEipSrcArray[5] = origEipSrcArray[4] + SMALL_BLOCK_SIZE ;
	origEipSrcArray[6] = origEipSrcArray[4] + BLOCK_SIZE + SMALL_BLOCK_SIZE;
	origEipSrcArray[7] = origEipSrcArray[4] + 2*BLOCK_SIZE + SMALL_BLOCK_SIZE - 4;

	//Create backups of the parent and grandparent return addresses, so they can be restored 
	//before returning. And then replace them with the values they would be if the code were
	//executing from the clean copy.
	__asm mov eax, [ebp+4];
	__asm mov origRetParent, eax;
	__asm sub eax, baseVA;	//now it should just be an RVA
	__asm add eax, memToCheck;	//add RVA to base of clean copy
	__asm mov [ebp+4], eax;	//put the absolute ret address for the clean copy into parent's return location
		
	__asm mov ebx, [ebp];
	__asm mov eax, [ebx+4];
	__asm mov origRetGrandparent, eax;
	__asm sub eax, baseVA; //now it should just be an RVA
	__asm add eax, memToCheck;	//add RVA to base of clean copy
	__asm mov [ebx+4], eax;	//put the absolute ret address for the clean copy into grandparent's return location
	//Now the attacker doesn't have to fix these each time through the loop

	//Set the control debug register (DR7) to a value based on the nonce
	//because we will then read that value through the checksum
	__asm	mov eax, nonce;
	__asm	shl eax, 16;
	__asm	mov dr7, eax;

	//Serializing instruction
	__asm xor eax,eax;
	__asm cpuid;
	//Optional - Just for doing a total time determination
	__asm rdtsc;
	__asm mov beforeUpperTime, edx;
	__asm mov beforeLowerTime, eax ;

	//REGISTER CONVENTIONS FOR THE BELOW CODE:
	//---long lived registers---
	//ecx = occasionally accumulates values read and holds EIP_DST right before inter-block transitions
	//ebx = address of base of checksum array
	//edi = data pointer, points at self memory to read and check
	//esi = x for PRNG
	//esp = checksum[1] for a memory layout of checksum[0],gap,[1],[2],[3],[4],[5]
	//---scratch registers---
	//eax = scratch register, occasionally accumulates values read
	//edx = scratch register, general purpose

	//NOTE!: In v6 I switched away from DP in tiresias pointing at tiresias's copy, 
	//and instead now it maintains the original client DP, and it changes it 
	//to point at tiresias' copy just in time. This is so that when the DP is updated
	//that it will have the same high kernel value as the client had, thus aleviating
	//the need to set the sign flag manually after the pushfd instruction
		//initializations for long-lived register values
	__asm	mov edi, clientAbsoluteSelfCheckAddress;	//Data Pointer pointing at attacker's clean copy
	__asm	mov ebx, numIterations;		//Number of times to loop
	__asm	mov esi, nonce;				//Pseudo Random Number (PRN)
	__asm	mov ecx, cleanMemBlockZeroAddress;	//The new code wants ecx to hold the EIP_DST, and cleanMemBlockZeroAddress points into the clean memory range
	__asm	sub esp, 0x14;
		//now esp points at checksum[1]
	__asm	mov dword ptr [esp-8], 0xdeadbeef;
	__asm	mov dword ptr [esp-4], 0;
	__asm	mov dword ptr [esp], 0xcafebabe;
	__asm	mov dword ptr [esp+4], 0xf005ba11;
	__asm	mov dword ptr [esp+8], 0xca55e77e;
	__asm	mov dword ptr [esp+0xC], 0xf01dab1e;
	__asm	mov dword ptr [esp+0x10], 0xb01dface;
	__asm	push ecx;

//BLOCKS AND SUBBLOCKS
//Each block will be divided into multiple sub-blocks. These are:
//1) PRN Update
//2) Memory Read
//3) State Read (currently unused)
//4) Checksum Update
//5) Inter-block Jump
//There can be multiple instances of 1-4 in a given block, and only one instance of 5

attack_blockZero:
	//////////////////////////////////
	//ONE TIME EIP MIX IN
	//////////////////////////////////
	__asm	add ecx, [esp];	//ecx = EIP_DST + EIP_SRC
	__asm	add esp, 4;	//to make it point back at checksum[1] instead of the tmp storage gap

	//////////////////////////////////
	//UPDATE PRN SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx. UPDATES: esi(PRN), ecx(accumulator)
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN

	//////////////////////////////////
	//MEMORY READING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx, UPDATES:edi(DP), ecx(accumulator)
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(clientAbsoluteSelfCheckAddress, memRange);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP

	//Extra subblocks to pad out size to have all blocks be the same size but
	//still have room to remove these to make space for the minichecksums
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(clientAbsoluteSelfCheckAddress, memRange);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP

	//////////////////////////////////
	//ADDITIONAL STATE READING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx, [esp-4] UPDATES: ecx(accumulator)
	READ_UEE_STATE_WITH_XOR_DR7_ADD_EFLAGS;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP XOR DR7 + EFLAGS

	//Incoporates either the return address into SendSelfMeasurementPackets or
	//the return address into FilterPackets into the accumulator.
	//CLOBBERS: eax, edx UPDATES: ecx(accumulator)
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP XOR DR7 + EFLAGS + ret XOR PRN

	//////////////////////////////////
	//CHECKSUM MIXING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx UPDATES:checksum[numIterations%5]
	SUBBLOCK_CHECKSUM_UPDATE;

	//////////////////////////////////
	//JUMP SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: ecx, eax.
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
attack_blockOne:
	COMPLETE_V6_TIRESIAS_BLOCK_VAR1(clientAbsoluteSelfCheckAddress, memRange, cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
	COMPLETE_V6_TIRESIAS_BLOCK_VAR2(clientAbsoluteSelfCheckAddress, memRange, cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
	COMPLETE_V6_TIRESIAS_BLOCK_VAR3(clientAbsoluteSelfCheckAddress, memRange, cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
	COMPLETE_V6_TIRESIAS_BLOCK_VAR4(clientAbsoluteSelfCheckAddress, memRange, cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
attack_blockNminus2:
	COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR1(clientAbsoluteSelfCheckAddress, memRange, cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so that
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect to see 64 byte cache lines, but am using 32 for backwards compat)
attack_miniFrag1:
	//This is like SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D without random order traversal
	__asm add ecx, edi;		//ecx = PRN + DP
	__asm xor ecx, [edi];	//ecx = PRN + DP XOR [DP]
	__asm add edi, 4;		//Move the data pointer forward in memory

	__asm and eax, 3;
	__asm xor [esp + eax*4], ecx;
	__asm sub eax, 1;

	__asm bt dword ptr [esp+0x10], 1;

	__asm jmp attack_miniFrag2;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
attack_blockNminus1:
	COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR2(clientAbsoluteSelfCheckAddress, memRange, cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so that
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect to see 64 byte cache lines, but am using 32 for backwards compat)
attack_miniFrag2:
	//This is the first part of SUBBLOCK_CHECKSUM_UPDATE
	__asm rcr dword ptr [esp-0x08], 1;
	__asm rcr dword ptr [esp], 1;
	__asm rcr dword ptr [esp+0x04], 1;
	__asm rcr dword ptr [esp+0x08], 1;
	__asm rcr dword ptr [esp+0x0C], 1;
	__asm rcr dword ptr [esp+0x10], 1;
	__asm jmp attack_miniFrag3;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
attack_blockN:
	COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR3(clientAbsoluteSelfCheckAddress, memRange, cleanMemBlockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so thatto
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect 64 byte cache lines, but am using 32 for backwards compat)'
attack_miniFrag3:

	__asm cmp edi, esi;	//Check to see if we've covered all of memory yet
	__asm jb attack_miniFrag1;		//Exit the loop if done (jump above = unsigned)
	
attack_setRange:
	__asm add rangeCtr, 1;
	__asm sub esp, 8;//protect esp-8 value. Can delete when no more functions in the switch
	__asm push eax;//protect eax value. Can delete when no more functions in the switch
	switch(rangeCtr){
		//First we cover our own driver, as normal
		case 0:
			KdPrint(("Output checksum before minichecksum\n"));
			KdPrint(("[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n"));
			KdPrint(("Mini self-checksum, edi = 0x%08x, esi = 0x%08x\n", (unsigned int)memToCheck, ((((unsigned int)NdisRequest+6)-(unsigned int)baseVA+(unsigned int)memToCheck) & 0xFFFFFFFC)));
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, memToCheck; //the base of the clean memory space, starting with the PE headers
			__asm	mov esi, NdisRequest; //This is the last function in our .text section
			__asm	add esi, 6; //because NdisRequest is a 6 byte jump
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	sub esi, baseVA;//now correct to be the NdisRequest in the clean memory space. Subtract to make it an offset
			__asm	add esi, memToCheck;//add the offset to the base of the clean memory space
			__asm	mov eax, ebx;	//First time only, set up eax to be decrementing counter starting at known value (0 at this point)
			__asm	jmp attack_miniFrag1;
		//Then we cover ndis
		case 1:
			KdPrint(("Output checksum after minichecksum\n"));
			KdPrint(("[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n"));
			//Find the ndis range
			moduleInfo->ndisInfo.base = SearchForDriver(theDriverObject, L"ndis.sys");
			if(moduleInfo->ndisInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"ndis.sys", moduleInfo->ndisInfo.base, &ndisStart, &ndisEnd, &(moduleInfo->ndisInfo.timeDateStamp), &(moduleInfo->ndisInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			KdPrint(("ndisStart = %#x\nndisEnd = %#x\n", ndisStart, ndisEnd));
			__asm pop eax;
			__asm add esp, 8;

			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, ndisStart;
			__asm	mov esi, ndisEnd;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp attack_miniFrag1; 
		case 2:
			KdPrint(("Output checksum after ndis minichecksum\n"));
			KdPrint(("[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n"));

			//Find the nt range
			moduleInfo->ntInfo.base = SearchForDriver(theDriverObject, L"ntoskrnl.exe");
			if(moduleInfo->ntInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"ntoskrnl.exe", moduleInfo->ntInfo.base, &ntStart, &ntEnd, &(moduleInfo->ntInfo.timeDateStamp), &(moduleInfo->ntInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			KdPrint(("ntStart = %#x\nntEnd = %#x\n", ntStart, ntEnd));
			//This is theoretically equivalent to KiServiceTable (unexported symbol)
			ntSSDTStart = (unsigned int) (KeServiceDescriptorTable.ServiceTableBase);
			//This is theoretically equivalent to KiServiceLimit (unexported symbol)
			ntSSDTEnd = ntSSDTStart + ( KeServiceDescriptorTable.NumberOfServices * sizeof(int));
			KdPrint(("ntSSDTStart = %#x\nntSSDTEnd = %#x\n", ntSSDTStart, ntSSDTEnd));
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, ntStart;
			__asm	mov esi, ntSSDTStart;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp attack_miniFrag1; 
		case 3:
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, ntSSDTEnd;
			__asm	mov esi, ntEnd;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp attack_miniFrag1; 
		case 4:
			//Find the hal range
			moduleInfo->halInfo.base = SearchForDriver(theDriverObject, L"hal.dll");
			if(moduleInfo->halInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"hal.sys", moduleInfo->halInfo.base, &halStart, &halEnd, &(moduleInfo->halInfo.timeDateStamp), &(moduleInfo->halInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			ret = getHalpRealModeStartAndEnd(moduleInfo->halInfo.base, moduleInfo->halInfo.timeDateStamp, moduleInfo->halInfo.sizeOfImage, &halpRealModeStart, &halpRealModeEnd);
			if (ret != GENERIC_SUCCESS) return NDIS_FAILURE;
			KdPrint(("halStart = %#x\nhalEnd = %#x\nhalpRealModeStart = %#x\nhalpRealModeEnd = %#x\n", halStart, halEnd, halpRealModeStart, halpRealModeEnd));
			__asm pop eax;
			__asm add esp, 8;

			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, halStart;
			__asm	mov esi, halpRealModeStart;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp attack_miniFrag1;
		case 5:
			__asm pop eax;
			__asm add esp, 8;
			__asm	mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
			__asm	mov edi, halpRealModeEnd;
			__asm	mov esi, halEnd;
			__asm	and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
			__asm	jmp attack_miniFrag1;

		case 6:
			//The halStart and halEnd don't matter since I'm not going to use it.
			//Just setting the base, timeDateStamp, and sizeOfImage for these modules
			moduleInfo->bootvidInfo.base = SearchForDriver(theDriverObject, L"bootvid.dll");
			if(moduleInfo->bootvidInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"bootvid.dll", moduleInfo->bootvidInfo.base, &halStart, &halEnd, &(moduleInfo->bootvidInfo.timeDateStamp), &(moduleInfo->bootvidInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			moduleInfo->kdcomInfo.base = SearchForDriver(theDriverObject, L"kdcom.dll");
			if(moduleInfo->kdcomInfo.base == NULL) return NDIS_FAILURE;
			tmp = FindTextSectionStartAndEnd(L"kdcom.dll", moduleInfo->kdcomInfo.base, &halStart, &halEnd, &(moduleInfo->kdcomInfo.timeDateStamp), &(moduleInfo->kdcomInfo.sizeOfImage));
			if(tmp != STATUS_SUCCESS) return NDIS_FAILURE;
			__asm pop eax;
			__asm add esp, 8;
			break;
	}

//This label is used as the boundary of the self-check function checking itself
selfCheckFunctionEnd:

	//Set the checksum values to send back
	
	__asm mov eax, outputChecksum;
	__asm mov ebx, [esp-8];
	__asm mov [eax], ebx;
		//check out my wicked sweet memory to memory move ;)
	__asm pop dword ptr [eax+4];
	__asm pop dword ptr [eax+8];
	__asm pop dword ptr [eax+0xC];
	__asm pop dword ptr [eax+0x10];
	__asm pop dword ptr [eax+0x14];
		//At this point esp should hopefully be pointing at the caller-save registers

	//Serializing instruction
	__asm xor eax,eax;
	__asm cpuid;
	__asm rdtsc;
	__asm mov afterUpperTime, edx;
	__asm mov afterLowerTime, eax;
	*upperCycleCount = afterUpperTime - beforeUpperTime;
	*lowerCycleCount = afterLowerTime - beforeLowerTime;
	KdPrint(("*upperCycleCount = %#x, *lowerCycleCount = %#x\n", *upperCycleCount, *lowerCycleCount));

	KdPrint(("outputChecksum[0] = 0x%08x\n",outputChecksum[0]));
	KdPrint(("outputChecksum[1] = 0x%08x\n",outputChecksum[1]));
	KdPrint(("outputChecksum[2] = 0x%08x\n",outputChecksum[2]));
	KdPrint(("outputChecksum[3] = 0x%08x\n",outputChecksum[3]));
	KdPrint(("outputChecksum[4] = 0x%08x\n",outputChecksum[4]));
	KdPrint(("outputChecksum[5] = 0x%08x\n",outputChecksum[5]));

	//Restore the parent and grandparent return addresses before returning
	__asm mov eax, origRetParent;
	__asm mov [ebp+4], eax;
		
	__asm mov eax, [ebp];
	__asm mov ebx, origRetGrandparent;
	__asm mov [eax+4], ebx;

	return GENERIC_SUCCESS;
}

NTSTATUS
SendSelfMeasurementsPackets(PDRIVER_OBJECT driverObject, 
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

	KdPrint(("In SendSelfMeasurementsPackets\n"));

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
	responseHdr.type = TIMING_TEST;
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
		ret = SelfCheck_v6(driverObject, randFromServer, numIterations, pSelfCheck->baseVA, &(pSelfCheck->moduleInfo), &pSelfCheck->upperCycleCount, &pSelfCheck->lowerCycleCount, (unsigned int *)pSelfCheck->checksum);
normalparent:
		if(ret != GENERIC_SUCCESS) return ret;
		if (gAttackActivated == 1)
			pSelfCheck->baseVA = gCheckmateCleanImage;
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