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

#include "measure_self.h"
#include "windows.h" //for winnt.h for PIMAGE_DOS_HEADER etc
#include "pe.h"
#include "file_access.h"
#include "parse_symbols.h"
#include "measure_binary.h"
#include "database_mysql2.h"
extern "C"{
	#include "database_mysql.h"
}
#include <mysql.h>
#include <vector>

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
extern "C" HANDLE mysqlMutex;
extern char * gffStoragePath;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//If a prerequisite is needed, the id of the entry in the Prerequisites
//table after insertion is passed back in the prereqID field
int AnalyzeFileForSelfMeasurement(HANDLE mysqlMutex, char * fullFileName, st_msg_t * stm){

	PIMAGE_DOS_HEADER pDosH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pFirstSectH = NULL;
	unsigned int alignmentOffset;

	int ret = 0;
	FILE * fileStream;

	//Open the file to read the headers
	errno_t err = fopen_s(&fileStream,fullFileName,"rb");
	if(err != 0){
		printf("AnalyzeFileForBinaryMeasurement:error: Couldn't fopen_s %s, errno = %d\n", fullFileName, errno);
		return GENERIC_ERROR;
	}

	if(ParsePEHeaders(fileStream, &pDosH, &pNtH, &pFirstSectH) == GENERIC_ERROR){
		printf("Unsupported case in %s\n", fullFileName);
		fclose(fileStream);
		return GENERIC_ERROR;
	}

	unsigned int baseVADiff = FindBaseVADiff(stm->baseVA, pNtH);
	char * relocBuf = FindRelocs(fileStream, pNtH, pFirstSectH);
	unsigned int outputBufLen;

	unsigned int endAlignUpPadding;
	char * relocatedSectionBuffer;
	//relocatedSectionBuffer alloced inside GetRelocatedSection, make sure to dealloc outside
	ret = GetRelocatedSection(fileStream, pNtH, pFirstSectH, baseVADiff, relocBuf, &alignmentOffset, &endAlignUpPadding, &relocatedSectionBuffer, &outputBufLen);
	if(ret == GENERIC_ERROR){
		printf("AnalyzeFileForSelfMeasurement: GetRelocatedSection failed\n");
		free(pDosH);
		free(relocBuf);
		free(relocatedSectionBuffer);
		fclose(fileStream);	
		return GENERIC_ERROR;
	}

	//Calculate the checksum using a modified version of the same code which the client uses
	printf("\n\n SelfCheck_v6_tiresias\n\n");
	ret = SelfCheck_v6_tiresias(relocatedSectionBuffer, stm);
	if(ret != GENERIC_SUCCESS){
		printf("AnalyzeFileForSelfMeasurement: SelfCheck_v6_tiresias failed\n");
		free(pDosH);
		free(relocBuf);
		fclose(fileStream);
		return GENERIC_ERROR;
	}

	//Put the checksum into the database, so that server can get it back out
	unsigned int ChecksumID;
	ret = InsertChecksum(stm, &ChecksumID);
	if(ret != GENERIC_SUCCESS){
		printf("AnalyzeFileForSelfMeasurement: InsertChecksum failed\n");
		free(pDosH);
		free(relocBuf);
		free(relocatedSectionBuffer);
		fclose(fileStream);
		return GENERIC_ERROR;
	}

	free(pDosH);
	free(relocBuf);
	free(relocatedSectionBuffer);
	fclose(fileStream);
	return GENERIC_SUCCESS;
}

int SelfCheck_v6_tiresias(	char * memToCheck,
						    st_msg_t * stm)
{
	unsigned int beforeUpperTime, beforeLowerTime;	//Used to store the halves of the timestamp counter
	unsigned int afterUpperTime, afterLowerTime;	//Used to store the halves of the timestamp counter
	unsigned int upperDiff, lowerDiff;	//Used to store the halves of the timestamp counter
	unsigned int memRange; //codeEnd - codeStart, for use in keeping memory reads in bounds
	unsigned int blockZeroAddress;
	//The absolute address where the client SelfCheck_vX function starts
	unsigned int clientAbsoluteSelfCheckAddress;
	//The difference between the original location to be
	//self-checksummed, vs where tiresias is currently keeping stuff in memory
	unsigned int clientVsTiresiasMemBase;
	//The place in the client's memory where the minichecksum should stop checksumming
	unsigned int clientAbsoluteMinichecksumEndAddress;
	//used to determine which memory range the minichecksum should be operating on next
	unsigned int rangeCtr;
	//This is used for tiresias(but not attack) to hold the dr7 value
	unsigned int tiresiasDR7;
	//This is used by the code to keep track of which index block of the 
	//tiresias/original code would be executing
	unsigned int currentIndex;
	//This holds the EIP_SRC which would have been pushed onto the stack by
	//the inter-block call
	unsigned int origEipSrcArray[NUM_BLOCKS];
	//This holds the addresses of the starts of the blocks used by the variant tiresias blocks
	unsigned int tiresiasEipDstArray[NUM_BLOCKS];
	//origGrandparentRetAddrArray is used to store the values the client should have seen on
	//the stack when it integrated in the saved return address of the parent or grandparent
	unsigned int origGrandparentRetAddrArray[4]; //Size should be set to the number of msgType values
	unsigned int origParentRetAddrArray[4]; //Size should be set to the number of msgType values
	unsigned int tmp;
	unsigned int nonce = stm->nonce;
	unsigned int baseVA = stm->baseVA;
	api_module_info_t * moduleInfo = &(stm->moduleInfo);
	msgType inResponseToType = stm->inResponseToType;
	unsigned int * outputChecksum = &(stm->checksum[0]);
	//variables to hold memory ranges over which successive minichecksums will scan
	unsigned int ndisStart, ndisEnd, ntStart, ntEnd, ntSSDTStart, ntSSDTEnd, halStart, halEnd, halpRealModeStart, halpRealModeEnd;
	int ret;
	//misc junk to make various functions happy
	char * relocatedSection = NULL;
	unsigned int relocSectLen, sectionStartRVA, sectionEndRVA;
	dia_symbol_t ssdtSym1, ssdtSym2, hackSym1, hackSym2, hackSym3, halSym1, halSym2;
	resolved_symbol_t resolvedHackSym1, resolvedHackSym2, resolvedHackSym3;
	vector<resolved_symbol_t *> resolvedBinaryEntries;
	vector<dia_symbol_t *> diaSymbolVector;
	char * fullFileName;
	st_msg_t fakeStm;

	/*INITIALIZATION*/
	rangeCtr = -1; //Set this to the 1+number of ranges we set in setRange:
	unsigned int numIterations = 2500000;
	if(stm->inResponseToType == TIMING_TEST){
		numIterations = nonce;
	}
	currentIndex = 0;
	//Place these at whatever clientbase+x address you have to place breakpoints in the client code while debugging
	//memToCheck[0x490] = 0xcc;
	//memToCheck[0xa9f] = 0xcc;
	//memToCheck[0xb30] = 0xcc;
	//memToCheck[0xc23] = 0xcc;

	blockZeroAddress = baseVA + CLIENT_RELATIVE_BLOCKZERO;
	clientVsTiresiasMemBase = (baseVA - (unsigned int)memToCheck);
	clientAbsoluteSelfCheckAddress = baseVA + CLIENT_RELATIVE_CHECKSUM_START;
	clientAbsoluteMinichecksumEndAddress = baseVA + CLIENT_RELATIVE_MINICHECK_END;
	memRange = (unsigned int)(CLIENT_RELATIVE_CHECKSUM_END - CLIENT_RELATIVE_CHECKSUM_START + 0x10);

	//place all the loaded module information into the database
	ret = SelfCheckLoadedModuleDatabaseInsertion(stm);
	if(ret != GENERIC_SUCCESS){
		printf("SelfCheck_v6_tiresias: SelfCheckLoadedModuleDatabaseInsertion failed\n");
		return ret;
	}

	//Want to get the address of blockZero into a variable
	__asm{
		lea edi, blockZero;		// blockZero is text (code) address declared below
		mov tmp, edi;
	}

	tiresiasEipDstArray[0] = tmp;
	tiresiasEipDstArray[1] = tiresiasEipDstArray[0] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[2] = tiresiasEipDstArray[1] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[3] = tiresiasEipDstArray[2] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[4] = tiresiasEipDstArray[3] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[5] = tiresiasEipDstArray[4] + TIRESIAS_BLOCK_SIZE;
	tiresiasEipDstArray[6] = tiresiasEipDstArray[5] + TIRESIAS_SMALL_BLOCK_SIZE;
	tiresiasEipDstArray[7] = tiresiasEipDstArray[6] + TIRESIAS_SMALL_BLOCK_SIZE;

	origEipSrcArray[0] = baseVA+CLIENT_RELATIVE_BLOCKZERO+BLOCK_SIZE;
	origEipSrcArray[1] = origEipSrcArray[0] + BLOCK_SIZE;
	origEipSrcArray[2] = origEipSrcArray[1] + BLOCK_SIZE;
	origEipSrcArray[3] = origEipSrcArray[2] + BLOCK_SIZE;
	origEipSrcArray[4] = origEipSrcArray[3] + BLOCK_SIZE;
	origEipSrcArray[5] = origEipSrcArray[4] + SMALL_BLOCK_SIZE ;
	origEipSrcArray[6] = origEipSrcArray[4] + BLOCK_SIZE + SMALL_BLOCK_SIZE;
	origEipSrcArray[7] = origEipSrcArray[4] + 2*BLOCK_SIZE + SMALL_BLOCK_SIZE - 4;

	memset(origParentRetAddrArray, 0, 4*sizeof(unsigned int));
	memset(origGrandparentRetAddrArray, 0, 4*sizeof(unsigned int));
	origParentRetAddrArray[TIMING_TEST] = baseVA + CLIENT_RELATIVE_PARENT_RET_NORMAL;
	origParentRetAddrArray[TICKSTAMP_ATTESTATION] = baseVA + CLIENT_RELATIVE_PARENT_RET_TICKSTAMP_ATTESTATION;
	origGrandparentRetAddrArray[TIMING_TEST] = baseVA + CLIENT_RELATIVE_GRANDPARENT_RET_TIMING_TEST;
	origGrandparentRetAddrArray[TICKSTAMP_ATTESTATION] = baseVA + CLIENT_RELATIVE_GRANDPARENT_RET_TICKSTAMP_ATTESTATION;

	//Set the control debug register (DR7) to a value based on the nonce
	//because we will then read that value through the checksum
	__asm{
		mov eax, nonce;
		shl eax, 16;
		or eax, 0x0400; //this is tiresias-specific, because the DR7 has that bit hardcoded
		mov tiresiasDR7, eax;
	}

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

	//NOTE!: In v6 I switched away from DP in tiresias pointing at tiresias's copy, 
	//and instead now it maintains the original client DP, and it changes it 
	//to point at tiresias' copy just in time. This is so that when the DP is updated
	//that it will have the same high kernel value as the client had, thus aleviating
	//the need to set the sign flag manually after the pushfd instruction
	__asm{
		//initializations for long-lived register values
		mov edi, clientAbsoluteSelfCheckAddress;			//original client Data Pointer
		mov ebx, numIterations;		//Number of times to loop
		mov esi, nonce;				//Pseudo Random Number (PRN)
		mov ecx, blockZeroAddress;	//The new code wants ecx to hold the EIP_DST
		sub esp, 0x14;
		//now esp points at checksum[1]
		mov dword ptr [esp-8], 0xdeadbeef;
		mov dword ptr [esp-4], 0;
		mov dword ptr [esp], 0xcafebabe;
		mov dword ptr [esp+4], 0xf005ba11;
		mov dword ptr [esp+8], 0xca55e77e;
		mov dword ptr [esp+0xC], 0xf01dab1e;
		mov dword ptr [esp+0x10], 0xb01dface;
		//call ecx;
		push ecx;
	};

//BLOCKS AND SUBBLOCKS
//Each block will be divided into multiple sub-blocks. These are:
//1) PRN Update
//2) Memory Read
//3) State Read (currently unused)
//4) Checksum Update
//5) Inter-block Jump
//There can be multiple instances of 1-4 in a given block, and only one instance of 5

blockZero:
	//////////////////////////////////
	//ONE TIME EIP MIX IN
	//////////////////////////////////
	__asm{
		add ecx, [esp];	//ecx = EIP_DST + EIP_SRC
		add esp, 4;	//to make it point back at checksum[1] instead of the tmp storage gap
	};

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
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP

	//Extra subblocks to pad out size to have all blocks be the same size but
	//still have room to remove these to make space for the minichecksums
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D_TIRESIAS(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP

	//////////////////////////////////
	//ADDITIONAL STATE READING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx, [esp-4] UPDATES: ecx(accumulator)
	READ_UEE_STATE_WITH_XOR_DR7_ADD_EFLAGS_TIRESIAS(tiresiasDR7);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP XOR DR7 + EFLAGS

	//Incoporates either the return address into SendSelfMeasurementPackets or
	//the return address into FilterPackets into the accumulator.
	//CLOBBERS: eax, edx UPDATES: ecx(accumulator)
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType);
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
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex);
blockOne:
	COMPLETE_V6_TIRESIAS_BLOCK_VAR1(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType);
	COMPLETE_V6_TIRESIAS_BLOCK_VAR2(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType);
	COMPLETE_V6_TIRESIAS_BLOCK_VAR3(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType);
	COMPLETE_V6_TIRESIAS_BLOCK_VAR4(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType);
blockNminus3:
	COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR1(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType);
	COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR2(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType);
	COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR3(clientAbsoluteSelfCheckAddress, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType);
	//In the tiresias/attack version, since it's using an array to look up its jumps, it doesn't need to
	//worry about alignment, so it also doesn't need to deal with inlining the minichecksums
	//so it can save a little time by not having to execute the jumps between the fragments
miniFrag1:
	//This is like SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D without random order traversal
	__asm add ecx, edi;		//ecx = PRN + DP
	__asm mov edx, clientVsTiresiasMemBase;
	__asm sub edi, edx;
	__asm xor ecx, [edi];	//ecx = PRN + DP XOR [DP]
	__asm add edi, edx;
	__asm add edi, 4;		//Move the data pointer forward in memory

	__asm and eax, 3;
	__asm xor [esp + eax*4], ecx;
	__asm sub eax, 1;
	__asm bt dword ptr [esp+0x10], 1;
miniFrag2:
	__asm rcr dword ptr [esp-0x08], 1;
	__asm rcr dword ptr [esp], 1;
	__asm rcr dword ptr [esp+0x04], 1;
	__asm rcr dword ptr [esp+0x08], 1;
	__asm rcr dword ptr [esp+0x0C], 1;
	__asm rcr dword ptr [esp+0x10], 1;
miniFrag3:
	__asm cmp edi, esi;	//Check to see if we've covered all of memory yet
	__asm jb miniFrag1;
setRange:
	__asm add rangeCtr, 1;
	__asm sub esp, 8;//protect the esp-8 value
	__asm push eax;	//protect the eax value
	switch(rangeCtr){
		//First we cover our own driver, as normal
		case 0:
			printf("Output checksum before minichecksum\n");
printf("junk=%#x\n[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");
//			printf("[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");
			__asm pop eax;
			__asm add esp, 8;
			__asm{
				mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
				//Since we're now using DP as the original address...
				mov edi, clientAbsoluteSelfCheckAddress;
				//Align down, so that the headers are included
				and di, 0xF000;
				//Similarly the ending address must be the original ending address, 
				//for the comparison to terminate the loop
				mov esi, clientAbsoluteMinichecksumEndAddress;
				and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible 
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
				mov eax, ebx;	//First time only, set up eax to be decrementing counter starting at known value (0 at this point)
				jmp miniFrag1;
			}
		//Then we cover ndis
		//Luckily, we don't have to fix the IAT for ndis.sys, since it's in the 
		case 1:
			printf("Output checksum after minichecksum\n");
printf("junk=%#x\n[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");
			//printf("(eax,ignore = %#x)\n[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");

			//First load .text section for ndis

			//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE relocatedSection MEMORY RETURNED
			ret = OpenBinaryToGetRelocatedROSection("ndis.sys", ".text", stm->hostID, (unsigned int)moduleInfo->ndisInfo.base, moduleInfo->ndisInfo.timeDateStamp, moduleInfo->ndisInfo.sizeOfImage, &relocatedSection, &relocSectLen, &sectionStartRVA, &sectionEndRVA);
			if(ret != GENERIC_SUCCESS){
				memset(&(stm->checksum), 0xFF, 6*sizeof(unsigned int));
				return ret;
			}

			//ndisStart and ndisEnd should be set to the values on the client
			ndisStart = (unsigned int)(moduleInfo->ndisInfo.base) + sectionStartRVA;
			ndisEnd = (unsigned int)(moduleInfo->ndisInfo.base) + sectionEndRVA;
			//Set this such that the original address in the client can have this value subtracted from
			//it in order to point at tiresias' real data buffer, relocatedSection
			clientVsTiresiasMemBase = ndisStart - (unsigned int)relocatedSection;
			__asm pop eax;
			__asm add esp, 8; //unprotect the esp-8 value
			//Now set up to jump into the minichecksum
			__asm{
				mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
				mov edi, ndisStart;
				mov esi, ndisEnd;
				and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
				jmp miniFrag1;
			}
		case 2:
printf("junk=%#x\n[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");
			free(relocatedSection);
			//First load .text section for nt
			//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE relocatedSection MEMORY RETURNED
			ret = LoadSectionAndReconstructIAT("ntoskrnl.exe", ".text", stm->hostID, (unsigned int)moduleInfo->ntInfo.base, moduleInfo->ntInfo.timeDateStamp, moduleInfo->ntInfo.sizeOfImage, &relocatedSection, &relocSectLen, &sectionStartRVA, &sectionEndRVA);
			if(ret != GENERIC_SUCCESS){
				memset(&(stm->checksum), 0xFF, 6*sizeof(unsigned int));
				return ret; 
			}

			//ntStart and ntEnd should be set to the values on the client
			ntStart = (unsigned int)(moduleInfo->ntInfo.base) + sectionStartRVA;
			ntEnd = (unsigned int)(moduleInfo->ntInfo.base) + sectionEndRVA;

			//Now look up the values for the SSDT area to avoid
			ssdtSym1.rva = 0;
			ssdtSym1.symbolName = "_KiServiceTable";
			diaSymbolVector.push_back(&ssdtSym1);
			ssdtSym2.rva = 0;
			ssdtSym2.symbolName = "_KiServiceLimit";
			diaSymbolVector.push_back(&ssdtSym2);
			//Also look up the offset to the symbols where we will need to fix nt's self-modification
			hackSym1.rva = 0;
			hackSym1.symbolName = "_KiSystemCallExitBranch";
			diaSymbolVector.push_back(&hackSym1);
			hackSym2.rva = 0;
			hackSym2.symbolName = "_KeFlushCurrentTb@0";
			diaSymbolVector.push_back(&hackSym2);
			hackSym3.rva = 0;
			hackSym3.symbolName = "@RtlPrefetchMemoryNonTemporal@8";
			diaSymbolVector.push_back(&hackSym3);


			//gotta get the file name
			ret = FindFile(gffStoragePath, "ntoskrnl.exe", moduleInfo->ntInfo.timeDateStamp, moduleInfo->ntInfo.sizeOfImage, &fullFileName);
			if(ret != GENERIC_SUCCESS){
				ret = FindFile(gffStoragePath, "ntkrnlpa.exe", moduleInfo->ntInfo.timeDateStamp, moduleInfo->ntInfo.sizeOfImage, &fullFileName);
				if(ret != GENERIC_SUCCESS){
					memset(&(stm->checksum), 0xFF, 6*sizeof(unsigned int));
					return ret;
				}
				//I don't think I've ever seen the other two filenames, so I'm going to stop looking for them
			}
			ret = FindRVAofSymbols(&diaSymbolVector, fullFileName);
			if(ret != GENERIC_SUCCESS){
				memset(&(stm->checksum), 0xFF, 6*sizeof(unsigned int));
				return ret;
			}
			
			ntSSDTStart = ntStart + diaSymbolVector.at(0)->rva - sectionStartRVA; // 0x2c480 for my test
			ntSSDTEnd = ntStart + diaSymbolVector.at(1)->rva - sectionStartRVA; //0x2c8f0 for my test

			//place the resolved binary symbols into the database so we can use HallOfHacks
			resolvedHackSym1.hostID = stm->hostID;
			resolvedHackSym1.binID = 0xFFFFFFFF;
			resolvedHackSym1.symbolName = hackSym1.symbolName;
			resolvedHackSym1.rva = hackSym1.rva;
			resolvedBinaryEntries.push_back(&resolvedHackSym1);
			resolvedHackSym2.hostID = stm->hostID;
			resolvedHackSym2.binID = 0xFFFFFFFF;
			resolvedHackSym2.symbolName = hackSym2.symbolName;
			resolvedHackSym2.rva = hackSym2.rva;
			resolvedBinaryEntries.push_back(&resolvedHackSym2);
			resolvedHackSym3.hostID = stm->hostID;
			resolvedHackSym3.binID = 0xFFFFFFFF;
			resolvedHackSym3.symbolName = hackSym3.symbolName;
			resolvedHackSym3.rva = hackSym3.rva;
			resolvedBinaryEntries.push_back(&resolvedHackSym3);
			InsertResolvedBinarySymbols(&resolvedBinaryEntries);

			//This will apply the fixups to the section
			strncpy_s(fakeStm.bNameA,MAX_BIN_NAME_LEN,"ntoskrnl.exe",MAX_BIN_NAME_LEN);
			fakeStm.hostID = stm->hostID;
			HallOfHacks(fullFileName, &fakeStm, ".text", sectionStartRVA, relocatedSection, relocSectLen, 0);
			free(fullFileName);

			//Set this such that the original address in the client can have this value subtracted from
			//it in order to point at tiresias' real data buffer, relocatedSection
			clientVsTiresiasMemBase = ntStart - (unsigned int)relocatedSection;
			__asm pop eax;
			__asm add esp, 8; //unprotect the esp-8 value
			//Now set up to jump into the minichecksum
			__asm{
				mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
				mov edi, ntStart;
				mov esi, ntSSDTStart;
				and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
				jmp miniFrag1;
			}
		case 3:
printf("junk=%#x\n[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");
			__asm pop eax;
			__asm add esp, 8; //unprotect the esp-8 value
			__asm{
				mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
				mov edi, ntSSDTEnd;
				mov esi, ntEnd;
				and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
				jmp miniFrag1;
			}
		case 4:
printf("junk=%#x\n[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");
			free(relocatedSection);
			//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE relocatedSection MEMORY RETURNED
			ret = LoadSectionAndReconstructIAT("hal.dll", ".text", stm->hostID, (unsigned int)moduleInfo->halInfo.base, moduleInfo->halInfo.timeDateStamp, moduleInfo->halInfo.sizeOfImage, &relocatedSection, &relocSectLen, &sectionStartRVA, &sectionEndRVA);
			if(ret != GENERIC_SUCCESS){
				memset(&(stm->checksum), 0xFF, 6*sizeof(unsigned int));
				return ret; 
			}
			//halStart and halEnd should be set to the values on the client
			halStart = (unsigned int)(moduleInfo->halInfo.base) + sectionStartRVA;
			halEnd = (unsigned int)(moduleInfo->halInfo.base) + sectionEndRVA;
			//Set this such that the original address in the client can have this value subtracted from
			//it in order to point at tiresias' real data buffer, relocatedSection
			clientVsTiresiasMemBase = halStart - (unsigned int)relocatedSection;

			//gotta get the file name
			ret = FindFile(gffStoragePath, "hal.dll", moduleInfo->halInfo.timeDateStamp, moduleInfo->halInfo.sizeOfImage, &fullFileName);
			if(ret != GENERIC_SUCCESS){
				memset(&(stm->checksum), 0xFF, 6*sizeof(unsigned int));
				return ret;
			}

			diaSymbolVector.clear();
			halSym1.rva = 0;
			halSym1.symbolName = "_HalpRealModeStart";
			diaSymbolVector.push_back(&halSym1);
			halSym2.rva = 0;
			halSym2.symbolName = "_HalpRealModeEnd";
			diaSymbolVector.push_back(&halSym2);

			ret = FindRVAofSymbols(&diaSymbolVector, fullFileName);
			free(fullFileName);
			if(ret != GENERIC_SUCCESS){
				memset(&(stm->checksum), 0xFF, 6*sizeof(unsigned int));
				return ret;
			}
			
			halpRealModeStart = halStart + diaSymbolVector.at(0)->rva - sectionStartRVA; // 0x2c480 for my test
			halpRealModeEnd = halStart + diaSymbolVector.at(1)->rva - sectionStartRVA; //0x2c8f0 for my test

				
			__asm pop eax;
			__asm add esp, 8; //unprotect the esp-8 value
			__asm{
				mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
				mov edi, halStart;
				mov esi, halpRealModeStart;
				and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
				jmp miniFrag1;
			}

		case 5:
printf("junk=%#x\n[0] = %#x\ngap = %#x\n[1] = %#x\n[2] = %#x\n[3] = %#x\n[4] = %#x\n[5] = %#x\n");
			__asm pop eax;
			__asm add esp, 8; //unprotect the esp-8 value
			__asm{
				mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
											//value (if attacker uses interrupts etc)
											//only have to do this when there's a function call before this asm block
				mov edi, halpRealModeEnd;
				mov esi, halEnd;
				and si, 0xFFFC;	//4 byte align down, meaning we miss up to 3 bytes, but oh well, it makes tiresias verification possible
								//(as otherwise it doesn't know what the last 3 bytes of the ndis area of memory would be for instance)
				jmp miniFrag1;
			}
		case 6:
			free(relocatedSection);
			__asm pop eax;
			__asm add esp, 8; //unprotect the esp-8 value
			break;
	}

//This label is used as the boundary of the self-check function checking itself
selfCheckFunctionEnd:

	//Set the checksum values to send back
	__asm{
		mov eax, outputChecksum;
		mov ebx, [esp-8];
		mov [eax], ebx;
		//check out my wicked sweet memory to memory move ;)
		pop dword ptr [eax+4];
		pop dword ptr [eax+8];
		pop dword ptr [eax+0xC];
		pop dword ptr [eax+0x10];
		pop dword ptr [eax+0x14];
		//At this point esp should hopefully be pointing at the caller-save registers
	}

	__asm{rdtsc};
	__asm{mov afterUpperTime, edx};
	__asm{mov afterLowerTime, eax};
	upperDiff = afterUpperTime - beforeUpperTime;
	lowerDiff = afterLowerTime - beforeLowerTime;
	printf("upperDiff = %#x, lowerDiff = %#x\n", upperDiff, lowerDiff);

	printf("checksum[0] = 0x%8x\n", outputChecksum[0]);
	printf("checksum[1] = 0x%8x\n", outputChecksum[1]);
	printf("checksum[2] = 0x%8x\n", outputChecksum[2]);
	printf("checksum[3] = 0x%8x\n", outputChecksum[3]);
	printf("checksum[4] = 0x%8x\n", outputChecksum[4]);
	printf("checksum[5] = 0x%8x\n", outputChecksum[5]);
	return GENERIC_SUCCESS;
}

int SelfCheckLoadedModuleDatabaseInsertion(st_msg_t * stm){
	int ret;
	char * fixedLockStr;
	bin_data_t tmpBinary;

	//WRITE LOCK the table
	fixedLockStr = "LOCK TABLES LoadedModules WRITE";
	ret = ExecuteUpdateOrDeleteOrLock(SHARED, fixedLockStr, strlen(fixedLockStr));
	if(ret != GENERIC_SUCCESS){
		return ret;
	}

	tmpBinary.baseVA = (unsigned int) stm->moduleInfo.bootvidInfo.base;
	wcsncpy_s(tmpBinary.bNameW, MAX_BIN_NAME_LEN, L"bootvid.dll", MAX_BIN_NAME_LEN);
	tmpBinary.sizeOfImage = stm->moduleInfo.bootvidInfo.sizeOfImage;
	tmpBinary.numROSections = 0;
	tmpBinary.timeDateStamp = stm->moduleInfo.bootvidInfo.timeDateStamp;
	ret = InsertLoadedModule(&tmpBinary, stm->hostID);
	if(ret != GENERIC_SUCCESS){
		printf("SelfCheck_v6_tiresias: InsertLoadedModule bootvid failed\n");
		return GENERIC_ERROR;
	}
	tmpBinary.baseVA = (unsigned int) stm->moduleInfo.halInfo.base;
	wcsncpy_s(tmpBinary.bNameW, MAX_BIN_NAME_LEN, L"hal.dll", MAX_BIN_NAME_LEN);
	tmpBinary.sizeOfImage = stm->moduleInfo.halInfo.sizeOfImage;
	tmpBinary.timeDateStamp = stm->moduleInfo.halInfo.timeDateStamp;
	ret = InsertLoadedModule(&tmpBinary, stm->hostID);
	if(ret != GENERIC_SUCCESS){
		printf("SelfCheck_v6_tiresias: InsertLoadedModule hal failed\n");
		return GENERIC_ERROR;
	}
	tmpBinary.baseVA = (unsigned int) stm->moduleInfo.kdcomInfo.base;
	wcsncpy_s(tmpBinary.bNameW, MAX_BIN_NAME_LEN, L"kdcom.dll", MAX_BIN_NAME_LEN);
	tmpBinary.sizeOfImage = stm->moduleInfo.kdcomInfo.sizeOfImage;
	tmpBinary.timeDateStamp = stm->moduleInfo.kdcomInfo.timeDateStamp;
	ret = InsertLoadedModule(&tmpBinary, stm->hostID);
	if(ret != GENERIC_SUCCESS){
		printf("SelfCheck_v6_tiresias: InsertLoadedModule kdcom failed\n");
		return GENERIC_ERROR;
	}
	tmpBinary.baseVA = (unsigned int) stm->moduleInfo.ndisInfo.base;
	wcsncpy_s(tmpBinary.bNameW, MAX_BIN_NAME_LEN, L"ndis.sys", MAX_BIN_NAME_LEN);
	tmpBinary.sizeOfImage = stm->moduleInfo.ndisInfo.sizeOfImage;
	tmpBinary.timeDateStamp = stm->moduleInfo.ndisInfo.timeDateStamp;
	ret = InsertLoadedModule(&tmpBinary, stm->hostID);
	if(ret != GENERIC_SUCCESS){
		printf("SelfCheck_v6_tiresias: InsertLoadedModule ndis failed\n");
		return GENERIC_ERROR;
	}
	tmpBinary.baseVA = (unsigned int) stm->moduleInfo.ntInfo.base;
	wcsncpy_s(tmpBinary.bNameW, MAX_BIN_NAME_LEN, L"ntoskrnl.exe", MAX_BIN_NAME_LEN);
	tmpBinary.sizeOfImage = stm->moduleInfo.ntInfo.sizeOfImage;
	tmpBinary.timeDateStamp = stm->moduleInfo.ntInfo.timeDateStamp;
	ret = InsertLoadedModule(&tmpBinary, stm->hostID);
	if(ret != GENERIC_SUCCESS){
		printf("SelfCheck_v6_tiresias: InsertLoadedModule ntoskrnl failed\n");
		return GENERIC_ERROR;
	}
	//UNLOCK table
	fixedLockStr = "UNLOCK TABLES";
	ret = ExecuteUpdateOrDeleteOrLock(SHARED, fixedLockStr, strlen(fixedLockStr));
	if(ret != GENERIC_SUCCESS){
		return ret;
	}

	return GENERIC_SUCCESS;
}