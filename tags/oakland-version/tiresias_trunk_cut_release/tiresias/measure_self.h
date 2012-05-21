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

#ifndef MEASURE_SELF_H
#define MEASURE_SELF_H

#include "server_tiresias_protocol.h"

#include <windows.h>

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////
//This is the total number of blocks in the client (not an index of the last block)
#define NUM_BLOCKS						8
#define BLOCK_SIZE						0x96
//This is the size of things like COMPLETE_V*_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR*
//except for the first one, which is missing 4 bytes because the jump to the minichecksum
//is shorter than normal
#define SMALL_BLOCK_SIZE				0x7B
#define TIRESIAS_BLOCK_SIZE				0xE1
#define TIRESIAS_SMALL_BLOCK_SIZE		0xB9

//These are the current CHECKED build constants
//This is the RVA of client SelfCheck_v6
#define CLIENT_RELATIVE_CHECKSUM_START									0x490
//Find this in IDA by searching for blockZero
#define CLIENT_RELATIVE_BLOCKZERO										0x590
//Find this in IDA by searching for selfCheckV6End
#define CLIENT_RELATIVE_CHECKSUM_END									0xE5E
//Find this in IDA by searching for normalparent (CAREFUL in checked build, make sure you get instruction after call)
#define CLIENT_RELATIVE_PARENT_RET_NORMAL								0x1BD0
//Find this in IDA by searching for tpmparent (CAREFUL in checked build, make sure you get instruction after call)
#define CLIENT_RELATIVE_PARENT_RET_TICKSTAMP_ATTESTATION				0x1EF0
//Find this in IDA by searching for timegrandparent (CAREFUL in checked build, make sure you get instruction after call)
#define CLIENT_RELATIVE_GRANDPARENT_RET_TIMING_TEST						0x7A11
//Find this in IDA by searching for tpmgrandparent (CAREFUL in checked build, make sure you get instruction after call)
#define CLIENT_RELATIVE_GRANDPARENT_RET_TICKSTAMP_ATTESTATION			0x7CF1
//This is NdisRequest+6 because NdisRequest was found to be the last code in the client .text section
//and because NdisRequest is a 6 byte indirect jump through the IAT
#define CLIENT_RELATIVE_MINICHECK_END									0x8012

//Jump short "a" bytes past the next instruction (range of +127 to -128) if parity flag is set
#define JP(a)			\
	__asm _emit 0x7A	\
	__asm _emit a	\

//Jump short "a" bytes past the next instruction (range of +127 to -128) if zero flag is set
#define JE(a)			\
	__asm _emit 0x74	\
	__asm _emit a		\


//Memory for this looks like
//[low--------------------------high]
//checksum[0],gap,[1],[2],[3],[4],[5]
//________________^^^_________________
//________________ESP_________________
//esp is assumed to be pointing at checksum[1] when this code runs

//bt dword ptr [esp+0x10], 1	/* sets CF to the value for bit 0 of [esp+0x10]*/
								/*[esp+0x10] = checksum[5], therefore it's the 
								  least significant bit of the checksum. We basically
								  want to make sure that the lsb gets rotated to 
								  the msb if necessary*/
//rcr dword ptr [esp-0x08], 1	/*[esp-0x08] = checksum[0], so if CF is set the msb*/
								/* of this will be set, otherwise not. Either way the
								   lsb will move into CF */
//rcr dword ptr [esp], 1		/*rotate with carry checksum[1]/*
//rcr dword ptr [esp+0x04], 1	/*rotate with carry checksum[2]/*	
//rcr dword ptr [esp+0x08], 1	/*rotate with carry checksum[3]/*
//rcr dword ptr [esp+0x0C], 1	/*rotate with carry checksum[4]/*
//rcr dword ptr [esp+0x10], 1	/*rotate with carry checksum[5]/*
//CLOBBERS: none. UPDATES: entire checksum
#define ROTATE_CHECKSUM_BASED_AT_ESP_SINGLE_GAP	\
		__asm bt dword ptr [esp+0x10], 1		\
		__asm rcr dword ptr [esp-0x08], 1		\
		__asm rcr dword ptr [esp], 1			\
		__asm rcr dword ptr [esp+0x04], 1		\
		__asm rcr dword ptr [esp+0x08], 1		\
		__asm rcr dword ptr [esp+0x0C], 1		\
		__asm rcr dword ptr [esp+0x10], 1		\

/////////////////////////////////////////
//SUBBLOCKS
/////////////////////////////////////////

//Read the debug control register which we set to not have any
//debug breakpoints active, and we set some pseudo-random info
//in the upper bits based on the nonce
//NOTE: when recreating this in tiresias you will need to set
//the interrupt flag in eflags to 0. Also you will have to
//set the least significant 16 bits to 0x0400
//NOTE: tiresias has to use a separate stack location for 
//a faux-dr7. The attack shouldn't, it should just use real 
//dr7 like the normal code

//pushfd		/*store the eflags to the stack*/
//and [esp], 0xFFFFFDFF	/*get rid of the trap flag which is set while I'm debugging. Remove for final/*
//mov eax, dr7	/*read debug control register*/
//add ecx, eax	/*mix debug reg with accumulator*/
//xor ecx, [esp]/*mix the eflags with accumulator*/
//add esp, 4	/*reset the stack to point at checksum[1]
//CLOBBERS: eax, edx, [esp-4] UPDATES: ecx(accumulator)
/*		__asm and dword ptr [esp], 0xFFFFFDFF	\*/

#define READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS_TIRESIAS(tiresiasDR7)	\
		__asm pushfd				\
		__asm and dword ptr [esp], 0xFFFFFDFF	\
		__asm mov eax, tiresiasDR7	\
		__asm add ecx, eax			\
		__asm xor ecx, [esp]		\
		__asm add esp, 4			\

//DIFFERENCE FROM READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS:
//reverses order of EFLAGS/DR7 accumulator incorporation
#define READ_UEE_STATE_WITH_ADD_EFLAGS_XOR_DR7_TIRESIAS(tiresiasDR7)	\
		__asm pushfd				\
		__asm and dword ptr [esp], 0xFFFFFDFF	\
		__asm mov eax, tiresiasDR7	\
		__asm add ecx, [esp]		\
		__asm xor ecx, eax			\
		__asm add esp, 4			\

//DIFFERENCE FROM READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS:
//reverses order of ADD/XOR accumulator incorporation
#define READ_UEE_STATE_WITH_XOR_DR7_ADD_EFLAGS_TIRESIAS(tiresiasDR7)	\
		__asm pushfd				\
		__asm and dword ptr [esp], 0xFFFFFDFF	\
		__asm mov eax, tiresiasDR7	\
		__asm xor ecx, eax			\
		__asm add ecx, [esp]		\
		__asm add esp, 4			\

//DIFFERENCE FROM READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS:
//reverses order of ADD/XOR accumulator incorporation
//reverses order of EFLAGS/DR7 accumulator incorporation
#define READ_UEE_STATE_WITH_XOR_EFLAGS_ADD_DR7_TIRESIAS(tiresiasDR7)	\
		__asm pushfd				\
		__asm and dword ptr [esp], 0xFFFFFDFF	\
		__asm mov eax, tiresiasDR7	\
		__asm xor ecx, [esp]		\
		__asm add ecx, eax			\
		__asm add esp, 4			\

//SUBBLOCK TO INCORPORATE RETURN ADDRESSES ON THE STACK INTO
// last bits of PRN will determine which return addy we use
// test esi, esi
// the default one is the first return address (into SendSelfMeasurement..)
// mov eax, [ebp+4]
// if last byte of PRN contains even number of ones, use the default return
// address (we will jump past the next instruction which overwrites it the
// first return address with the second one 
// JP_6			
// The next couple lines of code goes up a stack frame to recover the return
// address into the primary FilterPackets routine
// mov edx, [ebp]	
// mov eax, [edx+4]
// xor the return address we chose to use with the PRN	
// xor eax, esi	
// incorporate into the accumulator
// add ecx, eax	
//CLOBBERS: eax, edx, UPDATES: ecx(accumulator)
#define SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)		\
	__asm test esi, esi					\
	__asm mov edx, inResponseToType		\
	__asm lea eax, origParentRetAddrArray		\
	JP(0x6)								\
	__asm lea eax, origGrandparentRetAddrArray	\
	__asm mov eax, [eax+edx*4]			\
	__asm xor eax, esi					\
	__asm add ecx, eax					\

//C pseudocode:
//daddr = (unsigned int *) (codeStart + (x % memRange));
//mov eax, esi	/*Move PRN to eax to be divided*/
//xor edx, edx	/*Clear out the top part so it doesn't mess up the calculation*/
//div memRange	/*edx:eax divided by memRange. quotient->eax, remainder->edx*/
//add edx, codeStart	/**/
/*Now edi (DP) = code start + (x (esi) % memRange)*/
//CLOBBERS: eax, edx. UPDATES: edi
#define PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
		__asm mov eax, esi			\
		__asm xor edx, edx			\
		__asm div memRange			\
		__asm add edx, codeStart	\
		__asm mov edi, edx			\

//NOTE: KEEP COMMENTED CODE IN SYNC WITH THE ACTUAL CODE!!!
//Update x for the T function PRNG
//C version: x = x + (x*x | 5); //implicit mod 2^32
//mov eax, esi	/* Create a copy of x before squaring*/
//mul eax		/* eax = x*x */
//or eax, 5		/* eax = (x*x | 5) */
//add esi, eax	/* PRN = x + (x*x | 5) */
//mov eax, esi	/* mix esi (PRN) with the accumulator
//CLOBBERS: eax, edx. UPDATES: esi(PRN), ecx(accumulator)
#define SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN	\
	__asm{							\
		__asm mov eax, esi			\
		__asm mul eax				\
		__asm or eax, 5				\
		__asm add esi, eax			\
		__asm xor ecx, esi			\
	};

//DIFFERENCE FROM SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN
//mixes PRN with accumulator with an ADD instead of XOR
#define SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN	\
	__asm{							\
		__asm mov eax, esi			\
		__asm mul eax				\
		__asm or eax, 5				\
		__asm add esi, eax			\
		__asm add ecx, esi			\
	};

//NOTE: KEEP COMMENTED CODE IN SYNC WITH THE ACTUAL CODE!!!
//mov edx, clientVsTiresiasMemBase /*Move the difference between client's DP and tiresias's DP
									/* into a register. The reasoning being that it's faster
										to do one memory to register move and then 2 register-only 
										operations, than to do two memory & register operations */
//add ecx, edi /*Mix into the accumulator the data pointer (DP) to the verified memory to be read*/
//sub edi, edx /*Sets the value back to reading tiresias's copy of the original data*/
//xor ecx, [edi] /*Mix into the accumulator the 4 bytes of memory pointed to by the DP*/
//add edi, edx /*Makes the value what it would have been in the original code*/
/*Update the DP to point at some other pseudo-randomly chosen location in the verified memory*/
//PSEUDO_RAND_UPDATE_DP(codeStart, memRange) //clobbers: eax, esi, ecx. updates: edx
//CLOBBERS: eax, edx, UPDATES:edi(DP), ecx(accumulator)
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase) \
	__asm{							\
		__asm mov edx, clientVsTiresiasMemBase \
		__asm add ecx, edi			\
		__asm sub edi, edx			\
		__asm xor ecx, [edi]		\
		__asm add edi, edx			\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};

//DIFFERENCE FROM SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS: 
//reversed order of *DP vs DP incorporation
//CLOBBERS: eax, edx, UPDATES:edi, ecx
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase) \
	__asm{							\
		__asm mov edx, clientVsTiresiasMemBase \
		__asm sub edi, edx			\
		__asm add ecx, [edi]		\
		__asm add edi, edx			\
		__asm xor ecx, edi			\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};

//DIFFERENCE FROM SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS: 
//reversed order of XOR, ADD.
//CLOBBERS: eax, edx, UPDATES:edi, ecx
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase) \
	__asm{							\
		__asm mov edx, clientVsTiresiasMemBase \
		__asm xor ecx, edi			\
		__asm sub edi, edx			\
		__asm add ecx, [edi]		\
		__asm add edi, edx			\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};

//DIFFERENCE FROM SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS: 
//reversed order of XOR, ADD. Also reversed order of *DP vs DP incorporation
//CLOBBERS: eax, edx, UPDATES:edi, ecx
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase) \
	__asm{							\
		__asm mov edx, clientVsTiresiasMemBase \
		__asm sub edi, edx			\
		__asm xor ecx, [edi]		\
		__asm add edi, edx			\
		__asm add ecx, edi			\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};


//============================================================================

//NOTE: KEEP COMMENTED CODE IN SYNC WITH THE ACTUAL CODE!!!
//Update checksum using the accumulator
//checksum[numIterations%4] ^= accumulator
//(this is new in v6, it used to be %5, but X felt the decrease in code was
//worth updating one more index only implicitly)
//numIterations gets monotonically decremented in SUBBLOCK_INTERBLOCK_TRANSFER
//so this will just go from index 3, 2, 1, 0 (and the other parts of the checksum
//at index [5] (esp+16) and index [0] (esp-8) get updated only by the 
//ROTATE_CHECKSUM_BASED_AT_ESP_SINGLE_GAP)

//mov eax, ebx	/*load the numIterations into eax to be bitwise modded by 4*/
//and eax, 3	/*keep only the bottom 2 bits of numIterations, thus doing % 4*/
//xor [esp + eax*4], ecx /*mix in the accumulator with the next piece of the checksum*/
//Rotate entire checksum by one bit, to add diffusion
//ROTATE_CHECKSUM_BASED_AT_ESP_SINGLE_GAP;
//CLOBBERS: eax, edx UPDATES:checksum[numIterations%5]
#define SUBBLOCK_CHECKSUM_UPDATE				\
	__asm {										\
		__asm mov eax, ebx						\
		__asm and eax, 3						\
		__asm xor [esp + eax*4], ecx			\
		ROTATE_CHECKSUM_BASED_AT_ESP_SINGLE_GAP	\
	};

//NOTE: KEEP COMMENTED CODE IN SYNC WITH THE ACTUAL CODE!!!

//============================================================================

//NOTE: KEEP COMMENTED CODE IN SYNC WITH THE ACTUAL CODE!!!
//sub ebx, 1		/*decrement numIterations*/
//test ebx, ebx		/*check if it's 0 and time to exit*/
//jz miniFrag1		/*exit to minichecksum if necessary*/
//
//xor edx, edx		/*so that when we mov into the lower byte the upper are clear*/
//mov eax, esi		/*move the PRN into eax to be divided to determine where we call next*/
//and eax, 7		/*Now that we only have 8 blocks, we only need to use 3 bits of the PRN to choose where to go next*/
					/*This way we don't have to use the div we used to use to do a modulo operation*/
//mov dl, BLOCK_SIZE/*We're now going to do (random block index) * BLOCK_SIZE*/
//mul dl			/*(random block index) * BLOCK_SIZE result goes into AX (remember top bits are still 0)*/
//mov ecx, blockZeroAddress	/*get the base of the array of blocks into eax so we can do...
//add ecx, eax		/*ecx = blockZeroAddress + ((PRN % NUM_BLOCKS) * BLOCK_SIZE)*/
					/*so now ecx points at the next block to call to 
					  so ecx = EIP_DST, and EIP_SRC will get pushed into the stack gap*/
//call ecx			/*Go to the next block*/
//CLOBBERS: ecx, eax, edx UPDATES:ebx,ecx
#define SUBBLOCK_INTERBLOCK_TRANSFER(blockAddressTable)			\
	__asm{									\
		__asm sub ebx, 1					\
		__asm test ebx, ebx					\
		__asm jz setRange					\
											\
		__asm lea edx, blockAddressTable	\
		__asm mov eax, esi					\
		__asm and eax, 7					\
		__asm mov ecx, [edx+eax*4]			\
		__asm call ecx						\
	};

//Standard check for exit condition
//sub ebx, 1		/*decrement numIterations*/
//test ebx, ebx		/*check if it's 0 and time to exit*/
//jz miniFrag1		/*exit to minichecksum if necessary*/
//
//lea edx, origEipSrcArray /*get the base of the array with precomputed EIP_SRC values for each block index*/
//mov eax, currentIndex/*get the current index into that array*/
//push [edx+eax*4]	/*This pushes EIP_SRC for this indexed block in the original code*/
//mov eax, esi		/*move the PRN into eax to be divided to determine where we call next*/
//and eax, 7		/*Now that we only have 8 blocks, we only need to use 3 bits of the PRN to choose where to go next*/
					/*This way we don't have to use the div we used to use to do a modulo operation*/
//mov currentIndex, eax /*update the currentIndex for the next block we will jump to*/
//xor edx, edx		/*so that when we mov into the lower byte the upper are clear*/
//mov dl, BLOCK_SIZE/*We're now going to do (random block index) * BLOCK_SIZE*/
//mul dl			/*(random block index) * BLOCK_SIZE result goes into AX (remember top bits are still 0)*/
//mov ecx, blockZeroAddress	/*get the base of the array of blocks into eax so we can do...
//add ecx, eax		/*ecx = blockZeroAddress + ((PRN % NUM_BLOCKS) * BLOCK_SIZE)*/
					/*so now ecx points at the next block to call to 
					  so ecx = EIP_DST, and EIP_SRC will get pushed into the stack gap*/
//lea edx, tiresiasEipDstArray	/*load up the base of the array of where to jump to next*/
//mov eax, currentIndex	/*load up the index of where to jump to next*/
//jmp [edx+eax*4]	/*Go to the next block*/
#define SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)	\
	__asm{									\
		__asm sub ebx, 1					\
		__asm test ebx, ebx					\
		__asm jz setRange					\
											\
		__asm lea edx, origEipSrcArray		\
		__asm mov eax, currentIndex			\
		__asm push [edx+eax*4]				\
		__asm xor edx, edx					\
		__asm mov eax, esi					\
		__asm and eax, 7					\
		__asm mov currentIndex, eax			\
		__asm mov dl, BLOCK_SIZE			\
		__asm mul dl						\
		__asm mov ecx, blockZeroAddress		\
		__asm add ecx, eax					\
		__asm lea edx, tiresiasEipDstArray	\
		__asm mov eax, currentIndex			\
		__asm jmp [edx+eax*4]				\
	};


#define COMPLETE_V6_TIRESIAS_BLOCK_VAR0(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_XOR_DR7_ADD_EFLAGS_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

#define COMPLETE_V6_TIRESIAS_BLOCK_VAR1(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_XOR_DR7_ADD_EFLAGS_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

#define COMPLETE_V6_TIRESIAS_BLOCK_VAR2(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_XOR_EFLAGS_ADD_DR7_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

#define COMPLETE_V6_TIRESIAS_BLOCK_VAR3(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_XOR_EFLAGS_ADD_DR7_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

#define COMPLETE_V6_TIRESIAS_BLOCK_VAR4(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

#define COMPLETE_V6_TIRESIAS_BLOCK_VAR5(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

#define COMPLETE_V6_TIRESIAS_BLOCK_VAR6(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_EFLAGS_XOR_DR7_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

#define COMPLETE_V6_TIRESIAS_BLOCK_VAR7(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_EFLAGS_XOR_DR7_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + DR7 XOR EFLAGS
#define COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR0(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS_TIRESIAS(tiresiasDR7)		\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + *DP XOR DP + DR7 XOR EFLAGS
#define COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR1(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_DR7_XOR_EFLAGS_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + EFLAGS XOR DR7
#define COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR2(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_EFLAGS_XOR_DR7_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + *DP XOR DP + EFLAGS XOR DR7
#define COMPLETE_V6_TIRESIAS_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR3(codeStart, memRange, clientVsTiresiasMemBase, tiresiasDR7, origEipSrcArray, tiresiasEipDstArray, currentIndex, origGrandparentRetAddrArray, inResponseToType)	\
	__asm add ecx, [esp]								\
	__asm add esp, 4									\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP_TIRESIAS(codeStart, memRange, clientVsTiresiasMemBase)	\
	READ_UEE_STATE_WITH_ADD_EFLAGS_XOR_DR7_TIRESIAS(tiresiasDR7)	\
	SUBBLOCK_READ_AND_XOR_RETURN_ADDRESS_WITH_PRN_TIRESIAS(origGrandparentRetAddrArray, inResponseToType)			\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_TIRESIAS(blockZeroAddress, origEipSrcArray, tiresiasEipDstArray, currentIndex)		\


////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

int AnalyzeFileForSelfMeasurement(HANDLE mysqlMutex, char * fullFileName, st_msg_t * binary);
int SelfCheck_v6_tiresias(char * memToCheck, st_msg_t * stm);
int SelfCheckLoadedModuleDatabaseInsertion(st_msg_t * stm);

#endif