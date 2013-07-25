#ifndef _BIOS_MEASURE
#define _BIOS_MEASURE

/*
	This software is the copyrighted work of MITRE.  No ownership or other proprietary interest in this 
	software is granted to you other than what is granted in this license.     
	 
	MITRE IS PROVIDING THE SOFTWARE "AS IS" AND ACCORDINGLY MAKES NO WARRANTY, EXPRESS OR IMPLIED, AS 
	TO THE ACCURACY, CAPABILITY, EFFICIENCY, MERCHANTABILITY, OR FUNCTIONING  OF THE SOFTWARE AND DOCUMENTATION.  
	IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL, CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR SPECIAL 
	DAMAGES RELATED TO THE SOFTWARE, EVEN IF MITRE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.             
	 
	You accept this software on the condition that you indemnify and hold harmless MITRE, its Board of Trustees, 
	officers,  agents, and employees, from any and all liability damages to third parties, including attorneys' 
	fees, court costs, and other related costs and expenses, arising out of your use of this software irrespective 
	of the cause of said liability.
	
	MIT License:
	Copyright (c) 2013 The MITRE Corporation

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////

#define PA_DOWN_INT(a)		((unsigned int)(a) & 0xFFFFF000)

//This is the total number of blocks in the client (not an index of the last block)
#define NUM_BLOCKS				8
//Calculated in IDA with the IDA calculator expression "blockOne - blockZero"
#define BLOCK_SIZE				0x75
//This is the size of things like COMPLETE_V*_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR*
//except for the first one, which is missing 4 bytes because the jump to the minichecksum
//is shorter than normal
//Calculated in IDA with the IDA calculator expression miniFrag1 - blockNminus2
#define SMALL_BLOCK_SIZE				0x5a
//This is the amount that the short block is smaller than the regular BLOCK_SIZE
//This is due to the fact that the numIterations == 0 exit condition is to jump to
//miniFrag1, but for this block, that distance can be covered with a 8 bit jump rather
//than a 32 bit jump (also a the 32 bit jump has a 2 byte opcode and the 8 bit has a 1 byte opcode)
#define SHORT_BLOCK_SIZE_DIFF	4

//Jump short "a" bytes past the next instruction (range of +127 to -128) if parity flag is set
#define JP(a)			\
	__asm _emit 0x7A	\
	__asm _emit a	\

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
//mov ecx, esi	/* mix esi (PRN) with the accumulator
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
/*Mix into the accumulator the data pointer (DP) to the verified memory to be read*/
//__asm add ecx, edi
/*Mix into the accumulator the 4 bytes of memory pointed to by the DP*/
//__asm xor ecx, [edi]
/*Update the DP to point at some other pseudo-randomly chosen location in the verified memory*/
//PSEUDO_RAND_UPDATE_DP(codeStart, memRange) //clobbers: eax, esi, ecx. updates: edx
//CLOBBERS: eax, edx, UPDATES:edi(DP), ecx(accumulator)
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange) \
	__asm{							\
		__asm add ecx, edi			\
		__asm xor ecx, [edi]		\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};

//DIFFERENCE FROM SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D: 
//reversed order of *DP vs DP incorporation
//CLOBBERS: eax, edx, UPDATES:edi, ecx
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP(codeStart, memRange) \
	__asm{							\
		__asm add ecx, [edi]		\
		__asm xor ecx, edi			\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};

//DIFFERENCE FROM SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D: 
//reversed order of XOR, ADD.
//CLOBBERS: eax, edx, UPDATES:edi, ecx
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(codeStart, memRange) \
	__asm{							\
		__asm xor ecx, edi			\
		__asm add ecx, [edi]		\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};

//DIFFERENCE FROM SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D: 
//reversed order of XOR, ADD. Also reversed order of *DP vs DP incorporation
//CLOBBERS: eax, edx, UPDATES:edi, ecx
#define SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP(codeStart, memRange) \
	__asm{							\
		__asm xor ecx, [edi]		\
		__asm add ecx, edi			\
		PSEUDO_RAND_UPDATE_DP(codeStart, memRange)	\
	};

//NOTE: KEEP COMMENTED CODE IN SYNC WITH THE ACTUAL CODE!!!

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
#define SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable)			\
	__asm{									\
		__asm sub ebx, 1					\
		__asm test ebx, ebx					\
		__asm jz setRange					\
											\
		__asm lea edx, blockAddressTable	\
		__asm mov eax, esi					\
		__asm and eax, 7					\
		__asm mov edx, [edx+eax*4]			\
		__asm adc ecx, edx \
		__asm jmp edx						\
	};

#define SUBBLOCK_INTERBLOCK_TRANSFER_VAR1(blockAddressTable)			\
	__asm{									\
		__asm sub ebx, 1					\
		__asm test ebx, ebx					\
		__asm jz setRange					\
											\
		__asm lea edx, blockAddressTable	\
		__asm mov eax, esi					\
		__asm and eax, 7					\
		__asm mov edx, [edx+eax*4]			\
		__asm xor ecx, edx				\
		__asm jmp edx						\
	};


//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP XOR DR7 + EFLAGS
#define COMPLETE_V6_BLOCK_VAR0(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + *DP XOR DP + PRN XOR *DP + DP XOR DR7 + EFLAGS
#define COMPLETE_V6_BLOCK_VAR1(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR1(blockAddressTable)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP XOR EFLAGS + DR7
#define COMPLETE_V6_BLOCK_VAR2(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + *DP XOR DP + PRN XOR *DP + DP XOR EFLAGS + DR7
#define COMPLETE_V6_BLOCK_VAR3(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR1(blockAddressTable)		\

//ecx = EIP_DST XOR PRN + EIP_SRC XOR DP + *DP XOR PRN + DP XOR *DP + DR7 XOR EFLAGS
#define COMPLETE_V6_BLOCK_VAR4(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable)		\

//ecx = EIP_DST XOR PRN + EIP_SRC XOR *DP + DP XOR PRN + *DP XOR DP + DR7 XOR EFLAGS
#define COMPLETE_V6_BLOCK_VAR5(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR1(blockAddressTable)		\

//ecx = EIP_DST XOR PRN + EIP_SRC XOR DP + *DP XOR PRN + DP XOR *DP + EFLAGS XOR DR7
#define COMPLETE_V6_BLOCK_VAR6(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable)		\

//ecx = EIP_DST XOR PRN + EIP_SRC XOR *DP + DP XOR PRN + *DP XOR DP + EFLAGS XOR DR7
#define COMPLETE_V6_BLOCK_VAR7(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_D_ADD_DP(codeStart, memRange)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR1(blockAddressTable)		\


//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + DR7 XOR EFLAGS
#define COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR0(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + *DP XOR DP + DR7 XOR EFLAGS
#define COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR1(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR1(blockAddressTable)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + EFLAGS XOR DR7
#define COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR2(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable)		\

//ecx = EIP_DST + EIP_SRC XOR PRN + *DP XOR DP + EFLAGS XOR DR7
#define COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR3(codeStart, memRange, blockAddressTable)	\
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN					\
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_D_XOR_DP(codeStart, memRange)	\
	SUBBLOCK_CHECKSUM_UPDATE							\
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR1(blockAddressTable)		\

#endif
