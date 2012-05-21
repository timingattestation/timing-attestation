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

//We are not able to use things like MmProbeAndLockPages() or
//MmIsAddressValid(), because they are not guaranteed to always
//allow us to access arbitrary memory without causing a page fault.
//Thus we need to know details about how Windows' paging system
//works, as well as things like how large and small pages are
//handled when the system is using PAE (Page Address Extentions)

//TODO: In the future we need to support non-PAE mode as well IF we
//find that it is a legit config for a default MITRE system.
//TODO: In the mean time we should bail out if the system is non-PAE.

#include "precomp.h"
#include "misc.h" //For GENERIC_ERROR/SUCCESS
#include "safe_mem_access.h"


////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
unsigned int gOSDependent_pfnBase;

///////////
// Also
// bool gPFNFound (in Passthru.h)
//
///////////

////////////////////////////////////////////////////////
//BEGIN CODE
////////////////////////////////////////////////////////

void FindPFNBase(){
	unsigned long MmUnlockPagesOffset = 0x93;
	unsigned long MmProbeAndLockPagesOffset = 0x260;
	unsigned long MmMapLockedPagesSpecifyCacheOffset = 0x211;

	unsigned char MmUnlockPagesSig[5] = {0x6b, 0xc0, 0x1c, 0x03, 0x05};
	unsigned char MmProbeAndLockPagesSig[5] = {0x6b, 0xff, 0x1c, 0x03, 0x3d};
	unsigned char MmMapLockedPagesSpecifyCacheSig[7] = {0x8b, 0xd8, 0x6b, 0xdb, 0x1c, 0x03, 0x1d};

	unsigned long results[3];
	unsigned long tolerance = 0x20;
	unsigned long i;

	gPFNFound = FALSE;

	for (i=0;i<3;i++)
		results[i] = i;

	for (i=MmUnlockPagesOffset - tolerance;i<MmUnlockPagesOffset + tolerance;i++)
	{
		unsigned char *sig = (unsigned char *)MmUnlockPages + i;
		if (memcmp(sig,MmUnlockPagesSig,sizeof(MmUnlockPagesSig)) == 0)
		{
			unsigned long offset;
			unsigned long *pfndatabase;
			offset = i + sizeof(MmUnlockPagesSig);
			pfndatabase = *((unsigned long *)((unsigned long)MmUnlockPages + offset));
			results[0] = *pfndatabase;
			break;
		}

	}

	for (i=MmProbeAndLockPagesOffset - tolerance;i<MmProbeAndLockPagesOffset + tolerance;i++)
	{
		unsigned char *sig = (unsigned char *)MmProbeAndLockPages + i;
		if (memcmp(sig,MmProbeAndLockPagesSig,sizeof(MmProbeAndLockPagesSig)) == 0)
		{
			unsigned long offset;
			unsigned long *pfndatabase;
			offset = i + sizeof(MmProbeAndLockPagesSig);
			pfndatabase = *((unsigned long *)((unsigned long)MmProbeAndLockPages + offset));
			results[1] = *pfndatabase;
			break;
		}

	}

	for (i=MmMapLockedPagesSpecifyCacheOffset - tolerance;i<MmMapLockedPagesSpecifyCacheOffset + tolerance;i++)
	{
		unsigned char *sig = (unsigned char *)MmMapLockedPagesSpecifyCache + i;
		if (memcmp(sig,MmMapLockedPagesSpecifyCacheSig,sizeof(MmMapLockedPagesSpecifyCacheSig)) == 0)
		{
			unsigned long offset;
			unsigned long *pfndatabase;
			offset = i + sizeof(MmMapLockedPagesSpecifyCacheSig);
			pfndatabase = *((unsigned long *)((unsigned long)MmMapLockedPagesSpecifyCache+ offset));
			results[2] = *pfndatabase;
			break;
		}

	}


	if (results[0] == results[1] || results[0] == results[2])
	{
		gOSDependent_pfnBase = results[0];
		KdPrint(("found pfnbase of 0x%x\n", results[0]));
		gPFNFound = TRUE;
	} else if (results[1] == results[2]) {
		gOSDependent_pfnBase = results[1];
		KdPrint(("found pfnbase of 0x%x\n", results[1]));
		gPFNFound = TRUE;
	} else {
		KdPrint(("no suitable pfnbase found so gPFNFound = FALSE\n"));
		DbgPrint("no suitable pfnbase found so gCrashed = TRUE\n");
		gPFNFound = FALSE;
	}
}


int CheckPageForSafeAccess(unsigned int startVA)
{
	int pageSpan = 1;
	if (startVA % 0x1000)
		pageSpan++;
	CheckVARangeForSafeAccess(startVA,pageSpan);
}

int CheckVARangeForSafeAccess(unsigned int startVA, unsigned int numPages){
	//For sanity checking memory locations before we touch them
	unsigned int pdeLower32 = 0, x = 0, holderVA;
	unsigned int * pdePtr = 0;
	unsigned int * ptePtr = 0;
	pfn_t * pfnPtr = 0;
	unsigned int myCR4 = 0;
	char paeEnabled = 0, pseEnabled = 0;

	//This is "mov eax, CR4" but the assembler wouldn't let
	//me do that instruction, even though it worked for cr0
	__asm{	_emit 0x0F
			_emit 0x20
			_emit 0xE0};
	__asm{ mov myCR4, eax };

	if(myCR4 & PAE_BIT){
		paeEnabled = 1;
	}
	if(!paeEnabled){
		//__asm{int 3}
		//Testing on a non-PAE system hasn't been done yet
		return GENERIC_ERROR;
	}

	if(myCR4 & PSE_BIT){
		pseEnabled = 1; //TODO: not sure what I'm going to use this for yet...
	}


	//This calculation is taken from MmIsAddressValid()'s asm (and it happens to yield the same asm ;))
	if(paeEnabled){
		pdePtr = (unsigned int *)(((startVA >> 0x12) & 0x3FF8) + 0xC0600000);
	}
	else{
		//placeholder, haven't tested against non-PAE yet
		pdePtr = (unsigned int *)(((startVA >> 0x12) & 0x3FF8) + 0xC0300000);
	}
	pdeLower32 = *pdePtr;

	//ptePtr = (unsigned int *)(((startVA >> 9) & 0x7FFF
	//Check if the present bit is set for the PDE
	if((pdeLower32 & 1) == 0){
		KdPrint(("CheckVARangeForSafeAccess: Present bit missing on PDE for %#x\n", startVA));
		return GENERIC_ERROR;
	}

	//Do the PFN checking if the large page (2MB in PAE) bit is set in the PDE
	//TODO: add a check and differentiate between PAE mode and non
	if((pdeLower32 & 0x80) == 0x80){
		for(x = 0; x < numPages; x++){
			holderVA = startVA + x*PAGE_SIZE;
			//First find the PDE for the VA
			//Now get the PFN for the first 

			//Should be taking the upper 11 bits from the lower 32 bits of the
			//PDE, but should ALSO be taking the lower 4 bits from the
			//I.e. the PDE is 64bits, and the PFN should be 15 bits
			//TODO: is there a maximum size of a PFN number?
			pfnPtr = (pfn_t *)(gOSDependent_pfnBase + ((pdeLower32 >> 0xC) * sizeof(pfn_t)));
			//That got the base pointer, now we need to move to the correct PFN for the desired VA
			//Per the intel manual, we want to use the lower 21 bits as an index into the
			//large page. Because the divide gets rid of the bottom 12 bits, we
			//only have to AND the remaining 9 bits (0x1FF)
			pfnPtr += (((unsigned int)holderVA / 0x1000) & 0x1FF);

			//If there could be another iteration through the loop, and if
			//0x1FF would wrap around to 0 on that loop, recalculate
			//the pdePtr now
			if(((holderVA / 0x1000) & 0x1FF) == 0x1FF){
				holderVA += 0x1000;
				pdePtr = (unsigned int *)(((holderVA >> 0x12) & 0x3FF8) - 0x3FA00000);						
				pdeLower32 = *pdePtr;
			}

			//TODO: would a better check be to check if the PTEentry field of the
			//pfn points back at the same VA as holderVA

			//Check if the PFN is on the active list, if not bail out
			//0x6 = Active
			//0x3 = Modified
			//0x2 = Standby
			if(((pfnPtr->flags >> 8) & 0x0F) != 0x6){
				KdPrint(("CheckVARangeForSafeAccess: PFN for %#x is not on the active list\n", startVA));
				return GENERIC_ERROR;
			}
			
			//Even if it's on the active list, if the ref count is 0 (which I
			//haven't actually seen in practice), bailout too
			if(pfnPtr->refCount == 0){
				KdPrint(("CheckVARangeForSafeAccess: PFN for %#x hash refcount of 0\n", startVA));
				return GENERIC_ERROR;
			}
		}
	}
	else{ //if PDE doesn't point to a large page, it points to a page table
		for (x=0;x<numPages;x++)
		{
			holderVA = startVA + x*PAGE_SIZE;
			ptePtr = (unsigned int *)(((holderVA >> 9) & 0x7FFFF8) + 0xC0000000);
			if ((*ptePtr & 0x1) != 0x1)
			{
				KdPrint(("CheckVARangeForSafeAccess: Present bit missing on PTE for %#x\n", holderVA));
				return GENERIC_ERROR;
			}
		}
	}

	return GENERIC_SUCCESS;
}
