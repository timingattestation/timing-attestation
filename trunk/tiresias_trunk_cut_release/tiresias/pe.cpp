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

#include "pe.h"
#include <vector>
#include <map>
#include <list>
#include <string>
#include "sha.h"
#include "measure_binary.h"
#include "database_mysql2.h"
#include "parse_symbols.h"
#include "file_access.h"

extern "C"{
	#include "database_mysql.h"
}


using namespace std;

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
extern map<string,vector<int>> gSectionPageNotes;

extern char * gffStoragePath;
extern "C" HANDLE mysqlMutex;

typedef list <sha_256_t *> shaList;

struct TRANSLATION {
		WORD langID;			// language ID
		WORD charset;			// character set (code page)
} m_translation;

static LPCTSTR Keys[] = {
		_T("CompanyName"),
			_T("FileDescription"),
			_T("FileVersion"),
			_T("ProductName"),
			_T("ProductVersion"),
			NULL
	};

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////


//Takes a filename to open (only one can be open at a time, since the stream will be a global)
//sets some useful globals
//caller must call free(pDosH) eventually to avoid memory leak
int ParsePEHeaders(FILE * fileStream, PIMAGE_DOS_HEADER * pDosH, PIMAGE_NT_HEADERS * pNtH, PIMAGE_SECTION_HEADER * pFirstSectH){

	char * callerFreeBuffer = (char *)malloc(0x400); //The 0x400 is just to get the DOS/NT header
	if(callerFreeBuffer != NULL){
		unsigned int bytesRead = fread(callerFreeBuffer, sizeof(char), 0x400, fileStream);
		if(bytesRead != 0x400){
			printf("ParsePEHeaders:error: file was not read, or didn't contain 0x200 bytes\n");
			free(callerFreeBuffer);
			return GENERIC_ERROR;
		}
		
		//Find the base VA, find the offset between base VA and real VA
		*pDosH = (PIMAGE_DOS_HEADER)callerFreeBuffer;
		*pNtH = (PIMAGE_NT_HEADERS)(callerFreeBuffer + (*pDosH)->e_lfanew);

		if((*pNtH)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0){
			printf("ParsePEHeaders:error: This file contains delayed imports which I don't handle yet\n");
			free(callerFreeBuffer);
			return GENERIC_ERROR;
		}

		unsigned int newSize = (*pDosH)->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (*pNtH)->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
		callerFreeBuffer = (char *)realloc(callerFreeBuffer, newSize);
		if(callerFreeBuffer != NULL){
			fseek(fileStream, 0, 0);
			bytesRead = fread(callerFreeBuffer, sizeof(char), newSize, fileStream);
		
			if(bytesRead != newSize){
				printf("ParsePEHeaders:error: file was not read, or didn't contain %u bytes\n", newSize);
				if(callerFreeBuffer != NULL){
					free(callerFreeBuffer);
				}
				return GENERIC_ERROR;
			}
			*pDosH = (PIMAGE_DOS_HEADER)callerFreeBuffer;
			*pNtH = (PIMAGE_NT_HEADERS)(callerFreeBuffer + (*pDosH)->e_lfanew);
			*pFirstSectH = (PIMAGE_SECTION_HEADER)((char *)(*pNtH) + sizeof(IMAGE_NT_HEADERS));
		}
	}

	return GENERIC_SUCCESS;
}

//returns 0 on error, else a valid pointer to a section header
PIMAGE_SECTION_HEADER rvaToSectH(unsigned int rva, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH){
	PIMAGE_SECTION_HEADER pSectH = pFirstSectH;
	PIMAGE_SECTION_HEADER pDesiredSect = 0;
	for(int i = 0; i < pNtH->FileHeader.NumberOfSections; i++){
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


char * AllocBufForSect(FILE * fileStream, PIMAGE_SECTION_HEADER pDesiredSect){
	//Read the relocation section data
	char * buf = (char *)malloc(pDesiredSect->SizeOfRawData);
	if(buf == 0){
		printf("AllocBufForSect:error: Malloc failed\n");
		return NULL;
	}
	fseek(fileStream, pDesiredSect->PointerToRawData, 0);
	unsigned int bytesRead = fread(buf, sizeof(char), pDesiredSect->SizeOfRawData, fileStream);
	if(bytesRead != pDesiredSect->SizeOfRawData){
		printf("Error in AllocBufForSect, file was not read, or didn't contain %d bytes\n", (int)pDesiredSect->SizeOfRawData);
		free(buf);
		return NULL;
	}

	return buf;
}

//Reads exported symbol information from the binary and adds it to tiresias.exports
//for use with pointer table verification
int ParseExports(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH, loadedModulesEntry_t * lmEntry)
{
	unsigned int i;
	unsigned int j;
	//Want to get the range of the exports as defined by the data directory entry
	//so that we can detect forwarded exports (which are entries where the RVA points
	//within the exports section)
	unsigned int exportsRVA = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	unsigned int exportsRVAEnd = exportsRVA + pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	unsigned int ret;
	PIMAGE_SECTION_HEADER pExportsSect = rvaToSectH(exportsRVA, pNtH, pFirstSectH);
	if(pExportsSect == 0){//Couldn't find section
		printf("ParseExports: rvaToSectH failed\n");
		return GENERIC_ERROR;
	}

	char * exportBuf = AllocBufForSect(fileStream, pExportsSect);
	if(exportBuf == NULL){
		printf("ParseExports: AllocBufForSect failed\n");
		return GENERIC_ERROR;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(exportBuf + exportsRVA - pExportsSect->VirtualAddress);
	unsigned int *exportedFunctionArray = (unsigned int *)(exportBuf + pExportDir->AddressOfFunctions - pExportsSect->VirtualAddress);
	unsigned int *exportedNameArray = (unsigned int *)(exportBuf + pExportDir->AddressOfNames - pExportsSect->VirtualAddress);
	unsigned short *ordinalArray = (unsigned short *)(exportBuf + pExportDir->AddressOfNameOrdinals - pExportsSect->VirtualAddress);

	vector<export_t *> exportSymbols(pExportDir->NumberOfFunctions);
	for (i=0;i<pExportDir->NumberOfFunctions;i++)
	{
		exportSymbols[i] = (export_t *)malloc(sizeof(export_t));
		if(exportSymbols[i] == NULL){
			ret = GENERIC_ERROR;
			goto end;
		}
		//Check if this is a forwarded export
		//If you want a good example to look at, see videoprt.sys
		if(exportedFunctionArray[i] > exportsRVA && exportedFunctionArray[i] < exportsRVAEnd){
			//If this holds, then the RVA actually points to a string specifying
			//module.functionname
			//First we will check if we already have the exports name->RVA mappings
			//in the database
			char * forwardedExportBuf;
			ret = ReadDataAtRVAFromFileIntoBuffer(fileStream, exportedFunctionArray[i], &forwardedExportBuf, 256, pNtH, pFirstSectH);
			if(ret != GENERIC_SUCCESS){
				printf("ParseExports: ReadDataAtRVAFromFileIntoBuffer for exportedFunctionArray[%u]=%#x failed\n", i, exportedFunctionArray[i]);
				goto end;
			}
			char * context;
			char * moduleName = strtok_s(forwardedExportBuf, ".", &context);
			char * functionName = strtok_s(NULL,".", &context);
			//The problem at this point is 
			loadedModulesEntry_t forwardedTolmEntry;
			ret = SelectLoadedModuleEntryByRegexpNameAndHostID(moduleName, lmEntry->hostID, &forwardedTolmEntry);
			if(ret != GENERIC_SUCCESS){
				printf("ParseExports: SelectLoadedModuleEntryByNameAndHostID failed\n");
				free(forwardedExportBuf);
				goto end;
			}
		
			//There is one really weird case in videoprt.sys where the first VideoPortCheckForDeviceExistance
			//that you come across forwards to...VIDEOPRT.VideoPortCheckForDeviceExistance
			//I want to skip this case for now until we find out we can't
			if(forwardedTolmEntry.id == lmEntry->id){
				exportSymbols[i]->rva = 0;
				goto bailout;
			}

			exportsEntry_t exportsEntry;
			char tmpName[MAX_EXPORT_NAME_LEN];
			exportsEntry.name = tmpName;
			//The caller needs to have allocated MAX_EXPORT_NAME_LEN worth of space for entry->name before calling this
			ret = SelectExportEntryByNameAndLoadedModuleID(functionName, forwardedTolmEntry.id, &exportsEntry);
			if(ret == GENERIC_SUCCESS){
				//If the entry is already there, just set it
				//Now, here comes the trick. We know that the other code to reconstruct the IAT takes whatever RVA is in
				//server.exports, and add it to the base address for that particular module. But because this is a
				//forwarded export, you need the "RVA" to be such that when it's added to the base of the one module
				//it points into the forwarded-to module.
				exportSymbols[i]->rva = (forwardedTolmEntry.baseVA + exportsEntry.RVA) - lmEntry->baseVA;
			}
			else if(ret == NO_RESULTS_FOUND){
				//If not we will just recursivly call ParseExports on that module
				//NOTE: this holds a slight possibility of infinite recursion
				//but I'll deal with that if I ever see it
				unsigned int rva;
				ret = ParseExportsForwardingRecursionHelper(functionName, &forwardedTolmEntry, &rva);
				if(ret != GENERIC_SUCCESS){
					printf("ParseExports: ParseExportsRecursionHelper failed\n");
					free(forwardedExportBuf);
					goto end;
				}
				//Now, here comes the trick. We know that the other code to reconstruct the IAT takes whatever RVA is in
				//server.exports, and add it to the base address for that particular module. But because this is a
				//forwarded export, you need the "RVA" to be such that when it's added to the base of the one module
				//it points into the forwarded-to module.
				exportSymbols[i]->rva  = (forwardedTolmEntry.baseVA + rva) - lmEntry->baseVA;
			}
			else{
				printf("ParseExports: SelectExportEntryByNameAndLoadedModuleID failed\n");
				free(forwardedExportBuf);
				goto end;
			}
			free(forwardedExportBuf);
		}
		else{
			exportSymbols[i]->rva = exportedFunctionArray[i];
		}
bailout:
		exportSymbols[i]->name[0] = 'N';
		exportSymbols[i]->name[1] = 'O';
		exportSymbols[i]->name[2] = 'N';
		exportSymbols[i]->name[3] = 'A';
		exportSymbols[i]->name[4] = 'M';
		exportSymbols[i]->name[5] = 'E';
		exportSymbols[i]->name[6] = '\0';
		exportSymbols[i]->ordinal = i;
	}

	//now go in and fill in the actual name fields for each of the exported
	//symbols. Note that not every symbol has an associated name, Hence it is
	//exported by ordinal only. 
	__asm{nop};
	for (i=0;i<pExportDir->NumberOfNames;i++)
	{
		char *name = (char *)(exportBuf + exportedNameArray[i] - pExportsSect->VirtualAddress);
		int ord = ordinalArray[i];
		memset(&(exportSymbols[ord]->name),'\0',51);
		for (j=0;j<strlen(name) && j < 52; j++)
		{
			exportSymbols[ord]->name[j] = name[j];
		}
		exportSymbols[ord]->name[51] = '\0';
	}

	ret = InsertExports(lmEntry->id,&(exportSymbols));
	if (ret != GENERIC_SUCCESS)
	{
		printf("ParseExports: InsertExports failed\n");
		goto end;
	}
	
	
end:
	for (i=0;i<exportSymbols.size();i++)
	{
		if(exportSymbols[i] != NULL){
			free(exportSymbols[i]);
		}
	}
	exportSymbols.clear();
	free(exportBuf);
	return ret;
}

//NOTE: the lmEntry is for the new module which exports are being forwarded to
//which needs to be opened
int ParseExportsForwardingRecursionHelper(char * functionName, loadedModulesEntry_t * lmEntry, unsigned int * rva){
	int ret;
	char * fullFileName;
	FILE * fileStream;
	PIMAGE_DOS_HEADER pDosH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pFirstSectH = NULL;

	//Now we need to get things set up to ultimately call ParseExports() on the module
	//specified by lmEntry->name
	ret = FindFile(gffStoragePath, lmEntry->name, lmEntry->timeDateStamp, lmEntry->sizeOfImage, &fullFileName);
	if(ret == GENERIC_ERROR){
		//For kernel variants like ntkrnlpa.exe, they are found
		//in memory in the loaded modules list as ntoskrnl.exe but their
		//memory measurements need to be taken from the right kernel version.
		//So we need to try alternative names
		if(_stricmp(lmEntry->name, "ntoskrnl.exe")==0){
			ret = FindFile(gffStoragePath, "ntkrnlpa.exe", lmEntry->timeDateStamp, lmEntry->sizeOfImage, &fullFileName);
			if(ret == GENERIC_ERROR){
				ret = FindFile(gffStoragePath, "ntkrnlmp.exe", lmEntry->timeDateStamp, lmEntry->sizeOfImage, &fullFileName);
				if(ret == GENERIC_ERROR){
					printf("ParseExportsForwardingRecursionHelper: Couldn't find replacement for ntoskrnl.exe\n");
					return GENERIC_ERROR;
				}
			}
		}
		else{
			printf("ParseExportsForwardingRecursionHelper: FindFile failed: Couldn't find match for %s-%x-%x\n", 
					lmEntry->name,
					lmEntry->timeDateStamp,
					lmEntry->sizeOfImage);
			return ret;
		}
	}

	if(fullFileName != NULL){
		//Open the file to read the headers
		errno_t err = fopen_s(&fileStream,fullFileName,"rb");
		if(err != 0){
			printf("ParseExportsForwardingRecursionHelper:error: Couldn't fopen_s %s, errno = %d\n", fullFileName, errno);
			free(fullFileName);
			return GENERIC_ERROR;
		}

		if(ParsePEHeaders(fileStream, &pDosH, &pNtH, &pFirstSectH) == GENERIC_ERROR){
			printf("ParseExportsForwardingRecursionHelper: ParsePEHeaders failed, unsupported case in %s\n", fullFileName);
			free(fullFileName);
			fclose(fileStream);
			return GENERIC_ERROR;
		}

		ret = ParseExports(fileStream, pNtH, pFirstSectH, lmEntry);
		if(ret != GENERIC_SUCCESS){
			printf("ParseExportsForwardingRecursionHelper: ParseExports failed\n");
			free(fullFileName);
			fclose(fileStream);
			free(pDosH);
			return ret;
		}

		//If we can ultimately call ParseExports on the forwarded-to module, then look up the RVA
		exportsEntry_t exportsEntry;
		char tmpName[MAX_EXPORT_NAME_LEN];
		exportsEntry.name = tmpName;
		//The caller needs to have allocated MAX_EXPORT_NAME_LEN worth of space for entry->name before calling this
		ret = SelectExportEntryByNameAndLoadedModuleID(functionName, lmEntry->id, &exportsEntry);
		if(ret != GENERIC_SUCCESS){
			printf("ParseExportsForwardingRecursionHelper: SelectExportEntryByNameAndLoadedModuleID failed\n");
			free(fullFileName);
			fclose(fileStream);
			free(pDosH);
			return ret;
		}

		*rva = exportsEntry.RVA;
	}

	return GENERIC_SUCCESS;
}

//Returns a pointer to a buffer which holds the relocations information
char * FindRelocs(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH){
	unsigned int relocRVA = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	PIMAGE_SECTION_HEADER pRelocSect = rvaToSectH(relocRVA, pNtH, pFirstSectH);
	if(pRelocSect == 0){//Couldn't find section
		printf("rvaToSectH failed in FindExports\n");
		return 0;
	}
	
	char * relocBuf = AllocBufForSect(fileStream, pRelocSect);
	if(relocBuf == NULL){
		printf("AllocBufForSect failed in FindRelocs\n");
	}
	return relocBuf;
}

unsigned int FindBaseVADiff(unsigned int realVA, PIMAGE_NT_HEADERS pNtH){
	return (realVA - pNtH->OptionalHeader.ImageBase);
}

//both pSections and numROSections should be pass by reference vars
int FindROSections(PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH, PIMAGE_SECTION_HEADER * pSections, unsigned int * numROSections){

	//iterate through all sections to find desired section and relocations information
	PIMAGE_SECTION_HEADER pSectH = pFirstSectH;
	*numROSections = 0;
	for(int i = 0; i < pNtH->FileHeader.NumberOfSections; i++){

		//For every other section which matches the criteria, add it to the pointer array.
		if((pSectH->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ &&
			(pSectH->Characteristics & IMAGE_SCN_MEM_WRITE) == 0 && 
			(pSectH->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 )
		{

			//Skip PAGEVRF* sections, because they're used by the driver verifier
			//and apparently discardable when the verifier isn't used (though 
			//they're not marked that way!)
			if(memcmp(&(pSectH->Name[0]), "PAGEVRF", 7) == 0){
				pSectH++;
				continue;
			}

			//Skip PAGESPEC because Pavel Lebedinsky said in an OSR thread that
			//it is also discardable
			if(memcmp(&(pSectH->Name[0]), "PAGESPEC", 8) == 0){
				pSectH++;
				continue;
			}

			//If we already have the maximum, but we want one more, error out
			if(*numROSections == MAX_SECTS_TO_MEASURE){
				printf("numROSections: more than MAX_SECTS_TO_MEASURE\n");
				return GENERIC_ERROR;
			}

			pSections[*numROSections] = pSectH;
			(*numROSections)++;
		}
		pSectH++;
	}

	return GENERIC_SUCCESS;
}

//Applies relocations to a single section (as given by an RVA) in a given file
//Returns a pointer to a buffer which contains the data for the section, with relocations applied
//Note, the beginning of the buffer may not be the beginning of the data, if it's a section which
//will be mapped to a non-page-aligned address. External functions must offset into the buffer as
//necessary.
//Making the caller responsible for the offset was decided upon because it makes it more clear that
//the buffer address which is returned is unmodified, and is the address to be free()d.
//Returns NULL on error or pointer to malloced memory holding a relocated section on success
//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE MEMORY RETURNED
int GetRelocatedSection(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pSectH, unsigned int baseVADiff, char * relocBuf, unsigned int * alignmentOffset, unsigned int * endAlignUpPadding, char **outputBuffer, unsigned int * outputBufLen){
	int ret;
	unsigned int sectSize = 0;

	unsigned int totalRelocSize = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
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
	unsigned int sectionStart = PA_DOWN_INT(pSectH->VirtualAddress);
	unsigned int sectionEnd = PA_UP_INT(pSectH->VirtualAddress + sectSize);
	unsigned int numPagesInSect = (sectionEnd - sectionStart) / PAGE_SIZE;
	*endAlignUpPadding = sectionEnd - (pSectH->VirtualAddress + sectSize);

	unsigned int fileOffset = 0;
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
		fileOffset = pSectH->PointerToRawData;
		*alignmentOffset = 0;
	}
	else if(pSectH->PointerToRawData == pSectH->VirtualAddress && 
			((pSectH->PointerToRawData & 0xFFF) != 0)){
		//If the VirtualAddress == PointerToRawData (and are both unaligned)
		//then the virtual address *for relocations purposes*
		//will be the address aligned down (since relocation chunks start
		//on aligned boundaries)
		//Since it's aligned down, we need to read in the information before
		fileOffset = PA_DOWN_INT(pSectH->PointerToRawData);
		*alignmentOffset = (pSectH->PointerToRawData & 0xFFF);
	}
	*outputBufLen += (pSectH->PointerToRawData & 0xFFF) + sectSize;

	*outputBuffer = (char *)malloc(*outputBufLen);
	if(*outputBuffer == NULL){
		printf("GetRelocatedSection: malloc failed\n");
		return NULL;
	}
	if(fseek(fileStream, fileOffset, 0) != 0){
		printf("GetRelocatedSection: fseek failed\n");
		return GENERIC_ERROR;
	}

	unsigned int bytesRead = fread(*outputBuffer, sizeof(char), *outputBufLen, fileStream);
	if(bytesRead != *outputBufLen){
		printf("GetRelocatedSection: file was not read, or didn't contain %d bytes\n", (numPagesInSect * PAGE_SIZE));
		return GENERIC_ERROR;
	}

	ret = ApplyRelocations(*outputBuffer, *outputBufLen, relocBuf, totalRelocSize, sectionStart, numPagesInSect, baseVADiff);

	return GENERIC_SUCCESS;
}

int ApplyRelocations(char * outputBuffer, unsigned int outputBufLen, char * relocBuf, unsigned int totalRelocSize, unsigned int sectionStart, unsigned int numPagesInSect, unsigned int baseVADiff){

	IMAGE_BASE_RELOCATION * pCurrentRelocBlock;
	unsigned int offset = 0;
	unsigned int totalRelocsProcessed = 0;

	//This should point at the page which we want to find relocations for.
	//Should be given as a page-aligned RVA
	unsigned int currentRVA = 0; 

	//Used as the offset into the buffer we've just allocated
	char * currentFileOffset = outputBuffer;
	
	//Here's the important fact about relocations: because we page align down section addresses
	//(so that they match potential relocations block virtual addresses, which can start at 0)
	//it is possible for a single page's relocations block to actually apply to multiple SECTIONS
	//worth of addresses. Therefore, it is legitimate for us to apply the relocations in a single
	//sections block multiple times to a chunk of memory (which maybe the first time the hash
	//only cares about the bottom part of, and the second time maybe it only cares about the top
	//part of). Therefore, the best way to do it is NOT to keep a running total of the relocations
	//we've applied (as we used to do), but rather, to just find and apply relocations starting
	//at the beginning of the relocations for each section.
	for(unsigned int i = 0; i < numPagesInSect; i++){
		currentRVA = sectionStart + (i * PAGE_SIZE);
		if(i != 0){
			currentFileOffset += PAGE_SIZE;
		}
		if(currentFileOffset > (outputBuffer + outputBufLen)){
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
		unsigned int relocOffset = sizeof(IMAGE_BASE_RELOCATION); //Used as an offset to step through reloc entries
		unsigned short * relocEntry;
		unsigned short offsetIntoPage = 0;
		int * relocPtr;

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
			if((unsigned int)relocPtr + sizeof(unsigned int) > (unsigned int)(outputBuffer + outputBufLen)){
				break;
			}

			*relocPtr += baseVADiff; //AT LAST! Perform the relocation!
			relocOffset += sizeof(short);
		}

		//reminder: offset is used to make sure the next pCurrentRelocBlock gets set
		totalRelocsProcessed += pCurrentRelocBlock->SizeOfBlock;
	}

	return GENERIC_SUCCESS;

}

//This is yet another place where we pretend we're the OS loader, and recreate its 
//effects to the memory image
int ReconstructImports(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pSectH, char * relocatedSectionBuffer, unsigned int relocatedSectionBufLen, unsigned int alignmentOffset, unsigned int baseVADiff, st_msg_t * stm){
	int ret;
	char * importDescriptorsBuf;
	unsigned int importDescriptorsBufLen;
	unsigned int importsRVA;
	PIMAGE_SECTION_HEADER pFirstSectH;

	//Check if the IAT (not the IMAGE_IMPORT_DESCRIPTOR structures!) is in this section
	importsRVA = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	//Determine whether the IAT falls within this section
	if(importsRVA < pSectH->VirtualAddress ||
		importsRVA >= (pSectH->VirtualAddress + pSectH->Misc.VirtualSize))
	{
		return GENERIC_SUCCESS;
	}

	//If so, then parse the IMAGE_IMPORT_DESCRIPTORs in order to see which modules this module imports from.
	//The problem is, the IMAGE_IMPORT_DESCRIPTORs need not necessarily be in the same section as the IAT
	//so we need to go out to file to read that information.
	pFirstSectH = PIMAGE_SECTION_HEADER((unsigned char *)pNtH + sizeof(IMAGE_NT_HEADERS));
	importsRVA = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	importDescriptorsBufLen = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	ret = ReadDataAtRVAFromFileIntoBuffer(fileStream, importsRVA, &importDescriptorsBuf, importDescriptorsBufLen, pNtH, pFirstSectH);
	if(ret != GENERIC_SUCCESS){
		printf("ReconstructImports: ReadDataAtRVAFromFileIntoBuffer for importsRVA failed\n");
		return ret;
	}

	//So here's the trick at this point: we know that to start with, the import names table (INT)
	//and import address table (IAT) point at the same hint/string data structures. We don't want to 
	//go out and read in the INT from file, because actually we don't know how large it is until
	//we walk it and find the null terminating entry. But since we already know that *this* section
	//which we have the data for already, has the IAT, and because the import descriptors have pointers
	//into the IAT too, we can walk the IAT entries and find the min and max hint/name RVAs, which
	//gives us the approximate size (we still need to pad the end, since we don't know how long the 
	//last string is.

	PIMAGE_IMPORT_DESCRIPTOR impDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)importDescriptorsBuf;
	unsigned int outOfBounds = (unsigned int)(importDescriptorsBuf + importDescriptorsBufLen);

	unsigned int sectionRVA;
	//This is the for-each import descriptor loop
	while(impDescriptor->Name != NULL){
		//extra sanity check, just incase
		if((unsigned int)impDescriptor >= outOfBounds){
			break;
		}
		//read the start of the IAT, and convert that RVA into a section-relative address
		sectionRVA = impDescriptor->FirstThunk - pSectH->VirtualAddress;

		//now read the alls the RVAs of the name/hint structures out of the not-yet-filled-in IAT
		unsigned int * iatPtr = (unsigned int *)(relocatedSectionBuffer+alignmentOffset+sectionRVA);
		unsigned int minRVA = 0xFFFFFFFF, maxRVA = 0;
		while(*iatPtr != NULL){
			if(*iatPtr < minRVA){
				minRVA = *iatPtr;
			}
			if(*iatPtr > maxRVA){
				maxRVA = *iatPtr;
			}
			iatPtr++;
		}

		//Now that we have the approximate size of the name/hint entries, we can convert the RVAs to
		//file offsets and read the name/hint data in from file

		//The 0x104 below is to pad buffer to hopefully guarantee we get the import function name string
		unsigned int hintNameBufLen = maxRVA - minRVA + 0x104;
		char * hintNameBuf;
		ret = ReadDataAtRVAFromFileIntoBuffer(fileStream, minRVA, &hintNameBuf, hintNameBufLen, pNtH, pFirstSectH);
		if(ret != GENERIC_SUCCESS){
			printf("ReconstructImports: ReadDataAtRVAFromFileIntoBuffer for minRVA failed\n");
			if(importDescriptorsBuf != NULL){
				free(importDescriptorsBuf);
			}
			return ret;
		}

		//We now have all of the functions names to be imported from this module
		//so we have to open up the module, and search its EAT for the RVA in that
		//module for the imported function
		//And yet...there is yet another challenge...the names of the modules which we are
		//importig from are given only as RVAs...RVAs which need not necessarily be in any
		//data buffer we've already read in from file...
		//Once more into the file!
		char * exportingModuleNameBuf;
		ret = ReadDataAtRVAFromFileIntoBuffer(fileStream, impDescriptor->Name, &exportingModuleNameBuf, 0x104, pNtH, pFirstSectH);
		if(ret != GENERIC_SUCCESS){
			printf("ReconstructImports: ReadDataAtRVAFromFileIntoBuffer for impDescriptor->Name = %#x failed\n", (unsigned int)impDescriptor->Name);
			free(importDescriptorsBuf);
			free(hintNameBuf);
			return ret;
		}

		//OK, *now* we can go open the file that is exporting functions for this imports descriptor
		FILE * exportingFileStream;
		loadedModulesEntry_t lmEntry;
		//when this returns, fopen_s has already been called on fileStream
		ret = OpenHostSpecificModule(stm, exportingModuleNameBuf, &exportingFileStream, &lmEntry);
		if(ret != GENERIC_SUCCESS){
			printf("ReconstructImports: OpenHostSpecificModule failed\n");
			free(importDescriptorsBuf);
			free(hintNameBuf);
			free(exportingModuleNameBuf);
			return ret;
		}

		PIMAGE_DOS_HEADER exportingModuleDosHdr;
		PIMAGE_NT_HEADERS exportingModuleNtHdr;
		PIMAGE_SECTION_HEADER exportingModuleFirstSectionHdr;
		//Don't forget to free(exportingModuleDosHdr) when done, or on error!
		ret = ParsePEHeaders(exportingFileStream, &exportingModuleDosHdr, &exportingModuleNtHdr, &exportingModuleFirstSectionHdr);
		if(ret != GENERIC_SUCCESS){
			printf("ReconstructImports: ParsePEHeaders failed\n");
			free(importDescriptorsBuf);
			free(hintNameBuf);
			free(exportingModuleNameBuf);
			fclose(exportingFileStream);
			return ret;
		}

		//check for if the exports already exist for this module
		//so that we don't call ParseExports multiple times on the same module
		unsigned int exists;
		ret = CheckIfExportExistsForLoadedModuleID(lmEntry.id, &exists);
		if(ret == GENERIC_ERROR){
			printf("ReconstructImports: CheckIfExportExistsForLoadedModuleID failed\n");
			free(importDescriptorsBuf);
			free(hintNameBuf);
			free(exportingModuleNameBuf);
			fclose(exportingFileStream);
			free(exportingModuleDosHdr);
			return ret;
		}
		else if(ret == NO_RESULTS_FOUND){
			ret = ParseExports(exportingFileStream, exportingModuleNtHdr, exportingModuleFirstSectionHdr, &lmEntry);
			if(ret != GENERIC_SUCCESS){
				printf("ReconstructImports: ParseExports failed\n");
				free(importDescriptorsBuf);
				free(hintNameBuf);
				free(exportingModuleNameBuf);
				fclose(exportingFileStream);
				free(exportingModuleDosHdr);
				return ret;
			}
		}

		//Finally, finally, finally, we can start to loop through the name/hint array and fill 
		//in values to the IAT
		//One caveat: it looks like the name/hint structures are aligned on 2 byte boundaries
		//so we need to align up the pointer as we walk forward if we would be ending on a 
		iatPtr = (unsigned int *)(relocatedSectionBuffer+alignmentOffset+sectionRVA);
		char * nameHintPtr = hintNameBuf;
		exportsEntry_t exportsEntry;
		char eName[MAX_EXPORT_NAME_LEN];
		exportsEntry.name = eName;
		while(*iatPtr != NULL){

			//Because things are not always in order, we need to use the RVA already in the IAT
			//to help calculate a relative offset into the name/hint buffer
			//We're not going to use the hint to look up the RVA, since it's just as easy to
			//look it up in the db by the string, so that's why we're adding 2, to get past the hint
			nameHintPtr = hintNameBuf + ((*iatPtr) - minRVA) + 2;
			//sanity check
			if((unsigned int)nameHintPtr > (unsigned int)hintNameBuf + hintNameBufLen){
				printf("ReconstructImports: sanity check failed, nameHintPtr exceeded bounds\n");
				free(importDescriptorsBuf);
				free(hintNameBuf);
				free(exportingModuleNameBuf);
				fclose(exportingFileStream);
				free(exportingModuleDosHdr);
				return GENERIC_ERROR;
			}
			//The caller needs to have allocated MAX_EXPORT_NAME_LEN worth of space for entry->name before calling this
			ret = SelectExportEntryByNameAndLoadedModuleID(nameHintPtr, lmEntry.id, &exportsEntry);
			if(ret != GENERIC_SUCCESS){
				printf("ReconstructImports: SelectExportEntryByNameAndLoadedModuleID failed\n");
				free(importDescriptorsBuf);
				free(hintNameBuf);
				free(exportingModuleNameBuf);
				fclose(exportingFileStream);
				free(exportingModuleDosHdr);
				return ret;
			}

			*iatPtr = lmEntry.baseVA + exportsEntry.RVA;
			iatPtr++;
		}//end for each IAT entry
		free(hintNameBuf);
		free(exportingModuleNameBuf);
		fclose(exportingFileStream);
		free(exportingModuleDosHdr);
		impDescriptor++;
	}//end the for-each import descriptor loop
	
	free(importDescriptorsBuf);
	return GENERIC_SUCCESS;
}


unsigned int FindFileOffsetToImportDescriptors(PIMAGE_NT_HEADERS pNtH){
	PIMAGE_SECTION_HEADER pFirstSectHdr;
	unsigned int importsRVA;
	PIMAGE_SECTION_HEADER pImportsSectH;
	pFirstSectHdr = PIMAGE_SECTION_HEADER((unsigned char *)pNtH + sizeof(pNtH));
	importsRVA = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	pImportsSectH = rvaToSectH(importsRVA, pNtH, pFirstSectHdr);
	if(pImportsSectH == NULL){
		printf("FindFileOffsetToImportDescriptors: rvaToSectH failed\n");
		return GENERIC_ERROR;
	}
	return (importsRVA - pImportsSectH->VirtualAddress) + pImportsSectH->PointerToRawData;
}