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

#ifndef PE_H
#define PE_H

#include <windows.h>
#include <winver.h>
#include <iostream>
#include <vector>
#include <string>
#include <winnt.h>
#include "server_tiresias_protocol.h"
#include <vector>
extern "C" {
	#include "database_mysql.h"
}
using namespace std;
////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////



////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

char * AllocBufForSect(FILE * fileStream, PIMAGE_SECTION_HEADER pDesiredSect);
int ApplyRelocations(char * outputBuffer, unsigned int outputBufLen, char * relocBuf, unsigned int totalRelocSize, unsigned int sectionStart, unsigned int numPagesInSect, unsigned int baseVADiff);
char * FindRelocs(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH);
unsigned int FindBaseVADiff(unsigned int realVA, PIMAGE_NT_HEADERS pNtH);
unsigned int FindFileOffsetToImportDescriptors(PIMAGE_NT_HEADERS pNtH);
int FindROSections(PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH, PIMAGE_SECTION_HEADER * pSections, unsigned int * numROSections);
int GetRelocatedSection(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pSectH, unsigned int baseVADiff, char * relocBuf, unsigned int * alignmentOffset, unsigned int * endAlignUpPadding, char ** outputBuffer, unsigned int * outputBufLen);
int ParseExports(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH, loadedModulesEntry_t * lmEntry);
int ParseExportsForwardingRecursionHelper(char * functionName, loadedModulesEntry_t * lmEntry, unsigned int * rva);
int ParsePEHeaders(FILE * fileStream, PIMAGE_DOS_HEADER * pDosH, PIMAGE_NT_HEADERS * pNtH, PIMAGE_SECTION_HEADER * pFirstSectH);
int ReconstructImports(FILE * fileStream, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pSectH, char *relocatedSectionBuffer, unsigned int relocatedSectionBufLen, unsigned int alignmentOffset, unsigned int baseVADiff, st_msg_t * stm);
PIMAGE_SECTION_HEADER rvaToSectH(unsigned int rva, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH);
#endif