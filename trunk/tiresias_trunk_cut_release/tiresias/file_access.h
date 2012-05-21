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

//For any functions that needs to access the filesystem 
//e.g. to get known good files, read the config file, etc

#ifndef FILES_H
#define FILES_H

#include "global_includes.h"
#include <windows.h>
#include "server_tiresias_protocol.h"
extern "C"{
	#include "database_mysql.h"
}
////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////
#define MAX_LINE 255
#define DATETIMESTAMP_STR_SIZE 10
#define SIZEOFIMAGE_STR_SIZE 10

////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////
int FindFile(char * filesDirectory, char * name, unsigned int timeDateStamps, unsigned int sizeOfImage, char ** fullName);
int LoadSectionAndReconstructIAT(char * binaryName, char * sectionName, unsigned int hostID, unsigned int baseVA, unsigned int timeDateStamp, unsigned int sizeOfImage, char ** relocatedSection, unsigned int * relocSectLen, unsigned int * sectionStartRVA, unsigned int * sectionEndRVA);
int OpenBinaryToGetRelocatedROSection(char * binaryName, char * sectionName, unsigned int hostID, unsigned int baseVA, unsigned int timeDateStamp, unsigned int sizeOfImage, char ** relocatedSection, unsigned int * relocSectLen, unsigned int * sectionStartRVA, unsigned int * sectionEndRVA);
int OpenHostSpecificModule(st_msg_t * stm, char * fileName, FILE ** fileStream, loadedModulesEntry_t * loadedModuleEntry);
int ReadConfigAndSetGlobs(char * configFileName);
int ReadDataAtRVAFromFileIntoBuffer(FILE * fileStream, unsigned int rva, char ** buffer, unsigned int bufferLen, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH);
void UItoHexA(unsigned int val, char * str);

#endif