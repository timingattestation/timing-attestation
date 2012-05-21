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

#include "measure_binary.h"
#include "server_client_protocol.h"
#include <map>
#include <list>
#include <string>
#include "sha.h"
#include "pe.h"
#include "file_access.h"
#include "parse_symbols.h"
#include "database_mysql2.h"

extern "C" {
	#include "database_mysql.h"
}
using namespace std;
////////////////////////////////////////////////////////
//GLOBALS & TYPEDEFS
////////////////////////////////////////////////////////
map<string,vector<int>> gSectionPageNotes;
typedef list <sha_256_t *> shaList;

//EXTERNS
extern "C" MYSQL mysql;
extern "C" HANDLE mysqlMutex;
extern int gQuiet;
extern SOCKET gAcceptedSocket;


////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//This function is responsible for our special hacks
//which are necessary for modules which modify themselves

//With appologies to They Might Be Giants' "Hall of Heads"

//Here in the HallOfHacks()
//You look through the keyhole
//This is the HallOfHacks()
//One step through the doorway
//
//Roll out that special hack
//This is our favorite one
//Please don't try to leave
//Don't leave the HallOfHacks()
//
//Hide underneath the porch
//Hide down behind the furnace
//You can't get away
//You can't really hide
//Once you hear the call
//The song of the HallOfHacks()
//
//You can't run away
//Your feet won't help you run
//You can't run away
//Out of the HallOfHacks()
//This function is responsible for our special hacks
//which are necessary for modules which modify themselves
//alignmentOffset is the amount at the beginning of the buffer which preceeds the actual
//section data, but which was necessary to read in from file to satisfy the relocation code
int HallOfHacks(char * fullFileName, st_msg_t * binary, char * sectionName, unsigned int sectionRVA, char * relocatedSectionBuffer, unsigned int sectionSize, unsigned int alignmentOffset){
	unsigned int symbolRVA;
	int ret;
	unsigned char * holderVA;

	//The NT hacks
	if(_strnicmp(binary->bNameA, "ntoskrnl.exe", MAX_BIN_NAME_LEN) == 0){
		if(strncmp(sectionName, ".text", MAX_SECT_NAME_CHAR_LEN) == 0){
			//The KiSystemCallExitBranch Hack
			//Example output from windbg !chkimg -d -nospec
			//80540aaa - nt!KiSystemCallExitBranch+1
			//[ 05:06 ]
			ret = SelectResolvedBinarySymbolRVAByNameAndHostID("_KiSystemCallExitBranch", binary->hostID, &symbolRVA);
			if(ret != GENERIC_SUCCESS){
				if(ret == NO_RESULTS_FOUND){
					printf("HallOfHacks: SelectResolvedBinarySymbolRVAByNameAndHostID NO_RESULTS_FOUND, presumably symbol resolution isn't working\n");
				}
				else{
					printf("HallOfHacks: SelectResolvedBinarySymbolRVAByNameAndHostID GENERIC_ERROR\n");
				}
				return ret;
			}
			//The +1 is because the actual change is at KiSystemCallExitBranch+1, see !chkimg in windbg
			//TODO: why did I originally have the " - sectionRVA"?
			holderVA = (unsigned char *)(relocatedSectionBuffer + symbolRVA + 1 - sectionRVA);
			//The actual change is that something which is 5 on disk is 6 in memory
			*holderVA = 6;

			//The KeFlushCurrentTb Hack
			//Example output from windbg !chkimg -d -nospec nt
			//80544ffe-8054500f  18 bytes - nt!KeFlushCurrentTb+2 (+0x4554)
			//[ d8 0f 22 d8 c3 0f 20 e0:e0 25 7f ff ff ff 0f 22 ]
			//80545016 - nt!KeFlushCurrentTb+1a (+0x18)
			//[ c3:00 ]

			ret = SelectResolvedBinarySymbolRVAByNameAndHostID("_KeFlushCurrentTb@0", binary->hostID, &symbolRVA);
			if(ret != GENERIC_SUCCESS){
				if(ret == NO_RESULTS_FOUND){
					printf("HallOfHacks: SelectResolvedBinarySymbolRVAByNameAndHostID NO_RESULTS_FOUND, presumably symbol resolution isn't working\n");
				}
				else{
					printf("HallOfHacks: SelectResolvedBinarySymbolRVAByNameAndHostID GENERIC_ERROR\n");
				}
				return ret;
			}
			//The +2 is because the actual change is at KeFlushCurrentTb+2
			holderVA = (unsigned char *)(relocatedSectionBuffer + symbolRVA + 2 - sectionRVA);
			//The change here is a bit elaborate, see documentation or RE it yourself :P
			unsigned char change[18] = {0xe0, 0x25, 0x7f, 0xff, 0xff, 0xff, 0x0f, 0x22, 0xe0, 0x0d, 0x80, 0x00, 0x00, 0x00, 0x0f, 0x22, 0xe0, 0xc3};
			memcpy(holderVA, change, 18);
			//The +1a is because the second change is at KeFlushCurrentTb+1a
			holderVA = (unsigned char *)(relocatedSectionBuffer + symbolRVA + 0x1a - sectionRVA);
			//The actual change is that something which is 0xC3 (ret) on disk is 0x00 in memory
			*holderVA = 0;

			//The RtlPrefetchMemoryNonTemporal Hack
			//80545a04 - nt!RtlPrefetchMemoryNonTemporal (+0x9ee)
			//[ c3:90 ]
			ret = SelectResolvedBinarySymbolRVAByNameAndHostID("@RtlPrefetchMemoryNonTemporal@8", binary->hostID, &symbolRVA);
			if(ret != GENERIC_SUCCESS){
				if(ret == NO_RESULTS_FOUND){
					printf("HallOfHacks: SelectResolvedBinarySymbolRVAByNameAndHostID NO_RESULTS_FOUND, presumably symbol resolution isn't working\n");
				}
				else{
					printf("HallOfHacks: SelectResolvedBinarySymbolRVAByNameAndHostID GENERIC_ERROR\n");
				}
				return ret;
			}
			holderVA = (unsigned char *)(relocatedSectionBuffer + symbolRVA - sectionRVA);
			//The actual change is that something which is 0xC3 (ret) on disk is 0x90 (nop) in memory
			*holderVA = 0x90;
		}//end .text section nt hacks
	}//end nt hacks


	return GENERIC_SUCCESS;
}


