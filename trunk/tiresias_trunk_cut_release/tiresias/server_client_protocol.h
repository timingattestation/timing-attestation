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

#ifndef _SERVER_CLIENT_PROTOCOL_H
#define _SERVER_CLIENT_PROTOCOL_H

#include "sha.h"

////////////////////////////////////////////////////////
//STRUCTURES & MACROS
////////////////////////////////////////////////////////
//KEEP ALL STRUCTURES/MACROS IN THIS FILE IN SYNC
//BETWEEN THE SERVER AND CLIENT
////////////////////////////////////////////////////////

//BEGIN BINARY MEASUREMENT DATA TYPES
#define MAX_SECT_NAME_CHAR_LEN 9
#define MAX_BIN_NAME_LEN	30
typedef struct bin_data{
	//Truncated for security against malformed packets
	wchar_t bNameW[MAX_BIN_NAME_LEN];

	//Virtual address where the code is based in memory
	//Needed to generate a relocated version offline for comparison
	unsigned int baseVA;

	//_IMAGE_NT_HEADER._IMAGE_FILE_HEADER.TimeDateStamp
	//This is set when the file is linked. Using it as a unique ID until I find counter-examples
	unsigned int timeDateStamp;	

	//The total size of the module address space as given in the PE headers (i.e. not including
	//dynamically allocated space). This is the RVA just past the last used byte
	unsigned int sizeOfImage;

	//Number of sections which are read-only, and thus appropriate for hashing
	//Note: a packet may not have this many in it, which signals that the data is fragmented
	unsigned int numROSections; //Should be no larger than MAX_SECTS_TO_MEASURE

} bin_data_t;

//END BINARY MEASUREMENT DATA TYPES

#endif