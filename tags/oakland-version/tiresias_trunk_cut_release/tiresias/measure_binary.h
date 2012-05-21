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

#ifndef MEASURE_BINARY_H
#define MEASURE_BINARY_H

#include <windows.h>
#include <winnt.h>
#include "server_tiresias_protocol.h"
#include <vector>

using namespace std;

////////////////////////////////////////////////////////
//STRUCTS
////////////////////////////////////////////////////////

typedef struct _export{
	unsigned int rva;
	char name[52];
	unsigned int ordinal;
} export_t;

////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

int HallOfHacks(char * fullFileName, st_msg_t * binary, char * sectionName, unsigned int sectionRVA, char * relocatedSectionBuffer, unsigned int sectionSize, unsigned int alignmentOffset);
#endif