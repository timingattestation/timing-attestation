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

#ifndef _SAFE_MEM_ACCESS_H
#define _SAFE_MEM_ACCESS_H

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////


//Physical Address Extentions
#define PAE_BIT			0x20	//if 1 PAE mode enabled, if 0 not
//Page Size Extentions
#define PSE_BIT			0x10	//if 1 large pages are allowed, if 0 pages must be 4kb

////////////////////////////////////////////////////////
//STRUCTURES
////////////////////////////////////////////////////////


//this structure is likely Windows XP specific 
typedef struct pfn{
	//LSBs
	unsigned int dontCare1[3];
	unsigned short flags;
	unsigned short refCount;
	unsigned int dontCare2[3];
	//MSBs - just cause I tend to forget :)
} pfn_t;


////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

void FindPFNBase();
int CheckPageForSafeAccess(unsigned int startVA);
int CheckVARangeForSafeAccess(unsigned int startVA, unsigned int numPages);


#endif