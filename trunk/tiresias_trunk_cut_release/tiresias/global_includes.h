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

//Just like it says, anything which should be included 
//pretty much everywhere should go here

#ifndef GLOBAL_INCLUDES_H
#define GLOBAL_INCLUDES_H

#include <stdio.h>

#define INVALID_CONFIG		-4
#define TOO_MANY_RESULTS_FOUND	-3
#define NO_RESULTS_FOUND	-2
#define GENERIC_ERROR		-1
#define GENERIC_SUCCESS		0
//The below indicates both that we put a new prerequsite
//into play as well as that there is already one being
//waited on
#define PREREQ_REQUESTED_BUT_NOT_YET_DONE					1
//The below specifically is trying to convey that something has already
//been requested and processed by server (so it is in tiresias.binaries)
//but it has not finished measuring yet
#define PREREQ_MEASURED_BUT_NOT_YET_DONE	2

#define PAGE_SIZE 0x1000
//PA stands for Page Align
#define PA_DOWN_SHORT(a)	((unsigned short)(a) & ~PAGE_SIZE)
#define PA_DOWN_INT(a)		((unsigned int)(a) & 0xFFFFF000)
#define PA_UP_SHORT(a)		(((unsigned short)(a) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE-1))
#define PA_UP_INT(a)		(((unsigned int)(a) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE-1))
//these are broken
//#define PA_UP_INT(a)		(PA_DOWN_INT(a) + PAGE_SIZE)
//#define PA_UP_SHORT(a)		(PA_DOWN_SHORT(a) + PAGE_SIZE)

typedef enum{
	SERVER,
	TIRESIAS,
	SHARED
} databaseType;

#endif