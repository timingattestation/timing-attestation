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

//These are just misc defines and globals
//the globals can probably be moved elsewhere, 
//the #defines have nowhere better to go
#ifndef _MISC_H
#define _MISC_H

#pragma data_seg(".data")

#define DWORD unsigned long
#define WORD unsigned short
#define BOOL unsigned long
#define BYTE unsigned char

#define TRUE	1
#define FALSE	0

#define NT_FAILURE			-5
#define HAL_FAILURE			-4
#define NDIS_FAILURE		-3
#define STACK_VERIFY_FAIL	-2
#define GENERIC_ERROR		-1
#define GENERIC_SUCCESS		0

#define MAKELONG(a, b) ((LONG) (((WORD) (a)) | ((DWORD) ((WORD) (b))) << 16))
#else
#warning MISC skipped because it's already been included
#endif

//The below had to be moved here due to some code reorganization for public release
//They are found in UtilRtns.c
unsigned int FindSelfTimeDateStamp(unsigned int myBaseVA);
int FindTextSectionStartAndEnd(wchar_t * name, unsigned char * baseVA, unsigned int * start, unsigned int * end, unsigned int * timeDateStamp, unsigned int * sizeOfImage);
int getHalpRealModeStartAndEnd(unsigned int baseVA, unsigned int timeDateStamp, unsigned int sizeOfImage, unsigned int *halpRealModeStart, unsigned int *halpRealModeEnd); 
unsigned char * SearchForDriver(PDRIVER_OBJECT theDriverObject, wchar_t * searchedDriverName);
void EnableWP();
void DisableWP();
