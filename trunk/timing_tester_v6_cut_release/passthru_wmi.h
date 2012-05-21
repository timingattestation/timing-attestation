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

//Taken from example code and unchanged

#ifndef _passthru_wmi_h_
#define _passthru_wmi_h_

// PassthruStatistics - PassthruStatistics
#define PassthruStatisticsGuid \
    { 0x5635de7f,0x44e4,0x4dd6, { 0xb2,0xa8,0x2a,0x2a,0x88,0x8a,0x49,0xb3 } }

DEFINE_GUID(PassthruStatistics_GUID, \
            0x5635de7f,0x44e4,0x4dd6,0xb2,0xa8,0x2a,0x2a,0x88,0x8a,0x49,0xb3);

// PassthruIPAddrArray - PassthruIPAddrArray
#define PassthruIPAddrArrayGuid \
    { 0x5635de81,0x44e4,0x4dd6, { 0xb2,0xa8,0x2a,0x2a,0x88,0x8a,0x49,0xb3 } }

DEFINE_GUID(PassthruIPAddrArray_GUID, \
            0x5635de81,0x44e4,0x4dd6,0xb2,0xa8,0x2a,0x2a,0x88,0x8a,0x49,0xb3);


typedef struct _PassthruIPAddrArray
{
    // 
    ULONG NumberElements;
    #define PassthruIPAddrArray_NumberElements_SIZE sizeof(ULONG)
    #define PassthruIPAddrArray_NumberElements_ID 1

    // 
    ULONG IPAddrArray[1];
    #define PassthruIPAddrArray_IPAddrArray_ID 2

} PassthruIPAddrArray, *PPassthruIPAddrArray;

#endif
