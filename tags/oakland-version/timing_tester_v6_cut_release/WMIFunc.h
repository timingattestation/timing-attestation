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

//Taken from example passthru intermediate driver code and unchanged

//****************************************************************************//
//*                                                                           //
//* Copyright (C) 2003, James Antognini, antognini@mindspring.com.            //
//*                                                                           //
//****************************************************************************//
//http://www.wd-3.com/archive/ExtendingPassthru2.htm
//Companion Sample Code for the Article
//"Extending the Microsoft PassThru NDIS Intermediate Driver"
//
//Portions Copyright ©1992-2000 Microsoft Corporation; used by permission.
//Portions Copyright © 2003 Printing Communications Associates, Inc. (PCAUSA)
//
//The right to use this code in your own derivative works is granted so long as
//
//Your own derivative works include significant modifications of your own.
//You retain the above copyright notices and this paragraph in its entirety within sources derived from this code.
//This product includes software developed by PCAUSA. The name of PCAUSA may not be used to endorse or promote products derived from this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

// High-order byte has to be 0xFF, to indicate custom OID, per DDK ("Filling in an NDIS_GUID Structure").

#define OID_CUSTOM_DRIVER_STATISTICS  0xFFA0C901
//#define OID_CUSTOM_DRIVER_QUERY       0xFFA0C902
#define OID_CUSTOM_ARRAY              0xFFA0C903
//#define OID_CUSTOM_STRING             0xFFA0C904

#ifdef __cplusplus  // C++ conversion
extern "C"
{
#endif

NDIS_STATUS                                                 
PassthruWMIGetAddrArray(                                 
                        PADAPT,                          
                        PULONG,                          
                        PPassthruIPAddrArray             
                       );                                 

NDIS_STATUS                                                 
PassthruWMISetAddrArray(                                
                        PADAPT,                         
                        ULONG,                          
                        PPassthruIPAddrArray            
                       );                                


#ifdef __cplusplus  // C++ conversion
}
#endif
