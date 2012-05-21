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

/**************************************************************************************************/      
/*                                                                                                */      
/* Copyright (C) 2003, James Antognini, antognini@mindspring.com.                                 */
/*                                                                                                */      
/**************************************************************************************************/      
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

#ifdef __cplusplus  // C++ conversion
extern "C"
{
#endif

#include <ndis.h>
#include "passthru.h"
                                                   
#ifdef __cplusplus  // C++ conversion
}
#endif

/**************************************************************************************************/      
/*                                                                                                */      
/**************************************************************************************************/      
extern "C"
NDIS_STATUS                                                        
PassthruWMIGetAddrArray(                                         
                        PADAPT               pAdapt,
                        PULONG               pUlInArr,// Address of size of provided structure.  Will be updated with amount needed or actually used.,                                  
                        PPassthruIPAddrArray pInArr   // Address of provided structure, with number of elements first.                          
                       )
{
 NDIS_STATUS             status = NDIS_STATUS_SUCCESS;
 LOCK_STATE              saveLockState;                                                                                                           
 ULONG                   ulBfrNeeded;                                                                

 NdisAcquireReadWriteLock(                            // Get lock.
                          &pAdapt->IPAddrArrLock,
                          FALSE,                      // Read access.
                          &saveLockState
                         );
                                                                                                                                             
 ulBfrNeeded = pAdapt->pIPAddrArray->ulArrayStr -     // Determine amount of space needed to set answer.
               FIELD_OFFSET(IPAddrFilterArray, IPAddrArray);
                                                                                                                                                          
 if (ulBfrNeeded>*pUlInArr)                           // Is provided structure too small?                                                                                
   status = NDIS_STATUS_BUFFER_TOO_SHORT;                                                                                                                      
 else                                                                                                                                                     
   NdisMoveMemory(pInArr,                             // Copy address array into provided structure.
                  &pAdapt->pIPAddrArray->IPAddrArray,
                  ulBfrNeeded
                 );
                                                                                                                                                          
 *pUlInArr = ulBfrNeeded;                             // Show amount that is needed or that was actually used.                                            

 NdisReleaseReadWriteLock(                            // Release lock.
                          &pAdapt->IPAddrArrLock,
                          &saveLockState
                         );

 return status;
}

/**************************************************************************************************/      
/*                                                                                                */      
/**************************************************************************************************/      
extern "C"
NDIS_STATUS                                                       
PassthruWMISetAddrArray(                                         
                        PADAPT               pAdapt,
                        ULONG                ulElems, // Number of elements.  0 => default.                    
                        PPassthruIPAddrArray pInArr   // Address of provided structure.  NULL if ulElems = 0.                          
                                                      //   Otherwise, ulElems is assumed equal to pInArr->NumberElements, but this is not checked.
                       )                                        
{
 NDIS_STATUS             status;
 ULONG                   ulArrStr;
 LOCK_STATE              saveLockState;                                                                                                           
                                                                                                                                             
 NdisAcquireReadWriteLock(                            // Get lock.
                          &pAdapt->IPAddrArrLock,
                          TRUE,                       // Write access.
                          &saveLockState
                         );
                                                                                                                                             
 do                                                                                                                                          
   {                                                                                                                                         
    if (NULL!=pAdapt->pIPAddrArray)                   // Answer area allocated (this should be true except when the first set is being done)?
      {
       // Note:  A possible optimization is to leave the existing area in place if it is big enough to accommodate the current request.

       ulArrStr = pAdapt->pIPAddrArray->ulArrayStr;   // Get structure's size.
       NdisFreeMemory(                                // Free structure's storage.
                      pAdapt->pIPAddrArray,
                      ulArrStr,
                      0
                     );
	   pAdapt->pIPAddrArray = NULL;					  // so we don't free it again later
      }
       
    ulArrStr =                                        // Get size of fixed portion.
      FIELD_OFFSET(IPAddrFilterArray, IPAddrArray) +
      FIELD_OFFSET(PassthruIPAddrArray, IPAddrArray);  
    ulArrStr += ulElems*sizeof(ULONG);                // Add size of variable portion.
       
    status =                                          // Allocate nonpaged storage for IP-address-array structure.
      NdisAllocateMemoryWithTag((PVOID *)&pAdapt->pIPAddrArray,	
                                ulArrStr,
                                TAG
                               );
       
    if (NDIS_STATUS_SUCCESS!=status)       
      {       
       KdPrint(("PassthruWMISetAddrArray():  Couldn't get storage\n"));                                            
       status = NDIS_STATUS_RESOURCES;       
       goto Done;
       // break;			// unreachable    
      }       

    pAdapt->pIPAddrArray->ulArrayStr = ulArrStr;      // Save structure size.                                                                                                                                             
                                                                                                                                             
    if (0!=ulElems)                                   // Non-zero number of array elements?                                                                                                                                             
      {
       NdisMoveMemory(                                // Copy supplied array.
                      &pAdapt->pIPAddrArray->IPAddrArray,
                      pInArr,
                      FIELD_OFFSET(PassthruIPAddrArray, IPAddrArray) +
                        (pInArr->NumberElements*sizeof(pInArr->IPAddrArray))
                     );

//     ULONG i;
//     for (i = 0; i < pAdapt->pIPAddrArray->IPAddrArray.NumberElements; i ++)
//       {
//        PULONG pI = ((PULONG)&pAdapt->pIPAddrArray->IPAddrArray.IPAddrArray) + i;
//        PUCHAR pC = (PUCHAR)pI;
//        KdPrint(("IP address = %03d.%03d.%03d.%03d\n", *pC, *(pC+1), *(pC+2), *(pC+3)));
//       }
      }
    else                                                                                                                                             
      pAdapt->pIPAddrArray->                          // Set default IP-address array.                                                                                                                                             
                IPAddrArray.NumberElements = 0;
                                                                                                                                             
   } while(0);                                                                                                                               
                                                                                                                                             
Done:                                                                                                                                             
 NdisReleaseReadWriteLock(                            // Release lock.
                          &pAdapt->IPAddrArrLock,
                          &saveLockState
                         );

 return status;
}
