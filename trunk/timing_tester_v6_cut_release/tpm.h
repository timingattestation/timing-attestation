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

#ifndef _TPM_H
#define _TPM_H

#include "server_client_protocol.h"

//TSS Specification Defines
#define TPM_ORD_PcrRead 0x15

#define TCG_HASH_SIZE					20
#define TCG_DATA_OFFSET					10
#define TCG_BUFFER_SIZE					((TCG_DATA_OFFSET+4+TCG_HASH_SIZE))
#define TCG_TICK_SIZE					32
#define TCG_SIGNATURE_SIZE				256
#define TPMMAX							4096

#define ACCESS(l)		(0x0000 | ((l) << 12))
#define STS(l)			(0x0018 | ((l) << 12))
#define DATA_FIFO(l)	(0x0024 | ((l) << 12))
#define DID_VID(l)		(0x0F00 | ((l) << 12))

#define ACCESS_ACTIVE_LOCALITY		0x20
#define ACCESS_RELINQUISH_LOCALITY	0x20
#define ACCESS_REQUEST_USE			0x02

#define STS_VALID			0x80
#define STS_COMMAND_READY	0x40
#define STS_DATA_AVAIL		0x10
#define STS_DATA_EXPECT		0x08
#define STS_GO				0x20

//tis functions
int TIS_Init(void);
int TIS_RequestLocality(int l);
int TIS_RecvData(unsigned char *buf, int count);
int TIS_Recv(unsigned char *buf, int count);
int TIS_Send(unsigned char *buf, int len);
unsigned int TIS_Transmit(unsigned char *blob);
void TIS_WaitStatus(unsigned int condition);

//utility functions
VOID PrintHash(unsigned char *hash);
unsigned char Read8(unsigned int offset);
unsigned short Read16(unsigned int offset);
unsigned long Read32(unsigned int offset);
void Write8(unsigned char val, unsigned int offset);
void Write16(unsigned short val, unsigned int offset);
void Write32(unsigned long val, unsigned int offset);
unsigned long ntohl(unsigned long in);

//TPM Command functions
unsigned long long TPM_GetTicks();
unsigned int TPM_PcrRead(unsigned long index, unsigned char *value);
int TPM_TickStampBlob(tick_stamp_t *tickStamp);
unsigned int TPM_GetKeyHandle(unsigned char *buf);
unsigned int TPM_ResetPCR23();
unsigned int TPM_ExtendPCR23(unsigned char *hash);

//globals
extern PVOID gTPMLinearAddress;
extern SIZE_T gTPMRegisterSize;
extern int gLocality;
extern int gTPMEnabled;

#endif