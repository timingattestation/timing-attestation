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

//This code is the driver for the TPM device.
//Do not change this code unless you REALLY know what you're doing
#include "precomp.h"
#include "misc.h"
#include <ntddk.h>
#include "tpm.h"
#include "server_client_protocol.h"

PVOID gTPMLinearAddress;
SIZE_T gTPMRegisterSize;
int gLocality;
int gTPMEnabled;
int gKeyHandleSet;
unsigned char gKeyHandle[4];

//sets gLocality to the requested locality
//returns the new locality on success, 
//and -1 on error
int TIS_RequestLocality(int l)
{
	Write8(ACCESS_RELINQUISH_LOCALITY, ACCESS(gLocality));
	Write8(ACCESS_REQUEST_USE, ACCESS(l));
	if (Read8(ACCESS(l) & ACCESS_ACTIVE_LOCALITY))
		return gLocality = l;
	return GENERIC_ERROR;
}

//initializes the TPM by relinquishing access to
//all localities then grabbing locality 0. 
//On success sets gLocality to 0 and returns 1
//on Error returns 0
int TIS_Init()
{
	unsigned vendor;
	unsigned int i;

	for (i=0;i<5;i++)
	{
		Write8(ACCESS_RELINQUISH_LOCALITY, ACCESS(i));
	}

	if (TIS_RequestLocality(0) < 0) 
	{
		KdPrint(("TIS_Init: failed to grab locality 0\n"));
		return 0;
	}

	KeStallExecutionProcessor(10);
	vendor = Read32(DID_VID(0));
	DbgPrint("TIS_Init: vendor id: 0x%x\n", vendor);
	
	if ((vendor & 0xFFFF) == 0xFFFF)
	{
		KdPrint(("TIS_Init: invalid vendor id\n"));
		return 0;
	}

	gLocality = 0;

	return 1;
}

//sends len bytes of buf to the TPM data buffer
//returns the number of bytes sent on success
//returns -1 on error 
int TIS_Send(unsigned char *buf, int len)
{
	int status, burstcnt = 0;
	int count = 0;
	unsigned short stat;

	if (TIS_RequestLocality(gLocality) == -1)
	{
		KdPrint(("TIS_Send: couldnt gain locality: %x\n", gLocality));
		return GENERIC_ERROR;
	}

	Write8(STS_COMMAND_READY, STS(gLocality));
	TIS_WaitStatus(STS_COMMAND_READY);
	
	while (count < len - 1)
	{
		burstcnt = Read8(STS(gLocality) + 1);
		burstcnt += Read8(STS(gLocality) + 2) << 8;
		if (burstcnt == 0)
		{
			KeStallExecutionProcessor(10);
		} else {
			for (; burstcnt > 0 && count < len - 1; burstcnt--) 
			{
				Write8(buf[count], DATA_FIFO(gLocality));
				count++;
			}

			for (status = 0; (status & STS_VALID) == 0; )
				status = Read8(STS(gLocality));
			
			if ((status & STS_DATA_EXPECT) == 0)
			{
				KdPrint(("TIS_Send: Overflow\n"));
				return GENERIC_ERROR;
			}
		}
	}

	Write8(buf[count], DATA_FIFO(gLocality));

	for (status = 0; (status & STS_VALID) == 0; )
		status = Read8(STS(gLocality));

	if ((status & STS_DATA_EXPECT) != 0)
	{
		KdPrint(("TIS_Send: last byte didnt stick\n"));
		return GENERIC_ERROR;
	}

	Write8(STS_GO, STS(gLocality));
	return len;
}

//Receive count bytes of data from the TPM data buffer into buf
//returns the number of bytes read 
int TIS_RecvData(unsigned char *buf, int count)
{
	int size = 0, burstcnt = 0, status;
	status = Read8(STS(gLocality));
	while ( ((status & STS_DATA_AVAIL) || (status & STS_VALID)) && size < count)
	{
		if (burstcnt == 0)
		{
			burstcnt = Read8(STS(gLocality) + 1);
			burstcnt += Read8(STS(gLocality) + 2) << 8;
		}
		if (burstcnt == 0)
		{
			KeStallExecutionProcessor(10);
		} else {
			for (; burstcnt > 0 && size < count; burstcnt--) 
			{
				buf[size] = Read8(DATA_FIFO(gLocality));
				size++;
			}
		}
		status = Read8(STS(gLocality));
	}
	return size;
}

//read count bytes into buf from the TPM's data buffer
//returns the number of read bytes on success
//returns <= 0 on error
int TIS_Recv(unsigned char *buf, int count)
{
	int expected, status;
	int size = 0;

	if (count < 6)
		return 0;

	TIS_WaitStatus(STS_DATA_AVAIL);
	status = Read8(STS(gLocality));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) != (STS_DATA_AVAIL | STS_VALID))
		return GENERIC_ERROR;

	if ((size = TIS_RecvData(buf, 6)) < 6)
		return GENERIC_ERROR;

	expected = ntohl(*(unsigned *)(buf + 2));

	if (expected > count)
		return GENERIC_ERROR;

	if ((size += TIS_RecvData(&buf[6], expected - 6 - 1)) < expected - 1)
		return GENERIC_ERROR;

	TIS_WaitStatus(STS_DATA_AVAIL);
	status = Read8(STS(gLocality));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) != (STS_DATA_AVAIL | STS_VALID))
		return GENERIC_ERROR;

	if ((size += TIS_RecvData(&buf[size], 1)) != expected)
		return GENERIC_ERROR;

	status = Read8(STS(gLocality));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) == (STS_DATA_AVAIL | STS_VALID))
		return GENERIC_ERROR;

	Write8(STS_COMMAND_READY, STS(gLocality));

	return expected;
}

//Sends a command blob to the TPM and reads the response 
//back into blob. Note this uses polled I/O style, so if you
//send a command to the TPM that takes a long time, you are going
//to completely stall the CPU while you wait for the response
//returns 1 on success, 0 on error
unsigned int TIS_Transmit(unsigned char *blob)
{
	int len;
	unsigned int size;

	size = ntohl(*(unsigned int *)&blob[2]);
	len = TIS_Send(blob, size);
	if (len < 0)
	{
		KdPrint(("tis_transmit: tis_send returned %d\n", len));
		return 0;
	}

	TIS_WaitStatus(STS_DATA_AVAIL);
	
	len = TIS_Recv(blob, TPMMAX);
	if (len < 0)
	{
		KdPrint(("tis_transmit: tis_recv returned %x\n", len));
		return 0;
	}

	return 1;
}

//waits for the TPM status buffer to meet the required condition
void TIS_WaitStatus(unsigned int condition)
{
	unsigned short status;
	status = Read16(STS(gLocality));
	while (!(status & condition))
	{
		KeStallExecutionProcessor(1);
		status = Read16(STS(gLocality));
	}
}

//returns 0 on failure
//returns unsigned long long representing
//current tick count on the tpm timer
unsigned long long TPM_GetTicks()
{
	unsigned char buffer[2+4+4+32];
	unsigned char count[8];
	unsigned int ret;
	unsigned int i;

	memset(buffer,0x00, 42);
	buffer[1] = 0xC1;
	buffer[5] = 0x0a;
	buffer[9] = 0xf1;

	ret = TIS_Transmit(buffer);
	if (!ret) {
		KdPrint(("TPM_GetTicks: tis_transmit failed\n"));
		return ret;
	}

	count[0] = buffer[19];
	count[1] = buffer[18];
	count[2] = buffer[17];
	count[3] = buffer[16];
	count[4] = buffer[15];
	count[5] = buffer[14];
	count[6] = buffer[13];
	count[7] = buffer[12];

	return *(unsigned long long *)(count);
}

//reads the 20 byte PCR[index] value from the tpm and stores it in 
//*value. value must already be allocated when function is called
//returns 1 on success, 0 on failure
unsigned int TPM_PcrRead(unsigned long index,
                    unsigned char *value)  {						
    unsigned i; 
    unsigned int ret;								
    int size = 6;							
    unsigned long send_buffer[2];
	unsigned char *buffer;
    send_buffer[0] = TPM_ORD_PcrRead;
    send_buffer[1] = index;

    if (value==0) 
	{
		KdPrint(("TPM_PcrRead: null buffer passed in for storage\n"));
		return 0;
	}

	buffer = ExAllocatePool(NonPagedPool, TCG_BUFFER_SIZE);
	if (!buffer)
	{
		KdPrint(("Tpm_PcrRead: ExAllocatePool failed\n"));
		return 0;
	}

	memset(buffer,0x00,TCG_BUFFER_SIZE);

    buffer[0] = 0x00;							
    buffer[1] = 0xc1;							
    size+=sizeof(send_buffer);						
    *(unsigned long *)(buffer+2) = ntohl(size);									
    for (i=0; i<sizeof(send_buffer)/sizeof(*send_buffer); i++)	{
        *((unsigned long *)(buffer+6)+i) = ntohl(send_buffer[i]);		
    } 
    ret = TIS_Transmit(buffer);

	if (ret == 0)	{
		KdPrint(("TPM_PcrRead: TIS_Transmit returned 0\n"));
		ExFreePool(buffer);
        return ret;	
	}

	memcpy(value, &buffer[TCG_DATA_OFFSET], TCG_HASH_SIZE);
    ret = ntohl(*(unsigned long *)(buffer+6));
	ExFreePool(buffer);

	return 1;
}

//in: tickStamp->nonce (antireplay value), tickStamp->digest (digest to sign)
//out: tickStamp->ticks, tickStamp->signature
int TPM_TickStampBlob(tick_stamp_t *tickStamp)
{
	unsigned char commandBlob[54];
	unsigned char *buffer;
	unsigned int ret;
	unsigned int i;

	memset(commandBlob,0x00,54);
	commandBlob[1] = 0xC1;
	commandBlob[5] = 0x36;
	commandBlob[9] = 0xF2;
	
	memset(gKeyHandle,0x00,4);
	if (!TPM_GetKeyHandle(gKeyHandle))
	{
		KdPrint(("TPM_TickStampBlob: TPM_GetKeyHandle failed to find suitable signing key\n"));
		return GENERIC_ERROR;
	}

	memcpy(&commandBlob[10],gKeyHandle,4);
	memcpy(&commandBlob[14],tickStamp->nonce,20);
	memcpy(&commandBlob[34],tickStamp->digest,20);

	buffer = ExAllocatePool(NonPagedPool, TPMMAX);
	if (!buffer)
	{
		KdPrint(("Tpm_TickStampBlob: ExAllocatePool failed\n"));
		return GENERIC_ERROR;
	}

	memset(buffer,0x00,TPMMAX);
	memcpy(buffer,commandBlob,54);
	
	ret = TIS_Transmit(buffer);

	if (!ret)
	{
		KdPrint(("TPM_TickStampBlob: TIS_transmit failed: %d\n", ret));
		ExFreePool(buffer);
		return GENERIC_ERROR;
	}

	memcpy(tickStamp->ticks,&(buffer[10]),32);
	memcpy(tickStamp->signature,&(buffer[10+32+4]),256);
	ExFreePool(buffer);
	return GENERIC_SUCCESS;
}

//in: buffer, a buffer of at least 4 bytes to store the key handle
//out: buffer holds the handle of the first key in the tpm
//returns 1 on success, 0 on failure
unsigned int TPM_GetKeyHandle(unsigned char *buf)
{
	unsigned char *transmitBuffer;
	unsigned int ret;

	transmitBuffer = ExAllocatePool(NonPagedPool,TPMMAX);
	if (!transmitBuffer)
	{
		KdPrint(("TPM_GetKeyHandle: ExAllocatePool returned null\n"));
		return 0;
	}

	memset(transmitBuffer,0x00,TPMMAX);
	transmitBuffer[1] = 0xC1;
	transmitBuffer[5] = 0x12;
	transmitBuffer[9] = 0x65;
	transmitBuffer[13] = 0x07;

	ret = TIS_Transmit(transmitBuffer);
	if (!ret)
	{
		KdPrint(("TPM_GetKeyHandle: TIS_transmit failed: %d\n", ret));
		ExFreePool(transmitBuffer);
		return 0;
	}
	memcpy(buf,&transmitBuffer[16],4);
	ExFreePool(transmitBuffer);

	KdPrint(("TPM_GetKeyHandle: found key: %02x%02x%02x%02x\n", buf[0],buf[1],buf[2],buf[3]));

	//Make sure buf actually contains a key
	if (buf[0]==0x00&&buf[1]==0x00&&buf[2]==0x00&&buf[3]==0x00)
		return 0;
	else
		return 1;
}

//returns 1 on success, 0 on failure
unsigned int TPM_ResetPCR23()
{
	unsigned char *transmitBuffer;
	unsigned int ret;
	transmitBuffer = ExAllocatePool(NonPagedPool,TPMMAX);
	if (!transmitBuffer)
	{
		KdPrint(("TPM_ResetPCR23: ExAllocatePool returned null\n"));
		return 0;
	}
	memset(transmitBuffer,0x00,TPMMAX);

	transmitBuffer[1] = 0xC1;
	transmitBuffer[5] = 0x0F;
	transmitBuffer[9] = 0xC8;
	transmitBuffer[11] = 0x03;
	transmitBuffer[14] = 0x80;

	ret = TIS_Transmit(transmitBuffer);
	if (!ret)
	{
		KdPrint(("TPM_ResetPCR23(): TIS_Transmit failed: %d\n", ret));
		ExFreePool(transmitBuffer);
		return 0;
	}

	ExFreePool(transmitBuffer);
	return 1;
}

//returns 1 on success, 0 on failure
unsigned int TPM_ExtendPCR23(unsigned char *digest)
{
	unsigned char *transmitBuffer;
	unsigned int ret;
	transmitBuffer = ExAllocatePool(NonPagedPool,TPMMAX);
	if (!transmitBuffer)
	{
		KdPrint(("TPM_ExtendPCR23: ExAllocatePool returned null\n"));
		return 0;
	}
	memset(transmitBuffer,0x00,TPMMAX);

	transmitBuffer[1] = 0xC1;
	transmitBuffer[5] = 0x22;
	transmitBuffer[9] = 0x14;
	transmitBuffer[13] = 0x17;
	memcpy(&transmitBuffer[14],digest,20);

	ret = TIS_Transmit(transmitBuffer);
	if (!ret)
	{
		KdPrint(("TPM_ExtendPCR23(): TIS_Transmit failed: %d\n", ret));
		ExFreePool(transmitBuffer);
		return 0;
	}

	ExFreePool(transmitBuffer);
	return 1;
}


//below are utility functions for the TPM Driver
unsigned char Read8(unsigned int offset)
{
	return READ_REGISTER_UCHAR( (PUCHAR) ((unsigned int)gTPMLinearAddress + offset));
}

unsigned short Read16(unsigned int offset)
{
	return READ_REGISTER_USHORT( (PUSHORT) ((unsigned int)gTPMLinearAddress + offset));
}

unsigned long Read32(unsigned int offset)
{
	return READ_REGISTER_ULONG( (PULONG) ((unsigned int)gTPMLinearAddress + offset));
}

void Write8(unsigned char val, unsigned int offset)
{
	WRITE_REGISTER_UCHAR( (PUCHAR) ((unsigned int)gTPMLinearAddress + offset), val);
}

void Write16(unsigned short val, unsigned int offset)
{
	WRITE_REGISTER_USHORT( (PUSHORT) ((unsigned int)gTPMLinearAddress + offset), val);
}

void Write32(unsigned long val, unsigned int offset)
{
	WRITE_REGISTER_ULONG( (PULONG) ((unsigned int)gTPMLinearAddress + offset), val);
}

unsigned long ntohl(unsigned long in) {
    unsigned char *s = (unsigned char *)&in;
    return (unsigned long)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
}

VOID PrintHash(unsigned char *hash)
{
	DbgPrint("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],hash[8],hash[9],hash[10],hash[11],hash[12],hash[13],hash[14],hash[15],hash[16],hash[17],hash[18],hash[19]);
}


