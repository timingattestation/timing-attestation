/*
	This software is the copyrighted work of MITRE.  No ownership or other proprietary interest in this 
	software is granted to you other than what is granted in this license.     
	 
	MITRE IS PROVIDING THE SOFTWARE "AS IS" AND ACCORDINGLY MAKES NO WARRANTY, EXPRESS OR IMPLIED, AS 
	TO THE ACCURACY, CAPABILITY, EFFICIENCY, MERCHANTABILITY, OR FUNCTIONING  OF THE SOFTWARE AND DOCUMENTATION.  
	IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL, CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR SPECIAL 
	DAMAGES RELATED TO THE SOFTWARE, EVEN IF MITRE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.             
	 
	You accept this software on the condition that you indemnify and hold harmless MITRE, its Board of Trustees, 
	officers,  agents, and employees, from any and all liability damages to third parties, including attorneys' 
	fees, court costs, and other related costs and expenses, arising out of your use of this software irrespective 
	of the cause of said liability.
	
	MIT License:
	Copyright (c) 2013 The MITRE Corporation

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

/*
	You must invoke this code from within SMRAM. We had to remove all Manufacturer-specific offsets and such, so there
	are some blanks which you must fill in yourself (#define's).  But other than that, this code is complete.
*/


//define this if you are trying to compile for SMM mode
#define PHYSICAL_MODE
#define EXPERIMENTAL_MODE			1	// captures additonal RDTSC measurements

#include "bios_chronomancy.h"
#include "linear_measurement_ranges.h"

#define ACCESS(l)					(0x0000 | ((l) << 12))
#define STS(l)						(0x0018 | ((l) << 12))
#define DATA_FIFO(l)				(0x0024 | ((l) << 12))
#define DID_VID(l)					(0x0F00 | ((l) << 12))

#define TPMMAX 1024

#define ACCESS_ACTIVE_LOCALITY		0x20
#define ACCESS_RELINQUISH_LOCALITY	0x20
#define ACCESS_REQUEST_USE			0x02

#define STS_VALID					0x80
#define STS_COMMAND_READY			0x40
#define STS_DATA_AVAIL				0x10
#define STS_DATA_EXPECT				0x08
#define STS_GO						0x20

#define LOCALITY					0
#define NUM_ITERATIONS				2500000			// number of iterations for SelfCheck_v6_bios()

// The following 3 values are specific/proprietary to the manufacturer so we cannot share these addresses
#define OUR_BASE_ADDR				0xDEADBEEF		// *** YOU DEFINE *** Base Address in SMRAM where this binary will be located (defined by you when you paste this executable into the SMRAM binary)
#define SMM_DATA_STORE				0xDEADBEEF		// *** YOU DEFINE *** This is where BC code will store the measurement data
#define KERN_DATA_STORE				0xDEADBEEF		// *** YOU DEFINE *** BC code will move the data to this address, accessible by the kernel
#define DATA_STORE_SIZE				0x340
#define IVT_BASE					0x00000000		// IVT is located at 0000:0000h in RAM

// data storage will have the following structure:
// unsigned int NumBytes_of_Data
// <DATA BYTES>
// to read/write it the chain will be walked

//structures
//nonce and digest into TPM_TickStampBlob
//ticks and signature out of TPM_TickStampBlob
typedef struct tick_stamp{
	unsigned char ticks[32];
	unsigned char digest[20];
	unsigned char nonce[20];
	unsigned char signature[256];
} tick_stamp_t;

//selfcheck related functions
#if EXPERIMENTAL_MODE == 1
int SelfCheck_v6_bios(unsigned int nonce,
					  unsigned int numIterations,
					  unsigned int measurementSlices[NUM_SLICES][2],
					  unsigned int * upperCycleCount,
					  unsigned int * lowerCycleCount,
					  unsigned int * outputChecksum,
						unsigned int * linearSweepTickStamps);	// additional RDTSC measurements
#else
int SelfCheck_v6_bios(unsigned int nonce,
					  unsigned int numIterations,
					  unsigned int measurementSlices[NUM_SLICES][2],
					  unsigned int * upperCycleCount,
					  unsigned int * lowerCycleCount,
					  unsigned int * outputChecksum);
#endif

//specific tpm functions i've implemented
unsigned long long TPM_GetTicks();
unsigned int TPM_GetTSN(unsigned char *tsn);
unsigned int TPM_WriteNVSpace(unsigned int nvindex, unsigned char *data, unsigned int datalen);
unsigned int TPM_ReadNVSpace(unsigned int nvindex, unsigned char *data, unsigned int datalen);
unsigned int TPM_LoadKey(unsigned char *key, unsigned int keylen, unsigned char *keyhandle);

//tpm driver functions
unsigned int TIS_Transmit(unsigned char *blob);
int TIS_Send(unsigned char *buf, int len);
void TIS_WaitStatus(unsigned int condition);
int TIS_Recv(unsigned char *buf, int count);
int TIS_Send(unsigned char *buf, int len);
int TIS_RecvData(unsigned char *buf, int count);
int TIS_RequestLocality(int l);

//standard libc type functions i've reimplemented to eliminate dependencies
unsigned long ntohl(unsigned long in);
unsigned short ntohs(unsigned short in);
void clearbuf(unsigned char *buf, unsigned int n);
void memcopy(unsigned char *dst, unsigned char *src, unsigned int n);

//basic primitives for read/writing to memory. 
unsigned char Read8(unsigned int offset);
unsigned short Read16(unsigned int offset);
unsigned int Read32(unsigned int offset);
void Write8(unsigned char val, unsigned int offset);
void Write16(unsigned short val, unsigned int offset);
void Write32(unsigned int val, unsigned int offset);

// functions related to storing the timing data to memory for later access
void InitStorage(unsigned int, unsigned int);
void StoreData(unsigned char *, unsigned int);		// called when AL == 0xAF
void CopyStoredData();								// called when AL == 0xAE

//use this as the entry point into the code
void BiosEntryPoint()
{
//VARS_START:										// for easier insertion into SMRAM
	unsigned int upperCycleCount;
	unsigned int lowerCycleCount;
	
#if EXPERIMENTAL_MODE == 1
	unsigned int linearSweepTickStamps[4];	// 16 
	// for rdtsc, experiment version only:
	unsigned int rdtsc_start_out[2];// 8
	unsigned int rdtsc_start_in[2];	// 8
	unsigned int rdtsc_end_in[2];	// 8
	unsigned int rdtsc_end_out[2];	// 8
#endif

	unsigned int checksum[6];
	unsigned int keylen;
	unsigned char tsn[20];
	unsigned char keyhandle[4];
	unsigned char keydata[1024];

	tick_stamp_t startStamp;
	tick_stamp_t endStamp;				// local vars size == 0x6d8 up to and including this line

	unsigned int measurementSlices[NUM_SLICES][2];	// actual linear slices defined in SelfCheck_v6()
//VARS_END

	// our header, this simplifies the patching into SMI Handler, NOP out all up to here in binary
	__asm {
		pushad;
		mov eax, 0xdffffffc;		// backup orig SMI Handler ESP, massaging these pushes and pops is too much of a PITA
		mov [eax], esp;
		
		mov ebp, 0xdfffff00;		
		mov esp, ebp;
		sub esp, 0x1000;			// just overestimate for simplicity, we wipe it anyway at the end
	};

		//test for john's magic value
#ifdef PHYSICAL_MODE
// checks whether the signal to take TPM measurements has been received
	__asm {
		in al, 0xB2;
		cmp al, 0xAE;				// nothing special about this value, just unused value chosen at random
		jnz COPY_TO_KERN_DSTORE;
	};
#endif 

	// Initialize Storage Location.  Set to all 0xFF's.  Must run before any measurements taken.
	InitStorage(SMM_DATA_STORE, DATA_STORE_SIZE);
	InitStorage(IVT_BASE, IVT_LEN);

	//Load signing key into the TPM. We are assuming the signing key is stored at NV space 0xA (arbitrarily chosen)
	//So before this works you have to make sure to define that NV space using TPM utilities and define NV space
	//0xA to be large enough (>800 bytes approx) and then write the key there.
	clearbuf(keyhandle, 4);
	clearbuf(keydata, 1024);
	keylen = 0;

	//why bother doing error handling since we cant recover from errors in bios anyhow!
	//note that 559 is just the fixed length of a TPM signing key
	TPM_ReadNVSpace(0xa, keydata, 559);

	//if successfuly, keyhandle will be a 32bit unique ID for the signing key that allows
	//us to identify it in command blobs
	TPM_LoadKey(keydata, 559, keyhandle);

	//get the tick session nonce from the tpm, which should act as a TPM generated nonce value
	//to protect us from precomputation attacks. Note that right now this TSN value is changing
	//every time we read it, which it should not. So we will not be able to verify that the TSN
	//is legit... but hopefully on another TPM chip, this will work..
	clearbuf(tsn, 20);
	TPM_GetTSN(tsn);

	//tsn should not be known apriori by attacker so precomputation should be infeasible...
	memcopy(startStamp.nonce, tsn, 20);
	memcopy(startStamp.digest, tsn, 20);
	
#if EXPERIMENTAL_MODE == 1
	// crude rdtsc timer, to roughly correlate TPM timer measurements
	__asm {
		cpuid;
		rdtsc;
		bswap eax;
		bswap edx;
		mov [rdtsc_start_out], edx;
		mov [rdtsc_start_out + 4], eax;
	};
#endif
	
	//ill go ahead and keep the starticks in here for extra info, but its not really needed
	//since the ticks will be encoded by the tickstamp
	TPM_TickStampBlob(&startStamp, keyhandle);
	
#if EXPERIMENTAL_MODE == 1
	// crude rdtsc timer, to roughly correlate TPM timer measurements
	__asm {
		cpuid;
		rdtsc;
		bswap eax;
		bswap edx;
		mov [rdtsc_start_in], edx;
		mov [rdtsc_start_in + 4], eax;
	};
#endif

	//the nonce passed to the selfcheck should be derived from the start tickstamp. This assures
	//that the start tickstamp was calulcated BEFORE the selfchecksum began
	//SelfCheck_v6_bios(*(unsigned int *)&startStamp.signature[0], NUM_ITERATIONS, firmware_start, firmware_end, &upperCycleCount, &lowerCycleCount, checksum);
#if EXPERIMENTAL_MODE == 1
	SelfCheck_v6_bios(*(unsigned int *)&startStamp.signature[0], NUM_ITERATIONS, measurementSlices, &upperCycleCount, &lowerCycleCount, checksum, linearSweepTickStamps);
#else
	SelfCheck_v6_bios(*(unsigned int *)&startStamp.signature[0], NUM_ITERATIONS, measurementSlices, &upperCycleCount, &lowerCycleCount, checksum);
#endif
	//use the signature from the first tickstamp as the nonce to the second tickstamp
	//this assures that the start tickstamp is calculated before the end tickstamp
	memcopy(endStamp.nonce,startStamp.signature,20);

	//use the first 20 bytes of the checksum as the bytes to sign. This assures that the endstamp is 
	//calculated after the checksum is complete.
	memcopy(endStamp.digest, (unsigned char *)(&checksum[0]), 20);

#if EXPERIMENTAL_MODE == 1
	// crude rdtsc timer, to roughly correlate TPM timer measurements
	__asm {
		cpuid;
		rdtsc;
		bswap eax;
		bswap edx;
		mov [rdtsc_end_in], edx;
		mov [rdtsc_end_in + 4], eax;
	};
#endif

	TPM_TickStampBlob(&endStamp, keyhandle);

#if EXPERIMENTAL_MODE == 1
	// crude rdtsc timer, to roughly correlate TPM timer measurements
	__asm {
		cpuid;
		rdtsc;
		bswap eax;
		bswap edx;
		mov [rdtsc_end_out], edx;
		mov [rdtsc_end_out + 4], eax;
	};
#endif

	// I'm not crazy about the way we call this, but we care only about the starting address in memory
	// of the data (we copy it byte by byte to its destination).  Data must (and will be) be contiguous.
	// This works but throws a compiler warning (and rightfully so!)
	// I can make a wrapper function to handle the int array more cleanly.  :/  (things to do which shall likely not be done...)
	StoreData((unsigned char *)checksum, 24);		
	
	StoreData(startStamp.ticks, 32);
	StoreData(startStamp.digest, 20);
	StoreData(startStamp.nonce, 20);
	StoreData(startStamp.signature, 256);

	StoreData(endStamp.ticks, 32);
	StoreData(endStamp.digest, 20);
	StoreData(endStamp.nonce, 20);
	StoreData(endStamp.signature, 256);
	
#if EXPERIMENTAL_MODE == 1
	// for experiment version only - store rdtsc timer
	StoreData((unsigned char *)rdtsc_start_out, 8);		// start at 0xA02CC
	StoreData((unsigned char *)rdtsc_end_out, 8);
	StoreData((unsigned char *)rdtsc_start_in, 8);		
	StoreData((unsigned char *)rdtsc_end_in, 8);
	StoreData((unsigned char *)linearSweepTickStamps, 16);
#endif
	
	// wipe our stack frame (again, overestimate usage)
	//InitStorage(0xe0000000 - 0x2000, 0x2000);
	
	goto RETURN_TO_BIOS;
	
#ifdef PHYSICAL_MODE
// checks whether the signal to copy the TPM measurements to the kernel's data store has been received
COPY_TO_KERN_DSTORE:
	__asm {
		in al, 0xb2;
	  cmp al, 0xaf;
	  jnz CLEAR_KERN_DSTORE;
	};
	InitStorage(KERN_DATA_STORE, DATA_STORE_SIZE);
	CopyStoredData();
	
CLEAR_KERN_DSTORE:
	__asm {
		in al, 0xb2;
	  cmp al, 0xad;
	  jnz RETURN_TO_BIOS;
	};
	InitStorage(KERN_DATA_STORE, DATA_STORE_SIZE);
	
RETURN_TO_BIOS:
	__asm {
		mov eax, 0xdffffffc;		// restore orig. SMI Handler ESP
		mov esp, [eax];
		//mov [eax], 0xffffffff;	// wipe the modification
		
		popad;						
		mov edi, RET_CTRL_FLOW;		// this is the address of the funciton you hooked to call this code
		call edi;	
	};
#endif
}

// initializes a memory range with 0xFF's
// must run before any measurements are taken to not corrupt timing
// must be run (period) because read and copy rely heavily on this area
// being formatted properly.
void InitStorage(unsigned int base, unsigned int numBytes) {
	numBytes /= 4;
	__asm {
		push eax;
		push edi;
		push ecx;
		
		// writing dwords minimizes the # of IO cycles to memory
		mov eax, 0xffffffff;
		mov ecx, numBytes;	
		mov edi, base;
		rep stosd;
		
		pop ecx;
		pop edi;
		pop eax;
	};
}

// copies the data from SMM storage (0xA0000) to 0x90000 where the kernel may access it.
// this funciton is called when the kernel outputs 0xAF to port 0xB2.
// the data in SMM storage will be initialized and written-to during the bios boot process so there will
// never be sensitive SMM data copied to 0x90000.  
void CopyStoredData() {
	__asm {
		push ecx;
		mov esi, SMM_DATA_STORE;
		mov edi, KERN_DATA_STORE;
		
		// walk the data chain until 0xFFFFFFFF is found, then start writing the data.
COPY_NEXT_FIELD:
		mov ecx, [esi];			// the first DWORD is the number of bytes to copy
		cmp ecx, 0xffffffff;// marks the end of the stored TPM data
		jz END_OF_DATA;
		mov [edi], ecx;
		add edi, 4;					// the length of the data
		add esi, 4;
		rep movsb;
		jmp COPY_NEXT_FIELD;
		
END_OF_DATA:
		//mov [edi], dword ptr 0xFFFFFFFF;		
		mov al, 0xff;	// work around
		mov ecx, 4;
		rep stosb;
		pop ecx;
	};
}

// inputs:
// source - location of the start of data to be written
// numBytes - length in bytes of data to write
// reads dword starting at DATA_DEST_ADDR, if it is not equal to 0xFFFFFFFF, then that means
// data is already written there.  cycles to the next available structure location.
// If 0xFFFFFFFF is found, then space is available so it writes the data structure there.
// The data structure: (very simple)
// DWORD dataBytes		// so we can "walk" from structure to structure
// CHAR  data (n-bytes)
void StoreData(unsigned char *source, unsigned int numBytes)
{
	__asm {
	
		mov esi, [source];
		mov edi, SMM_DATA_STORE;
		mov ecx, numBytes;
		
		// walk the data chain until 0xFFFFFFFF is found, then start writing the data.
WALK_DATA_CHAIN:
		mov eax, [edi];
		cmp eax, 0xffffffff;
		jz WRITE_DATA;
		add edi, eax;			// cycle to next data structure
		add edi, 4;				// +4 for first dword in structure
		jmp WALK_DATA_CHAIN;
		
WRITE_DATA:
		mov [edi], ecx;		// first DWORD in chain is the # bytes indicating size of data
		add edi, 4;
		rep movsb;				// now write the actual data bytes to storage location
		mov [edi], 0xffffffff;		// ensure bytes following are 0xFFFFFFFF
	};
}

//in: tickStamp->nonce (antireplay value), tickStamp->digest (digest to sign)
//out: tickStamp->ticks, tickStamp->signature
//returns 1 on success, 0 on failure
int TPM_TickStampBlob(tick_stamp_t *tickStamp, unsigned char *keyHandle)
{
	unsigned char buffer[1024];
	unsigned int ret;
	unsigned int i;

	clearbuf(buffer,1024);
	buffer[1] = 0xC1;
	buffer[5] = 0x36;
	buffer[9] = 0xF2;

	memcopy(&buffer[10],keyHandle,4);
	memcopy(&buffer[14],tickStamp->nonce,20);
	memcopy(&buffer[34],tickStamp->digest,20);
	
	ret = TIS_Transmit(buffer);
	if (!ret)
	{
		return 0;
	}

	memcopy(tickStamp->ticks,&(buffer[10]), 32);							// HERE!!!!
	memcopy(tickStamp->signature,&(buffer[10+32+4]), 256);
	return 1;
}

unsigned int TPM_LoadKey(unsigned char *key, unsigned int keylen, unsigned char *keyhandle)
{
	unsigned char transmitBuffer[1024];
	unsigned int ret;
	unsigned int i;

	clearbuf(transmitBuffer,1024);

	transmitBuffer[1] = 0xC1;
	transmitBuffer[4] = 0x02; //size of blob should be fixed 
	transmitBuffer[5] = 0x3d;
	transmitBuffer[9] = 0x41;
	transmitBuffer[10] = 0x40;

	memcopy(&transmitBuffer[14],key,keylen);
				
	ret = TIS_Transmit(transmitBuffer);
	if (!ret)
	{
		return 0;
	}
	
	memcopy(keyhandle,&transmitBuffer[10],4);

	return 1;
}

//in: nvindex (must be defined before hand), data, datalen
//returns 1 on success, 0 on failure
unsigned int TPM_WriteNVSpace(unsigned int nvindex, unsigned char *data, unsigned int datalen)
{
	unsigned char transmitBuffer[1024];
	unsigned int ret;
	unsigned int i;

	if (22+datalen>=1024)
		return 0;
	
	clearbuf(transmitBuffer,1024);
	transmitBuffer[1] = 0xC1;
	*(unsigned int *)&transmitBuffer[2] = ntohl(22+datalen);
	*(unsigned int *)&transmitBuffer[9] = ntohl(0xcd);
	*(unsigned int *)&transmitBuffer[10] = ntohl(nvindex);
	*(unsigned int *)&transmitBuffer[18] = ntohl(datalen);
	
	memcopy(&transmitBuffer[22],data,datalen);

	ret = TIS_Transmit(transmitBuffer);
	if (!ret)
	{
		return 0;
	}

	return 1;
}

//in: nvindex (must be defined before hand), datalen
//out: data which contains datalen bytes from nv space nvindex
//returns 1 on success, 0 on failure
unsigned int TPM_ReadNVSpace(unsigned int nvindex, unsigned char *data, unsigned int datalen)
{
	unsigned char transmitBuffer[1024];
	unsigned int ret;
	unsigned int i;
	
	clearbuf(transmitBuffer,1024);
	transmitBuffer[1] = 0xC1;
	*(unsigned int *)&transmitBuffer[2] = ntohl(0x16); //size of blob
	*(unsigned int *)&transmitBuffer[6] = ntohl(0xcf); //read nv space ordinal
	*(unsigned int *)&transmitBuffer[10] = ntohl(nvindex);
	*(unsigned int *)&transmitBuffer[18] = ntohl(datalen);

	ret = TIS_Transmit(transmitBuffer);
	if (!ret)
	{
		return 0;
	}

	memcopy(data,&transmitBuffer[14],datalen);
   
	return 1;
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

	//memset(buffer,0x00, 42);
	for (i=0;i<42;i++)
		buffer[i] = 0x00;

	buffer[1] = 0xC1;
	buffer[5] = 0x0a;
	buffer[9] = 0xf1;

	ret = TIS_Transmit(buffer);
	if (!ret) {
		//error
		return 0;
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

//returns 0 on failure
//returns 1 on success at the TSN in the tsn buf
unsigned int TPM_GetTSN(unsigned char *tsn)
{
	unsigned char buffer[2+4+4+32];
	unsigned char count[8];
	unsigned int ret;
	unsigned int i;

	//memset(buffer,0x00, 42);
	for (i=0;i<42;i++)
		buffer[i] = 0x00;

	buffer[1] = 0xC1;
	buffer[5] = 0x0a;
	buffer[9] = 0xf1;

	ret = TIS_Transmit(buffer);
	if (!ret) {
		//error
		return 0;
	}

	memcpy(tsn,&buffer[22],20);
	return 1;
}


unsigned int TIS_Transmit(unsigned char *blob)
{
	int len;
	unsigned int size;

	size = ntohl(*(unsigned int *)&blob[2]);
	len = TIS_Send(blob, size);
	if (len < 0)
	{
		return 0;
	}

	TIS_WaitStatus(STS_DATA_AVAIL);
	
	len = TIS_Recv(blob, TPMMAX);
	if (len < 0)
	{
		return 0;
	}

	return 1;
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
	status = Read8(STS(LOCALITY));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) != (STS_DATA_AVAIL | STS_VALID))
		return -1;

	if ((size = TIS_RecvData(buf, 6)) < 6)
		return -1;

	expected = ntohl(*(unsigned *)(buf + 2));

	if (expected > count)
		return -1;

	if ((size += TIS_RecvData(&buf[6], expected - 6 - 1)) < expected - 1)
		return -1;

	TIS_WaitStatus(STS_DATA_AVAIL);
	status = Read8(STS(LOCALITY));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) != (STS_DATA_AVAIL | STS_VALID))
		return -1;

	if ((size += TIS_RecvData(&buf[size], 1)) != expected)
		return -1;

	status = Read8(STS(LOCALITY));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) == (STS_DATA_AVAIL | STS_VALID))
		return -1;

	Write8(STS_COMMAND_READY, STS(LOCALITY));

	return expected;
}

//Receive count bytes of data from the TPM data buffer into buf
//returns the number of bytes read 
int TIS_RecvData(unsigned char *buf, int count)
{
	int size = 0, burstcnt = 0, status;
	status = Read8(STS(LOCALITY));
	while ( ((status & STS_DATA_AVAIL) || (status & STS_VALID)) && size < count)
	{
		if (burstcnt == 0)
		{
			burstcnt = Read8(STS(LOCALITY) + 1);
			burstcnt += Read8(STS(LOCALITY) + 2) << 8;
		}
		if (burstcnt != 0) {
			for (; burstcnt > 0 && size < count; burstcnt--) 
			{
				buf[size] = Read8(DATA_FIFO(LOCALITY));
				size++;
			}
		}
		status = Read8(STS(LOCALITY));
	}
	return size;
}

//sends len bytes of buf to the TPM data buffer
//returns the number of bytes sent on success
//returns -1 on error 
int TIS_Send(unsigned char *buf, int len)
{
	int status, burstcnt = 0;
	int count = 0;
	unsigned short stat;

	if (TIS_RequestLocality(LOCALITY) == -1)
	{
		return -1;
	}
	
	// to-do: try inserting a call to cpuid to serialize the instrucitons up to this point.
	// it *may* be conrtibuting factor to the odd variance that we are seeing.  Assuming this
	// variance makes any sort of difference.

	Write8(STS_COMMAND_READY, STS(LOCALITY));
	TIS_WaitStatus(STS_COMMAND_READY);
	
	while (count < len - 1)
	{
		burstcnt = Read8(STS(LOCALITY) + 1);
		burstcnt += Read8(STS(LOCALITY) + 2) << 8;
		
		if (burstcnt != 0)
		{
			for (; burstcnt > 0 && count < len - 1; burstcnt--) 
			{
				Write8(buf[count], DATA_FIFO(LOCALITY));
				count++;
			}

			for (status = 0; (status & STS_VALID) == 0; )
				status = Read8(STS(LOCALITY));
			
			if ((status & STS_DATA_EXPECT) == 0)
			{
				return -1;
			}
		}

	}

	Write8(buf[count], DATA_FIFO(LOCALITY));

	for (status = 0; (status & STS_VALID) == 0; )
		status = Read8(STS(LOCALITY));

	if ((status & STS_DATA_EXPECT) != 0)
	{
		return -1;
	}

	Write8(STS_GO, STS(LOCALITY));
	return len;
}

//waits for the TPM status buffer to meet the required condition
void TIS_WaitStatus(unsigned int condition)
{
	unsigned short status;
	status = Read16(STS(LOCALITY));
	while (!(status & condition))
	{
		//bios notes: how do we sleep in bios?
		//KeStallExecutionProcessor(1);
		status = Read16(STS(LOCALITY));
	}
}

//returns the new locality on success, 
//and -1 on error
int TIS_RequestLocality(int l)
{
	Write8(ACCESS_RELINQUISH_LOCALITY, ACCESS(LOCALITY));
	Write8(ACCESS_REQUEST_USE, ACCESS(l));
	if (Read8(ACCESS(l) & ACCESS_ACTIVE_LOCALITY))
		return 0;
	return -1;
}

//below are utility functions for the TPM Driver
//bios notes: 0xfed40000 is a physical address, dont know if we need
//to be doing anything special to access it
#ifdef PHYSICAL_MODE
unsigned char Read8(unsigned int offset)
{
	return *((unsigned char *)((unsigned int)0xfed40000 + offset));
}

unsigned short Read16(unsigned int offset)
{
	return *((unsigned short *)((unsigned int)0xfed40000 + offset));
}

unsigned int Read32(unsigned int offset)
{
	return *((unsigned int *)((unsigned int)0xfed40000 + offset));
}

void Write8(unsigned char val, unsigned int offset)
{
	*((unsigned char *)((unsigned int)0xfed40000 + offset)) = val;
}

void Write16(unsigned short val, unsigned int offset)
{
	*((unsigned short *)((unsigned int)0xfed40000 + offset)) = val;
}

void Write32(unsigned int val, unsigned int offset)
{
	*((unsigned int *)((unsigned int)0xfed40000 + offset)) = val;
}
#endif

unsigned long ntohl(unsigned long in)
{
    unsigned char *s = (unsigned char *)&in;
    return (unsigned long)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
}

unsigned short ntohs(unsigned short in)
{
	unsigned char *s = (unsigned char *)&in;
	return (unsigned short)(s[0] << 8 | s[1]);
}

void clearbuf(unsigned char *buf, unsigned int n)
{
	unsigned int i;
	for (i=0;i<n;i++)
		buf[i] = 0x00;
}

void memcopy(unsigned char *dst, unsigned char *src, unsigned int n)
{
	unsigned int i;
	for (i=0;i<n;i++)
		dst[i] = src[i];
}

//v6_bios changes:
//removed debug register incorporating code
//removed return address incorporating code
#if EXPERIMENTAL_MODE == 1
int SelfCheck_v6_bios(unsigned int nonce,
					  unsigned int numIterations,
					  unsigned int measurementSlices[NUM_SLICES][2],
					  unsigned int * upperCycleCount,
					  unsigned int * lowerCycleCount,
					  unsigned int * outputChecksum,
						unsigned int * linearSweepTickStamps)
#else
int SelfCheck_v6_bios(unsigned int nonce,
					  unsigned int numIterations,
					  unsigned int measurementSlices[NUM_SLICES][2],
					  unsigned int * upperCycleCount,
					  unsigned int * lowerCycleCount,
					  unsigned int * outputChecksum)
#endif
{
	unsigned int beforeUpperTime, beforeLowerTime;	//Used to store the halves of the timestamp counter
	unsigned int afterUpperTime, afterLowerTime;	//Used to store the halves of the timestamp counter
	unsigned int upperDiff, lowerDiff;	//Used to store the halves of the timestamp counter
	unsigned int selfCheckStart;
	unsigned int selfCheckEnd;
	unsigned char * codeStart, * codeEnd;
	unsigned int memRange; //codeEnd - codeStart, for use in keeping memory reads in bounds
	unsigned int blockZeroAddress;
	unsigned int i;
	unsigned int slice;		
	unsigned int startedLinearMeasurement = 0;
	int ret;
	unsigned int blockAddressTable[NUM_BLOCKS];

selfCheckV6Start:
	/*INITIALIZATION*/
	slice = 0;
	
	/* 	this is where we define the linear ranges that we'll measure after the self-measurement 
		check has taken place.  Our actual slices are proprietary to the manufacturer so we had to undefine them, but
		we left some lame samples just to provide an idea of how to use them. 
		
		*Note: 
		the start (left value) address must be 4-byte aligned
		the end (right value) address must end on a (4-byte-aligned - 1) address, whatever that would be called
	*/
#if BIOS_REV == 29	// these slice definitions must be measured 
	measurementSlices[0][0] = BIOS_START;		measurementSlices[0][1] = BIOS_END;
	measurementSlices[1][0] = 0x00000000;		measurementSlices[1][1] = 0x00001FFB;	// random address end to show "alignment"
	measurementSlices[2][0] = 0x000A0000;		measurementSlices[2][1] = 0x000CFFFF;	// really no limit to the size of the slices you define
#elif BIOS_REV == 30
	measurementSlices[0][0] = BIOS_START;		measurementSlices[0][1] = BIOS_END;
	measurementSlices[1][0] = 0x000A0000;		measurementSlices[1][1] = 0x000CFFFF;
#elif BIOS_REV == 31
	measurementSlices[0][0] = BIOS_START;		measurementSlices[0][1] = BIOS_END;
	measurementSlices[1][0] = 0x000A0000;		measurementSlices[1][1] = 0x000CFFFF;
#elif BIOS_REV == 32
	measurementSlices[0][0] = BIOS_START;		measurementSlices[0][1] = BIOS_END;
	measurementSlices[1][0] = 0x000A0000;		measurementSlices[1][1] = 0x000CFFFF;
#endif

	__asm {
		lea edi, selfCheckV6Start; 
		add edi, OUR_BASE_ADDR;
		mov selfCheckStart, edi;
		lea edi, selfCheckV6End; 
		add edi, OUR_BASE_ADDR;
		mov selfCheckEnd, edi;
	}
	
	codeStart = (unsigned char *)selfCheckStart;
	codeEnd = (unsigned char *)selfCheckEnd;
	__asm{
		//Want to get the address of blockZero into a variable
		lea edi, blockZero;		// blockZero is text (code) address declared below
		add edi, OUR_BASE_ADDR;
		mov blockZeroAddress, edi;
	}

	for (i=0;i<NUM_BLOCKS;i++)
	{
		blockAddressTable[i] = blockZeroAddress + (i*BLOCK_SIZE);
	}

	//The memory range should cover all of SelfCheck_v6_3, the prolog (this code), blocks, and epilog
	memRange = (unsigned int)codeEnd - (unsigned int)codeStart;

	//Serializing instruction
	__asm{xor eax,eax};
	__asm{cpuid};
	//Optional - Just for doing a total time determination
	__asm{rdtsc};
	__asm{mov beforeUpperTime, edx};
	__asm{mov beforeLowerTime, eax};

	//REGISTER CONVENTIONS FOR THE BELOW CODE:
	//---long lived registers---
	//ecx = occasionally accumulates values read and holds EIP_DST right before inter-block transitions
	//ebx = address of base of checksum array
	//edi = data pointer, points at self memory to read and check
	//esi = x for PRNG
	//esp = checksum[1] for a memory layout of checksum[0],gap,[1],[2],[3],[4],[5]
	//---scratch registers---
	//eax = scratch register, occasionally accumulates values read
	//edx = scratch register, general purpose

	__asm{
		//initializations for long-lived register values
		mov edi, codeStart;			//Data Pointer
		mov ebx, numIterations;		//Number of times to loop
		mov esi, nonce;				//Pseudo Random Number (PRN)
		mov ecx, blockZeroAddress;	//The new code wants ecx to hold the EIP_DST
		sub esp, 0x14;					//memory is like checksum[0],gap,[1],[2],[3],[4],[5] so +8 to get to checksum[1]
		//now esp points at checksum[1]
		mov dword ptr [esp-8], 0xdeadbeef;
		mov dword ptr [esp-4], 0;
		mov dword ptr [esp], 0xcafebabe;
		mov dword ptr [esp+4], 0xf005ba11;
		mov dword ptr [esp+8], 0xca55e77e;
		mov dword ptr [esp+0xC], 0xf01dab1e;
		mov dword ptr [esp+0x10], 0xb01dface;
	};

//BLOCKS AND SUBBLOCKS
//Each block will be divided into multiple sub-blocks. These are:
//1) PRN Update
//2) Memory Read
//3) State Read
//4) Checksum Update
//5) Inter-block Jump
//NOTE! There can be multiple instances of 1-4 in a given block, and only one instance of 5

blockZero:
	//////////////////////////////////
	//UPDATE PRN SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx. UPDATES: esi(PRN), ecx(accumulator)
	SUBBLOCK_UPDATE_PRN_WITH_XOR_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN

	//////////////////////////////////
	//MEMORY READING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx, UPDATES:edi(DP), ecx(accumulator)
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D(codeStart, memRange);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP

	//Extra subblocks to pad out size to have all blocks be the same size but
	//still have room to remove these to make space for the minichecksums
	SUBBLOCK_UPDATE_PRN_WITH_ADD_PRN;
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN
	SUBBLOCK_READ_AND_UPDATE_DP_WITH_XOR_DP_ADD_D(codeStart, memRange);
	//ecx = EIP_DST + EIP_SRC XOR PRN + DP XOR *DP + PRN XOR DP + *DP

	//////////////////////////////////
	//CHECKSUM MIXING SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: eax, edx UPDATES:checksum[numIterations%5]
	SUBBLOCK_CHECKSUM_UPDATE;

	//////////////////////////////////
	//JUMP SUB BLOCK
	//////////////////////////////////
	//CLOBBERS: ecx, eax.
	SUBBLOCK_INTERBLOCK_TRANSFER_VAR0(blockAddressTable);
blockOne:
	COMPLETE_V6_BLOCK_VAR1(codeStart, memRange, blockAddressTable);
	COMPLETE_V6_BLOCK_VAR2(codeStart, memRange, blockAddressTable);
	COMPLETE_V6_BLOCK_VAR3(codeStart, memRange, blockAddressTable);
	COMPLETE_V6_BLOCK_VAR4(codeStart, memRange, blockAddressTable);
blockNminus2:
	COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR1(codeStart, memRange, blockAddressTable);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so that
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect to see 64 byte cache lines, but am using 32 for backwards compat)
miniFrag1:
	//This is like SUBBLOCK_READ_AND_UPDATE_DP_WITH_ADD_DP_XOR_D without random order traversal
	__asm add ecx, edi;		//ecx = PRN + DP
	__asm xor ecx, [edi];	//ecx = PRN + DP XOR [DP]
	__asm add edi, 4;		//Move the data pointer forward in memory

	__asm and eax, 3;
	__asm xor [esp + eax*4], ecx;
	__asm sub eax, 1;

	__asm bt dword ptr [esp+0x10], 1;

	__asm jmp miniFrag2;
	__asm nop;
	__asm nop;
	__asm nop;
blockNminus1:
	COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR2(codeStart, memRange, blockAddressTable);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so that
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect to see 64 byte cache lines, but am using 32 for backwards compat)
miniFrag2:
	//This is the first part of SUBBLOCK_CHECKSUM_UPDATE
	__asm rcr dword ptr [esp-0x08], 1;
	__asm rcr dword ptr [esp], 1;
	__asm rcr dword ptr [esp+0x04], 1;
	__asm rcr dword ptr [esp+0x08], 1;
	__asm rcr dword ptr [esp+0x0C], 1;
	__asm rcr dword ptr [esp+0x10], 1;
	__asm jmp miniFrag3;
	__asm nop;
	__asm nop;
blockN:
	COMPLETE_V6_BLOCK_WITH_SPACE_FOR_MINICHECKSUM_VAR3(codeStart, memRange, blockAddressTable);
//MINICHECKSUM FRAGMENT (each fragment should be less than 32 bytes so thatto
//it's less than one cache line (ASSUMPTION: cache lines <= 32 bytes...in practice
//I only expect 64 byte cache lines, but am using 32 for backwards compat)'
miniFrag3:
	__asm cmp edi, esi;		//Check to see if we've covered all of memory yet
	__asm jb miniFrag1;		//Exit the loop if done (jump above = unsigned)

#if EXPERIMENTAL_MODE == 1
	// take an rdtsc tickstamp to mark end of self measure, the rest will be the minifrag linear sweeps
	__asm {
		// don't clobber the linear sweep Start TickStamp...
		cmp startedLinearMeasurement, 1;
		je setRange;
		
		cpuid;
		rdtsc;
		bswap eax;
		bswap edx;
		mov ebx, linearSweepTickStamps;
		mov [ebx], edx;
		mov [ebx + 4], eax;
		mov startedLinearMeasurement, 1;
	};
#endif

	/* 
		Self-Check complete, now we measure the linear slices
		loops thru and measures each slice defined in measurementSlices[][] 2-D array
	*/
setRange:
	// jwb: this is a tad ugly but it works and it avoids the use of the for-loop which in VC++
	// seems to clobber everything of value in the inline assembly...
	__asm {
		mov ebx, slice;
		mov ecx, NUM_SLICES;		
		cmp ebx, ecx;
		jge selfCheckFunctionEnd;

		mov ecx, dword ptr [esp-8];	//initialize ecx to the checksum[0], which is the most-likely-smashed 
									//value (if attacker uses interrupts etc)
									//only have to do this when there's a function call before this asm block
			
		mov ebx, slice;				// cycle through each measurement slice -- JWB
		shl ebx, 3;
		add ebx, measurementSlices;
		mov edi, [ebx];
		mov esi, [ebx+4];			// edi, esi now have their measurement range
		inc slice;
				
		sub esi, 4;					//we don't want the last byte read to ever be outside of the range, otherwise it can cause 
									//the inability for tiresias to reconstruct
		jmp miniFrag1; 
	};			

//This label is used as the boundary of the self-check function checking itself
selfCheckFunctionEnd:
#if EXPERIMENTAL_MODE == 1
// take another rdtsc tickstamp to mark end of linear sweeps
	__asm {
		cpuid;
		rdtsc;
		bswap eax;
		bswap edx;
		mov ebx, linearSweepTickStamps;
		mov [ebx + 8], edx;
		mov [ebx + 12], eax;
	};	
#endif

	//Set the checksum values to send back
	__asm {
		mov eax, outputChecksum;
		mov ebx, [esp-8];
		mov [eax], ebx;
		//check out my wicked sweet memory to memory move ;)
		pop dword ptr [eax+4];
		pop dword ptr [eax+8];
		pop dword ptr [eax+0xC];
		pop dword ptr [eax+0x10];
		pop dword ptr [eax+0x14];
		//At this point esp should hopefully be pointing at the caller-save registers
	}

	//Serializing instruction
	__asm{xor eax,eax};
	__asm{cpuid};
	__asm{rdtsc};
	__asm{mov afterUpperTime, edx};
	__asm{mov afterLowerTime, eax};
	*upperCycleCount = afterUpperTime - beforeUpperTime;
	*lowerCycleCount = afterLowerTime - beforeLowerTime;

selfCheckV6End:
	return 0; //success
}
