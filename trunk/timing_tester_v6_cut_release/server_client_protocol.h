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

#ifndef _SERVER_CLIENT_PROTOCOL_H
#define _SERVER_CLIENT_PROTOCOL_H

#include "sha.h"
#include "pe.h"

////////////////////////////////////////////////////////
//STRUCTURES & MACROS
////////////////////////////////////////////////////////
//KEEP ALL STRUCTURES/MACROS IN THIS FILE IN SYNC
//BETWEEN THE SERVER AND CLIENT
////////////////////////////////////////////////////////

//KEEP THIS ENUM IN SYNC BETWEEN SERVER/CLIENT/TIRESIAS!
//NOTE: if you update msgType don't forget to update MsgTypeToString
typedef enum{
	SELF_ATTESTATION,
	ERROR_MSG,
	TIMING_TEST,
	TICKSTAMP_ATTESTATION,
	TOGGLE_ATTACK,
} msgType;

//BEGIN BINARY MEASUREMENT DATA TYPES
//Sent Client->Server
//8 is size of the not-guaranteed-to-be-null-terminated section name in the PE format
#define MAX_SECT_NAME_CHAR_LEN	(IMAGE_SIZEOF_SHORT_NAME + 1)	// Must be at least one more than sizeof((PIMAGE_SECTION_HEADER*)0->Name) 
typedef struct sect_data{
	//Section name can be 8 chars, and is non guaranteed to be null  
	//terminated, so I add the extra char to guarantee it
	char sName[MAX_SECT_NAME_CHAR_LEN];		

	//The relative virtual address where the section is based
	unsigned int RVA;

	//number of bytes in the section, either SizeOfRawData or 
	//misc.VirtualSize as appropriate
	unsigned int SizeOfHashedData;	

	//total number of hashes there should be for all this section data
	//if != numHashes, then the data was fragmented
	unsigned int totalNumHashes;

	//Number of hashes of size PAGE_SIZE or below which cover the entire section
	unsigned int numHashes;

	//the hashes contained in the packet start at this index in hashes[numHashes]
	//if != 0, then this data is a fragment
	unsigned short startIndex;

	//Array of sha256_t's. Actual size in packet is hashes[numHashes]
	sha_256_t * hashes;	
} sect_data_t;

//Sent Client->Server
#define MAX_BIN_NAME_WCHAR_LEN	17
typedef struct bin_data{
	//Truncated for security against malformed packets
	wchar_t bNameW[MAX_BIN_NAME_WCHAR_LEN];							

	//Virtual address where the code is based in memory
	//Needed to generate a relocated version offline for comparison
	unsigned int baseVA;

	//_IMAGE_NT_HEADER._IMAGE_FILE_HEADER.TimeDateStamp
	//This is set when the file is linked. Using it as a unique ID until I find counter-examples
	unsigned int timeDateStamp;	

	//Number of sections which are read-only, and thus appropriate for hashing
	//Note: a packet may not have this many in it, which signals that the data is fragmented
	unsigned int numROSections; //Should be no larger than MAX_SECTS_TO_MEASURE

	//Actual size in packet is sections[numROSects]
	sect_data_t * sections;
} bin_data_t;

//END BINARY MEASUREMENT DATA TYPES
//BEGIN SELF MEASUREMENT DATA TYPES
//Sent Client->Server
#define SELF_CHECKSUM_SIZE 6
#define MAX_MSG_SIZE_IP_UDP_SELFCHECKSUM (sizeof(EthHdr) + sizeof(IPHdr) + sizeof(UDPHeader) + sizeof(response_hdr_t) + sizeof(self_check_t))
typedef struct tick_stamp {
	unsigned char ticks[32];
	unsigned char digest[20];
	unsigned char nonce[20];
	unsigned char signature[256];
} tick_stamp_t;

typedef struct base_and_version{
	char * base;	//Where this module is currently based in memory
	unsigned int timeDateStamp; //first half of version info
	unsigned int sizeOfImage;	//second half of version info
} base_and_version_t;

typedef struct api_module_info{
	base_and_version_t ndisInfo;
	base_and_version_t halInfo;
	base_and_version_t ntInfo;
	base_and_version_t bootvidInfo;
	base_and_version_t kdcomInfo;
}api_module_info_t;

typedef struct self_check{
	//Random number used to seed PRNG for self-checksum
	unsigned int nonce;

	//_IMAGE_NT_HEADER._IMAGE_FILE_HEADER.TimeDateStamp
	//This is set when the file is linked. Using it as a unique ID until I find counter-examples
	//NOTE: this is the timeDateStamp of our own driver
	unsigned int timeDateStamp;	

	//Virtual address where the code is based in memory
	//Needed to generate a relocated version offline for comparison
	unsigned int baseVA;

	//Each piece of the self-attestation checksum will be stored here
	unsigned int checksum[SELF_CHECKSUM_SIZE];

	//I changed this to go below checksum for now, so that we 
	//are backwards compatible with older version like client rev 1220

	//This is so that timing tests can self-report the number
	//of cycles (according to rdtsc) it took to run a given 
	//instance of the self-check function
	unsigned int upperCycleCount;
	unsigned int lowerCycleCount;

	tick_stamp_t startTickStamp;
	tick_stamp_t endTickStamp;

	//This holds the information about where modules that we call into
	//e.g. ndis, are located in memory
	api_module_info_t moduleInfo;

} self_check_t;

//END SELF MEASUREMENT DATA TYPES
//BEGIN GENERAL MEASUREMENT DATA TYPES

//Sent Client->Server
typedef struct response_hdr{
	unsigned int rand;	//Random number
	unsigned int fragmentNumber;//This indicates the order in which fragments are set out
	unsigned int pendingID; //client should just echo back the value in the request_hdr
							//it received
	msgType type;		//one of the above
	unsigned short numElements;	//Number of whatever structs contained in this message
} response_hdr_t;

//Sent Server->Client
typedef struct request_hdr{
	unsigned int rand;	//Random number
	unsigned int pendingID; //Unique number for this measurement request
							//references the PendingMeasurementEvents table
	msgType type;		//one of the above
	char wcharArraySize;  //Size (as number of wchar_ts) of wcharArray, *including null*
	wchar_t * wcharArray; //Array of wchar_ts which specifies the 
} request_hdr_t;


#define MAX_SSDT_ENTRIES 300
#define NUM_SSDT_MODULES 4

typedef enum{
	NTOSKRNL = 0,
	NDIS,
	HAL,
	UNKNOWN
} SSDTRef;

typedef struct ssdt_full_data{
	//number of entries
	unsigned int n;

	//stores the individual entries
	unsigned int ssdt[MAX_SSDT_ENTRIES];
	
	//base addresses of the modules the ssdt references
	unsigned long module_start_addresses[NUM_SSDT_MODULES];

	//end addresses of the modules the ssdt references
	unsigned long module_end_addresses[NUM_SSDT_MODULES];
} ssdt_full_data_t;

// IDT measurement protocol

#pragma pack(1)

// the data returned by the sidt instruction
typedef struct idtInfo
{
	WORD IDTLimit;		// the length of the table in bytes - 1 (actually the index of the last byte)
	WORD LowIDTbase;	// low 16 bits of IDT table pointer
	WORD HiIDTbase;		// high 16 bits of IDT table pointer
} idtInfo_t;

typedef struct idtEntry
{
  WORD LowOffset;
  WORD selector;
  BYTE unused_lo;
  unsigned char unused_hi:5;
  unsigned char DPL:2;
  unsigned char P:1;
  WORD HiOffset;
} idtEntry_t;

typedef struct idtHashResp
{
	WORD		cpuId;
	sha_256_t	hash;
	idtInfo_t	idtInfo;
} idtHashResp_t;

typedef struct idtFullResp
{
	WORD		cpuId;
	WORD		total;
	WORD		first;
	WORD		count;
	idtEntry_t	enteries[];
} idtFullResp_t;
#pragma pack()

typedef struct pcr_data{
	unsigned char pcrs[24][20];
} pcr_data_t;

//END GENERAL MEASUREMENT DATA TYPES
////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////
NTSTATUS SendPacket(PADAPT pAdapt, unsigned char * pktBuffer, unsigned int len, unsigned short fragOffsetAndFlags);
void SendErrorPacket(PADAPT pAdapt, char * errMsg, unsigned int errMsgLenWithNull, unsigned int randFromServer, unsigned int pendingIDFromServer);

#endif
