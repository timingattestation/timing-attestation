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

#include "global_includes.h"

////////////////////////////////////////////////////////
//STRUCTURES & MACROS
////////////////////////////////////////////////////////
//KEEP ALL STRUCTURES/MACROS IN THIS FILE IN SYNC
//BETWEEN THE SERVER AND CLIENT
////////////////////////////////////////////////////////

//KEEP THIS ENUM IN SYNC BETWEEN SERVER/CLIENT/TIRESIAS!
typedef enum{
	SELF_ATTESTATION,
	ERROR_MSG,
	TIMING_TEST,
	TICKSTAMP_ATTESTATION,
	TOGGLE_ATTACK,
} msgType;
//NOTE: if you update msgType don't forget to update MsgTypeToString

//Sent Client->Server
#define MAX_BIN_NAME_LEN	30
#define MAX_BIN_NAME_WCHAR_LEN	30

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

typedef struct module_data{
	wchar_t bNameW[MAX_BIN_NAME_LEN];
	unsigned int baseVA;
	unsigned int sizeOfImage;
	unsigned int timeDateStamp;
} module_data_t;

typedef struct loaded_module_data{
	unsigned int module_count;
	module_data_t *modules;
} loaded_module_data_t;

//END GENERAL MEASUREMENT DATA TYPES

//PROTOTYPES
char * MsgTypeToString(msgType m);

#endif