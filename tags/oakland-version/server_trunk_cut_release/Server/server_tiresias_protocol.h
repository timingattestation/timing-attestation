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

//This is for communications between server and tiresias
//Formerly parts of socket.h

#ifndef _SERVER_TIRESIAS_PROTOCOL_H
#define _SERVER_TIRESIAS_PROTOCOL_H

#include "global_includes.h"
#include "server_client_protocol.h"
#include <vector>
#include <map>
#include <string>
#include <queue>

extern "C" {
	#include "database_mysql.h"
}

using namespace std;

#include "thread_pcap.h"
///#include "WinSock2.h"
using namespace std;

/////////////////////////////////////////////////////////////
// STRUCTURES
/////////////////////////////////////////////////////////////

//KEEP THIS STRUCT IN SYNC BETWEEN SERVER/TIRESIAS
//Server-Tiresias message. Obviously based on bin_data_t
#define SELF_CHECKSUM_SIZE 6
#define MAX_BIN_NAME_LEN	30
typedef struct st_msg{
	//Truncated for security against malformed packets
	wchar_t bNameW[MAX_BIN_NAME_LEN];
	char bNameA[MAX_BIN_NAME_LEN];

	//Determines what type of information is being requested
	msgType type;

	//"Real" virtual address where the code is based in memory
	//Needed to generate a relocated version offline for comparison
	unsigned int baseVA;

	//The total size of the module address space as given in the PE headers (i.e. not including
	//dynamically allocated space). This is the RVA just past the last used byte
	unsigned int sizeOfImage;

	////These are the locations of where the self-checksum start and end,
	////relative to the baseVA
	//unsigned int relativeChecksumStart;
	//unsigned int relativeChecksumEnd;

	////The location of the ending address for the minichecksum
	////relative to the baseVA
	//unsigned int relativeMinicheckEnd;

	////This is the location of the first code block
	////relative to the baseVA
	//unsigned int relativeBlockZero;

	//_IMAGE_NT_HEADER._IMAGE_FILE_HEADER.TimeDateStamp
	//This is set when the file is linked. Using it as a unique ID until I find counter-examples
	unsigned int timeDateStamp;	

	//This is actually going to be reset by tiresias to whatever the correct number is. So it's
	//just here to be an easy storage location for the variable so it can follow the rest around
	//as needed
	unsigned int numROSections;

	//Random number used to seed PRNG for self-checksum
	unsigned int nonce; 

	//Each piece of the self-attestation checksum will be stored here
	unsigned int checksum[SELF_CHECKSUM_SIZE];

	//Used to communicate to the server whether tiresias received this structure and whether
	//it completed processing it or an error occurred
	unsigned int sequenceNum;

	//I prefer to add this field to make the struct more complicated rather than make 
	//storage structures more complicated
	//Not currently used by the tiresias side
	unsigned int miscFlags;

	//We insert the hostID when the message is sent, so that when it comes back, we can make
	//sure that FindNewestMatchingBinaryMeasurementEvent() can be given the notion of which
	//host this binary measurement event applies to (since there are race conditions otherwise
	//if we don't include hostID in the SQL used in that function.)
	unsigned int hostID;

	//This holds the information about where modules that we call into
	//e.g. ndis, are located in memory
	api_module_info_t moduleInfo;

	//In order to verify the new inclusion of the return addresses
	//we need to be able to tell tiresias what type of measurement
	//this self-check came back in response to; because there will
	//be a different offset which tiresias should assume based
	//on a different location in FilterPacket() on the client where
	//SendSelfMeasurementsPackets() was called from
	msgType inResponseToType;

} st_msg_t;

//KEEP THIS LIST IN SYNC BETWEEN SERVER/TIRESIAS
/////////////////////////////////////////////////////////////
// MACROS
/////////////////////////////////////////////////////////////
//The general error message types which can be sent
//in the error response (we don't currently use success)
#define ST_GENERIC_SUCCESS			0
#define ST_ERR_GENERIC_ERROR		1
#define ST_ERR_CANT_FIND_FILE		2

//The status of requests from tiresias to server for 
//prerequisites. When a request is sent it's set to
//pending, and when server has fielded the request
//it marks it as done. It's tiresias's job to then
//remove the request from the DB.
#define PREREQ_STATUS_NEW			0
#define PREREQ_STATUS_SENT			1
#define PREREQ_STATUS_DONE			2
#define PREREQ_STATUS_FAILED		-1

//MISC FLAGS
#define FLAGS_ACKED		0x00000001
#define FLAGS_DONE		0x00000002
#define FLAGS_ERROR		0x00000004
#define FLAGS_PREREQ	0x00000008

////////////////////////////////////////////////////////
//CLASSES
////////////////////////////////////////////////////////

//TODO: need to make a mutex which guards access
typedef map<unsigned int, st_msg_t *> stm_map_t;
typedef vector <sha_256_t> sha_vect_t;

////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////
int SetupConnectionSocket();
int RequestChecksumMeasurementFromTiresias(SOCKET s, unsigned int hostID, self_check_t * selfCheck, msgType inResponseToType);
DWORD WINAPI TiresiasResponseListenerThread(LPVOID lpParam);
int SendSTMsg(SOCKET acceptedSocket, st_msg_t * stm);
int SelfCheckToSTMsg(self_check_t * s, st_msg_t * m);
int STMsgToSelfCheck(st_msg_t * m, self_check_t * s);
#endif