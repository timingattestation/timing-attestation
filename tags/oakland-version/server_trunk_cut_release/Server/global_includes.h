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

//Just like it says, anything which should be included 
//pretty much everywhere should go here

#ifndef GLOBAL_INCLUDES_H
#define GLOBAL_INCLUDES_H

#include <stdio.h>
#include <windows.h>
#include <string.h>

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////

#define INVALID_CONFIG	-3
#define	RET_ARP_FAIL	-2
#define GENERIC_ERROR	-1
#define GENERIC_SUCCESS	0
//The below indicates both that we put a new prerequsite
//into play as well as that there is already one being
//waited on
#define PREREQ_REQUESTED_BUT_NOT_YET_DONE					1
//The below specifically is trying to convey that something has already
//been requested and processed by server (so it is in tiresias.binaries)
//but it has not finished measuring yet
#define PREREQ_MEASURED_BUT_NOT_YET_DONE	2

#define PAGE_SIZE 0x1000

////////////////////////////////////////////////////////
//STRUCTURES
////////////////////////////////////////////////////////


typedef unsigned int		uint32_t;
typedef uint32_t	sha_uint_t;

/* Struct for SHA-256 checksums */
typedef struct
{
        sha_uint_t h0;
        sha_uint_t h1;
        sha_uint_t h2;
        sha_uint_t h3;
        sha_uint_t h4;
        sha_uint_t h5;
        sha_uint_t h6;
        sha_uint_t h7;
} sha_256_t;

//This is a catch all struct for recording timing information about
//measurements as well as queuing them for moving them between threads
typedef struct measurement_event{
	unsigned int id;		//The id field when this is put into the database
	unsigned int type;		//"msgType" of measurement requested
	unsigned int nonce;		//The fresh random value for this measurement request
	unsigned int timeInSeconds;		//Time when the measurement was first requested by the server
	unsigned int timeInMicroseconds;	//Time when the measurement was first requested by the server
	unsigned int meRTTInMicroseconds;	//measurement event amount of time before a reply was seen (Round Trip Time)
	unsigned int netRTTInMicroseconds;	//Average network RTT to the host (measured out of band)
	//The below is so that we can queue packets for the MeasurementParsingThread
	unsigned int ip;		//IP that the measurement was directed at (for lookup of host,
							//and for queueing me_t until the response is seen);
	unsigned int hostID;	//The database entry for the host with the ip_netorder_int == measurement_event.ip
	unsigned int overloadedForeignID; //This is a foreign key to some other table, where the table is determined
									//by this struct's type field.
									//If type == SELF_ATTESTATION or TIMING_TEST?, it references Checksums(id)
	unsigned int previousPendingID;	//Ref PendingMeasurementEvents table
	unsigned char * pktData;//A copy of the full packet, including all headers
	unsigned int pktLen;//The length of the full packet, including all headers
	unsigned int lowerTiming;
	unsigned int upperTiming;
} me_t;

typedef enum{
	CLIENT_ERROR,
	SERVER_ERROR,
	TIRESIAS_ERROR
} errorType;

typedef enum{
	SERVER,
	TIRESIAS,
	SHARED
} databaseType;

#endif