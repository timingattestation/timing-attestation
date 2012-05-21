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

//NOTE: A self measurement packet should never be fragmented.

#include <map>
#include "parse_self_measurement.h"
#include "server_client_protocol.h" //for response_hdr_t
#include "server_tiresias_protocol.h" //for RequestChecksumMeasurementFromTiresias
#include "database_mysql.h"
#include "database_mysql2.h"

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

extern "C" MYSQL mysqlMeasurements;
extern "C" HANDLE mysqlMutex;

extern SOCKET tiresiasConnectSocket;
extern int gVerbose, gQuiet;
extern char gffAlertingEnabled; //used like a bool, but want it to work in C files if necessary
extern HANDLE alertEvent;

//In file_access.cpp
extern unsigned int movingAverageWindowLength;
extern unsigned int selfTestAlertingThreshold;

// In thread_measurement_parsing
extern map<unsigned int, unsigned int> selfTestCountsOutsideWindows;
map<unsigned int, unsigned int>::iterator itr;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//When a timing-test self-checksum packet comes back, this function is responsible
//for doing something useful with it.
//E.g. it should
//1) print out the measurement values
//2) enter the result (including timing information) into the database
//3) query tiresias for what the value should be
//4) make a determination of whether the checksum is correct, and if the
//response was received within the expected amount of time
int
ParseSelfMeasurementTimingTest(me_t * incomingME){
	int ret;
	//TODO: get rid of buffer and dataSize. The function definition was refactored
	//and it was just faster to move them from the definition to the body
	unsigned char * buffer = incomingME->pktData;
	unsigned int dataSize = incomingME->pktLen;
	response_hdr_t * responseHdr = (response_hdr_t *)buffer;
	buffer += sizeof(response_hdr_t);
	self_check_t * selfCheck = (self_check_t *)buffer;
	bool nullSelfMeasurement = false;
	int previousPendingID = 0;

	unsigned int LCL = 0;
	unsigned int UCL = 0;

	unsigned int matchingNullSelfTestEvent = 0;
	unsigned int netRTTFromNullSelfTest = 0;

	printf("timing test measurement received\n");
	printf("upperCycleCount:lowerCycleCount = %u:%u \n", selfCheck->upperCycleCount, selfCheck->lowerCycleCount);
	printf("checksum[0] = 0x%08x\n", selfCheck->checksum[0]);
	printf("checksum[1] = 0x%08x\n", selfCheck->checksum[1]);
	printf("checksum[2] = 0x%08x\n", selfCheck->checksum[2]);
	printf("checksum[3] = 0x%08x\n", selfCheck->checksum[3]);
	printf("checksum[4] = 0x%08x\n", selfCheck->checksum[4]);
	printf("checksum[5] = 0x%08x\n", selfCheck->checksum[5]);
	//Look up the hostID for the given IP address
	ret = SelectHostIDByNetorderIP(incomingME->ip, &(incomingME->hostID));
	if(ret != GENERIC_SUCCESS){
		printf("ParseSelfMeasurement: SelectHostIDByNetorderIP failed\n");
		return GENERIC_ERROR;
	}

	//Lookup the pending measurement event, retrieve the values
	//(necessary to calculate when it left vs. when it came back)
	me_t pendingME;
	ret = SelectPendingMEByIncomingME(incomingME, &pendingME);
	if(ret != GENERIC_SUCCESS){
		printf("ParseSelfMeasurement: SelectPendingMEByIncomingME failed\n");
		return GENERIC_ERROR;
	}
	//This updates the fields that came back from the RDTSC self-computed runtime
	ret = UpdateTiminginPendingMeasurements(&pendingME, selfCheck->lowerCycleCount, selfCheck->upperCycleCount);
	if(ret != GENERIC_SUCCESS){
		printf("ParseSelfMeasurement: UpdateTiminginPendingMeasurements failed\n");
		return GENERIC_ERROR;
	}

	ret = MovePendingMeasurementToFinalMeasurements(incomingME, &pendingME, true);
	if(ret != GENERIC_SUCCESS){
		printf("ParseSelfMeasurement: MovePendingMeasurementToFinalMeasurements failed\n");
		return GENERIC_ERROR;
	}

	// finally delete the accompanying null self measurement event
	ret = DeleteFromTableByID("PendingMeasurementEvents", pendingME.id);
	if(ret != GENERIC_SUCCESS){
		printf("ParseSelfMeasurement: DeleteFromTableByID PendingMeasurementEvents failed\n");
		return GENERIC_ERROR;
	}

	//Ask tiresias what the correct checksum should be
	ret = RequestChecksumMeasurementFromTiresias(tiresiasConnectSocket, incomingME->hostID, selfCheck, TIMING_TEST);
	if(ret != GENERIC_SUCCESS){
		printf("ParseSelfMeasurement: RequestChecksumMeasurementFromTiresias failed\n");
		return GENERIC_ERROR;
	}

	// s00p3r s1mpl3 (i.e. dumbed down for public release) check timing against limits
	char hostIP[16];
	SelectHostIPByID(incomingME->hostID,hostIP);
	SelectLimitsByHost(hostIP, &LCL, &UCL);
	if(incomingME->meRTTInMicroseconds < LCL || incomingME->meRTTInMicroseconds > UCL){
		printf("Alert!  Timing fail! \nLower: %u Upper: %u\nmeRTT = %u\n",LCL,UCL,incomingME->meRTTInMicroseconds);
	}else{
		printf("Within limits: \nLower: %u Upper: %u\nmeRtt = %u\n",LCL,UCL,incomingME->meRTTInMicroseconds);
	}

	return GENERIC_SUCCESS;
}