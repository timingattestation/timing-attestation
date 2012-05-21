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

#include "thread_measurement_parsing.h"
  
#include "parse_self_measurement.h"
#include "parse_error_msg.h"
#include "parse_tpm_measurement.h"
#include "database_mysql.h"
#include "main.h"

#include <map>


////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////
//MAKE SURE THIS DOESN'T DIFFER FROM OTHER INSTANCES
//I.e. search for other NOTE_SIZE macros when changing
#define NOTE_SIZE 100



////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
extern "C" MYSQL mysqlMeasurements;
extern "C" HANDLE mysqlMutex;



//The pcap thread just queues up the relevant information so that
//it can pass it off to the measurement
queue<me_t *> measurementEventQueue;

//For the pcap thread to wake the measurement parsing thread
HANDLE measurementEvent;

//To prevent the pcap and measurement parsing thread from stomping on the queue
HANDLE measurementEventQueueMutex;

// To hold the count of self test times outside of the moving average window per host
map<unsigned int, unsigned int> selfTestCountsOutsideWindows;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//If measurementEvent is signaled, it means the pcap component has queued
//a me_t that this code should dequeue and execute the appropriate parsing
//code for.
DWORD WINAPI MeasurementParsingThread(LPVOID lpParam){
	me_t * tmpME;
	unsigned int ret;


	//This creates the event in a set state, so that it's like
	//the event has been signaled
	measurementEvent = CreateEvent(NULL, true, false, NULL);
	if(measurementEvent == NULL){
		printf("MeasurementParsingThread: CreateEvent failed\n");
		CentralExit(GENERIC_ERROR);
	}

	measurementEventQueueMutex = CreateMutex(NULL, FALSE, NULL);
	if(measurementEventQueueMutex == NULL){
		printf("InitializeDatabaseConnection CreateMutex for measurementEventQueueMutex failed\n");
		return GENERIC_ERROR;
	}



	while(1){ //I don't want to indent just for this

	WaitForSingleObject(measurementEvent, INFINITE);
	ResetEvent(measurementEvent);



	//Empty out the queue
	while(measurementEventQueue.size() != 0){
		//Get the mutex
		if(WaitForSingleObject(measurementEventQueueMutex, INFINITE) != WAIT_OBJECT_0){
			printf("MeasurementParsingThread: Couldn't acquire mutex. Returning\n");
			__asm{int 3};
		}
		//Get the reference to the me_t which was allocated in thread_pcap.cpp
		tmpME = measurementEventQueue.front();
		//since me_t has no destructor which will be automatically called
		//we can just shrink the queue right away to release the mutex sooner
		measurementEventQueue.pop();
		
		//Release Mutex
		if(!ReleaseMutex(measurementEventQueueMutex)){
			printf("MeasurementParsingThread: Couldn't release mutex. Returning\n");
			__asm{int 3};
		}

		switch(tmpME->type){
			case ERROR_MSG:				
				ret = ParseClientErrorPacket(tmpME);
				if(ret != GENERIC_SUCCESS){
					printf("MeasurementParsingThread: ParseClientErrorPacket failed\n");
				}
				break;
			case TIMING_TEST:
				//TODO: technically this should not parse the packet before returning, 
				//it should just queue the information and wake a thread to consume the queue
				ret = ParseSelfMeasurementTimingTest(tmpME);
				if(ret != GENERIC_SUCCESS){
					printf("MeasurementParsingThread: ParseSelfMeasurement failed\n");
				}
				break;
			case TICKSTAMP_ATTESTATION:
				ret = ParseTickStampAttestationMeasurement(tmpME);
				if (ret != GENERIC_SUCCESS){
					printf("MeasurementParsingThread: ParseTickStampAttestation failed\n");
				}
				break;
			default: 
				//LOGME
				printf("packet_handler: got a msgType we don't understand: %#x\n", tmpME->type);
				break;
		}

		//Release the memory allocated in thread_pcap.cpp
		free(tmpME->pktData);
		free(tmpME);
	}//end emptying the queue
	//_CrtDumpMemoryLeaks();
	}//end while(1);

	return GENERIC_SUCCESS;
}