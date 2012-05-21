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

//A separate thread which is used for handling comparisons between incoming measurements
//and the values in the database put there by tiresias, or previous measurements which
//did not have any known good measurement from tiresias

#include "thread_comparing.h"
#include "server_tiresias_protocol.h"
#include "database_mysql2.h"
#include "parse_self_measurement.h"
#include "main.h"

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////
//MAKE SURE THIS DOESN'T DIFFER FROM OTHER INSTANCES
//I.e. search for other NOTE_SIZE macros when changing
#define NOTE_SIZE 100


////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
//Signals when there is data ready to perform a comparison
HANDLE comparisonEvent;

//EXTERNS
extern char gffAlertingEnabled; //used like a bool, but want it to work in C files if necessary
extern HANDLE alertEvent;
extern stm_map_t stmStorage;
extern HANDLE stmStorageMutex;

//In database_mysql.c
extern "C" MYSQL mysqlMeasurements;
extern "C" MYSQL mysqlTiresias;
extern "C" HANDLE mysqlMutex;

//in main.cpp
extern int gVerbose, gQuiet;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//If comparisonEvent is signaled, it means we have an entry in both the measurements and tiresias tables
//This should pull the entries out and compare them
DWORD WINAPI ComparisonThread(LPVOID lpParam){
	queue<st_msg_t *> holderQueue;
	stm_map_t::const_iterator holderIterator;
	st_msg_t * stm;
	self_check_t selfCheck;
	int ret;
	stm_map_t::iterator stmIterator;

	//This creates the event in a set state, so that it's like
	//the event has been signaled
	comparisonEvent = CreateEvent(NULL, true, false, NULL);
	if(comparisonEvent == NULL){
		printf("ComparisonThread: CreateEvent failed\n");
		CentralExit(GENERIC_ERROR);
	}
	while(1){
		WaitForSingleObject(comparisonEvent, INFINITE);
		ResetEvent(comparisonEvent);
		//TODO: Add code here to check if a global exit condition has been reached, and if so
		//cleanup any memory and ExitThread();

		//Now loop through the storage and pull out all the done entries, and process them all
		if(WaitForSingleObject(stmStorageMutex, INFINITE) != WAIT_OBJECT_0){
			printf("ComparisonThread: Couldn't acquire mutex. Returning\n");
			__asm{int 3};
			//free any outstanding resources here
			//TODO: Should we just completely destroy the stmStorage and holderQueue? AFAIK this is not something we 
			//can recover from...will decide if and when we ever get to this case
			return GENERIC_ERROR;
		}

		//This is the structure recommended for deleteing from a map while iterating through it
		//This is necessary so as not to have the iterator get invalidated when the .erase()
		// is called ("it" would be invalidated if the thing it's pointing to is invalidated)
		stm_map_t::iterator it = stmStorage.begin();
		while(it != stmStorage.end()){
			stmIterator = it++;
			if(stmIterator->second == NULL){
				holderQueue.push(it->second);
				stmStorage.clear();
				break;
			}
			if((stmIterator->second->miscFlags & FLAGS_DONE) != 0){
				//If we try to erase(it) it will become invalid
				//so we're copying it to a sacrificial iterator
				holderQueue.push(stmIterator->second);
				stmStorage.erase(stmIterator);
			}
		}
		if(!ReleaseMutex(stmStorageMutex)){
			printf("ComparisonThread: Couldn't release mutex. Returning\n");
			__asm{int 3};
			//free any outstanding resources here
			//TODO: Should we just completely destroy the stmStorage and holderQueue? AFAIK this is not something we 
			//can recover from...will decide if and when we ever get to this case
			return GENERIC_ERROR;
		}

		//Do the comparison
		while(!holderQueue.empty()){
			stm = holderQueue.front();
			holderQueue.pop(); //pop early incase we have to abort

			switch(stm->type){
				case SELF_ATTESTATION:
					STMsgToSelfCheck(stm, &selfCheck);
					ret = CompareSelfChecksums(&selfCheck);
					if(ret != GENERIC_SUCCESS){
						printf("ComparisonThread: CompareSelfChecksum() failed for %ws\n", stm->bNameW);
					}
					break;
			}

			free(stm);

		}//Done for each st_msg_t
	} //While(1)

	return GENERIC_SUCCESS;
}

int CompareSelfChecksums(self_check_t * selfCheck){
	int ret = 0;
	bool differenceDetected = false;
	self_check_t selfCheckTiresias;

	ret = SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp(selfCheck, &selfCheckTiresias);
	if(ret != GENERIC_SUCCESS){
		printf("CompareSelfChecksums: SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp failed\n");
		return GENERIC_ERROR;
	}

	for(unsigned int i = 0; i < SELF_CHECKSUM_SIZE; i++){
		if(selfCheck->checksum[i] != selfCheckTiresias.checksum[i]){
			differenceDetected = true;
			break;
		}
	}

	if(differenceDetected){
		printf("CHECKSUMS DIFFERS: nonce = %#x, timeDateStamp = %#x, baseVA = %#x\n",selfCheck->nonce,selfCheck->timeDateStamp, selfCheck->baseVA);
		printf("Measured: 0x%08x%08x%08x%08x%08x%08x\n", selfCheck->checksum[0], selfCheck->checksum[1], selfCheck->checksum[2], selfCheck->checksum[3], selfCheck->checksum[4], selfCheck->checksum[5]);
		printf("Tiresias: 0x%08x%08x%08x%08x%08x%08x\n", selfCheckTiresias.checksum[0], selfCheckTiresias.checksum[1], selfCheckTiresias.checksum[2], selfCheck->checksum[3], selfCheckTiresias.checksum[4], selfCheckTiresias.checksum[5]);
		differenceDetected = false;
	}
	else{
		if(!gQuiet) printf("No difference in checksum detected\n");
	}

	return GENERIC_SUCCESS;
}