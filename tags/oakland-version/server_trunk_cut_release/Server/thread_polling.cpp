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

//This is a thread which is used for the server to request
//measurements with some second level time interval as 
//specified in the config file

#include "thread_polling.h"
#include "request_measurement.h"
#include "database_mysql2.h"
#include <time.h>
extern "C"{
	#include "database_mysql.h"
}

using namespace std;

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////

#define MAX_LINE 255

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

bool gbPollingEnabled;
HANDLE pollingEvent;


//EXTERNS
extern "C" MYSQL mysqlMeasurements;
extern "C" MYSQL mysqlTiresias;
extern "C" HANDLE mysqlMutex;
extern string gffDefaultSrcIPStr;
extern string gffDefaultDstIPStr;
extern string gffDefaultDstHostName;
extern unsigned int gffPollingFrequency;
extern unsigned int gffPollingTolerance;
extern unsigned int measurementRate;

////////////////////////////////////////////////////////
//CODE START
////////////////////////////////////////////////////////

DWORD WINAPI PollingThread(LPVOID lpParam){
	queue<int> allHostsToBeMeasured;
	vector<string> allTypesToBeMeasured;
	unsigned int holder;
	int ret;
	char hostIP[16];
	char hostName[128];
	wstring binName;
	int binID = 0;
	unsigned int lastTimeMeasurementRequested = 0;
	unsigned int currentTimeInSeconds = 0;
	time_t rawtime;
	unsigned int waitTime = measurementRate * 1000;

	//Special strings which are accepted instead of a module name
	//in order to poll on different measurement types
	string tickstamp = "TICKSTAMP_ATTESTATION";
	string timingTest = "TIMING_TEST";

	//This creates the event in a set state, so that it's like
	//the event has been signaled
	pollingEvent = CreateEvent(NULL, true, false, NULL);
	if(pollingEvent == NULL){
		printf("PollingThread: CreateEvent failed\n");
		return GENERIC_ERROR;
	}
	//Don't start the polling thread until the main thread says so
	WaitForSingleObject(pollingEvent, INFINITE);
	while(1){
		if(!gbPollingEnabled){
			//This is how we stop polling it if was already started
			WaitForSingleObject(pollingEvent, INFINITE); //Breaks out of wait every x milliseconds
		}
		WaitForSingleObject(pollingEvent, gffPollingFrequency); //Breaks out of wait every x milliseconds
		ResetEvent(pollingEvent);
		//TODO: Add code here to check if a global exit condition has been reached, and if so
		//cleanup_full any memory and ExitThread();

		ret = SelectAllHostsToMeasureForPolling(gffPollingTolerance, &allHostsToBeMeasured);
		if(ret != GENERIC_SUCCESS){
			continue;
		}

		//By adding the pollingEvent condition here we can break out earlier
		while(allHostsToBeMeasured.size() > 0 && gbPollingEnabled){
			holder = allHostsToBeMeasured.front();
			allHostsToBeMeasured.pop();

			ret = SelectHostIPByID((int)holder, hostIP);
			if(ret != GENERIC_SUCCESS){
				printf("PollingThread: SelectHostIPByID failed\n");
				continue;
			}

			ret = SelectHostNameByID((int)holder, hostName);
			if(ret != GENERIC_SUCCESS){
				printf("PollingThread: SelectHostNameByID failed\n");
				continue;
			}

			ret = SelectModulesToMeasure(&allTypesToBeMeasured);

			for(unsigned int j=0; j < allTypesToBeMeasured.size(); j++){
				if(!gbPollingEnabled) break; //Allow us to error out earlier
				string binNameA = allTypesToBeMeasured.at(j);
				wstring binNameW;
				binNameW.assign(binNameA.begin(), binNameA.end());

				// get the current time for rate checking
				time(&rawtime);
				currentTimeInSeconds = (unsigned int)rawtime;
				if((currentTimeInSeconds - lastTimeMeasurementRequested) < measurementRate){
					Sleep(waitTime);
				}

				// set the time for requesting the last actual measurement request now
				time(&rawtime);
				lastTimeMeasurementRequested = (unsigned int)rawtime;

				if(binNameA.compare(tickstamp) == 0){
					ret = BuildTickStampAttestationRequestPacket((char *)gffDefaultSrcIPStr.c_str(), hostIP, hostName, 2500000);
					if(ret != GENERIC_SUCCESS){
						printf("PollingThread: BuildTickStampAttestationRequestPacket TICKSTAMP_ATTESTATION failed\n");
						continue;
					}
				}
				else if(binNameA.compare(timingTest) == 0){
					ret = BuildTimingTestRequestPacket((char *)gffDefaultSrcIPStr.c_str(),(char *)gffDefaultDstIPStr.c_str(),
													(char *)gffDefaultDstHostName.c_str(), 2500000);
					if(ret != GENERIC_SUCCESS){
						printf("PollingThread: BuildTimingTestRequestPacket failed for numIterations = 2500000 (default)\n");
						continue;
					}
				}
			}

			allTypesToBeMeasured.clear();
		}//End for all hosts to be measured
	}//end while(1)

	return GENERIC_SUCCESS;
}