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

//Tiresias is the oracle responsible for determining what a memory section should look like after
//relocations are performed

#include <windows.h>
#include <io.h>
#include <list>
#include <utility>
#include <vector>

#include "main.h"
#include "sha.h"
#include "file_access.h"
#include "server_tiresias_protocol.h"
#include "measure_binary.h"
#include "measure_self.h"
#include "database_mysql2.h"

//LEAK DETECTION!
//#define _CRTDBG_MAP_ALLOC
//#include <stdlib.h>
//#include <crtdbg.h>
//#ifdef _DEBUG
//#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
//#define new DEBUG_NEW
//#endif

int gQuiet, gVerbose;

extern "C" {
	#include "database_mysql.h"
	extern HANDLE mysqlMutex;
	extern int gDeleteDB;
}

using namespace std;

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

//gff = global from file
char * gffStoragePath;
char * gffDeviceConfigPath;
unsigned int gffMaxWaitTimeout;

HANDLE hWaitForResponse, hServerRequestListenerThread;
typedef list <sha_256_t *> shaList;

//EXTERNS
typedef vector <st_msg_t *> stMsgStorage;
extern stMsgStorage stMsgStorageVector;
extern HANDLE stMsgStorageVectorMutex;
extern stMsgStorage pendingSTMsgStorageVector;
extern SOCKET gAcceptedSocket;
extern struct sockaddr_in tiresias;

DWORD WINAPI ServerRequestListenerThread(LPVOID lpParam);

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//This function is so that you can set a breakpoint on it to see
//why the server fails to start at the beginning.
int CentralExit(int ret){
	return ret;
}


int PopulateTablesFromGlobalsFromConfigFile(){
	int ret;

	ret = InsertExpectedBinarySymbols(&gExpectedBinarySymbols);
	if (ret != GENERIC_SUCCESS)
	{
		printf("PopulateTablesFromGlobalsFromConfigFile: InsertExpectedBinarySymbols failed");
		return ret;
	}

	return GENERIC_SUCCESS;
}

//Just so I can have more threads created inline in less space.
HANDLE CreateThreadHelper(LPTHREAD_START_ROUTINE startFunction){
	HANDLE hThread;

	hThread = CreateThread(
				NULL,			// default security attributes
				0,				// use default stack size
				startFunction,	// thread function address
				NULL,			// argument to thread function
				0,				// use default creation flags
				NULL);			// returns the thread identifier

	return hThread;
}

int main(int argc, char ** argv){
	shaList h;
	int ret;
	st_msg_t * tmpStm;

	printf("Tiresias $Rev: 2618 $\n");

	if(argc >= 2 && strcmp(argv[1], "Q") == 0){
		printf("Quiet output enabled\n");
		gQuiet = 1;
	}
	else{
		gQuiet = 0;
	}

	if(argc >= 2 && strcmp(argv[1], "V") == 0){
		printf("Verbose output enabled\n");
		gVerbose = 1;
	}
	else{
		gVerbose = 0;
	}

    //do not use the D command line option in "production" environments.
	if(argc >= 2 && strcmp(argv[1], "D") == 0){
		printf("Option D given: Deleting the databases and recreating them\n");
		gDeleteDB = 1;
	}
	else{
		gDeleteDB = 0;
	}

	//Read the configuration file and set appropriate globals
	//must do this first so we can init our DB connection
	ret = ReadConfigAndSetGlobs("tiresias_config.txt");
	if(ret != GENERIC_SUCCESS){
		printf("PopulateTablesFromGlobalsFromConfigFile: ReadConfigAndSetGlobs failed");
		return CentralExit(GENERIC_ERROR);
	}

	//Make sure we can connect to the database
	if(InitializeDatabaseConnection() == GENERIC_ERROR){
		return CentralExit(GENERIC_ERROR);
	}

	//Move symbols from file to db
	ret = PopulateTablesFromGlobalsFromConfigFile();
	if (ret != GENERIC_SUCCESS)
	{
		printf("PopulateTablesFromConfigFile failed with ret = %u", ret);
		return CentralExit(ret);
	}

	//Initialize threads
	gAcceptedSocket = GENERIC_ERROR; //Initialize to a known state
	hServerRequestListenerThread = CreateThreadHelper(ServerRequestListenerThread);
	if (hServerRequestListenerThread == NULL){
		printf("CreateThread Error on ServerRequestListenerThread");
		return CentralExit(GENERIC_ERROR);
	}

	hWaitForResponse = CreateEvent(NULL, true, false, NULL);
	st_msg_t msgFromServer;
	char * fullFileName = 0;
	while(1){

		//We have now moved request reception to its own thread, which
		//will signal on hWaitForResponse when a message is received

		//Wait for there to be a st_msg_t in the binList to process
		//Decided to wait with a fixed time rather than infinite
		//This means that even if there's a race condition where the event gets
		//reset even if there's something in storage, it will still see it in
		//a maximum of gffMaxWaitTimeout/1000 seconds
		ret = WaitForSingleObject(hWaitForResponse,gffMaxWaitTimeout);
		if(ret != WAIT_OBJECT_0){
			if(ret == WAIT_TIMEOUT){
				if(gVerbose) printf("Wait timeout\n");
			}
			else{
				printf("Wait error?\n");
				__asm{int 3};
			}
		}

		//If there are measurement requests which are pending on a
		//prerequisite, add them back in to try again incase the
		//prerequisite has been fulfilled
		if(pendingSTMsgStorageVector.size() != 0){
			//Must aquire mutex before modifying stMsgStorageVector
			if(WaitForSingleObject(stMsgStorageVectorMutex,INFINITE) != WAIT_OBJECT_0){
				printf("main: Couldn't acquire mutex. Returning\n");
				__asm{int 3};
				return GENERIC_ERROR;
			}

			stMsgStorageVector.insert(stMsgStorageVector.begin(), pendingSTMsgStorageVector.begin(), pendingSTMsgStorageVector.end());
			pendingSTMsgStorageVector.clear();

			if(!ReleaseMutex(stMsgStorageVectorMutex)){
				printf("main: Couldn't release mutex. Returning\n");
				__asm{int 3};
				return GENERIC_ERROR;
			}
		}

		while(stMsgStorageVector.size() > 0){
			//Must aquire mutex before modifying stMsgStorageVector
			if(WaitForSingleObject(stMsgStorageVectorMutex,INFINITE) != WAIT_OBJECT_0){
				printf("main: Couldn't acquire mutex. Returning\n");
				__asm{int 3};
				return GENERIC_ERROR;
			}

			//Copy the data to a holder var so we can release the mutex
			memcpy(&msgFromServer, stMsgStorageVector.at(0), sizeof(st_msg_t));
			free(stMsgStorageVector.at(0));//Free the data which was malloced in ServerRequestListenerThread
			stMsgStorageVector.erase(stMsgStorageVector.begin());//Delete the entry in the vector

			if(!ReleaseMutex(stMsgStorageVectorMutex)){
				printf("main: Couldn't release mutex. Returning\n");
				__asm{int 3};
				return GENERIC_ERROR;
			}

			//Check if we have a file for the requested st_msg_t
			if (msgFromServer.type == SELF_ATTESTATION){
				//Check if we have a file for the requested st_msg_t
				//NOTE! we're responsible for freeing the memory which is allocated for fullFileName
				ret = FindFile(gffStoragePath, msgFromServer.bNameA, msgFromServer.timeDateStamp, msgFromServer.sizeOfImage, &fullFileName);
				if(ret == GENERIC_ERROR){
					//For kernel variants like ntkrnlpa.exe, they are found
					//in memory in the loaded modules list as ntoskrnl.exe but their
					//memory measurements need to be taken from the right kernel version.
					//So we need to try alternative names
					if(_stricmp(msgFromServer.bNameA, "ntoskrnl.exe")==0){
						ret = FindFile(gffStoragePath, "ntkrnlpa.exe", msgFromServer.timeDateStamp, msgFromServer.sizeOfImage, &fullFileName);
						if(ret == GENERIC_ERROR){
							ret = FindFile(gffStoragePath, "ntkrnlmp.exe", msgFromServer.timeDateStamp, msgFromServer.sizeOfImage, &fullFileName);
							if(ret == GENERIC_ERROR){
								goto stillbad;
							}
						}
					}
					else{
						stillbad:
						printf("main: FindFile failed: Couldn't find match for %s-%x-%x\n",
							msgFromServer.bNameA,
							msgFromServer.timeDateStamp,
							msgFromServer.sizeOfImage);
						SendError(gAcceptedSocket, msgFromServer.sequenceNum, ST_ERR_CANT_FIND_FILE);
						continue;
					}
				}
			}

			switch(msgFromServer.type){
				case SELF_ATTESTATION:
					printf("Computing self checksum for %s\n", fullFileName);
					ret = AnalyzeFileForSelfMeasurement(mysqlMutex, fullFileName, &msgFromServer);
					break;
				default:
					printf("main: Unhandled message type. Check that msgType is synchronized between all files\n");
			}
			//ret is set by one of the previous analysis mechanisms
			switch(ret){
				case PREREQ_MEASURED_BUT_NOT_YET_DONE:
				case PREREQ_REQUESTED_BUT_NOT_YET_DONE:
				/*there is an occasional race on the first measurement where even though
				//the server has already written the loaded modules measurement to the db
				//but SelectLoadedModuleEntryByNameAndHostID says there are 0 entries and
				//it returns no results found. So we're just going to accept that and try again*/
				case NO_RESULTS_FOUND:
					printf("Measurement requires a prerequisite, see Prerequisites table\n");
					//queue up the failed measurement to try again later
					tmpStm = (st_msg_t *)malloc(sizeof(st_msg_t));
					memcpy(tmpStm, &msgFromServer, sizeof(st_msg_t));
					pendingSTMsgStorageVector.push_back(tmpStm);
					break;
				case GENERIC_SUCCESS:
					//If the analysis was successful, tell the server we succeeded
					SendDone(gAcceptedSocket, msgFromServer.sequenceNum);
					break;
				default: 
					printf("failed on %s\n", fullFileName);
					SendError(gAcceptedSocket, msgFromServer.sequenceNum, ST_ERR_GENERIC_ERROR);
			}
			//Cleanup
			if (msgFromServer.type == SELF_ATTESTATION)
			{
				free(fullFileName);
			}
			ResetEvent(hWaitForResponse);
			//_CrtDumpMemoryLeaks();
		}
	}

	printf("Done\n");
	return GENERIC_SUCCESS;
}