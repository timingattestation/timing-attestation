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

//This of course is the main thread, which starts all other threads
//This implements the simple user interface as well

#define WIN32

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/applink.c>
#include <iostream>
#include <string>
#include <vector>
#include "pcap.h"
#include "request_measurement.h"
#include "file_access.h"
#include "server_tiresias_protocol.h"
#include "thread_pcap.h"
#include "thread_comparing.h"
#include "thread_polling.h"
#include "thread_measurement_parsing.h"
#include "database_mysql2.h"
#include "main.h" //Include this after HANDLE has already been included somewhere else

//LEAK DETECTION!
//#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#ifdef _DEBUG
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif

extern "C"{
	#include "database_mysql.h"
	unsigned int measurementRate;
}
//Different C variables are needed because database_mysql.c can't link against the C++ named ones
extern "C" int gcVerbose, gcQuiet;

#include <string>

using namespace std;

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
pcap_if_t * globDevice;
DeviceInfo * globDeviceInfoPtr;
int gVerbose, gQuiet;
HCRYPTPROV gCryptoContext;

HANDLE  hPcapThread, hTiresiasResponseThread, hComparisonThread, 
		hPollingThread, hMeasurementParsingThread, hAlertThread, hPulseCheckThread,
		hMonitorThread, hPrereqRequestingThread;

vector <string> gffHostsToMeasure;
vector <string> gffModulesToMeasure;
vector <string> gffBrandStringLimits;
vector <string> gffHostLimits;

//EXTERN GLOBALS
extern "C"{
	extern MYSQL mysqlMeasurements;
	extern HANDLE mysqlMutex;
	extern int gDeleteDB;
}

extern char gUseBroadcastMAC;

//In file_access.cpp
extern char gffSniffingInterface;
extern string gffDefaultSrcIPStr;
extern string gffDefaultDstIPStr;
extern string gffDefaultDstHostName;

extern char gffAlertingEnabled; //used like a bool, but want it to work in C files if necessary
extern char * gffEmailAddress; //Where to send alerts if email alerting is enabled
extern char * gffDevEmailAddress; //Where to send alerts if email alerting is enabled

//In thread_polling.cpp
extern bool gbPollingEnabled;
extern HANDLE pollingEvent;

// In thread thread_monitor_pending.cpp
extern HANDLE pendingMonitorEvent;

//In thread_pulsecheck.cpp
extern HANDLE pulseCheckEvent;

//For manually testing the self-checksumming
extern unsigned int gUserSpecifiedNonce; //In request_measurement.cpp

//TODO: If you put this in request_measurement.h you get a nasty tangle
//of redefinitions and such. Don't feel like fixing it now, so do later :)
DeviceInfo * GetAdapterInfo(pcap_if_t* Device);

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//This function is so that you can set a breakpoint on it to see
//why the server fails to start at the beginning.
int CentralExit(int ret){
	return ret;
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

int CreateAllThreads(){

	hPcapThread = CreateThreadHelper(PcapThread);
	if (hPcapThread == NULL){
		printf("CreateThread Error on PcapThread");
		return GENERIC_ERROR;
    }

	hTiresiasResponseThread = CreateThreadHelper(TiresiasResponseListenerThread);
	if (hTiresiasResponseThread == NULL){
		printf("CreateThread Error on TiresiasResponseListenerThread");
		return GENERIC_ERROR;
	}

	hComparisonThread = CreateThreadHelper(ComparisonThread);
	if (hComparisonThread == NULL){
		printf("CreateThread Error on ComparisonThread");
		return GENERIC_ERROR;	
	}

	hPollingThread = CreateThreadHelper(PollingThread);
	if (hPollingThread == NULL){
		printf("CreateThread Error on PollingThread");
		return GENERIC_ERROR;
	}

	hMeasurementParsingThread = CreateThreadHelper(MeasurementParsingThread);
	if (hMeasurementParsingThread == NULL){
		printf("CreateThread Error on MeasurementParsingThread");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}


//Should be called once to initialize the crypto context which will be used
//to generate random numbers
int RandInit(){
	//the PROV_RSA_FULL is just from an example
	if(!CryptAcquireContext(&gCryptoContext, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT )){
		printf("CryptAcquireContext returned error %d\n", (int)GetLastError());
		return GENERIC_ERROR;
	}
	return GENERIC_SUCCESS;
}

//Should be called at program exit to cleanly release the crypto contex
void RandDestroy(){
	CryptReleaseContext(gCryptoContext, 0);
}

int PopulateTablesFromGlobalsFromConfigFile(){
	int ret;

	//Now that the database connection is established, we can
	//insert hosts and modules specified in the file
	//NOTE: This function will deallocate all of the hosts and modules passed in
	//DO NOT USE THE REFERENCES TO THE HOSTS OR MODULES AFTER CALLING THIS FUNCTION
	ret = InsertHostsAndModulesFromFile(&gffHostsToMeasure, &gffModulesToMeasure);
	if(ret != GENERIC_SUCCESS || !gffHostsToMeasure.empty() || !gffModulesToMeasure.empty()){
		return ret;
	}

	//NOTE: This function will deallocate all of the limits passed in
	//DO NOT USE THE REFERENCES TO THE LIMITS AFTER CALLING THIS FUNCTION
	ret = InsertHostLimitsFromFile(&gffHostLimits);
	if(ret != GENERIC_SUCCESS || !gffHostLimits.empty()){
		return ret;
	}

	//NOTE: This function will deallocate all of the limits passed in
	//DO NOT USE THE REFERENCES TO THE LIMITS AFTER CALLING THIS FUNCTION
	ret = InsertBrandStringLimitsFromFile(&gffBrandStringLimits);
	if(ret != GENERIC_SUCCESS || !gffBrandStringLimits.empty()){
		return ret;
	}

	return GENERIC_SUCCESS;
}

int main(int argc, char ** argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum, ret;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	gUserSpecifiedNonce = 0;
	gbPollingEnabled = false;
	WSADATA w;								/* Used to open Windows connection */
	unsigned int hostID;

	/* Open windows connection, need to do this before using getaddrinfo*/
	if (WSAStartup(0x0101, &w) != 0)
	{
		fprintf(stderr, "Could not open Windows connection.\n");
		CentralExit(GENERIC_ERROR);
	}

	printf("Server $Rev: 2710 $\n");

	if(argc >= 2 && strcmp(argv[1], "V") == 0){
		printf("Verbose output enabled\n");
		gVerbose = gcVerbose = 1;
	}
	else{
		gVerbose = gcVerbose = 0;
	}

	if(argc >= 2 && strcmp(argv[1], "Q") == 0){
		printf("Quiet output enabled\n");
		gQuiet = gcQuiet = 1;
	}
	else{
		gQuiet = gcQuiet = 0;
	}

	//do not use the D command line option in "production" environments.
	if(argc >= 2 && strcmp(argv[1], "D") == 0){
		printf("Option D given: Deleting the databases and recreating them\n");
		gDeleteDB = 1;
	}
	else{
		gDeleteDB = 0;
	}

	//Read config file
	if(ReadConfigAndSetGlobs("server_config.txt") != GENERIC_SUCCESS){
		return CentralExit(GENERIC_ERROR);
	}

	//initialize openssl stuff for tpm use
	OpenSSL_add_all_algorithms();

	//Setup the database connections
	if(InitializeDatabaseConnection() != GENERIC_SUCCESS){
		return CentralExit(GENERIC_ERROR);
	}

	//Move data grabbed from the config file to the db
	ret = PopulateTablesFromGlobalsFromConfigFile();
	if (ret != GENERIC_SUCCESS)
	{
		printf("PopulateTablesFromConfigFile failed with ret = %u", ret);
		return CentralExit(ret);
	}

	//Resolve default destination host and ip now that the database is established
	ret = ProcessHost(gffDefaultDstHostName,gffDefaultDstIPStr,false,NOTREADY,&hostID);
	if(ret != GENERIC_SUCCESS){
		printf("ERROR: Unable to resolve default hostname and ip address\n");
	}

	if(SetupConnectionSocket() != GENERIC_SUCCESS){
		return CentralExit(GENERIC_ERROR);
	}

	/////////////////////////////////////////////////
	//Decide which device will be used
	/////////////////////////////////////////////////

	// Retrieve the device list
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return CentralExit(GENERIC_ERROR);
	}
	
	// Print the list
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		pcap_freealldevs(alldevs);
		return CentralExit(GENERIC_ERROR);
	}
	
	if(gffSniffingInterface == 0){
		printf("Enter the interface number (1-%d):",i);
		scanf_s("%d", &inum, 1);
	}
	else{
		inum = gffSniffingInterface;
	}

	// Check if the user specified a valid adapter
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		// Free the device list
		pcap_freealldevs(alldevs);
		return CentralExit(GENERIC_ERROR);
	}

	//Move to the chosen adapter and set the global device
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	globDevice = d;
	
	//Decided I only want to do this once (since it involves a large alloc & dealloc)
	//NOTE: CALLER MUST FREE THE RETURNED DeviceInfo!
	globDeviceInfoPtr = GetAdapterInfo(globDevice);
	if(globDeviceInfoPtr->Exists == false){
		cout << "Couldn't get adapter info\n";
		pcap_freealldevs(alldevs);
		free(globDeviceInfoPtr);
		return CentralExit(GENERIC_ERROR);
	}

	//Initialize the random number generation
	if(RandInit() != GENERIC_SUCCESS){
		printf("Main: RandInit() failed, exiting\n");
		pcap_freealldevs(alldevs); 
		free(globDeviceInfoPtr);
		return CentralExit(GENERIC_ERROR);
	}

	/////////////////////////////////////////////////
	//Create the other threads
	/////////////////////////////////////////////////
	ret = CreateAllThreads();
	if (ret != GENERIC_SUCCESS)
	{
		printf("main:CreateAllThreads failed with ret = %u", ret);
		RandDestroy();
		pcap_freealldevs(alldevs); 
		free(globDeviceInfoPtr);
		return CentralExit(ret);
	}

	gUseBroadcastMAC = 0;
	//TODO: How do I determine if the thread terminated prematurely?

	/////////////////////////////////////////////////
	//Main thread's main code
	/////////////////////////////////////////////////
	unsigned int input;
	wstring binNameW;
	wstring devNameW;
	string binNameA;
	vector<string> binaries;
	string hostIP, hostName;
	vector<string> hosts;
	vector<string> loadedModulesToBeMeasured;
	string srcIP, dstIP;
	string srcHostName, dstHostName;
	unsigned int numIterations;
	bool alphaCharDetected = false;
	unsigned int count = 0;

	while(1){
		input = 0;
		printf("Enter a command number:\n");
		printf("0: Quit\n");
		printf("1: Print options again\n");
		printf("2: Manually specify source/destination IP addresses for outbound packets\n");
		printf("7: Toggle polling thread on/off\n");
		printf("8: Use broadcast MAC (disabled by default)\n");
		printf("10: Toggle attack\n");
		printf("17: Timing test - variable iterations\n");
		printf("18: Timing test - 2500000 iterations hardcoded\n");
		printf("31: TickStamp Attestation - variable iterations\n");
		printf("32: TickStamp Attestation - 2500000 iterations hardcoded\n");
		while(!(cin >> input)){
			cin.clear();
			string s;
			cin >> s;
			cout << s << " is pretty clearly not an acceptable input\n";
		}
		printf("You entered %d\n", input);

		//_CrtDumpMemoryLeaks();

		int ret = 0;
		switch(input){
			case 0:
				printf("Shutting down\n");
				goto cleanup;
				break;
			case 1:
				continue;
			case 2:
				//prefer not to have it find its own source IP, because the system could
				//have multiple network interfaces
				cout << "Enter source IP (this system)\n";
				cin >> srcIP;
				printf("srcIP set to %s\n", srcIP.c_str());
				cout << "Enter destination IP (system to measure)\n";
				cin >> dstIP;
				printf("dstIP set to %s\n", dstIP.c_str());

				// get the host names
				ret = ResolveIPsAndNames(&srcIP, &dstIP, &srcHostName, &dstHostName);
				if(ret != GENERIC_SUCCESS){
					printf("main(): ResolveIPsAndNames failed\n");
				}

				gffDefaultSrcIPStr = srcIP;
				gffDefaultDstIPStr = dstIP;
				gffDefaultDstHostName = dstHostName;
				break;
			case 7:
				if(gbPollingEnabled){
					printf("Stopping polling thread\n");
					//ResetEvent(pulseCheckEvent);
					ResetEvent(pollingEvent);
					gbPollingEnabled = false;
				}
				else{
					printf("Starting polling thread\n");
					//SetEvent(pulseCheckEvent);
					SetEvent(pollingEvent);
					gbPollingEnabled = true;
				}
				break;
			case 8:
				printf("Using broadcast MAC address on measurement packet\n");
				gUseBroadcastMAC = 1;
				break;
			case 10:
				ret = ToggleAttackRequestPacket((char *)gffDefaultSrcIPStr.c_str(),
								(char *)gffDefaultDstIPStr.c_str(),
								(char *)gffDefaultDstHostName.c_str());
				break;
			case 17:
				cout << "Enter number of iterations you want to use for this query\n";
				cin >> numIterations;
				cout << "You entered " << numIterations;
				printf("Using source IP = %s, dest IP = %s\n", gffDefaultSrcIPStr.c_str(), gffDefaultDstIPStr.c_str());
				ret = BuildTimingTestRequestPacket((char *)gffDefaultSrcIPStr.c_str(),(char *)gffDefaultDstIPStr.c_str(),
													(char *)gffDefaultDstHostName.c_str(), numIterations);
				if(ret != GENERIC_SUCCESS){printf("BuildTimingTestRequestPacket failed for numIterations = %#x\n", numIterations);}
				break;
			case 18:
				numIterations = 2500000;
				cout << "numIterations = " << numIterations;
				printf("Using source IP = %s, dest IP = %s\n", gffDefaultSrcIPStr.c_str(), gffDefaultDstIPStr.c_str());
				ret = BuildTimingTestRequestPacket((char *)gffDefaultSrcIPStr.c_str(),(char *)gffDefaultDstIPStr.c_str(),
													(char *)gffDefaultDstHostName.c_str(), numIterations);
				if(ret != GENERIC_SUCCESS){printf("BuildTimingTestRequestPacket failed for numIterations = 2500000 (default)\n");}
				break;
			case 31:
				cout << "Enter number of iterations you want to use for this query\n";
				cin >> numIterations;
				cout << "You entered " << numIterations;
				printf("Using source IP = %s, dest IP = %s\n", gffDefaultSrcIPStr.c_str(), gffDefaultDstIPStr.c_str());
				ret = BuildTickStampAttestationRequestPacket((char *)gffDefaultSrcIPStr.c_str(),(char *)gffDefaultDstIPStr.c_str(),
													(char *)gffDefaultDstHostName.c_str(), numIterations);
				if(ret != GENERIC_SUCCESS){printf("BuildTickStampAttestationRequestPacket failed for numIterations = %#x\n", numIterations);}
				break;
			case 32:
				numIterations = 2500000;
				cout << "numIterations = " << numIterations;
				printf("Using source IP = %s, dest IP = %s\n", gffDefaultSrcIPStr.c_str(), gffDefaultDstIPStr.c_str());
				ret = BuildTickStampAttestationRequestPacket((char *)gffDefaultSrcIPStr.c_str(),(char *)gffDefaultDstIPStr.c_str(),
													(char *)gffDefaultDstHostName.c_str(), numIterations);
				if(ret != GENERIC_SUCCESS){printf("BuildTickStampAttestationRequestPacket failed for numIterations = 2500000 (default)\n");}
				break;
			default:
				printf("Invalid command number\n");
				break;
		}
	}

	//////////////////////////////
	//CLEANUP
	//////////////////////////////
cleanup:
	//TODO: allow for graceful termination
	TerminateThread(hPcapThread, 0);
	TerminateThread(hTiresiasResponseThread, 0);
	TerminateThread(hComparisonThread, 0);
	TerminateThread(hPollingThread, 0);

	CloseHandle(hPcapThread);
	CloseHandle(hTiresiasResponseThread);
	CloseHandle(hComparisonThread);
	CloseHandle(hPollingThread);

	//Get rid of our globals
	pcap_freealldevs(alldevs);
	RandDestroy();
	free(globDeviceInfoPtr);

    return 0;

}