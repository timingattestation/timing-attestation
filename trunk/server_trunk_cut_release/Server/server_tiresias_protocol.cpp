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

#include "server_tiresias_protocol.h"

#include "request_measurement.h"
#include "main.h"
extern "C"{
	#include "database_mysql.h"
}

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////
SOCKET tiresiasConnectSocket;
unsigned int gSequenceNum;
//Place to hold st_msg_t's sent to tiresias, while waiting to process them
stm_map_t stmStorage;
HANDLE stmStorageMutex;

//Externs
extern HANDLE comparisonEvent;
extern HANDLE alertEvent;
extern HANDLE prereqRequestEvent;
extern "C" HANDLE mysqlMutex;
extern char gffAlertingEnabled; //used like a bool, but want it to work in C files if necessary
extern string gffDefaultSrcIPStr;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//Setup the connection from server to tiresias' listening socket
int SetupConnectionSocket(){
	WSADATA w;								/* Used to open Windows connection */
	struct hostent *hp;
	struct sockaddr_in server;				/* Information about this server */
	char * host_name = "localhost";
	SOCKET sd;

	/* Open windows connection */
	if (WSAStartup(0x0101, &w) != 0)
	{
		fprintf(stderr, "Could not open Windows connection.\n");
		CentralExit(GENERIC_ERROR);
	}

	/* Open a datagram socket */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == INVALID_SOCKET)
	{
		fprintf(stderr, "Could not create socket.\n");
		WSACleanup();
		CentralExit(GENERIC_ERROR);
	}

	/* Clear out server struct */
	memset((void *)&server, '\0', sizeof(struct sockaddr_in));

	/* Set family and port */
	server.sin_family = AF_INET;
	server.sin_port = htons(0xd0ed);  //53485

	/* Get host name of this computer */
	gethostname(host_name, sizeof(host_name));
	hp = gethostbyname(host_name);

	/* Check for NULL pointer */
	if (hp == NULL){
		fprintf(stderr, "Could not get host name.\n");
		closesocket(sd);
		WSACleanup();
		return GENERIC_ERROR;
	}

	/* Assign the address */
	server.sin_addr.S_un.S_un_b.s_b1 = hp->h_addr_list[0][0];
	server.sin_addr.S_un.S_un_b.s_b2 = hp->h_addr_list[0][1];
	server.sin_addr.S_un.S_un_b.s_b3 = hp->h_addr_list[0][2];
	server.sin_addr.S_un.S_un_b.s_b4 = hp->h_addr_list[0][3];

	//server.sin_addr.S_un.S_un_b.s_b1 = 0;
	//server.sin_addr.S_un.S_un_b.s_b2 = 0;
	//server.sin_addr.S_un.S_un_b.s_b3 = 0;
	//server.sin_addr.S_un.S_un_b.s_b4 = 0;

	//server.sin_addr.S_un.S_un_b.s_b1 = 192;
	//server.sin_addr.S_un.S_un_b.s_b2 = 168;
	//server.sin_addr.S_un.S_un_b.s_b3 = 187;
	//server.sin_addr.S_un.S_un_b.s_b4 = 129;

	/* Bind local address to socket */
	if (bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) == -1){

		int why = WSAGetLastError();
		printf("last error = %d\n",why);

		fprintf(stderr, "Cannot bind address to socket.\n");
		closesocket(sd);
		WSACleanup();
		return GENERIC_ERROR;
	}

	tiresiasConnectSocket = sd;
	return GENERIC_SUCCESS;
}

//Should be asynchronous, as in it doesn't wait for the response, a separate thread listens for responses
int SendSTMsg(SOCKET acceptedSocket, st_msg_t * stm){
	unsigned int bytesSent = 0;
	stm_map_t::iterator stmIterator;

	//aquire mutex
	if(WaitForSingleObject(stmStorageMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SendSTMsg: Couldn't acquire mutex. Returning\n");
		__asm{int 3};
		//free any outstanding resources here
		free(stm);
		return GENERIC_ERROR;
	}
	stmStorage.insert(make_pair(stm->sequenceNum, stm));

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(0xd00d); //53261

	bytesSent = sendto(acceptedSocket, (const char *)stm, sizeof(st_msg_t), 0, (SOCKADDR*) &addr, sizeof(addr));
	if(bytesSent == SOCKET_ERROR || bytesSent != sizeof(st_msg_t)){
		//remove and dealloc the message we failed to send
		stmIterator = stmStorage.find(stm->sequenceNum);
		if(stmIterator != stmStorage.end()){
			stmStorage.erase(stmIterator);
		}
		else{
			printf("Couldn't find the stm in stmStorage. Debug why\n");
			__asm{int 3};
		}
		free(stm);
		if(!ReleaseMutex(stmStorageMutex)){
			printf("SendSTMsg: Couldn't release mutex. Returning\n");
			__asm{int 3};
			//free any outstanding resources here
			return GENERIC_ERROR;
		}
		return GENERIC_ERROR;
	}

	if(!ReleaseMutex(stmStorageMutex)){
		printf("SendSTMsg: Couldn't release mutex. Returning\n");
		__asm{int 3};
		//free any outstanding resources here
		stmIterator = stmStorage.find(stm->sequenceNum);
		if(stmIterator != stmStorage.end()){
			stmStorage.erase(stmIterator);
		}
		else{
			printf("Couldn't find the requested stm in stmStorage. Debug why\n");
			__asm{int 3};
		}
		free(stm);
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

//Copy the relevant data from a self_check_t to a st_msg_t
int SelfCheckToSTMsg(self_check_t * s, st_msg_t * m){
	unsigned int ret = 0;
	m->type = SELF_ATTESTATION;
	m->baseVA = s->baseVA;
	m->timeDateStamp = s->timeDateStamp;
	m->moduleInfo = s->moduleInfo;
	m->nonce = s->nonce;
	m->sequenceNum = gSequenceNum++;

	//This is basically what a memcpy would change it into anyway
	for(unsigned int i = 0; i < SELF_CHECKSUM_SIZE; i++){
		m->checksum[i] = s->checksum[i];
	}
	
	return GENERIC_SUCCESS;
}

//Copy the relevant data from a st_msg_t to a bin_data_t
int STMsgToSelfCheck(st_msg_t * m, self_check_t * s){
	s->baseVA = m->baseVA;
	s->timeDateStamp = m->timeDateStamp;
	s->moduleInfo = m->moduleInfo;
	s->nonce = m->nonce;

	//This is basically what a memcpy would change it into anyway
	for(unsigned int i = 0; i < SELF_CHECKSUM_SIZE; i++){
		s->checksum[i] = m->checksum[i];
	}

	return GENERIC_SUCCESS;
}

//This is the thread which listens for responses from tiresias
//This function definition is necessary to be used by CreateThread

//This is the a wrapper for cleanness
int RequestChecksumMeasurementFromTiresias(SOCKET s, unsigned int hostID, self_check_t * selfCheck, msgType inResponseToType){
	int ret = 0;

	st_msg_t * stm = (st_msg_t *)malloc(sizeof(st_msg_t));
	memset(stm, 0, sizeof(st_msg_t));
	SelfCheckToSTMsg(selfCheck, stm);
	memcpy(&(stm->bNameA[0]), "Checkmate.sys", strlen("Checkmate.sys"));
	memcpy(&(stm->bNameW[0]), L"Checkmate.sys", sizeof(wchar_t) * wcslen(L"Checkmate.sys"));
	stm->hostID = hostID;
	stm->inResponseToType = inResponseToType;

	ret = SendSTMsg(s, stm); //stm gets dealloced in here if this fails
	if(ret == GENERIC_ERROR){
		return GENERIC_ERROR;
	}
	//DON'T USE stm AFTER THIS
	//If SendSTMsg failed it's dealloced
	//If SendSTMsg succeeded it's queued and will be dealloced when dequeued

	return GENERIC_SUCCESS; 
}

DWORD WINAPI TiresiasResponseListenerThread(LPVOID lpParam){
	int ret;
	char * tok, * context;
	char recvbuf[4096] = "";
	st_msg_t * stm;
	int bytesRecv;
	unsigned int errorNum;
	sockaddr_in tiresias;
	tiresias.sin_family = AF_INET;
	tiresias.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	tiresias.sin_port = htons(0xd00d); //53261
	stm_map_t::iterator stmIterator;

	char line1[1024];
	char line2[1024];
	char line3[1024];
	char msgLines[3072];

	unsigned int len = 0;
	//, prereqID;

	int tiresias_length = sizeof(struct sockaddr_in);

	//Initialize the mutex
	stmStorageMutex = CreateMutex(NULL, FALSE, NULL);
	if(stmStorageMutex == NULL){
		printf("TiresiasResponseListenerThread: CreateMutex for stmStorageMutex failed\n");
		return GENERIC_ERROR;
	}

	while(1){

		bytesRecv = recvfrom(tiresiasConnectSocket,recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&tiresias, &tiresias_length);
		if(bytesRecv == 0 || bytesRecv == SOCKET_ERROR || bytesRecv == WSAECONNRESET){
			printf("Client: Connection Closed.\n");
			//continue;
			return GENERIC_ERROR;
		}

		if(WaitForSingleObject(stmStorageMutex, INFINITE) != WAIT_OBJECT_0){
			printf("TiresiasResponseListenerThread: Couldn't acquire mutex. Returning\n");
			__asm{int 3};
			//free any outstanding resources here
			//TODO: Should we just completely destroy the stmStorage? Since AFAIK this is not something we 
			//can recover from...will decide if and when we ever get to this case
			return GENERIC_ERROR;
		}

		switch(recvbuf[0]){
			case 'A':
				//Expecting message of the form
				//A:sequence num:
				//See SendAck() in Tiresias
				strtok_s(recvbuf, ":", &context);
				tok = strtok_s(NULL, ":", &context);
				stm = stmStorage[strtoul(tok, NULL, 10)];
				if(stm == NULL){
					__asm{int 3};
					//LOGME
					printf("The stmStorage entry is NULL\n");
					//invalid, discard
					break;
				}
				if(stm->miscFlags & ~FLAGS_ACKED){
					//LOGME
					printf("Got an ACK but other flags are already set.\n");
					printf("There is something wrong with the Server/Tiresias IPC communication (or struct initialization). Investigate\n");
					__asm{int 3};
				}
				stm->miscFlags |= FLAGS_ACKED;
				break;

			case 'D':
				//Expecting message of the form
				//D:sequence num:
				//See SendDone() in Tiresias
				strtok_s(recvbuf, ":", &context);
				tok = strtok_s(NULL, ":", &context);
				stm = stmStorage[strtoul(tok, NULL, 10)];
				if(stm == NULL){
					//invalid, discard
					//LOGME
					printf("The stmStorage entry is NULL\n");
					break;
				}
				if(!(stm->miscFlags & FLAGS_ACKED)){
					//LOGME
					printf("Got a DONE signal without having seen an ACK signal.\n");
					printf("There is something wrong with the Server/Tiresias IPC. Investigate\n");
					__asm{int 3};
				}
				stm->miscFlags |= FLAGS_DONE;

				//Signal to perform comparison
				SetEvent(comparisonEvent);
				break;

			case 'E':
				//Expecting message of the form
				//E:sequence num:error num:
				//See SendError() in Tiresias
				strtok_s(recvbuf, ":", &context);
				tok = strtok_s(NULL, ":", &context);
				stm = stmStorage[strtoul(tok, NULL, 10)];
				if(stm == NULL){
					//invalid, discard
					//LOGME
					printf("The stmStorage entry is NULL\n");
					break;
				}
				tok = strtok_s(NULL, ":", &context);
				errorNum = strtoul(tok, NULL, 10);
				//TODO: retry once? use misc flags to determine if it's already been retried?
				switch(errorNum){
					case ST_ERR_GENERIC_ERROR:
						printf("TiresiasResponseListenerThread: Tiresias returned ST_ERR_GENERIC_ERROR\n");
						break;
					case ST_ERR_CANT_FIND_FILE:
						//TODO: InsertErrorLog()
						//printf("TiresiasResponseListenerThread: Tiresias couldn't find binary %s with timeDateStamp = %#x\n", stm->bNameA, stm->timeDateStamp);
						//printf("Check that the known good storage is up to date\n");
						sprintf_s(line1,1024,"TiresiasResponseListenerThread: Tiresias couldn't find binary %s with timeDateStamp = %#x\n", stm->bNameA, stm->timeDateStamp);
						sprintf_s(line2,1024,"Check that the known good storage is up to date\n");
						sprintf_s(line3,1024,"Reported from Server on %s\n",gffDefaultSrcIPStr.c_str());
						sprintf_s(msgLines,3072,"%s%s%s",line1,line2,line3);

						printf(msgLines);
						ret = InsertErrorLog(TIRESIAS_ERROR, 0, stm->hostID, msgLines);
						if(ret != GENERIC_SUCCESS){
							printf("TiresiasResponseListenerThread: InsertErrorLog failed\n");
							return GENERIC_ERROR;
						}

					default:
						printf("TiresiasResponseListenerThread: Received error %#x from tiresias.\n", errorNum);
				
				}
				//Since there was an error and we're not going to request a comparison
				//just get rid of the stm
				stmIterator = stmStorage.find(stm->sequenceNum);
				if(stmIterator != stmStorage.end()){
					stmStorage.erase(stmIterator);
				}
				else{
					//LOGME
					printf("Couldn't find the stm in stmStorage. Debug why\n");
					__asm{int 3};
				}
				free(stm);
				break;

			default:
				printf("Error, unknown response from tiresias\n");
				__asm{int 3};
				break;

		}

		if(!ReleaseMutex(stmStorageMutex)){
			printf("TiresiasResponseListenerThread: Couldn't release mutex. Returning\n");
			__asm{int 3};
			//free any outstanding resources here
			//TODO: Should we just completely destroy the stmStorage? Since AFAIK this is not something we 
			//can recover from...will decide if and when we ever get to this case
			return GENERIC_ERROR;
		}
	}
	return GENERIC_SUCCESS;
}



