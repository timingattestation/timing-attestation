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

#include "server_tiresias_protocol.h"
#include <vector>
#include <map>
#include <winsock2.h>

using namespace std;

////////////////////////////////////////////////////////
//MACROS & TYPEDEFS
////////////////////////////////////////////////////////

SOCKET gAcceptedSocket;

struct sockaddr_in tiresias;		/* Information about tiresias*/
struct sockaddr_in server;			/* Information about the server */

typedef vector <st_msg_t *> stMsgStorage;
typedef map <st_msg_t *, unsigned int> storageMap;

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

//Place to hold st_msg_t's received from server, while waiting to process them
stMsgStorage stMsgStorageVector;
stMsgStorage pendingSTMsgStorageVector;

//Used to mediate access to stMsgStorageVector between 
//the main thread and ServerRequestListenerThread
HANDLE stMsgStorageVectorMutex;

//EXTERNS
extern HANDLE hWaitForResponse;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//This thread just continuously listens for requests from server
//and alerts the main thread when a new request has been received
DWORD WINAPI ServerRequestListenerThread(LPVOID lpParam){
	unsigned int ret;
	int totalBytesRecvd = 0;
	int bytesRecvd = 0;
	size_t bytesConverted;

	char buffer[4096];	
	int server_length = (int)sizeof(struct sockaddr_in);

	//Initialize the mutex
	stMsgStorageVectorMutex = CreateMutex(NULL, FALSE, NULL);
	if(stMsgStorageVectorMutex == NULL){
		printf("ServerRequestListenerThread: CreateMutex for stMsgStorageVectorMutex failed\n");
		return GENERIC_ERROR;
	}

	//Init the socket
	if(gAcceptedSocket == GENERIC_ERROR){
		//Setup a local listening socket for the server to communicate to this code with
		ret = InitializeSocket();
		if(ret != GENERIC_SUCCESS){
			printf("ServerRequestListenerThread: BindAndListen failed\n");
			__asm{int 3};
			return GENERIC_ERROR;
		}
	}

	while(1){

		/* Receive bytes from server */
		totalBytesRecvd = recvfrom(gAcceptedSocket, buffer, 4096, 0, (struct sockaddr *)&server, &server_length);
		if (totalBytesRecvd < 0)
		{
			fprintf(stderr, "Could not receive datagram.\n");
			closesocket(gAcceptedSocket);
			WSACleanup();
			return GENERIC_ERROR;
		}
		if(totalBytesRecvd != sizeof(st_msg_t)){
			printf("ServerRequestListenerThread: Wrong data size, investigate.\n");
			__asm{int 3};
			return GENERIC_ERROR;
		}

		st_msg_t * b = (st_msg_t *)malloc(sizeof(st_msg_t));
		memcpy(b, buffer, sizeof(st_msg_t));

		//Sanity check the data
		if(b->numROSections > MAX_SECTS_TO_MEASURE){
			printf("b->numROSections > MAX_SECTS_TO_MEASURE, data may be corrupt or MAX_SECTIONS may need to be increased\n");
			free(b);
			return GENERIC_ERROR;
		}
		size_t origsize = strlen(b->bNameA) + 1;
		wchar_t tmp[MAX_BIN_NAME_LEN];
		//convert from char * to wchar_t *
		mbstowcs_s(&bytesConverted, tmp, origsize, b->bNameA, _TRUNCATE);
		if(wcscmp(b->bNameW, tmp) != 0){
			printf("bNameA and bNameW fields don't match, probably corrupted data\n");
			free(b);
			return GENERIC_ERROR;
		}

		//Must aquire mutex before modifying stMsgStorageVector
		if(WaitForSingleObject(stMsgStorageVectorMutex, INFINITE) != WAIT_OBJECT_0){
			printf("ServerRequestListenerThread: Couldn't acquire mutex. Returning\n");
			__asm{int 3};
			free(b);
			return GENERIC_ERROR;
		}

		stMsgStorageVector.push_back(b);

		if(!ReleaseMutex(stMsgStorageVectorMutex)){
			printf("ServerRequestListenerThread: Couldn't release mutex. Returning\n");
			__asm{int 3};
			free(b);
			return GENERIC_ERROR;
		}

		//Ack the data
		ret = SendAck(gAcceptedSocket, b->sequenceNum);
		if(ret == GENERIC_ERROR){
			printf("Failed to send ack for data. This shouldn't occur, so investigate.\n");
			__asm{int 3};
			free(b);
			exit(-1);
		}

		//Wakeup the main thread to process the received data
		SetEvent(hWaitForResponse);
	}


	return GENERIC_SUCCESS;
}

//If this succeeds, gAcceptedSocket will be set up correctly
int InitializeSocket(){
	
	SOCKET sd;
	WSADATA w;							/* Used to open windows connection */
	char * host_name = "localhost";

	tiresias.sin_family = AF_INET;
	tiresias.sin_port =  htons(0xd00d); //53261

	tiresias.sin_addr.S_un.S_un_b.s_b1 = 127;
	tiresias.sin_addr.S_un.S_un_b.s_b2 = 0;
	tiresias.sin_addr.S_un.S_un_b.s_b3 = 0;
	tiresias.sin_addr.S_un.S_un_b.s_b4 = 1;

	//tiresias.sin_addr.S_un.S_un_b.s_b1 = 192;
	//tiresias.sin_addr.S_un.S_un_b.s_b2 = 168;
	//tiresias.sin_addr.S_un.S_un_b.s_b3 = 187;
	//tiresias.sin_addr.S_un.S_un_b.s_b4 = 129;

	//tiresias.sin_addr.S_un.S_un_b.s_b1 = 0;
	//tiresias.sin_addr.S_un.S_un_b.s_b2 = 0;
	//tiresias.sin_addr.S_un.S_un_b.s_b3 = 0;
	//tiresias.sin_addr.S_un.S_un_b.s_b4 = 0;



	//server.sin_family = AF_INET;
	//server.sin_port = htons(0xd0ed);  //53485
	//
	////server.sin_addr.S_un.S_un_b.s_b1 = 127;
	////server.sin_addr.S_un.S_un_b.s_b2 = 0;
	////server.sin_addr.S_un.S_un_b.s_b3 = 0;
	////server.sin_addr.S_un.S_un_b.s_b4 = 1;

	//server.sin_addr.S_un.S_un_b.s_b1 = 192;
	//server.sin_addr.S_un.S_un_b.s_b2 = 168;
	//server.sin_addr.S_un.S_un_b.s_b3 = 187;
	//server.sin_addr.S_un.S_un_b.s_b4 = 129;

	if(WSAStartup(0x0101, &w) != 0){
		fprintf(stderr, "Could not open Windows connection.\n");
		return GENERIC_ERROR;
	}

	/* Open a datagram socket */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == INVALID_SOCKET)
	{
		fprintf(stderr, "Could not create socket.\n");
		WSACleanup();
		return GENERIC_ERROR;
	}

	/* Bind address to socket */
	if (bind(sd, (struct sockaddr *)&tiresias, sizeof(struct sockaddr_in)) == -1)
	{
		fprintf(stderr, "Could not bind name to socket.\n");
		closesocket(sd);
		WSACleanup();
		return GENERIC_ERROR;
	}

	gAcceptedSocket = sd;
	return GENERIC_SUCCESS;
}

//DEPRECATED: Changed to using a dedicated thread
//int ReceiveSTMsg(SOCKET s){
//	unsigned int ret;
//	//char buf[255];
//	//memset(buf, 0, 255);
//	int totalBytesRecvd = 0;
//	int bytesRecvd = 0;
//	size_t bytesConverted;
//
//	char buffer[4096];	
//	int server_length = (int)sizeof(struct sockaddr_in);
//
//	while (1){
//		/* Receive bytes from server */
//		totalBytesRecvd = recvfrom(s, buffer, 4096, 0, (struct sockaddr *)&server, &server_length);
//		if (totalBytesRecvd < 0)
//		{
//			fprintf(stderr, "Could not receive datagram.\n");
//			closesocket(s);
//			WSACleanup();
//			return GENERIC_ERROR;
//		}
//
//		if(totalBytesRecvd > 0){
//			break;
//		}
//	}
//
//	st_msg_t * b = (st_msg_t *)malloc(sizeof(st_msg_t));
//	memcpy(b, buffer, sizeof(st_msg_t));
//
//	//Sanity check the data
//	if(b->numROSections > MAX_SECTS_TO_MEASURE){
//		printf("b->numROSections > MAX_SECTS_TO_MEASURE, data may be corrupt or MAX_SECTIONS may need to be increased\n");
//		return GENERIC_ERROR;
//	}
//	size_t origsize = strlen(b->bNameA) + 1;
//	wchar_t tmp[MAX_BIN_NAME_LEN];
//	//convert from char * to wchar_t *
//	mbstowcs_s(&bytesConverted, tmp, origsize, b->bNameA, _TRUNCATE);
//	if(wcscmp(b->bNameW, tmp) != 0){
//		printf("bNameA and bNameW fields don't match, probably corrupted data\n");
//		return GENERIC_ERROR;
//	}
//
//	//Ack the data
//	ret = SendAck(gAcceptedSocket, b->sequenceNum);
//	if(ret == GENERIC_ERROR){
//		printf("Failed to send ack for data. This shouldn't occur, so investigate.\n");
//		__asm{int 3};
//		exit(-1);
//	}
//
//	stMsgStorageVector.push_back(b);
//
//	SetEvent(hWaitForResponse);
//	return GENERIC_SUCCESS;
//}

//Acknowledge that we got a given piece of data
int SendAck(SOCKET s, unsigned int num){
	char finalMsgStr[14];
	memset(finalMsgStr, 0, 14);
	//Maximum size of the below string when interpolated =
	//3 hardcoded chars + 
	//1 * 10 chars for max 32 bit number (4billion) + 
	//1 null character = 14 chars
	char * msgStr = "A:%u:";
	unsigned int len = sprintf_s(finalMsgStr, 14, msgStr, num);
	if(len == 0){
		printf("SendAck sprintf_s failed\n");
		return GENERIC_ERROR;
	}
	unsigned int bytesSent = sendto(s, finalMsgStr, len, 0,(struct sockaddr *)&server, sizeof(struct sockaddr_in));
	if(bytesSent == SOCKET_ERROR){
		printf("SendAck send failed\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SendDone(SOCKET s, unsigned int num){
	char finalMsgStr[14];
	memset(finalMsgStr, 0, 14);
	//Maximum size of the below string when interpolated =
	//3 hardcoded chars + 
	//1 * 10 chars for max 32 bit number (4billion) + 
	//1 null character = 14 chars
	char * msgStr = "D:%u:";
	unsigned int len = sprintf_s(finalMsgStr, 14, msgStr, num);
	if(len == 0){
		printf("SendDone sprintf_s failed\n");
		return GENERIC_ERROR;
	}

	unsigned int bytesSent = sendto(s, finalMsgStr, len, 0, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
	if(bytesSent == SOCKET_ERROR){
		printf("SendDone send failed\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SendError(SOCKET s, unsigned int num, unsigned int stErrNo){
	char finalMsgStr[25];
	memset(finalMsgStr, 0, 25);
	//Maximum size of the below string when interpolated =
	//4 hardcoded chars + 
	//2 * 10 chars for max 32 bit number (4billion) + 
	//1 null character = 25 chars
	char * msgStr = "E:%u:%u:"; 
	unsigned int len = sprintf_s(finalMsgStr, 25, msgStr, num, stErrNo);
	if(len == 0){
		printf("SendError sprintf_s failed\n");
		return GENERIC_ERROR;
	}

	unsigned int bytesSent = sendto(s, finalMsgStr, len, 0, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
	if(bytesSent == SOCKET_ERROR){
		printf("SendError send failed\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}


char * MsgTypeToString(msgType m){
	switch(m){
		case SELF_ATTESTATION: 
			return "SELF_ATTESTATION";
		case ERROR_MSG: 
			return "ERROR_MSG";
		case TIMING_TEST: 
			return "TIMING_TEST";
		case TICKSTAMP_ATTESTATION:
			return "TICKSTAMP_ATTESTATION";
	}
	return NULL;
}