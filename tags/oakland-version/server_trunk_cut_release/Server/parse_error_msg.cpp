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

//This can be error messages from either server/client or server/tiresias
//communications

#include "parse_error_msg.h"
#include "server_client_protocol.h"

extern "C"{
	#include "database_mysql.h"
	extern MYSQL mysqlMeasurements;
	extern "C" HANDLE mysqlMutex;
}

//These are our error codes which the client can send back but which we don't want to
//put into it as-is for opsec reasons of not having useful strings in the client binary
char * error0 = "gCrashed = TRUE so ignoring server packets";
char * error1 = "gPFNFound = FALSE so ignoring server packets";
char * error11 = "Measurement type %s failed with ntStatus %s";
char * error17 = "Could not allocate memory\n";
char * error20 = "TPM Not Enabled on Client System\n";
char * error21 = "TPM TickStamp Failed. TPM Probably does not have a signing key properly loaded\n";


//TODO: document this somewhere real:
//The format of the error packet is response_hdr_t followed by a char array
//of size errMsgLenWithNull. The response_hdr_t.numElements holds the string length
//including the null character
int ParseClientErrorPacket(me_t * incomingME){
	response_hdr_t * responseHdr = (response_hdr_t *)incomingME->pktData;
	char errorMsgBuf[200];
	char * tok, * tok2, * context;
	char * errorStr;
	unsigned int offsetToString = sizeof(response_hdr_t);
	int ret;

	//Sanity checks
	if(responseHdr == NULL || incomingME->pktLen != (sizeof(response_hdr_t) + responseHdr->numElements))
	{
		printf("ParseClientErrorPacket: was sent an invalid error message\n");
		return GENERIC_ERROR;
	}

	if(offsetToString >= incomingME->pktLen){
		printf("ParseClientErrorPacket: malformed packet\n");
		return GENERIC_ERROR;
	}

	errorStr =(char *)responseHdr + offsetToString;

	if(errorStr == NULL || (strlen(errorStr)+1) != responseHdr->numElements){
		printf("ParseClientErrorPacket: was sent an invalid error message\n");
		return GENERIC_ERROR;
	}

	//Tokenize the error string
	//skip anything except lines starting with a number
	if(errorStr[0] != '0' && errorStr[0] != '1' && errorStr[0] != '2' && errorStr[0] != '3' &&
		errorStr[0] != '4' && errorStr[0] != '5' && errorStr[0] != '6' && errorStr[0] != '7' &&
		errorStr[0] != '8' && errorStr[0] != '9')
	{
		printf("INVALID FORMAT FOR ERROR MESSAGE\n");
		return GENERIC_ERROR;
	}
	//Get the number indicating the error type
	tok = strtok_s(errorStr, ":", &context);
	if(tok == NULL){
		printf("ParseClientErrorPacket:error: strtok unexpectedly failed. Check config file structure\n");
		return GENERIC_ERROR;
	}
	switch(strtoul(tok, NULL, 10)){
		case 0:
			//Nothing to interpolate
			strncpy_s(errorMsgBuf, 200, error0, 200);
			break;
		case 1:
			//Nothing to interpolate
			strncpy_s(errorMsgBuf, 200, error1, 200);
			break;
		case 11:
			tok = strtok_s(NULL, ":", &context);
			if(tok == NULL){
				printf("ParseClientErrorPacket:error: strtok unexpectedly failed for error type/case %d\n", 11);
				return GENERIC_ERROR;
			}
			tok2 = strtok_s(NULL, ":", &context);
			if(tok2 == NULL){
				printf("ParseClientErrorPacket:error: strtok 2 unexpectedly failed for error type/case %d\n", 11);
				return GENERIC_ERROR;
			}
			//Interpolate according to fixed error message string
			sprintf_s(errorMsgBuf, 200, error11, tok, tok2);
			break;
		case 17:
			//Nothing to interpolate
			strncpy_s(errorMsgBuf, 200, error17, 200);
			break;
		case 20:
			//Nothing to interpolate
			strncpy_s(errorMsgBuf, 200, error20, 200);
			break;
		case 21:
			//Nothing to interpolate
			strncpy_s(errorMsgBuf, 200, error21, 200);
			break;
		default:
			printf("UNKNOWN ERROR MESSAGE TYPE\n");
			//TODO: INSERT ERROR INTO DB
			errorMsgBuf[0] = 0;
			break;
	}

	printf("**********************************************\n\
ParseClientErrorPacket: Client sent error message: \n\
\t'%s'\n\
**********************************************\n", errorMsgBuf);

	ret = InsertErrorLog(CLIENT_ERROR, incomingME->timeInSeconds, incomingME->hostID, errorMsgBuf);
	if(ret != GENERIC_SUCCESS){
		printf("ParseClientErrorPacket: InsertErrorLog failed\n");
		return GENERIC_ERROR;
	}

	// Clean up the pending measurement for failed measurements
	ret = DeleteFromTableByID("PendingMeasurementEvents", incomingME->id);
	if(ret != GENERIC_SUCCESS){
		printf("ParseClientErrorPacket: DeleteFromTableByID PendingMeasurementEvents failed\n");
	}

	return GENERIC_SUCCESS;
}