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

#include "parse_tpm_measurement.h"
#include "server_client_protocol.h"
#include "database_mysql2.h"
#include "server_tiresias_protocol.h"
#include "request_measurement.h"

#include <vector>
#include <map>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

extern "C"{
	#include "database_mysql.h"
}
extern "C" char * gffServerDBName;
extern "C" char * gffTiresiasDBName;


extern int gVerbose, gQuiet;
extern SOCKET tiresiasConnectSocket;

using namespace std;

extern HANDLE alertEvent;
extern "C" HANDLE mysqlMutex;
extern char gffAlertingEnabled;
extern string gffDefaultSrcIPStr;
extern char * gffKeysFolder;
extern unsigned int gffTPMTicksDeltaLimit;


VOID PrintHash(unsigned char *hash);
int InsertTPMDeltaTicks(unsigned long long deltaTicks, unsigned int hostID, unsigned int *id);
RSA *GetTPMKeyForHost(char *hostName);
unsigned int VerifyTickStampSignature(RSA * signingKey, tick_stamp_t tickStamp);
unsigned long long GetTicksFromTickStamp(tick_stamp_t tickStamp);
void SHA1String(unsigned char *hash, unsigned char *msg, unsigned int len);

int ParseTickStampAttestationMeasurement(me_t * incomingME){
	response_hdr_t * responseHdr = (response_hdr_t *)(incomingME->pktData);
	self_check_t * selfCheck = (self_check_t *)(incomingME->pktData + sizeof(response_hdr_t));
	unsigned int hostID;
	int ret;
	RSA *tpmKey;
	unsigned long long deltaTicks;
	unsigned char hash[20];
	unsigned int insertID;

	char ipString[16];
	char hostName[128];
	bool alertOccured = false;

	ret = SelectHostIDByNetorderIP(incomingME->ip, &hostID);
	if (ret != GENERIC_SUCCESS)
	{
		printf("ParseTickStampAttestationMeasurement: SelectHostIDbyNetorderIP failed\n");
		return ret;
	}

	ret = SelectHostIPByID(incomingME->hostID, ipString);
	if(ret != GENERIC_SUCCESS){
		printf("ParseTickStampAttestationMeasurement: SelectHostIPByID failed\n");
		return ret;
	}
	ipString[15] = 0;

	//We need the hostname in order to find the public part of the tpm signing key
	memset(hostName,0x00,128);
	ret = SelectHostNameByID(incomingME->hostID, hostName);
	if (ret != GENERIC_SUCCESS)
	{
		printf("ParseTickStampAttestationMeasurement: SelectHostNameByID failed\n");
		return ret;
	}

	//printf("TickStampAttestation fail detected at IP: %s", ipString);;

	printf("Received TickStampAttestation from host: %d\n", hostID);

	tpmKey = GetTPMKeyForHost(hostName);
	if (tpmKey == NULL)
	{
		printf("ParseTickStampAttestationMeasurement: No TPM Key for host %s\n", hostName);
		return GENERIC_ERROR;
	}
	
	if (!VerifyTickStampSignature(tpmKey,selfCheck->startTickStamp) ||
		!VerifyTickStampSignature(tpmKey,selfCheck->endTickStamp))
	{
		printf("TickStamp Signature verification failed for host %u\n", incomingME->hostID);
	} else {
		printf("verified the tickstamp signature\n");
	}

	//Now we need to verify the data signed by the client is sane and legitimate
	//first make sure that the data signed by the client was actually the checksum.
	//otherwise the attacker could sign bogus data, then calculate the correct checksum outside of the
	//enclosure of the tickstamps. Then the checksum would be correct, and the difference in the tpm tick
	//counts would not reflect the actual time is took to calculate the self checksum
	SHA1String(hash,(unsigned char *)(&selfCheck->checksum[0]),SELF_CHECKSUM_SIZE*sizeof(unsigned int));
	if (memcmp(hash,selfCheck->endTickStamp.digest,20))
	{
		printf("Something other than the checksum was signed. Possible attack occuring\n");
	}

	
	//Make sure the client was actually seeding its tickstamp attestations off of the original server nonce
	//otherwise the client can perform precalculation attacks by precalculating a checksum off a bogus nonce
	//and then lieing to the server about what the nonce was
	SHA1String(hash,(unsigned char *)&(incomingME->nonce),sizeof(unsigned int));
	if (memcmp(hash,selfCheck->startTickStamp.nonce, 20))
	{
		printf("Tickstamps were not seeded off of original server nonce. Possible precalculation attack occuring\n");
	}
	

	deltaTicks = GetTicksFromTickStamp(selfCheck->endTickStamp);
	deltaTicks -= GetTicksFromTickStamp(selfCheck->startTickStamp);

	if (!gQuiet)
		printf("TickStamp Attestation took: %lld tpm ticks\n", deltaTicks);

	//COREY: deleting this for now since different keys generate different tick counts..
	/*
	if (deltaTicks > gffTPMTicksDeltaLimit)
	{
		memset(line1,0x00,1024);
		sprintf_s(line1, 1024, "TickStamp Attestation took %lld tpm ticks, which is suspiciously long\n", deltaTicks);
		alert.AppendNOMEKMessage(line1);
		alertOccured = true;
		printf("%s", line1);
	}
	*/

	ret = InsertTPMDeltaTicks(deltaTicks,hostID,&insertID);
	if (ret != GENERIC_SUCCESS)
	{
		printf("ParseTickStampAttestationMeasurement: InsertTPMDeltaTicks failed\n");
		return ret;
	}

	selfCheck->nonce = *((unsigned int *)(&selfCheck->startTickStamp.signature));

	//Ask tiresias what the correct checksum should be
	ret = RequestChecksumMeasurementFromTiresias(tiresiasConnectSocket, incomingME->hostID, selfCheck, TICKSTAMP_ATTESTATION);
	if(ret != GENERIC_SUCCESS){
		printf("ParseTickStampAttestationMeasurement: RequestChecksumMeasurementFromTiresias failed\n");
		return ret;
	}

	//Now move the pending measurement to the final measurements
	me_t pendingME; //just used to hold the values currently in the db for sanity checking

	ret = SelectPendingMEByIncomingME(incomingME, &pendingME);
	if(ret != GENERIC_SUCCESS){
		printf("ParseTickStampAttestationMeasurement: SelectPendingMEByIncomingME failed\n");
		return GENERIC_ERROR;
	}

	incomingME->overloadedForeignID = insertID;

	ret = MovePendingMeasurementToFinalMeasurements(incomingME, &pendingME, true);
	if(ret != GENERIC_SUCCESS){
		printf("ParseTickStampAttestationMeasurement: MovePendingMeasurementToFinalMeasurements failed\n");
		return GENERIC_ERROR;
	}

	return ret;
}

int InsertTPMDeltaTicks(unsigned long long deltaTicks, unsigned int hostID, unsigned int *id) {
	char * fixedInsertStr;
	unsigned int len;
	int ret;
	char query[300];

	fixedInsertStr = "INSERT INTO TPMTicks(hostID,deltaTicks) values (%u, %lld)";
	len = sprintf_s(query, 300, fixedInsertStr, hostID, deltaTicks);

	ret = ExecuteInsert(SERVER, query, len, id); 
	return ret;
}


RSA *GetTPMKeyForHost(char *hostName)
{
	RSA *key;
	char keyPath[256];
	FILE *fp;

	memset(keyPath,0x00,256);
	sprintf_s(keyPath,256,"%s%s.pem",gffKeysFolder,hostName);

	fopen_s(&fp, keyPath, "r");
	if (fp == NULL)
	{
		printf("GetTPMKeyForHost: failed to find tpm signing key for host %s\n", hostName);
		return NULL;
	}

	key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	if (key == NULL)
	{
		printf("GetTPMKeyForHost: PEM_read_RSA_PUBKEY failed on %s\n", keyPath);
		return NULL;
	}
	fclose(fp);

	return key;
}

//returns 1 if signature verifies
//returns 0 if signature fails verification
unsigned int VerifyTickStampSignature(RSA * signingKey, tick_stamp_t tickStamp)
{
	unsigned char sighash[20];
	unsigned char tpmbuf[82];
	int ret;
	
	memset(tpmbuf,0x00,82);
	
	//stamp in some tpm control bytes that end up in the blob the tpm signs
	//Reverse engineered this structure, seems to work. These bytes remain
	//constant no matter what data is being signed by the tpm
	tpmbuf[1] = 0x05;
	tpmbuf[2] = 0x54;
	tpmbuf[3] = 0x53;
	tpmbuf[4] = 0x54;
	tpmbuf[5] = 0x50;
	tpmbuf[29] = 0x34;

	//now stamp in actual meaningful data that the tpm incorporated into the signature
	memcpy(&tpmbuf[6],tickStamp.nonce,20);
	memcpy(&tpmbuf[30],tickStamp.digest,20);
	memcpy(&tpmbuf[50],tickStamp.ticks,32);

	SHA1String(sighash,tpmbuf,82);
	ret = RSA_verify(NID_sha1, sighash, 20, tickStamp.signature,256,signingKey);
	if (ret == 1)
		return 1;
	else
		return 0;
}

unsigned long long GetTicksFromTickStamp(tick_stamp_t tickStamp)
{
	unsigned char tickBuff[8];
	tickBuff[0] = tickStamp.ticks[9];
	tickBuff[1] = tickStamp.ticks[8];
	tickBuff[2] = tickStamp.ticks[7];
	tickBuff[3] = tickStamp.ticks[6];
	tickBuff[4] = tickStamp.ticks[5];
	tickBuff[5] = tickStamp.ticks[4];
	tickBuff[6] = tickStamp.ticks[3];
	tickBuff[7] = tickStamp.ticks[2];
	return *((unsigned long long *)tickBuff);
}

void SHA1String(unsigned char *hash, unsigned char *msg, unsigned int len)
{
	SHA_CTX sha;
	SHA1_Init(&sha);
	SHA1_Update(&sha, msg, len);
	SHA1_Final(hash, &sha);
}


VOID PrintHash(unsigned char *hash)
{
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],hash[8],hash[9],hash[10],hash[11],hash[12],hash[13],hash[14],hash[15],hash[16],hash[17],hash[18],hash[19]);
}
