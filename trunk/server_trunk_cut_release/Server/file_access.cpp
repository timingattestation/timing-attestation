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

//For any functions that needs to access the filesystem 
//e.g. to get known good files, read the config file, etc

#include "file_access.h"
#include "database_mysql2.h"
#include <windows.h>

#include <iostream>
#include <fstream>

#include <ctype.h>

//LEAK DETECTION!
//#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#ifdef _DEBUG
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

//In general config variables should be defined here and included as 
//extern vars in other files

//Used throughout
string gffDefaultSrcIPStr;
string gffDefaultDstIPStr;
string gffDefaultDstHostName;

//Used in main
char gffSniffingInterface;

//Used by alerting thread
char gffAlertingEnabled; //used like a bool, but want it to work in C files if necessary
char * gffEmailAddress; //Where to send analyst alerts if email alerting is enabled
char * gffDevEmailAddress; //Where to send developer alerts if email alerting is enabled

//Used by polling thread
unsigned int gffPollingFrequency;
unsigned int gffPollingTolerance;

//Used by pending monitor thread
unsigned int gffMonitorFrequency;
unsigned int gffMonitorStaleTolerance;
unsigned int gffMonitorFailTolerance;

//Used by self test moving average window
unsigned int movingAverageWindowLength;
unsigned int selfTestAlertingThreshold;

unsigned int measurementRate;

//used by tpm measurement
char *gffKeysFolder;
unsigned int gffTPMTicksDeltaLimit;

//EXTERNS

extern "C"{
	//Defined in database_mysql.c
	extern char * gffTiresiasDBName;
	extern char * gffServerDBName;
	extern char * gffSharedDBName;
	extern char * gffDatabaseUsername;
	extern char * gffDatabasePassword;
	extern MYSQL mysqlMeasurements;
	//extern HANDLE mysqlMeasurementsMutex;
	//extern HANDLE mysqlMutex;
}


//Define in main.cpp
extern vector <string> gffHostsToMeasure;
extern vector <string> gffModulesToMeasure;
extern vector <string> gffBrandStringLimits;
extern vector <string> gffHostLimits;

using namespace std;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//Really simple parser for my really simple config file format
int ReadConfigAndSetGlobs(char * configFileName){
	char * holder;
	char * tok, * tok2;
	unsigned int tokLen = 0;
	char line[MAX_LINE];
	string * s;
	char * context;
	FILE * myStream;
	unsigned int ret = 0;

	gffTiresiasDBName = NULL;
	gffServerDBName = NULL;
	gffDatabaseUsername = NULL;
	gffDatabasePassword = NULL;
	gffSniffingInterface = 0;
	gffAlertingEnabled = 0;
	gffDevEmailAddress = NULL;

	gffMonitorFrequency = 0;
	gffMonitorStaleTolerance = 0;
	gffMonitorFailTolerance = 0;

	errno_t err = fopen_s(&myStream, configFileName,"rb");
	if(err != 0){
		printf("ReadConfigAndSetGlobs:error: Couldn't open %s\n", configFileName);
		return GENERIC_ERROR;
	}

	while(!feof(myStream)){
		holder = fgets(line, MAX_LINE, myStream);
		if(holder == NULL){
			if(feof(myStream)){
				//successfully reached the end of file
				fclose(myStream);
				return GENERIC_SUCCESS;
				break;
			}
			else{
				printf("ReadConfigAndSetGlobs:error: fgets had an unexpected error\n");
				goto invalidConfig;
			}
		}
		//skip anything except lines starting with a number
		if(line[0] != '0' && line[0] != '1' && line[0] != '2' && line[0] != '3' &&
			line[0] != '4' && line[0] != '5' && line[0] != '6' && line[0] != '7' &&
			line[0] != '8' && line[0] != '9'){
			continue;
		}
		tok = strtok_s(line, ":", &context);
		if(tok == NULL){
			printf("ReadConfigAndSetGlobs:error: strtok unexpectedly failed. Check config file structure\n");
			goto invalidConfig;
		}
		switch(strtoul(tok, NULL, 10)){
			case 0:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "DATABASE_USERNAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 0 should be matched with DATABASE_USERNAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DATABASE_USERNAME"))){
					printf("ReadConfigAndSetGlobs:Error: DATABASE_USERNAME may have been truncated due to length. \
							Decrease DATABASE_USERNAME length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffDatabaseUsername = (char *) malloc(tokLen+1);
				if(gffDatabaseUsername == NULL){
					goto invalidConfig;
				}
				strcpy_s(gffDatabaseUsername, tokLen+1, tok);
				//printf("Found database username of '%s'\n", gffDatabaseUsername);
				break;
			case 1:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "DATABASE_PASSWORD") != 0){
					printf("ReadConfigAndSetGlobs:Error: 1 should be matched with DATABASE_PASSWORD\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DATABASE_PASSWORD"))){
					printf("ReadConfigAndSetGlobs:Error: DATABASE_PASSWORD may have been truncated due to length. \
							Decrease DATABASE_PASSWORD length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffDatabasePassword = (char *) malloc(tokLen+1);
				if(gffDatabasePassword == NULL){
					goto invalidConfig;
				}
				strcpy_s(gffDatabasePassword, tokLen+1, tok);
				//printf("Found database password of '%s'\n", gffDatabasePassword);
				break;
			case 2:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "TIRESIAS_DB_NAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 2 should be matched with TIRESIAS_DB_NAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("TIRESIAS_DB_NAME"))){
					printf("ReadConfigAndSetGlobs:Error: TIRESIAS_DB_NAME may have been truncated due to length. \
							Decrease TIRESIAS_DB_NAME length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffTiresiasDBName = (char *) malloc(tokLen+1);
				if(gffTiresiasDBName == NULL){
					goto invalidConfig;
				}
				strcpy_s(gffTiresiasDBName, tokLen+1, tok);
				printf("Found tiresias database name of '%s'\n", gffTiresiasDBName);
				break;
			case 3:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "SERVER_DB_NAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 3 should be matched with SERVER_DB_NAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("SERVER_DB_NAME"))){
					printf("ReadConfigAndSetGlobs:Error: SERVER_DB_NAME may have been truncated due to length. \
							Decrease SERVER_DB_NAME length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffServerDBName = (char *) malloc(tokLen+1);
				if(gffServerDBName == NULL){
					goto invalidConfig;
				}
				strcpy_s(gffServerDBName, tokLen+1, tok);
				printf("Found measurements database name of '%s'\n", gffServerDBName);
				break;
			case 25:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "SHARED_DB_NAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 2 should be matched with SHARED_DB_NAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("SHARED_DB_NAME"))){
					printf("ReadConfigAndSetGlobs:Error: SHARED_DB_NAME may have been truncated due to length. \
							Decrease SHARED_DB_NAME length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffSharedDBName = (char *) malloc(tokLen+1);
				if(gffSharedDBName == NULL){
					goto invalidConfig;
				}
				strcpy_s(gffSharedDBName, tokLen+1, tok);
				printf("Found shared database name of '%s'\n", gffSharedDBName);
				break;
			case 4:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "SNIFFING_INTERFACE") != 0){
					printf("ReadConfigAndSetGlobs:Error: 4 should be matched with SNIFFING_INTERFACE\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("SNIFFING_INTERFACE"))){
					printf("ReadConfigAndSetGlobs:Error: SNIFFING_INTERFACE may have been truncated due to length. \
							Decrease SNIFFING_INTERFACE length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffSniffingInterface = (char)strtoul(tok, NULL, 10);
				printf("Found sniffing interface of '%u'\n", gffSniffingInterface);
				break;
			case 5:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "DEFAULT_SRC_IP") != 0){
					printf("ReadConfigAndSetGlobs:Error: 5 should be matched with DEFAULT_SRC_IP\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DEFAULT_SRC_IP"))){
					printf("ReadConfigAndSetGlobs:Error: database name may have been truncated due to length. \
							Decrease DEFAULT_SRC_IP length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				if(isspace(tok[0])){
					gffDefaultSrcIPStr.assign("");
				}else{
					gffDefaultSrcIPStr.assign(tok);
				}
				printf("Found default source IP of '%s'\n", gffDefaultSrcIPStr.c_str());
				break;
			case 6:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "DEFAULT_DST_IP") != 0){
					printf("ReadConfigAndSetGlobs:Error: 6 should be matched with DEFAULT_DST_IP\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DEFAULT_DST_IP"))){
					printf("ReadConfigAndSetGlobs:Error: database name may have been truncated due to length. \
							Decrease DEFAULT_DST_IP length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				if(isspace(tok[0])){
					gffDefaultDstIPStr.assign("");
				}else{
					gffDefaultDstIPStr.assign(tok);
				}
				printf("Found default destination IP of '%s'\n", gffDefaultDstIPStr.c_str());
				break;
			case 7:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "DEFAULT_DST_HOSTNAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 7 should be matched with DEFAULT_DST_HOSTNAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DEFAULT_DST_HOSTNAME"))){
					printf("ReadConfigAndSetGlobs:Error: Decrease DEFAULT_DST_HOSTNAME length or increase MAX_LINE in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				if(isspace(tok[0])){
					gffDefaultDstHostName.assign("");
				}else{
					gffDefaultDstHostName.assign(tok);
				}

				printf("Found default destination hostname of '%s'\n", gffDefaultDstHostName.c_str());
				break;
			case 8:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "POLLING_FREQUENCY") != 0){
					printf("ReadConfig:Error: 8 should be matched with POLLING_FREQUENCY\n");
					fclose(myStream);
					return GENERIC_ERROR;
				}
				tok = strtok_s(NULL, ":", &context);
				gffPollingFrequency = strtoul(tok, NULL, 10);
				
				printf("Found polling frequency of '%d'\n", gffPollingFrequency);
				break;
			case 9:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "POLLING_TOLERANCE") != 0){
					printf("ReadConfig:Error: 9 should be matched with POLLING_TOLERANCE\n");
					fclose(myStream);
					return GENERIC_ERROR;
				}
				tok = strtok_s(NULL, ":", &context);
				gffPollingTolerance = strtoul(tok, NULL, 10);
				
				printf("Found polling tolerance of '%d'\n", gffPollingTolerance);
				break;
			case 12:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "HOSTS_TO_MEASURE") != 0){
					printf("ReadConfigAndSetGlobs:Error: 12 should be matched with HOSTS_TO_MEASURE\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("HOSTS_TO_MEASURE"))){
					printf("ReadConfigAndSetGlobs:Error: database name may have been truncated due to length. \
							Decrease HOSTS_TO_MEASURE length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				//Now we have a comma-deliminated list and we need to tokenize that as well.
				tok2 = strtok_s(tok, ",", &context);
				if(tok2 == NULL){
					printf("ReadConfigAndSetGlobs: HOSTS_TO_MEASURE error: strtok unexpectedly failed. Check CDL structure\n");
					goto invalidConfig;
				}
				printf("HostsToMeasure %s\n", tok2);
				s = new string(tok2);
				gffHostsToMeasure.push_back(*s);
				

				delete s;
				
				while(1){
					tok2 = strtok_s(NULL, ",", &context);
					if(tok2 == NULL){ break; }
					printf("HostsToMeasure %s\n", tok2);
					s = new string(tok2);
					gffHostsToMeasure.push_back(*s);
					delete s;
				}
				break;
			case 13:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "MODULES_TO_MEASURE") != 0){
					printf("ReadConfigAndSetGlobs:Error: 13 should be matched with MODULES_TO_MEASURE\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("MODULES_TO_MEASURE"))){
					printf("ReadConfigAndSetGlobs:Error: database name may have been truncated due to length. \
							Decrease MODULES_TO_MEASURE length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				//Now we have a comma-deliminated list and we need to tokenize that as well.
				tok2 = strtok_s(tok, ",", &context);
				if(tok2 == NULL){
					printf("ReadConfigAndSetGlobs: MODULES_TO_MEASURE error: strtok unexpectedly failed. Check CDL structure\n");
					goto invalidConfig;
				}
				printf("ModulesToMeasure %s\n", tok2);
				s = new string(tok2);
				gffModulesToMeasure.push_back(*s);


				delete s;

				while(1){
					tok2 = strtok_s(NULL, ",", &context);
					if(tok2 == NULL){ break; }
					printf("ModulesToMeasure %s\n", tok2);
					s = new string(tok2);
					gffModulesToMeasure.push_back(*s);


					delete s;
				}

				break;
			

			case 20:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "HOST_LIMITS") != 0){
					printf("ReadConfigAndSetGlobs:Error: 20 should be matched with HOST_LIMITS\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("HOST_LIMITS"))){
					printf("ReadConfigAndSetGlobs:Error: HOST_LIMITS is not properly set\n");
					goto invalidConfig;
				}
				//Now we have a comma-deliminated list and we need to tokenize that as well.
				tok2 = strtok_s(tok, ",", &context);
				if(tok2 == NULL){
					printf("ReadConfigAndSetGlobs: HOST_LIMITS error: strtok unexpectedly failed.\n");
					goto invalidConfig;
				}else{
					printf("HOST_LIMITS: %s\n", tok2);
					s = new string(tok2);
					gffHostLimits.push_back(*s);
					delete s;
				}

				while(1){
					tok2 = strtok_s(NULL, ",", &context);
					if(tok2 == NULL){ break; }
					printf("HOST_LIMITS: %s\n", tok2);
					s = new string(tok2);
					gffHostLimits.push_back(*s);
					delete s;
				}
				break;
			

			case 21:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "BRANDSTRING_LIMITS") != 0){
					printf("ReadConfigAndSetGlobs:Error: 21 should be matched with BRANDSTRING_LIMITS\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("BRANDSTRING_LIMITS"))){
					printf("ReadConfigAndSetGlobs:Error: BRANDSTRING_LIMITS is not properly set\n");
					goto invalidConfig;
				}
				//Now we have a comma-deliminated list and we need to tokenize that as well.
				tok2 = strtok_s(tok, ",", &context);
				if(tok2 == NULL){
					printf("ReadConfigAndSetGlobs: BRANDSTRING_LIMITS error: strtok unexpectedly failed.\n");
					goto invalidConfig;
				}else{
					printf("BRANDSTRING_LIMITS: %s\n", tok2);
					s = new string(tok2);
					gffBrandStringLimits.push_back(*s);
					delete s;
				}

				while(1){
					tok2 = strtok_s(NULL, ",", &context);
					if(tok2 == NULL){ break; }
					printf("BRANDSTRING_LIMITS: %s\n", tok2);
					s = new string(tok2);
					gffBrandStringLimits.push_back(*s);
					delete s;
				}
				break;
			case 26:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "KEYS_FOLDER_NAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 26 should be matched with KEYS_FOLDER_NAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("KEYS_FOLDER_NAME"))){
					printf("ReadConfigAndSetGlobs:Error: database name may have been truncated due to length. \
							Decrease KEYS_FOLDER_NAME length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffKeysFolder = (char *) malloc(tokLen+1);
				if(gffKeysFolder == NULL){
					goto invalidConfig;
				}
				strcpy_s(gffKeysFolder, tokLen+1, tok);
				break;
			case 27:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "TPM_TICKS_LIMIT") != 0){
					printf("ReadConfigAndSetGlobs:Error: 27 should be matched with TPM_TICKS_LIMIT\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("TPM_TICKS_LIMIT"))){
					printf("ReadConfigAndSetGlobs:Error: TPM_TICKS_LIMIT may have been truncated due to length. \
							Decrease TPM_TICKS_LIMIT length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffTPMTicksDeltaLimit = (unsigned int)strtoul(tok, NULL, 10);
				printf("Found tpm attestation tick limit of '%u'\n", gffTPMTicksDeltaLimit);
				break;
			default:
				printf("Unknown case in config file. Exiting. \n");
				goto invalidConfig;
		}
	}

	printf("\n");
	fclose(myStream);
	return GENERIC_SUCCESS;

invalidConfig:
	fclose(myStream);
	return INVALID_CONFIG;
}

//This can only be called after the database is initialized
//NOTE: This function will deallocate all of the hosts and modules passed in
//DO NOT USE THE REFERENCES TO THE HOSTS OR MODULES AFTER CALLING THIS FUNCTION
int InsertHostsAndModulesFromFile(vector <string> * hosts, vector <string> * modules){
	int ret;

	if(!modules->empty()){
		ret = InsertModulesToMeasureForPolling(modules);
		if(ret != GENERIC_SUCCESS){
			printf("InsertHostsAndModulesFromFile: InsertModulesToMeasureForPolling failed\n");
		}
	}

	if(!hosts->empty()){
		ret = InsertHostsToMeasureForPolling(hosts);
		if(ret != GENERIC_SUCCESS){
			printf("InsertHostsAndModulesFromFile: InsertHostsToMeasureForPolling failed\n");
		}		
	}

	return GENERIC_SUCCESS;
}

int InsertHostLimitsFromFile(vector <string> * limits){
	int ret;

	if(!limits->empty()){
		ret = InsertHostLimits(limits);
		if(ret != GENERIC_SUCCESS){
			printf("InsertLimitsFromFile: InsertHostLimits failed\n");
		}
	}

	return GENERIC_SUCCESS;
}

int InsertBrandStringLimitsFromFile(vector <string> * limits){
	int ret;

	if(!limits->empty()){
		ret = InsertBrandStringLimits(limits);
		if(ret != GENERIC_SUCCESS){
			printf("InsertLimitsFromFile: InsertBrandStringLimits failed\n");
		}
	}

	return GENERIC_SUCCESS;
}
