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

//This is where things using the MySQL C API go

#ifndef DATABASE_MYSQL_H
#define DATABASE_MYSQL_H

#include "global_includes.h"
#include "server_client_protocol.h" 
#include <mysql.h>
#include <stdio.h>

////////////////////////////////////////////////////////
//STRUCTS
////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////

#define ERROR_ARP_FAIL			-4
#define TOO_MANY_RESULTS_FOUND	-3
#define NO_RESULTS_FOUND		-2
#define INSERT_ERROR_DUPLICATE	1062
#define TABLE_ALREADY_DEFINED	1050

//Readiness values for the Hosts table

//The client has not yet been determined to be ready by the liveness thread
#define		NOTREADY		0
//The client is ready to be measured
#define		READY			1
//The client is not responding to any measurement requests
#define		NOT_RESPONDING	2
//Like NOT_RESPONDING, but for hosts on the same ethernet segment as
//the server
#define		ARP_FAIL		3
//The client is responding, but has indicated it has sent an
//error message indicating that it will not respond to 
//measurement requests (either because of a crash file found
//or because it can't find the PFN base)
#define		SELF_DISABLED	4


#define		POSSIBLE_NULL_ENTRY(var,row)	\
	if(row == NULL){var = 0;}					\
	else{var = strtoul(row, NULL, 10);}		\

////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

// Database Interface Functions - Use these when possible to reduce redundant code
int SelectSingleIntResult(unsigned int database, char * query, unsigned int length, unsigned int * result);
int ExecuteInsert(unsigned int database, char * query, unsigned int length, unsigned int * result);
int ExecuteUpdateOrDeleteOrLock(unsigned int database, char * query, unsigned int length);

//INSERTs
int InsertChecksum(self_check_t * check, unsigned int * checksumID);
int InsertErrorLog(unsigned int type, unsigned int timeInSeconds, unsigned int hostID, char * msg);
int InsertHost(char * hostname, char * ipStr, unsigned int ip, unsigned int * hostID);
int InsertHostToMeasure(unsigned int hostID, int state, unsigned int * hostToMeasureID);
int InsertME(me_t * me);

int InsertPendingME(me_t * me, int previousPendingID);
//You don't *have* to keep the above alphabetical...but you can if you want ;)

//SELECTs
int SelectChecksumIDByUniqueKey(self_check_t * check, unsigned int * checksumID);
int SelectLimitsByHost(char * host, unsigned int * LCL, unsigned int * UCL);
int SelectHostIPByID(int hostID, char * hostIP);
int SelectHostIDByHostNameAndIP(char * hostName, char * hostIP, unsigned int * hostID);
int SelectHostIDByIP(char * hostIP, unsigned int * hostID);
int SelectHostIDByNetorderIP(unsigned int ip, unsigned int * hostID);
int SelectHostIDFromHostsToMeasureByHostName(char * hostName, unsigned int * id);
int SelectHostIDFromHostsToMeasureByHostNameAndIP(char * hostName, char * ip, unsigned int * id);
int SelectHostNameByID(int hostID, char * hostName);
int SelectPreviousPendingIDFromPendingME(unsigned int pmeID, unsigned int nonce, unsigned int * previousPendingID);
int SelectPendingMEByIncomingME(me_t * incomingME, me_t * pendingME);
int SelectValuesForPendingMeById(unsigned int id, unsigned int * type, unsigned int * overloadedId, unsigned int * hostId, unsigned int * previousMeId);
//You don't *have* to keep the above alphabetical...but you can if you want ;)


//UPDATES
int UpdateHostToMeasure(unsigned int lastMeasuredTimeRequested, int state, unsigned int HostToMeasureID);
int UpdateHostToMeasureHostID(unsigned int HostToMeasureID, unsigned int hostID);
int UpdateMETime(me_t * me);
int UpdateNetRTTforNullSelfTests(me_t *me);
int UpdateTiminginPendingMeasurements(me_t * pendingME, unsigned int lower, unsigned int upper);
int UpdateNetRTTinPendingMeasurements(me_t * pendingME, unsigned int netRTTFromNullSelfTest);
int UpdatePendingMETime(unsigned int pendingID, unsigned int timeInSeconds, unsigned int timeInMicroseconds);
int UpdateRTTsInMeasurementEvents(me_t * incomingME, unsigned int netRTTFromNullSelfTest);
//You don't *have* to keep the above alphabetical...but you can if you want ;)


//DELETES
int DeleteFromTableByID(char * table, unsigned int id);
//You don't *have* to keep the above alphabetical...but you can if you want ;)


//Helpers
int InitializeDatabaseConnection();
MYSQL * OpenDatabaseConnection(char * dbName);
int CloseDatabaseConnection(MYSQL * connection);
int ReleaseMutexAndReturnError(HANDLE mutex, int err);
int CheckError(MYSQL * connection, unsigned int error);
int ReturnSingleUIntResult(MYSQL * connection, unsigned int *value);
int ReturnSingleCharPtrResult(MYSQL * connection, char * strPtr, unsigned int strSize);
int CreateTables(MYSQL * connection);
int CreateSharedTables(MYSQL * connection);
int ClearTablesReadFromConfigFile(MYSQL * conn);
int DeleteAndRecreateDatabase(MYSQL * connection, char * databaseName);



#endif