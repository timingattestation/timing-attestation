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

#include <string.h>
#include "database_mysql.h"
#include "global_includes.h"
#include "server_client_protocol.h"
#include <stdio.h>

HANDLE mysqlMutex;

//gff = global from file
//TODO: Technically since these variables are associated with the file operations, they
//should be in the file_access.cpp. But I don't know any way to get them to be linked
//correctly into the C file because if they're in the CPP file their names will be munged
//and then they can't be linked.
char * gffTiresiasDBName;
char * gffServerDBName;
char * gffSharedDBName;
char * gffDatabaseUsername;
char * gffDatabasePassword;

int gDeleteDB;
//Different C variables are needed because this file can't link against the C++ named ones
int gcVerbose, gcQuiet;

/////////////////////////////////////////////////////////////////////////////////////
//GENERIC INTERFACE METHODS
/////////////////////////////////////////////////////////////////////////////////////

int SelectSingleIntResult(unsigned int database, char * query, unsigned int length, unsigned int * result){
	MYSQL * conn;
	int ret;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectSingleIntResult: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	*result = 0;

	if(database == SERVER){
		conn = OpenDatabaseConnection(gffServerDBName);
	}else if(database == TIRESIAS){
		conn = OpenDatabaseConnection(gffTiresiasDBName);
	}else if(database == SHARED){
		conn = OpenDatabaseConnection(gffSharedDBName);
	}else{
		return GENERIC_ERROR;
	}


	if(conn == NULL){
		printf("SelectSingleIntResult: Open database connection failed failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, length)){	
		printf("SelectSingleIntResult: mysql_real_query failed\n");
		CloseDatabaseConnection(conn);

		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	ret = ReturnSingleUIntResult(conn, result);

	//////////////////////////////////
	CloseDatabaseConnection(conn);

	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectSingleIntResult: Couldn't release mutex. Returning\n");
		return GENERIC_ERROR;
	}

	return ret;
}

int ExecuteInsert(unsigned int database, char * query, unsigned int length, unsigned int * result){
	int holder;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("ExecuteInsert: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	if(database == SERVER){
		conn = OpenDatabaseConnection(gffServerDBName);
	}else if(database == TIRESIAS){
		conn = OpenDatabaseConnection(gffTiresiasDBName);
	}else if(database == SHARED){
		conn = OpenDatabaseConnection(gffSharedDBName);
	}else{
		return GENERIC_ERROR;
	}

	if(conn == NULL){
		printf("ExecuteInsert: Open database connection failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, length)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);	
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	*result = (unsigned int)mysql_insert_id(conn);

	CloseDatabaseConnection(conn);
		
	//////////////////////////////////
	if(!ReleaseMutex(mysqlMutex)){
		printf("ExecuteInsert: Couldn't release mutex. Returning\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int ExecuteUpdateOrDeleteOrLock(unsigned int database, char * query, unsigned int length){
	int holder;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("ExecuteUpdateOrDeleteOrLock(): Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	if(database == SERVER){
		conn = OpenDatabaseConnection(gffServerDBName);
	}else if(database == TIRESIAS){
		conn = OpenDatabaseConnection(gffTiresiasDBName);
	}else if(database == SHARED){
		conn = OpenDatabaseConnection(gffSharedDBName);
	}else{
		return GENERIC_ERROR;
	}

	if(0 != mysql_real_query(conn, query, length)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	CloseDatabaseConnection(conn);
	
	if(!ReleaseMutex(mysqlMutex)){
		printf("ExecuteUpdateOrDeleteOrLock(): Couldn't release mutex. Returning\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}



/////////////////////////////////////////
////////////////////////////////////////////
//INSERTS
/////////////////////////////////////////////////////////////////////////////////////

int InsertHost(char * hostname, char * ipStr, unsigned int ip, unsigned int * hostID){
	char query[200];
	char * fixedInsertStr;
	unsigned int len, ret;

	*hostID = 0;

	printf("InsertHost: hostname = %s\n", hostname);
	printf("InsertHost: ipStr = %s\n", ipStr);
	printf("InsertHost: ip = %u\n", ip);

	fixedInsertStr = "INSERT INTO Hosts VALUES (NULL, '%s', '%s', %u)";
	len = sprintf_s(query, 200, fixedInsertStr, hostname, ipStr, ip);

	ret = ExecuteInsert(SERVER, query, len, hostID);
	if(ret != GENERIC_SUCCESS){
		return GENERIC_ERROR;
	}

	if(*hostID == 0){
		printf("InsertHost(): ExecuteInsert failed\n");
		return GENERIC_ERROR;	
	}

	return GENERIC_SUCCESS;
}

int InsertHostToMeasure(unsigned int hostID, int state, unsigned int * hostToMeasureID){
	char query[100];
	char * fixedInsertStr;
	unsigned int len, ret;

	*hostToMeasureID = 0;

	fixedInsertStr = "INSERT INTO HostsToMeasure VALUES (NULL, 0, %u, %u)";
	len = sprintf_s(query, 100, fixedInsertStr, state, hostID);

	ret = ExecuteInsert(SERVER, query, len, hostToMeasureID);
	if(ret != GENERIC_SUCCESS){
		return GENERIC_ERROR;
	}

	if(*hostToMeasureID == 0){
		printf("InsertHostToMeasure(): ExecuteInsert failed\n");
		return GENERIC_ERROR;	
	}

	return GENERIC_SUCCESS;
}

//returns negative value on internal error, 0 on success, and positive value on possibly recoverable error
//Takes a me_t which has all the fields filled in or set to 0
//Returns the same me_t, but now with the pendingID field set to the
//ID of the row created by a successful insert
int InsertPendingME(me_t * incomingME, int previousPendingID){
	char query[300];
	char * fixedInsertStr;
	unsigned int len, ret;

	fixedInsertStr = "INSERT INTO PendingMeasurementEvents (type,nonce,timeInSeconds,timeInMicroseconds,hostID,overloadedForeignID,previousPendingID) VALUES ( %u, %u, %u, %u, %u, %u, %u)";
	len = sprintf_s(query, 300, fixedInsertStr, incomingME->type, incomingME->nonce, incomingME->timeInSeconds, incomingME->timeInMicroseconds, incomingME->hostID, incomingME->overloadedForeignID, previousPendingID);

	incomingME->id = 0;

	ret = ExecuteInsert(SERVER, query, len, &incomingME->id);
	if(ret != GENERIC_SUCCESS){
		return GENERIC_ERROR;
	}

	if(incomingME->id == 0){
		printf("InsertPendingME(): ExecuteInsert failed\n");
		return GENERIC_ERROR;	
	}

	return GENERIC_SUCCESS;
}

//TODO: support the newRTTInMicroseconds field
//returns negative value on internal error, 0 on success, and positive value on possibly recoverable error
int InsertME(me_t * me){
	char query[300];
	char * fixedInsertStr;
	unsigned int len, ret;

	fixedInsertStr = "INSERT INTO MeasurementEvents (type,nonce,timeInSeconds,timeInMicroseconds,meRTTInMicroseconds,netRTTInMicroseconds,lowerTiming,upperTiming,hostID,overloadedForeignID) VALUES (%u,%u,%u,%u,%u,%u,%u,%u,%u,%u)";
	len = sprintf_s(query, 300, fixedInsertStr, me->type, me->nonce, me->timeInSeconds, me->timeInMicroseconds, me->meRTTInMicroseconds, me->netRTTInMicroseconds, me->lowerTiming, me->upperTiming, me->hostID, me->overloadedForeignID);

	me->id = 0;

	ret = ExecuteInsert(SERVER, query, len, &me->id);
	if(ret != GENERIC_SUCCESS){
		return GENERIC_ERROR;
	}

	if(me->id == 0){
		printf("InsertME(): ExecuteInsert failed\n");
		return GENERIC_ERROR;	
	}	

	return GENERIC_SUCCESS;
}


//returns negative value on internal error, 0 on success, and positive value on possibly recoverable error
int InsertChecksum(self_check_t * check, unsigned int * checksumID){
	int ret = 0;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	MYSQL * conn;

	fixedInsertStr = "INSERT INTO Checksums VALUES (NULL, %u, %u, %u, %u, %u, %u, %u, %u, %u)";
	len = sprintf_s(query, 300, fixedInsertStr, check->nonce, check->timeDateStamp, check->baseVA, check->checksum[0], check->checksum[1], check->checksum[2], check->checksum[3], check->checksum[4], check->checksum[5]);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("InsertChecksum: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("InsertChecksum: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		ret = CheckError(conn,mysql_errno(conn));
		if(ret != INSERT_ERROR_DUPLICATE){
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, ret);
		}
		//When we already have this checksum, we instead have to lookup
		//the ID for the existing checksum
		holder = SelectChecksumIDByUniqueKey(check, checksumID);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	*checksumID = (unsigned int)mysql_insert_id(conn);
	if(*checksumID == 0){
		printf("InsertChecksum: mysql_insert_id failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("InsertChecksum: Couldn't release mutex. Exiting thread\n");
	
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}


int InsertErrorLog(unsigned int type, unsigned int timeInSeconds, unsigned int hostID, char * msg){
	unsigned int i = 0;
	int ret = 0;
	unsigned int len = 0;
	char query[512];
	char * fixedInsertStr;
	unsigned int result = 0;

	// stormy: this is to remove ' marks from the message so SQL will be happy
	len = strlen(msg);
	for(i = 0; i < len; ++i){
		if (msg[i] == '\''){  // Look for a '
			 msg[i] = '`'; // replace with a `
		 }
	}

	fixedInsertStr = "INSERT INTO ErrorLogs (Message,timeInSeconds, HostID, errorType) VALUES ('%s',%u,%u,%u)";
	len = sprintf_s(query, 512, fixedInsertStr, msg, timeInSeconds , hostID, type);

	ret = ExecuteInsert(SERVER, query, len, &result);
	if(ret != GENERIC_SUCCESS){
		return GENERIC_ERROR;
	}	

	return GENERIC_SUCCESS;
}

/////////////////////////////////////////////////////////////////////////////////////
//SELECTS
/////////////////////////////////////////////////////////////////////////////////////

int SelectValuesForPendingMeById(unsigned int id, unsigned int * type, unsigned int * overloadedId, unsigned int * hostId, unsigned int * previousMeId){
	char query[200];
	char * fixedInsertStr;
	char query2[200];
	char * fixedInsertStr2;
	char query3[200];
	char * fixedInsertStr3;
	char query4[200];
	char * fixedInsertStr4;
	unsigned int len;
	int ret;

	fixedInsertStr = "SELECT type FROM pendingMeasurementEvents WHERE id = %u";
	len = sprintf_s(query, 200, fixedInsertStr, id);
	ret = SelectSingleIntResult(SERVER, query, len, type);

	fixedInsertStr2 = "SELECT overloadedforeignid FROM pendingMeasurementEvents WHERE id = %u";
	len = sprintf_s(query2, 200, fixedInsertStr2, id);
	ret = SelectSingleIntResult(SERVER, query2, len, overloadedId);

	fixedInsertStr3 = "SELECT hostID FROM pendingMeasurementEvents WHERE id = %u";
	len = sprintf_s(query3, 200, fixedInsertStr3, id);
	ret = SelectSingleIntResult(SERVER, query3, len, hostId);

	fixedInsertStr4 = "SELECT previousPendingID FROM pendingMeasurementEvents WHERE id = %u";
	len = sprintf_s(query4, 200, fixedInsertStr4, id);
	ret = SelectSingleIntResult(SERVER, query4, len, previousMeId);

	return ret;
}


//returns negative value on error, checksum id on success
int SelectChecksumIDByUniqueKey(self_check_t * check, unsigned int * checksumID){
	char query[200];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "SELECT id FROM Checksums WHERE nonce = %u AND timeDateStamp = %u AND baseVA = %u";
	len = sprintf_s(query, 200, fixedInsertStr, check->nonce, check->timeDateStamp, check->baseVA);

	ret = SelectSingleIntResult(SERVER, query, len, checksumID);
	return ret;
}

int SelectHostNameByID(int hostID, char * hostName){
	MYSQL_RES * results;
	MYSQL_ROW row;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	MYSQL * conn;

	fixedInsertStr = "SELECT hostname FROM hosts where id = %d";
	len = sprintf_s(query, 300, fixedInsertStr, hostID);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectHostNameByID: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectHostNameByID: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectHostNameByID: mysql_real_query() failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectHostNameByID: mysql_store_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		printf("SelectHostNameByID: mysql_num_rows returned no results\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectHostNameByID: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//TODO: pass the len of the buffer to use instead of 16			
	strcpy_s(hostName,128,row[0]);
	//mysql_free_result(results);
	holder = GENERIC_SUCCESS;

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectHostNameByID: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return holder;
}

int SelectHostIPByID(int hostID, char * hostIP){
	MYSQL_RES * results;
	MYSQL_ROW row;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	MYSQL * conn;

	fixedInsertStr = "SELECT ip_str FROM hosts where id = %d order by id desc";
	len = sprintf_s(query, 300, fixedInsertStr, hostID);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectHostIPByID: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectHostIPByID: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("mysql_real_query() failed in SelectHostIPByID\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectHostIPByID: mysql_store_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		printf("SelectHostIPByID: mysql_num_rows returned no results\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectHostIPByID: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//TODO: pass the len of the buffer to use instead of 16			
	strcpy_s(hostIP,16,row[0]);
	//mysql_free_result(results);
	holder = GENERIC_SUCCESS;

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectHostIPByID: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return holder;
}

int SelectIDFromHostsToMeasureByHostID(unsigned int hostID, unsigned int * id){
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "SELECT id FROM HostsToMeasure WHERE hostID = %u";
	len = sprintf_s(query, 300, fixedInsertStr, hostID);

	ret = SelectSingleIntResult(SERVER, query, len, id);
	return ret;
}

int SelectHostIDByNetorderIP(unsigned int ip, unsigned int * hostID){
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "SELECT id FROM Hosts WHERE ip_netorder_int = %u ORDER BY ip_netorder_int DESC LIMIT 1"; //Descending order
	len = sprintf_s(query, 300, fixedInsertStr, ip);

	ret = SelectSingleIntResult(SERVER, query, len, hostID);
	return ret;
}

//This recreates the me_t which was put into the database
int SelectPendingMEByIncomingME(me_t * incomingME, me_t * pendingME){
	char query[300];
	MYSQL_RES * results;
	MYSQL_ROW row; //really a char **
	unsigned int numRows = 0, numFields = 0;
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	MYSQL * conn;

	fixedInsertStr = "SELECT * FROM PendingMeasurementEvents WHERE id = %u"; //
	len = sprintf_s(query, 300, fixedInsertStr, incomingME->id);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectPendingMEByIncomingME: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectPendingMEByIncomingME: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectPendingMEByIncomingME: mysql_real_query failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectPendingMEByIncomingME: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows != 1){
		mysql_free_result(results);
		if(numRows == 0){
			CloseDatabaseConnection(conn);
			printf("no results found...\n");
			return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
		}
		CloseDatabaseConnection(conn);
		printf("too many results found...\n");
		return ReleaseMutexAndReturnError(mysqlMutex, TOO_MANY_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectPendingMEByIncomingME: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numFields = mysql_num_fields(results);
	if(numFields != 11){
		printf("SelectPendingMEByIncomingME: mysql_num_fields says we have the wrong number of fields\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	pendingME->id = strtoul(row[0], NULL, 10);
	pendingME->type = strtoul(row[1], NULL, 10);
	pendingME->nonce = strtoul(row[2], NULL, 10);
	pendingME->timeInSeconds = strtoul(row[3], NULL, 10);
	pendingME->timeInMicroseconds = strtoul(row[4], NULL, 10);
	POSSIBLE_NULL_ENTRY(pendingME->netRTTInMicroseconds, row[5]);
	POSSIBLE_NULL_ENTRY(pendingME->lowerTiming, row[6]);
	POSSIBLE_NULL_ENTRY(pendingME->upperTiming, row[7]);
	POSSIBLE_NULL_ENTRY(pendingME->overloadedForeignID, row[8]);
	POSSIBLE_NULL_ENTRY(pendingME->previousPendingID, row[9]);
	pendingME->hostID = strtoul(row[10], NULL, 10);
	

	////TODO: if we want more checks, we can look up the hostID for
	////the incomingME-> and fill it in before calling this function
	////If we do that, add that check right here.
	if(pendingME->id != incomingME->id ||
		pendingME->type != incomingME->type ||
		pendingME->nonce != incomingME->nonce || 
		pendingME->hostID != incomingME->hostID ||
		pendingME->timeInMicroseconds == 0 || /*should have been set on outbound packet*/
		pendingME->timeInSeconds == 0 /*should have been set on outbound packet*/)
	{
		printf("SelectPendingMEByIncomingME: sanity checking new incoming measurement vs pending one failed\n");
		holder = GENERIC_ERROR;
	}
	else{
		holder = GENERIC_SUCCESS;
	}
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectPendingMEByIncomingME: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return holder;
}

//Implicitly if the attacker tries to send back a pendingID in the response packet which does not matching the
//nonce which came with the packet, the below select will fail. Therefore this is what's actually providing
//the attacker only a 1 in 4 billion chance of being able to forge the pendingID successfully when corrupting
//the data which comes back from the client.
int SelectPreviousPendingIDFromPendingME(unsigned int pmeID, unsigned int nonce, unsigned int * previousPendingID){
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "SELECT previousPendingID FROM PendingMeasurementEvents WHERE id = %u AND nonce = %u";
	len = sprintf_s(query, 300, fixedInsertStr, pmeID, nonce);

	ret = SelectSingleIntResult(SERVER, query, len, previousPendingID);
	return ret;
}


/////////////////////////////////////////////////////////////////////////////////////
//UPDATES
/////////////////////////////////////////////////////////////////////////////////////


int UpdatePendingMETime(unsigned int pendingID, unsigned int timeInSeconds, unsigned int timeInMicroseconds){
	char query[200];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "UPDATE PendingMeasurementEvents SET timeInSeconds = %u, timeInMicroseconds = %u where id = %u";
	len = sprintf_s(query, 200, fixedInsertStr, timeInSeconds, timeInMicroseconds, pendingID);

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}

int UpdateHostToMeasureHostID(unsigned int HostToMeasureID, unsigned int hostID){
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "UPDATE HostsToMeasure SET hostID = %d WHERE HostsToMeasure.id = %d";
	len = sprintf_s(query, 300, fixedInsertStr, hostID, HostToMeasureID);

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;

}

int UpdateHostToMeasure(unsigned int lastMeasuredTimeRequested,
						int state, unsigned int HostToMeasureID){
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	if(lastMeasuredTimeRequested > 0){
		fixedInsertStr = "UPDATE HostsToMeasure SET lastTimeMeasurementRequested = %d, readiness = %d WHERE HostsToMeasure.id = %d";
		len = sprintf_s(query, 300, fixedInsertStr, lastMeasuredTimeRequested, state, HostToMeasureID);
	}
	else{
		fixedInsertStr = "UPDATE HostsToMeasure SET readiness = %d WHERE HostsToMeasure.id = %d";
		len = sprintf_s(query, 300, fixedInsertStr, state, HostToMeasureID);
	}

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}

int UpdateMETime(me_t * me){
	char query[500];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "UPDATE measurementevents SET timeInSeconds = %d, timeInMicroseconds = %d  WHERE id = %d";
	len = sprintf_s(query, 500, fixedInsertStr, me->timeInSeconds, me->timeInMicroseconds,me->id);

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}

int UpdateNetRTTforNullSelfTests(me_t *me){
	char query[500];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "UPDATE PendingMeasurementEvents SET netRTTInMicroseconds = %u WHERE id = %d";
	len = sprintf_s(query, 500, fixedInsertStr, me->netRTTInMicroseconds, me->id);

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}

int UpdateTiminginPendingMeasurements(me_t * pendingME, unsigned int lower, unsigned int upper){
char query[500];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "UPDATE PendingMeasurementEvents SET lowerTiming = %u, upperTiming = %u WHERE id = %d";
	len = sprintf_s(query, 500, fixedInsertStr, lower, upper, pendingME->id);

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}

int UpdateNetRTTinPendingMeasurements(me_t * pendingME, unsigned int netRTTFromNullSelfTest){
	char query[500];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "UPDATE PendingMeasurementEvents SET netRTTInMicroseconds = %u WHERE id = %d";
	len = sprintf_s(query, 500, fixedInsertStr, netRTTFromNullSelfTest, pendingME->id);

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}

int UpdateRTTsInMeasurementEvents(me_t * incomingME, unsigned int netRTTFromNullSelfTest){
	char query[500], query2[500];
	char * fixedInsertStr;
	unsigned int len, len2;
	int ret;
	unsigned int calcRTT = 0;

	fixedInsertStr = "UPDATE MeasurementEvents SET netRTTInMicroseconds = %u WHERE id = %u";
	len = sprintf_s(query, 500, fixedInsertStr, netRTTFromNullSelfTest, incomingME->id);

	if(incomingME->meRTTInMicroseconds < netRTTFromNullSelfTest){
		printf("This is our supposed 'underflow' case...check what's up if we get here\n");
//				__asm{int 3};				
	}

	calcRTT = incomingME->meRTTInMicroseconds - netRTTFromNullSelfTest;
	if(calcRTT > 4000000000){
		printf("This is our supposed 'underflow' case...check what's up if we get here\n");
//				__asm{int 3};
	}

	fixedInsertStr = "UPDATE MeasurementEvents SET meRTTInMicroseconds = %u WHERE id = %u";
	len2 = sprintf_s(query2, 500, fixedInsertStr, calcRTT, incomingME->id);
	if(len2 > 500 || len2 == 0 || strlen(query2) > len2 ){__asm{int 3};}

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}

/////////////////////////////////////////////////////////////////////////////////////
//DELETES
/////////////////////////////////////////////////////////////////////////////////////

//This should only be used to delete the placeholder entries
//whicha re placed into measurements.binaries when an outbound
//binary measurement request is placed in PendingMeasurementEvents
int DeleteFromTableByID(char * table, unsigned int id){
	char query[100];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "DELETE FROM %s WHERE id = %d";
	len = sprintf_s(query, 100, fixedInsertStr, table, id);

	ret = ExecuteUpdateOrDeleteOrLock(SERVER, query, len);
	return ret;
}


/////////////////////////////////////////////////////////////////////////////////////
//HELPERS
/////////////////////////////////////////////////////////////////////////////////////


int ReleaseMutexAndReturnError(HANDLE mutex, int err){
	if(mutex == NULL){__asm{int 3}};
	ReleaseMutex(mutex);
	return err;
}

MYSQL * OpenDatabaseConnection(char * dbName){

	unsigned int wait_timeout = 60;	
	unsigned int read_timeout = 60;
	unsigned int write_timeout = 60;

	MYSQL *conn = mysql_init(NULL);
	if (conn == NULL) {
		printf("OpenDatabaseConnection: error %u: %s\n", mysql_errno(conn), mysql_error(conn));
		return NULL;
	}

	mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, (const char*)&wait_timeout);
	mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, (const char*)&read_timeout);
	mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, (const char*)&write_timeout);

	if(NULL == mysql_real_connect(conn, "127.0.0.1", gffDatabaseUsername, gffDatabasePassword, dbName, 3306, NULL, 0)){
		fprintf(stderr, "OpenDatabaseConnection: mysql_real_connect to %s failed. Error: %s\n", dbName, mysql_error(conn));
		return NULL;
	}

	return conn;
}

int CloseDatabaseConnection(MYSQL * connection){
	
	mysql_close(connection);
	mysql_library_end();

	return GENERIC_SUCCESS;
}

int InitializeDatabaseConnection(){

	MYSQL mysql; //Stores measurements received by server from client
	
	//TODO: low priority, save space by combining the repeated stuff into
	//a single function called multiple times. The downside would be getting
	//less verbose messages.

	if(mysql_init(&mysql) == NULL){
		printf("InitializeDatabaseConnection: mysql_init mysql failed\n");
		return GENERIC_ERROR;
	}

	if(NULL == mysql_real_connect(&mysql, "127.0.0.1", gffDatabaseUsername, gffDatabasePassword, gffServerDBName, 3306, NULL, 0)){
		printf("InitializeDatabaseConnection: mysql_real_connect %s 1 failed\n", gffServerDBName);
		return GENERIC_ERROR;
	}

	//do not use the D command line option in "production" environments.
	if(gDeleteDB){
		
		DeleteAndRecreateDatabase(&mysql, gffServerDBName);
		mysql_close(&mysql);
		mysql_library_end(); // stormy added, this is needed to clean up memory after a close - wackiness!

		if(mysql_init(&mysql) == NULL){
			printf("InitializeDatabaseConnection: mysql_init mysql failed2\n");
			return GENERIC_ERROR;
		}
		if(NULL == mysql_real_connect(&mysql, "127.0.0.1", gffDatabaseUsername, gffDatabasePassword, gffServerDBName, 3306, NULL, 0)){
			printf("InitializeDatabaseConnection: mysql_real_connect %s 2 failed\n", gffServerDBName);
			return GENERIC_ERROR;
		}
	}
	CreateTables(&mysql);

	mysqlMutex = CreateMutex(NULL, FALSE, NULL);
	if(mysqlMutex == NULL){
		printf("InitializeDatabaseConnection CreateMutex for mysqlMutex failed\n");
		return GENERIC_ERROR;
	}

	ClearTablesReadFromConfigFile(&mysql);

	mysql_close(&mysql);
	mysql_library_end(); // stormy added - needed to clean up memory after a close - wackiness!


	////////////////////
	//Now set up the shared tables
	if(mysql_init(&mysql) == NULL){
		printf("InitializeDatabaseConnection: mysql_init mysql failed\n");
		return GENERIC_ERROR;
	}

	if(NULL == mysql_real_connect(&mysql, "127.0.0.1", gffDatabaseUsername, gffDatabasePassword, gffSharedDBName, 3306, NULL, 0)){
		printf("InitializeDatabaseConnection: mysql_real_connect %s failed\n", gffSharedDBName);
		return GENERIC_ERROR;
	}

	//do not use the D command line option in "production" environments.
	if(gDeleteDB){
		
		DeleteAndRecreateDatabase(&mysql, gffSharedDBName);
		mysql_close(&mysql);
		mysql_library_end(); // stormy added, this is needed to clean up memory after a close - wackiness!

		if(mysql_init(&mysql) == NULL){
			printf("InitializeDatabaseConnection: mysql_init mysql failed2\n");
			return GENERIC_ERROR;
		}
		if(NULL == mysql_real_connect(&mysql, "127.0.0.1", gffDatabaseUsername, gffDatabasePassword, gffSharedDBName, 3306, NULL, 0)){
			printf("InitializeDatabaseConnection: mysql_real_connect %s 2 failed\n", gffSharedDBName);
			return GENERIC_ERROR;
		}
	}
	CreateSharedTables(&mysql);

	mysql_close(&mysql);
	mysql_library_end(); // stormy added - needed to clean up memory after a close - wackiness!

	return GENERIC_SUCCESS;
}

int ClearTablesReadFromConfigFile(MYSQL * conn){
	char * fixedInsertStr;
	unsigned int len;
	int holder;

	fixedInsertStr = "DELETE FROM ModulesToMeasure";
	len = strlen(fixedInsertStr);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("ClearTablesReadFromConfigFile: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, fixedInsertStr, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		printf("ClearTablesReadFromConfigFile: mysql_real_query() failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	fixedInsertStr = "DELETE FROM HostsToMeasure";
	len = strlen(fixedInsertStr);

	if(0 != mysql_real_query(conn, fixedInsertStr, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		printf("ClearTablesReadFromConfigFile: mysql_real_query() failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	CloseDatabaseConnection(conn);

	//////////////////////////////////
	if(!ReleaseMutex(mysqlMutex)){
		printf("ClearTablesReadFromConfigFile: Couldn't release mutex. Returning\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;

}

//Alter these defines as you add more tables of any given type
//Numbers are total number of tables, not index numbers of last table
#define NUM_MULTI		5
#define NUM_SELF		1
#define NUM_MISC		5
#define NUM_TPM			1
int CreateTables(MYSQL * mysql){

	char * multi[NUM_MULTI];
	char * self[NUM_SELF];
	char * misc[NUM_MISC];
	char * tpm[NUM_TPM];
	unsigned int i = 0;

	///////////////////////////////////
	//Multipurpose
	///////////////////////////////////
	//Not allowed to make a BLOB have a length limit, and not allowed
	//to make anything without a length limit a unique key so when
	// you operate on this table, you must always first look up whether
	//the note you want to insert already exists, and if so, then use
	//the looked up note id


	multi[0] =	"CREATE TABLE Hosts (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				hostname VARCHAR(255), \
				ip_str VARCHAR(15), \
				ip_netorder_int INTEGER UNSIGNED, \
				UNIQUE KEY(hostname, ip_str, ip_netorder_int))";

	multi[1] =	"CREATE TABLE HostsToMeasure (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				lastTimeMeasurementRequested INTEGER UNSIGNED, \
				readiness INTEGER UNSIGNED NOT NULL, \
				hostID INTEGER UNSIGNED NOT NULL, \
				FOREIGN KEY(hostID) REFERENCES Hosts(id),\
				UNIQUE KEY(hostID))";

	multi[2] =	"CREATE TABLE ModulesToMeasure (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				moduleName VARCHAR(255), \
				UNIQUE KEY(moduleName))";

//overloadedForeignID is a foreign key to some other table, where the table is determined
//by this table's type field.
//If type == SELF_ATTESTATION or TIMING_TEST?, overloadedForeignID references Checksums(id)

	multi[3] = 	"CREATE TABLE PendingMeasurementEvents (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				type INTEGER UNSIGNED NOT NULL, \
				nonce INTEGER UNSIGNED NOT NULL, \
				timeInSeconds INTEGER UNSIGNED NOT NULL, \
				timeInMicroseconds INTEGER UNSIGNED NOT NULL, \
				netRTTInMicroseconds INTEGER UNSIGNED, \
				lowerTiming INTEGER UNSIGNED, \
				upperTiming INTEGER UNSIGNED, \
				overloadedForeignID INTEGER UNSIGNED, \
				previousPendingID INTEGER UNSIGNED, \
				hostID INTEGER UNSIGNED NOT NULL, \
				FOREIGN KEY(hostID) REFERENCES Hosts(id),\
				UNIQUE KEY(type, nonce, timeInSeconds, timeInMicroseconds, hostID))";

//overloadedForeignID is a foreign key to some other table, where the table is determined
//by this table's type field.
//If type == SELF_ATTESTATION or TIMING_TEST?, overloadedForeignID references Checksums(id)

	multi[4] =	"CREATE TABLE MeasurementEvents (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				type INTEGER UNSIGNED NOT NULL, \
				nonce INTEGER UNSIGNED NOT NULL, \
				timeInSeconds INTEGER UNSIGNED NOT NULL, \
				timeInMicroseconds INTEGER UNSIGNED NOT NULL, \
				meRTTInMicroseconds INTEGER UNSIGNED NOT NULL, \
				netRTTInMicroseconds INTEGER UNSIGNED, \
				lowerTiming INTEGER UNSIGNED, \
				upperTiming INTEGER UNSIGNED, \
				overloadedForeignID INTEGER UNSIGNED, \
				hostID INTEGER UNSIGNED NOT NULL, \
				FOREIGN KEY(hostID) REFERENCES Hosts(id),\
				UNIQUE KEY(type, nonce, timeInSeconds, timeInMicroseconds, meRTTInMicroseconds, netRTTInMicroseconds, hostID))";

	///////////////////////////////////
	//For self measurements
	///////////////////////////////////
	self[0] =	"CREATE TABLE Checksums (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				nonce INTEGER UNSIGNED NOT NULL, \
				timeDateStamp INTEGER UNSIGNED NOT NULL, \
				baseVA INTEGER UNSIGNED NOT NULL, \
				c0 INTEGER UNSIGNED NOT NULL, \
				c1 INTEGER UNSIGNED NOT NULL, \
				c2 INTEGER UNSIGNED NOT NULL, \
				c3 INTEGER UNSIGNED NOT NULL, \
				c4 INTEGER UNSIGNED NOT NULL, \
				c5 INTEGER UNSIGNED NOT NULL, \
				UNIQUE KEY(nonce, timeDateStamp, baseVA))";

	///////////////////////////////////
	//For misc purposes
	///////////////////////////////////

	misc[0] =	"CREATE TABLE CPUIDInfo (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				brandString VARCHAR(48), \
				familyModel INTEGER UNSIGNED,	\
				cacheInfo1 INTEGER UNSIGNED,	\
				cacheInfo2 INTEGER UNSIGNED,	\
				cacheInfo3 INTEGER UNSIGNED,	\
				cacheInfo4 INTEGER UNSIGNED,	\
				hostID INTEGER UNSIGNED NOT NULL, \
				FOREIGN KEY(hostID) REFERENCES Hosts(id))";

	misc[1] =	"CREATE TABLE CPUControlLimits (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				brandString VARCHAR(48), \
				UpperCL INTEGER UNSIGNED NOT NULL, \
				LowerCL INTEGER UNSIGNED NOT NULL, \
				PRIMARY KEY(id,brandString))";

	misc[2] =	"CREATE TABLE HostControlLimits (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				host VARCHAR(48), \
				UpperCL INTEGER UNSIGNED NOT NULL, \
				LowerCL INTEGER UNSIGNED NOT NULL, \
				PRIMARY KEY(id,host))";

	misc[3] =	"CREATE TABLE TableVerificationPrerequisiteModules (		\
				id INTEGER UNSIGNED AUTO_INCREMENT,		\
				PRIMARY KEY(id),						\
				messageType INTEGER UNSIGNED NOT NULL,	\
				moduleName VARCHAR(255) NOT NULL,		\
				UNIQUE KEY(messageType, moduleName))";

	misc[4] =	"CREATE TABLE WindowAverages (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				RTT INTEGER UNSIGNED NOT NULL, \
				timeInSeconds INTEGER UNSIGNED NOT NULL, \
				hostID INTEGER UNSIGNED NOT NULL, \
				FOREIGN KEY(hostID) REFERENCES Hosts(id))";


	tpm[0] =	"CREATE TABLE TPMTicks (\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id), \
				hostID INTEGER UNSIGNED NOT NULL, \
				FOREIGN KEY(hostID) REFERENCES Hosts(id),\
				deltaTicks BIGINT UNSIGNED NOT NULL)";


	
	////////////////////////////////////////////////////////////////////////////

	// IMPORTANT:  Note the foreign key relationships currently require that self 
	// and binary are created before multi below, else on some systems the database 
	// will fail to get fully created.
	// 
	// Check that any changes you make to the schema do not break dependencies between 
	// tables please.


	for(i = 0; i < NUM_MULTI; i++){
		if(0 != mysql_real_query(mysql, multi[i], strlen(multi[i]))){
			if(CheckError(mysql,mysql_errno(mysql)) == GENERIC_ERROR){
				printf("Error creating the multi[%d] database table. Exiting loop.\n",i);
				return GENERIC_ERROR;
			}
		}
	}

	for(i = 0; i < NUM_SELF; i++){
		if(0 != mysql_real_query(mysql, self[i], strlen(self[i]))){
			if(CheckError(mysql,mysql_errno(mysql)) == GENERIC_ERROR){
				printf("Error creating the self[%d] database table. Exiting loop.\n", i);
				return GENERIC_ERROR;
			}
		}
	}

	for(i = 0; i < NUM_MISC; i++){
		if(0 != mysql_real_query(mysql, misc[i], strlen(misc[i]))){
			if(CheckError(mysql,mysql_errno(mysql)) == GENERIC_ERROR){
				printf("Error creating the misc[%d] database table. Exiting loop.\n", i);
				return GENERIC_ERROR;
			}
		}
	}

	for(i = 0; i < NUM_TPM; i++){
		if(0 != mysql_real_query(mysql, tpm[i], strlen(tpm[i]))){
			if(CheckError(mysql,mysql_errno(mysql)) == GENERIC_ERROR){
				printf("Error creating the tpm[%d] database table. Exiting loop.\n", i);
				return GENERIC_ERROR;
			}
		}
	}

	return GENERIC_SUCCESS;
}

#define NUM_SHARED		3

int CreateSharedTables(MYSQL * connection){

	char * shared[NUM_SHARED];

	unsigned int i = 0;

	///////////////////////////////////
	//For misc
	///////////////////////////////////


	shared[0] =	"CREATE TABLE Prerequisites (		\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id),					\
				type INTEGER UNSIGNED NOT NULL,		\
				name varchar(29),					\
				status INTEGER UNSIGNED,			\
				hostID INTEGER UNSIGNED NOT NULL,	\
				UNIQUE KEY(type, name, hostID))";
				//type will be a msgType
				//status is used to determine whether the prereq has been fulfilled yet

	//This table is filled in directly by server when it parses
	//a loaded module measurement reply. It is used by tiresias
	//to determine if any particular 3rd party software is
	//loaded which would change the measurement of some other
	//component (e.g. if the 3rd party software hooks nt).
	//The info is the normal info collected from the loaded 
	//modules list that would go into measurements.Binaries
	//However in our case we don't want to mix it into
	//tiresias' Binaries table, since currently tiresias
	//really only looks up the name field
	shared[1] =	"CREATE TABLE LoadedModules (			\
				id INTEGER UNSIGNED AUTO_INCREMENT,		\
				PRIMARY KEY(id),						\
				name VARCHAR(29) NOT NULL,				\
				baseVA INTEGER UNSIGNED NOT NULL,		\
				sizeOfImage INTEGER UNSIGNED NOT NULL,	\
				timeDateStamp INTEGER UNSIGNED NOT NULL, \
				hostID INTEGER UNSIGNED NOT NULL)";

	shared[2] =	"CREATE TABLE BinaryVersionInfo (			\
				id INTEGER UNSIGNED AUTO_INCREMENT,		\
				PRIMARY KEY(id),						\
				Name varchar(128),					\
				CompanyName VARCHAR(128) NOT NULL,				\
				ProductName VARCHAR(128) NOT NULL,		\
				Version VARCHAR(128) NOT NULL,	\
				Build VARCHAR(128) NOT NULL)";

	for(i = 0; i < NUM_SHARED; i++){
		if(0 != mysql_real_query(connection, shared[i], strlen(shared[i]))){
			if(CheckError(connection, mysql_errno(connection)) == GENERIC_ERROR){ 
				return GENERIC_ERROR;
			}
		}
	}

	return GENERIC_SUCCESS;
}

int CheckError(MYSQL * mysql, unsigned int error){
	switch(error){
		case INSERT_ERROR_DUPLICATE: //Allowed and ignored.
			return INSERT_ERROR_DUPLICATE;
			break;

		case TABLE_ALREADY_DEFINED: //Allowed and ignored.
			return TABLE_ALREADY_DEFINED;
			break;

		default:
			printf("unhandled mysql_real_query error: %s\n", mysql_error(mysql));
			return GENERIC_ERROR;
			break;
	}
}


//Helper function to return the value when we expect to get back a single column and
//single row integer result (such as when looking up a single ID field)
int ReturnSingleUIntResult(MYSQL * mysql, unsigned int *value){
	MYSQL_RES * results;
	MYSQL_ROW row; //really a char **
	*value = 0;

	results = mysql_store_result(mysql);
	if(results == NULL){
		printf("ReturnSingleUIntResult: mysql_use_result failed\n");
		return GENERIC_ERROR;
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		return NO_RESULTS_FOUND;//Will fail here if an empty set is returned
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("ReturnSingleUIntResult: mysql_fetch_row failed\n");
		mysql_free_result(results);
		return GENERIC_ERROR;
	}

	POSSIBLE_NULL_ENTRY(*value, row[0]);
	mysql_free_result(results);
	return GENERIC_SUCCESS;
}

int ReturnSingleCharPtrResult(MYSQL * mysql, char * strPtr, unsigned int strSize){
	MYSQL_RES * results;
	MYSQL_ROW row; //really a char **
	*strPtr = '\0';

	results = mysql_store_result(mysql);
	if(results == NULL){
		printf("ReturnSingleCharPtrResult: mysql_use_result failed\n");
		return GENERIC_ERROR;
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		return NO_RESULTS_FOUND;//Will fail here if an empty set is returned
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("ReturnSingleCharPtrResult: mysql_fetch_row failed\n");
		mysql_free_result(results);
		return GENERIC_ERROR;
	}

	//Using >= rather than just > to be cautious against possible off-by-one errors if the passed
	//in strSize was not also calculated as a strlen()
	if(strlen(row[0]) >= strSize){
		printf("ReturnSingleCharPtrResult: fetched string is too big\n");
		mysql_free_result(results);
		return GENERIC_ERROR;
	}

	strcpy_s(strPtr, strSize, row[0]);
	mysql_free_result(results);
	return GENERIC_SUCCESS;
}

//Just assume it will work, since this won't be used in production
int DeleteAndRecreateDatabase(MYSQL * mysql, char * databaseName){
	char query[50];
	unsigned int len;

	len = sprintf_s(query, 50, "DROP DATABASE %s", databaseName);
	mysql_real_query(mysql, query, len);
	len = sprintf_s(query, 50, "CREATE DATABASE %s", databaseName);
	mysql_real_query(mysql, query, len);

	return 0;
}

// This function attempts to return the host id from Hosts when that host exists
// in HostToMeasure based on the hostname and ip string matching in Hosts
int SelectHostIDFromHostsToMeasureByHostNameAndIP(char * hostName, char * ip, unsigned int * id){
	MYSQL_RES * results;
	MYSQL_ROW row;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	MYSQL * conn;
	
	fixedInsertStr = "select id from hoststomeasure where hostid = (select id from hosts where hostname like '%s' and ip_str like '%s')";

	len = sprintf_s(query, 300, fixedInsertStr, hostName, ip);
	if(len > 300 || len == 0 || strlen(query) > len ){__asm{int 3};}

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectHostIDFromHostsToMeasureByHostNameAndIP: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectHostIDFromHostsToMeasureByHostNameAndIP: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectHostIDFromHostsToMeasureByHostNameAndIP: mysql_real_query() failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectHostIDFromHostsToMeasureByHostNameAndIP: mysql_store_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectHostIDFromHostsToMeasureByHostNameAndIP: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	*id = (unsigned int)(atoi(row[0]));

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectHostIDFromHostsToMeasureByHostNameAndIP: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}


// This function attempts to return the host id from Hosts when that host exists
// in HostToMeasure based on the hostname matching in Hosts
int SelectHostIDFromHostsToMeasureByHostName(char * hostName, unsigned int * id){
	MYSQL_RES * results;
	MYSQL_ROW row;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	MYSQL * conn;
	
	fixedInsertStr = "select id from hoststomeasure where hostid = (select Min(id) from hosts where hostname like '%s')";

	len = sprintf_s(query, 300, fixedInsertStr, hostName);
	if(len > 300 || len == 0 || strlen(query) > len ){__asm{int 3};}

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectHostIDFromHostsToMeasureByHostName: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectHostIDFromHostsToMeasureByHostName: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectHostIDFromHostsToMeasureByHostName: mysql_real_query() failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectHostIDFromHostsToMeasureByHostName: mysql_store_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		printf("SelectHostIDFromHostsToMeasureByHostName: mysql_num_rows returned no results\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectHostIDFromHostsToMeasureByHostName: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	*id = (unsigned int)(atoi(row[0]));

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectHostIDFromHostsToMeasureByHostName: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SelectHostIDByHostNameAndIP(char * hostName, char * hostIP, unsigned int * hostID){
	MYSQL_RES * results;
	MYSQL_ROW row;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	MYSQL * conn;

	fixedInsertStr = "SELECT id FROM hosts where hostname like '%s' AND ip_str LIKE '%s'";
	len = sprintf_s(query, 300, fixedInsertStr, hostName, hostIP);
	if(len > 300 || len == 0 || strlen(query) > len ){__asm{int 3};}

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectHostIDByHostNameAndIP: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}
	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectHostIDByHostNameAndIP: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("mysql_real_query() failed in SelectHostIDByHostNameAndIP\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectHostIDByHostNameAndIP: mysql_store_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		printf("SelectHostIDByHostNameAndIP: mysql_num_rows returned no results\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectHostIDByHostNameAndIP: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	*hostID = (unsigned int)(atoi(row[0]));

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectHostIDByHostNameAndIP: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SelectHostIDByIP(char * hostIP, unsigned int * hostID){
	MYSQL_RES * results;
	MYSQL_ROW row;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	MYSQL * conn;

	fixedInsertStr = "SELECT id FROM hosts where ip_str LIKE '%s'";
	len = sprintf_s(query, 300, fixedInsertStr, hostIP);
	if(len > 300 || len == 0 || strlen(query) > len ){__asm{int 3};}

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectHostIDByIP: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectHostIDByIP: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectHostIDByIP: mysql_real_query() failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectHostIDByIP: mysql_store_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		printf("SelectHostIDByIP: mysql_num_rows returned no results\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectHostIDByIP: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	*hostID = (unsigned int)(atoi(row[0]));

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectHostIDByIP: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SelectLimitsByHost(char * host, unsigned int * LCL, unsigned int * UCL){
char query[300];
	char * fixedInsertStr;
	unsigned int len;
	MYSQL * conn;
	MYSQL_RES * results;
	MYSQL_ROW row;

	fixedInsertStr = "SELECT LowerCL, UpperCL FROM HostControlLimits WHERE host = '%s'";
	len = sprintf_s(query, 300, fixedInsertStr, host);
	if(len > 300 || len == 0 || strlen(query) > len ){__asm{int 3};}

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectLimitsByHost: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}
	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectLimitsByHost: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectLimitsByHost: mysql_real_query failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	
	results = mysql_store_result(conn);

	row = mysql_fetch_row(results);

	// if there were no limits yet, that's ok
	if(row == NULL){
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		if(!ReleaseMutex(mysqlMutex)){
			printf("SelectLimitsByHost: Couldn't release mutex.\n");
			return GENERIC_ERROR;
		}

		*LCL = 0;
		*UCL = 0;

		return GENERIC_SUCCESS;
	}

	*LCL = (int)(atoi(row[0]));
	*UCL = (int)(atoi(row[1]));

	mysql_free_result(results);
	CloseDatabaseConnection(conn);

	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectLimitsByHost: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}
