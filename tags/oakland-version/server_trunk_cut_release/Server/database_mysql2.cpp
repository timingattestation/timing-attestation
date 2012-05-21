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

//This file exists because I'd like to use C++ containers, and obviously can't in the .c file

#include "database_mysql2.h"
#include <time.h> 
#include "request_measurement.h"

extern "C"{
	//Defined in database_mysql.c
	extern char * gffTiresiasDBName;
	extern char * gffServerDBName;
	extern char * gffSharedDBName;
	extern char * gffDatabaseUsername;
	extern char * gffDatabasePassword;
	extern HANDLE mysqlMutex;
}

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////


// Generic hostname and IP processor
// Resolves the hostname or IP if one is missing, inserts or updates the Hosts table
// Inserts or updates the HostsToMeasure table if requested
int ProcessHost(string & hostName, string & ipStr, bool updateForPolling, int readinessState, unsigned int * hostID){
	int ret;
	bool hostNameExists = false;
	bool ipStrExists = false;
	bool matches = false;
	list<string> ipStrings;
	char * ipStrFromDB;
	unsigned int netorderIp, id, hostToMeasureID;

	// this call will try to populate hostName and ipStr based on which exists
	ret = CheckHostIPValues(ipStr, hostName, &ipStrExists, &hostNameExists);
	if(ret == GENERIC_ERROR){
		printf("ProcessHost(): CheckHostIPValues() failed\n");
		return GENERIC_ERROR;
	}
	
	// both should hopefully now exist
	if(hostNameExists == true && ipStrExists == true){
		// check if this hostName -> IP mapping exists in hosts
		ret = SelectHostIPsByHostName((char *)hostName.c_str(), &ipStrings);
		if(ret == GENERIC_ERROR){
			printf("ProcessHost(): SelectHostIPByHostName() failed\n");
			return GENERIC_ERROR;	
		}

		while(ipStrings.size() > 0){
			ipStrFromDB = new char[ipStrings.front().size()+1];
			ipStrFromDB[ipStrings.front().size()]=0;
			memcpy(ipStrFromDB,ipStrings.front().c_str(),ipStrings.front().size());			
			ipStrings.pop_front();

			// try to find the ipStr
			if(strcmp((char *)ipStr.c_str(),ipStrFromDB) == 0){	

				// flag that we found the entry for later
				matches = true;

				// get the hostID associated with this ipStr from the hosts table
				ret = SelectHostIDByHostNameAndIP((char *)hostName.c_str(), (char *)ipStr.c_str(), hostID);
				if(ret != GENERIC_SUCCESS){
					printf("ProcessHost(): SelectHostIDByIP() failed\n");	
					return GENERIC_ERROR;
				}

				// then check if this hostname is in the HostsToMeasure table
				ret = SelectHostIDFromHostsToMeasureByHostNameAndIP((char *)hostName.c_str(),(char *)ipStr.c_str(), &id);
				if(ret == GENERIC_ERROR){
					printf("ProcessHost(): SelectIDFromHostsToMeasureByHostID() failed\n");
					return GENERIC_ERROR;
				}

				// if the host exists in HostToMeasure, update it
				if(id > 0 && ret != NO_RESULTS_FOUND){
					// update HostsToMeasure to use this latest mapping
					ret = UpdateHostToMeasureHostID(id, *hostID);
					if(ret != GENERIC_SUCCESS){
						printf("ProcessHost(): UpdateHostToMeasureHostID() failed\n");
						return GENERIC_ERROR;
					}
					
					// update its readiness as well since its already in hosts to measure
					ret = UpdateHostToMeasure(0, READY, id);
					if(ret != GENERIC_SUCCESS){
						printf("ProcessHost(): UpdateHostToMeasure() failed\n");
						return GENERIC_ERROR;
					}
				}
				else if(updateForPolling == true)
				{
					// insert it if requested
					ret = InsertHostToMeasure(*hostID, READY, &hostToMeasureID);
					if(ret != GENERIC_SUCCESS){
						printf("ProcessHost(): InsertHostToMeasure() failed\n");
						return GENERIC_ERROR;
					}
				}
			}
		}

		// if the hostname -> ipStr mapping was not found in hosts, make a new entry in Hosts
		if(matches == false){
			netorderIp = inet_addr((char *)ipStr.c_str());
			
			ret = InsertHost((char *)hostName.c_str(), (char *)ipStr.c_str(), netorderIp, hostID);
			if(ret != GENERIC_SUCCESS){
				printf("ProcessHost(): InsertHost() failed\n");
				return GENERIC_ERROR;
			}

			id = 0;
			ret = SelectHostIDFromHostsToMeasureByHostName((char *)hostName.c_str(), &id);
			if(ret == GENERIC_ERROR){
				printf("ProcessHost(): SelectIDFromHostsToMeasureByHostID() failed\n");
				return GENERIC_ERROR;
			}

			// if the host exists in HostToMeasure, update it
			if(id > 0 && ret != NO_RESULTS_FOUND){
				// update HostsToMeasure to use this latest mapping
				ret = UpdateHostToMeasureHostID(id, *hostID);
				if(ret != GENERIC_SUCCESS){
					printf("ProcessHost(): UpdateHostToMeasureHostID() failed\n");
					return GENERIC_ERROR;
				}
					
				// update its readiness as well since its already in hosts to measure
				ret = UpdateHostToMeasure(0, READY, id);
				if(ret != GENERIC_SUCCESS){
					printf("ProcessHost(): UpdateHostToMeasure() failed\n");
					return GENERIC_ERROR;
				}
			}
			// If not found, make an entry in HostsToMeasure if requested
			else if(updateForPolling == true){	
				ret = InsertHostToMeasure(*hostID, readinessState, &hostToMeasureID);
				if(ret != GENERIC_SUCCESS){
					printf("ProcessHost(): InsertHostToMeasure() failed\n");
					return GENERIC_ERROR;
				}
			}
		}
	}
	// or if we at least have the IP address
	else if(hostNameExists == false && ipStrExists == true){
		
		// try to get the host id for this ip
		ret = SelectHostIDByIP((char *)ipStr.c_str(), hostID);
		if(ret == GENERIC_ERROR){
			printf("ProcessHost(): SelectHostIDByIP() failed\n");
			return GENERIC_ERROR;
		}

		// if it didn't exist, insert it
		if(*hostID < 1){
			netorderIp = inet_addr((char *)ipStr.c_str());
			ret = InsertHost((char *)hostName.c_str(), (char *)ipStr.c_str(), netorderIp, hostID);
			if(ret != GENERIC_SUCCESS){
				printf("ProcessHost(): InsertHost() failed\n");
				return GENERIC_ERROR;
			}
		

			// Make an entry in HostsToMeasure if requested
			if(updateForPolling == true){
				ret = InsertHostToMeasure(*hostID, readinessState, &hostToMeasureID);
				if(ret != GENERIC_SUCCESS){
					printf("ProcessHost(): InsertHostToMeasure() failed\n");
					return GENERIC_ERROR;
				}
			}
		}
	}
	// if neither, error out
	else{
		printf("ProcessHost(): Resolving host name and IP failed failed\n");
		return GENERIC_ERROR;
	}
	
	return GENERIC_SUCCESS;
}

int SelectUnfinishedPendingSelfAttestationMeIds(unsigned int timeLimit, vector<int> * v){
	MYSQL_RES * results;
	MYSQL_ROW row; 
	unsigned int len;
	int holder;
	unsigned int numRows = 0;
	MYSQL * conn;
	char query[400];

	len = sprintf_s(query, 400, "SELECT id FROM pendingmeasurementevents WHERE timeInSeconds < %u AND type = 0", timeLimit);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectUnfinishedPendingSelfAttestationMeIds: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}
	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectUnfinishedPendingSelfAttestationMeIds: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectUnfinishedPendingSelfAttestationMeIds: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows == 0){
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	for(unsigned int i = 0; i < numRows; i++){
		row = mysql_fetch_row(results);
		if(row == NULL){
			printf("SelectUnfinishedPendingSelfAttestationMeIds: mysql_fetch_row failed\n");
			mysql_free_result(results);
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
		}

		unsigned int temp = strtoul(row[0], NULL, 10);
		v->push_back(temp);
	}

	mysql_free_result(results);
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectUnfinishedPendingSelfAttestationMeIds: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SelectDataSetForLimitCalculations(unsigned int countFromTimeInSeconds, unsigned int count, queue<unsigned int> * q){
    MYSQL_RES * results;
	MYSQL_ROW row;
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	MYSQL * conn;
	unsigned int counter = 0;

	fixedInsertStr = "SELECT meRTTInMicroseconds FROM MeasurementEvents WHERE type = %d and timeInSeconds > %d";
	len = sprintf_s(query, 300, fixedInsertStr, SELF_ATTESTATION, countFromTimeInSeconds);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectDataSetForLimitCalculations: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectDataSetForLimitCalculations: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("mysql_real_query() failed in SelectDataSetForLimitCalculations\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectDataSetForLimitCalculations: mysql_store_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		mysql_free_result(results);
		printf("SelectDataSetForLimitCalculations: mysql_num_rows returned no results\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	while(counter < count){

		row = mysql_fetch_row(results);
		if(row == NULL){
			printf("SelectDataSetForLimitCalculations: mysql_fetch_row failed\n");
			mysql_free_result(results);
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
		}

		q->push((unsigned int)(atoi(row[0])));
		counter++;
	}

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectDataSetForLimitCalculations: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}




int SelectAllHostsToMeasure(queue<string> * q, queue<int> * r){

	MYSQL_RES * results;
	MYSQL_ROW row; //really a char **
	string hostIP;
	int hostID;
	char * endptr = "";
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	unsigned int numRows = 0, numFields = 0;
	MYSQL * conn;

	fixedInsertStr = "SELECT Hosts.id, Hosts.ip_str FROM Hosts INNER JOIN HostsToMeasure WHERE Hosts.id = HostsToMeasure.hostID";
	len = strlen(fixedInsertStr);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectAllHostsToMeasure: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectAllHostsToMeasure: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, fixedInsertStr, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectAllHostsToMeasure: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows == 0){//Will fail here if an empty set is returned
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	//This function expects that the results will be a single column of integers (IDs)
	for(unsigned int i = 0; i < numRows; i++){
		row = mysql_fetch_row(results);
		if(row == NULL){
			printf("SelectAllHostsToMeasure: mysql_fetch_row failed\n");
			mysql_free_result(results);
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
		}

		hostID = strtoul(row[0], &endptr, 10);

		r->push(hostID);
		q->push(row[1]);
	}
	holder = GENERIC_SUCCESS;
	mysql_free_result(results);

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectAllHostsToMeasure: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return holder;
}

//Document me
int SelectModulesToMeasure(vector<string> * v){
	MYSQL_RES * results;
	MYSQL_ROW row; 
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	unsigned int numRows = 0, numFields = 0;
	MYSQL * conn;

	fixedInsertStr = "SELECT moduleName FROM ModulesToMeasure";
	len = strlen(fixedInsertStr);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectModulesToMeasure: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectModulesToMeasure: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	//////////////////////////////////
	if(0 != mysql_real_query(conn, fixedInsertStr, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectModulesToMeasure: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows == 0){
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	//This function expects that the results will be a single column of wstrings
	for(unsigned int i = 0; i < numRows; i++){
		row = mysql_fetch_row(results);
		if(row == NULL){
			printf("SelectModulesToMeasure: mysql_fetch_row failed\n");
			mysql_free_result(results);
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
		}

		string temp = (string)row[0];
		v->push_back(temp);
	}

	mysql_free_result(results);
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectModulesToMeasure: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SelectHostIPsByHostName(char * hostName, list<string> * v){
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	MYSQL_RES * results;
	MYSQL_ROW row; 
	unsigned int numRows = 0, numFields = 0;
	MYSQL * conn;

	if(hostName == NULL || strlen(hostName) == 0){
		printf("SelectHostIPsByHostName(): hostName passed was null\n");
		return GENERIC_ERROR;
	}

	fixedInsertStr = "SELECT ip_str FROM Hosts WHERE hostName like '%s'";
	len = sprintf_s(query, 300, fixedInsertStr, hostName);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectHostIPsByHostName: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectHostIPsByHostName(): OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectHostIPsByHostName(): mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows == 0){
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	//This function expects that the results will be a single column of strings
	for(unsigned int i = 0; i < numRows; i++){
		row = mysql_fetch_row(results);
		if(row == NULL){
			printf("SelectHostIPsByHostName(): mysql_fetch_row failed\n");
			mysql_free_result(results);
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
		}

		string temp = (string)row[0];
		v->push_back(temp);
	}

	mysql_free_result(results);
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectHostIPsByHostName(): Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}
	
	return GENERIC_SUCCESS;
}

//TODO: Document me
int SelectAllHostsToMeasureForPolling(int tolerance, queue<int> * q){
	int hostID;
	MYSQL_RES * results;
	MYSQL_ROW row; 
	unsigned int len;
	int holder;
	unsigned int numRows = 0, numFields = 0;
	char query[200];
	MYSQL * conn;

	time_t rawtime;
	time (&rawtime);

	unsigned int tempTimeStamp = (unsigned int)rawtime;
	tempTimeStamp = tempTimeStamp - (unsigned int)tolerance;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectAllHostsToMeasureForPolling: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("SelectAllHostsToMeasureForPolling: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	len = sprintf_s(query, 200, "SELECT hostID FROM HostsToMeasure WHERE readiness = %u and lastTimeMeasurementRequested < %u",READY, tempTimeStamp);
	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectAllHostsToMeasureForPolling: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows == 0){//Will fail here if an empty set is returned
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}

	//This function expects that the results will be a single column of integers (IDs)
	for(unsigned int i = 0; i < numRows; i++){
		row = mysql_fetch_row(results);
		if(row == NULL){
			printf("SelectAllHostsToMeasureForPolling: mysql_fetch_row failed\n");
			mysql_free_result(results);
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
		}

		hostID = strtoul(row[0], NULL, 10);
		q->push(hostID);
	}

	mysql_free_result(results);
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectAllHostsToMeasureForPolling: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

int SelectHostIDByName(string hostName, unsigned int * hostID){
	char query[300];
	char * fixedInsertStr;
	unsigned int len;
	int ret;

	fixedInsertStr = "SELECT ID FROM hosts where hostname = '%s'";
	len = sprintf_s(query, 300, fixedInsertStr, hostName.c_str());

	ret = SelectSingleIntResult(SERVER, query, len, hostID);
	return ret;
}

int SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp(self_check_t * selfCheckInput, self_check_t * selfCheckTiresias){
	MYSQL_RES * results;
	MYSQL_ROW row; //really a char **
	unsigned int numRows = 0, numFields = 0;
	char query[200];
	unsigned int len;
	char * fixedSelectStr;
	MYSQL * conn;

	fixedSelectStr = "SELECT * FROM Checksums WHERE nonce = %#x AND timeDateStamp = %#x AND baseVA = %#x";
	len = sprintf_s(query, 200, fixedSelectStr, selfCheckInput->nonce, selfCheckInput->timeDateStamp, selfCheckInput->baseVA);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffTiresiasDBName);
	if(conn == NULL){
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: mysql_real_query failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows == 0){//Will fail here if an empty set is returned
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, NO_RESULTS_FOUND);
	}
	//There should only ever be one correct checksum value
	//for a given combination of nonce/timeDateStamp/baseVA
	if(numRows > 1){
		mysql_free_result(results);
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: More than one checksum found for the nonce/timeDateStamp/baseVA combination. Check tiresias database\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, TOO_MANY_RESULTS_FOUND);
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numFields = mysql_num_fields(results);
	if(numFields != (4 + SELF_CHECKSUM_SIZE)){
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: mysql_num_fields says we have the wrong number of fields\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);	
	}

	selfCheckTiresias->nonce = selfCheckInput->nonce;
	selfCheckTiresias->timeDateStamp = selfCheckInput->timeDateStamp;
	selfCheckTiresias->baseVA = selfCheckInput->baseVA;
	for(unsigned int i = 0; i < SELF_CHECKSUM_SIZE; i++){
		selfCheckTiresias->checksum[i] = strtoul(row[4+i], NULL, 10);
	}

	mysql_free_result(results);
	//////////////////////////////////
	CloseDatabaseConnection(conn);

	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}
	
	return GENERIC_SUCCESS;
}


int InsertBrandStringLimits(vector<string> * v){
	char query[200];
	char * fixedInsertStr;
	unsigned int len;
	char * cTemp;
	char * brandString;
	char * upper;
	char * lower;
	unsigned int id = 0;
	unsigned int lowerInt = 0;
	unsigned int upperInt = 0;
	int ret = 0;

	//For each host to measure in the vector
	for(unsigned int i=0; i < v->size(); i++){
		string temp = v->at(i);
		cTemp = (char *)temp.c_str();

		brandString = strtok_s(NULL, "||", &cTemp);
		if(brandString == NULL){
			printf("InsertBrandStringLimits: strtok_s() 1 failed\n");
			v->clear();
			return GENERIC_ERROR;
		}
	
		upper = strtok_s(NULL, "||", &cTemp);
		if(upper == NULL){
			printf("InsertBrandStringLimits: strtok_s() 2 failed\n");
			v->clear();
			return GENERIC_ERROR;
		}

		lower = strtok_s(NULL, "||", &cTemp);
		if(lower == NULL){
			printf("InsertBrandStringLimits: strtok_s() 3 failed\n");
			v->clear();
			return GENERIC_ERROR;
		}

		upperInt = atoi((const char *)upper);
		lowerInt = atoi((const char *)lower);

		id = 0;
		fixedInsertStr = "SELECT id FROM CPUControlLimits WHERE brandString = '%s' ORDER BY id DESC LIMIT 1";
		len = sprintf_s(query, 200, fixedInsertStr, brandString);
		SelectSingleIntResult(SERVER, query, len, &id);
		if(id == 0)
		{
			fixedInsertStr = "INSERT INTO CPUControlLimits VALUES(NULL,'%s',%u,%u)";
			len = sprintf_s(query, 200, fixedInsertStr, brandString, upperInt, lowerInt);

			ret = ExecuteInsert(SERVER, query, len, &id);
			if(ret != GENERIC_SUCCESS){
				v->clear();
				return GENERIC_ERROR;
			}
		}
	}
	
	v->clear();
	return GENERIC_SUCCESS;
}

int InsertHostLimits(vector<string> * v){
	char query[200];
	char * fixedInsertStr;
	unsigned int len;
	char * cTemp;
	char * host;
	char * upper;
	char * lower;
	unsigned int hostID = 0;
	unsigned int id = 0;
	unsigned int lowerInt = 0;
	unsigned int upperInt = 0;
	int ret = 0;

	//For each host to measure in the vector
	for(unsigned int i=0; i < v->size(); i++){
		string temp = v->at(i);
		cTemp = (char *)temp.c_str();

		host = strtok_s(NULL, "||", &cTemp);
		if(host == NULL){
			printf("InsertHostLimits: strtok_s() 1 failed\n");
			v->clear();
			return GENERIC_ERROR;
		}
	
		upper = strtok_s(NULL, "||", &cTemp);
		if(upper == NULL){
			printf("InsertHostLimits: strtok_s() 2 failed\n");
			v->clear();
			return GENERIC_ERROR;
		}

		lower = strtok_s(NULL, "||", &cTemp);
		if(lower == NULL){
			printf("InsertHostLimits: strtok_s() 3 failed\n");
			v->clear();
			return GENERIC_ERROR;
		}

		upperInt = atoi((const char *)upper);
		lowerInt = atoi((const char *)lower);

		// get hostID from host
		//ret = SelectHostIDByIP(host, &hostID);

		id = 0;
		fixedInsertStr = "SELECT id FROM HostControlLimits WHERE hostID = '%s' ORDER BY id DESC LIMIT 1";
		len = sprintf_s(query, 200, fixedInsertStr, host);
		SelectSingleIntResult(SERVER, query, len, &id);
		if(id == 0)
		{
			fixedInsertStr = "INSERT INTO HostControlLimits VALUES(NULL,'%s',%u,%u)";
			len = sprintf_s(query, 200, fixedInsertStr, host, upperInt, lowerInt);

			ret = ExecuteInsert(SERVER, query, len, &id);
			if(ret != GENERIC_SUCCESS){
				v->clear();
				return GENERIC_ERROR;
			}
		}
	}
	
	v->clear();
	return GENERIC_SUCCESS;
}

int InsertServerPrerequisiteForMessageType(int msgType, vector<string> * v){
	char query[200];
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	char * cTemp;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("InsertServerPrerequisiteForMessageType: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("InsertServerPrerequisiteForMessageType: OpenDatabaseConnection(gffServerDBName) failed\n");
		v->clear();
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//For each host to measure in the vector
	for(unsigned int i=0; i < v->size(); i++){
		string temp = v->at(i);
		cTemp = (char *)temp.c_str();

		fixedInsertStr = "INSERT INTO TableVerificationPrerequisiteModules VALUES(NULL,%i,'%s')";
		len = sprintf_s(query, 200, fixedInsertStr, msgType, cTemp);

		//////////////////////////////////
		if(0 != mysql_real_query(conn, query, len)){
			holder = CheckError(conn,mysql_errno(conn));
			
			// if error code is 1062, the entry already exists, so it's ok
			if(holder != 1062){
				CloseDatabaseConnection(conn);
				v->clear();
				return ReleaseMutexAndReturnError(mysqlMutex, holder);
			}
		}

	}
	CloseDatabaseConnection(conn);
	v->clear();
	//////////////////////////////////
	if(!ReleaseMutex(mysqlMutex)){
		printf("InsertServerPrerequisiteForMessageType: Couldn't release mutex. Returning\n");
		return GENERIC_ERROR;
	}
	return GENERIC_SUCCESS;
}


//TODO: Document me
int InsertModulesToMeasureForPolling(vector<string> * v){
	char query[200];
	char * fixedInsertStr;
	unsigned int len;
	int holder;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("InsertModulesToMeasureForPolling: Couldn't acquire mutex. Returning\n");
		__asm{int 3};
		//free outstanding resources
		v->clear();
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("InsertModulesToMeasureForPolling: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}
	//////////////////////////////////
	for(unsigned int i=0; i < v->size(); i++){
		string temp = v->at(i);
					
		fixedInsertStr = "INSERT INTO ModulesToMeasure(moduleName) VALUES ('%s')";
		len = sprintf_s(query, 200, fixedInsertStr, temp.c_str());

		if(0 != mysql_real_query(conn, query, len)){
			holder = CheckError(conn,mysql_errno(conn));
			if(holder != INSERT_ERROR_DUPLICATE){ //allow duplicates
				v->clear();
				ReleaseMutex(mysqlMutex);
				CloseDatabaseConnection(conn);
				printf("InsertModulesToMeasureForPolling: Couldn't release mutex. Returning\n");
				return GENERIC_ERROR;
			}
			else{
				printf("\n\n%s is already in ModulesToMeasure and we don't insert duplicates.\n\n", temp.c_str());
			}
		}

	}
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("InsertModulesToMeasureForPolling: Couldn't release mutex. Returning\n");
		//free outstanding resources
		v->clear();
		__asm{int 3};	
		return GENERIC_ERROR;
	}

	//We don't want the vector to have any entries when we're done with it.
	v->clear();
	
	return GENERIC_SUCCESS;
}

//TODO: Document me
int InsertHostsToMeasureForPolling(vector<string> * v){
	int ret;
	unsigned int hostID = 0, hostToMeasureID = 0;
	string ipAddress = "";
	char * cTemp = "";
	bool alphaCharDetected = false;

	//Changed so that every function which access the DB grabs the mutex itself

	//For each host to measure in the vector
	for(unsigned int i=0; i < v->size(); i++){
		//string temp = v->at(i);
		string temp = "";
		hostID = 0;
		ipAddress.clear();
		ipAddress = v->at(i);
		// change to NOTREADY below when pulse check works
		ret = ProcessHost(temp, ipAddress, true, READY, &hostID);
		if(ret != GENERIC_SUCCESS){
			printf("InsertHostsToMeasureForPolling(): ProcessHost() failed\n");
			// TODO: Log this error
		}

	}//end for each

	//Make sure the vector is completely empty when we're done
	v->clear();

	return GENERIC_SUCCESS;
}


//note: for now insert should always be == true
//ASSUMPTION: We assume that the hostID and binID are already set before we get in here
//If insert = true, always insert a new measurement
//If insert = false, just update an existing measurement (if any)
int MovePendingMeasurementToFinalMeasurements(me_t * incomingME, me_t * pendingME, bool insert){
	int ret;
	char name[MAX_BIN_NAME_LEN];
	unsigned __int64 dNewTimeInMicroseconds, dPendingTimeInMicroseconds;

	//Mark the event as done in the prerequisites
	unsigned int prereqID = 0;
	//I know the "0" string is confusing, see its reason in InsertPrereq
	name[0] = '0';
	name[1] = 0;

	//Delete the pending measurement event
	ret = DeleteFromTableByID("PendingMeasurementEvents", pendingME->id);
	if(ret != GENERIC_SUCCESS){
		printf("MovePendingMeasurementToFinalMeasurements: DeleteFromTableByID PendingMeasurementEvents failed\n");
		return GENERIC_ERROR;
	}

	ret = CleanUpStaleMatchingPendingEvents(pendingME);
	if(ret != GENERIC_SUCCESS){
		printf("MovePendingMeasurementToFinalMeasurements: CleanUpStaleMatchingPendingEvents failed\n");
		return GENERIC_ERROR;
	}

	//Update the final measurement event
	dNewTimeInMicroseconds = incomingME->timeInSeconds;
	dNewTimeInMicroseconds *= 1000000;
	dNewTimeInMicroseconds += incomingME->timeInMicroseconds;
	dPendingTimeInMicroseconds = pendingME->timeInSeconds;
	dPendingTimeInMicroseconds *= 1000000;
	dPendingTimeInMicroseconds += pendingME->timeInMicroseconds;
	incomingME->meRTTInMicroseconds = (unsigned int)(dNewTimeInMicroseconds - dPendingTimeInMicroseconds);

	incomingME->lowerTiming = pendingME->lowerTiming;
	incomingME->upperTiming = pendingME->upperTiming;

	if(insert){		//insert it if told there should be a new entry via insert param
		printf("Measurement type %s took %d(%#x) microseconds\n", MsgTypeToString((msgType)(incomingME->type)),incomingME->meRTTInMicroseconds,incomingME->meRTTInMicroseconds);
		ret = InsertME(incomingME);
		if(ret != GENERIC_SUCCESS){
			printf("MovePendingMeasurementToFinalMeasurements: InsertME failed\n");
			return GENERIC_ERROR;
		}
	}

	// TODO: update server prerequisite with this measurement event if needed
	//if we ever make this a focal point in that all measurements start
	//in the pending measurements table


	return GENERIC_SUCCESS;
}

int CleanUpStaleMatchingPendingEvents(me_t * pendingME){
	char query[256];
	char * fixedInsertStr;
	unsigned int len;
	unsigned int numRows;
	int holder;
	MYSQL * conn;
	MYSQL_RES * results;
	MYSQL_ROW row;

	fixedInsertStr = "SELECT id FROM PendingMeasurementEvents WHERE type = %d AND timeInSeconds = %d AND hostID = %d AND overloadedForeignID = %d AND id <> %d AND timeInSeconds < %d AND nonce = %d";
	len = sprintf_s(query, 256, fixedInsertStr, pendingME->type, pendingME->timeInSeconds, pendingME->hostID,pendingME->overloadedForeignID,pendingME->id,pendingME->timeInSeconds,pendingME->nonce);

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("CleanUpStaleMatchingPendingEvents: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffServerDBName);
	if(conn == NULL){
		printf("CleanUpStaleMatchingPendingEvents: OpenDatabaseConnection(gffServerDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		holder = CheckError(conn,mysql_errno(conn));
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, holder);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("CleanUpStaleMatchingPendingEvents: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
	}

	numRows = (unsigned int)mysql_num_rows(results);
	if(numRows == 0){
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		if(!ReleaseMutex(mysqlMutex)){
			printf("CleanUpStaleMatchingPendingEvents: Couldn't release mutex.\n");
			return GENERIC_ERROR;
		}
		return GENERIC_SUCCESS;
	}

	for(unsigned int i = 0; i < numRows; i++){
		row = mysql_fetch_row(results);
		if(row == NULL){
			printf("CleanUpStaleMatchingPendingEvents: mysql_fetch_row failed\n");
			mysql_free_result(results);
			CloseDatabaseConnection(conn);
			return ReleaseMutexAndReturnError(mysqlMutex, GENERIC_ERROR);
		}

		unsigned int temp = (unsigned int)row[0];
		fixedInsertStr = "DELETE FROM PendingMeasurementEvents WHERE id = %d";
		len = sprintf_s(query, 100, fixedInsertStr, temp);

		//if(0 != mysql_real_query(conn, query, len)){
		//	holder = CheckError(conn,mysql_errno(conn));
		//	CloseDatabaseConnection(conn);
		//	return ReleaseMutexAndReturnError(mysqlMutex, holder);
		//}

		printf("CleanUpStaleMatchingPendingEvents: delete sql = %s\n",query);
	}

	mysql_free_result(results);

	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("CleanUpStaleMatchingPendingEvents: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}

//I have no idea why this stupid thing couldn't be linked into this file when it was
//defined in server_client_protocol.cpp...so moving it here was a gross hack
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