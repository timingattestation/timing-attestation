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

#include "database_mysql.h"
#include "sha.h"

HANDLE mysqlMutex;

char * gffTiresiasDBName;
char * gffSharedDBName;
char * gffDatabaseUsername;
char * gffDatabasePassword;

int gDeleteDB;

int InitializeDatabaseConnection(){
	
	MYSQL mysql;

	if(mysql_init(&mysql) == NULL)
	{
		printf("InitializeDatabaseConnection: mysql_init failed\n");
		return GENERIC_ERROR;
	}

	if(NULL == mysql_real_connect(&mysql, "127.0.0.1", gffDatabaseUsername, gffDatabasePassword, gffTiresiasDBName, 3306, NULL, 0)){
		printf("InitializeDatabaseConnection: mysql_real_connect failed\n");
		return GENERIC_ERROR;
	}

	//do not use the D command line option in "production" environments.
	if(gDeleteDB){
		DeleteAndRecreateDatabase(&mysql, gffTiresiasDBName);
		mysql_close(&mysql);
		mysql_library_end();  

		if(mysql_init(&mysql) == NULL){
			printf("InitializeDatabaseConnection: mysql_init mysqlMeasurements failed2\n");
			return GENERIC_ERROR;
		}
		if(NULL == mysql_real_connect(&mysql, "127.0.0.1", gffDatabaseUsername, gffDatabasePassword, gffTiresiasDBName, 3306, NULL, 0)){
			printf("InitializeDatabaseConnection: mysql_real_connect 2 failed\n");
			return GENERIC_ERROR;
		}
	}
	CreateTables(&mysql);

	mysql_close(&mysql);
	mysql_library_end();

	mysqlMutex = CreateMutex(NULL, FALSE, NULL);
	if(mysqlMutex == NULL){
		printf("InitializeDatabaseConnection CreateMutex for mysqlMutex failed\n");
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
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




int ReleaseMutexAndReturnError(HANDLE mutex,int err){
	ReleaseMutex(mutex);
	return err;
}

/////////////////////////////////////////////////////////////////////////////////////
//INSERTS
/////////////////////////////////////////////////////////////////////////////////////

int InsertLoadedModule(bin_data_t * bin, unsigned int hostID){
	char query[200];
	char * fixedInsertStr;
	unsigned int len, result;
	int ret;

	fixedInsertStr = "INSERT INTO %s.LoadedModules(name, baseVA, sizeOfImage, timeDateStamp, hostID) VALUES ('%ws', %u, %u, %u, %u)";
	len = sprintf_s(query, 200, fixedInsertStr, gffSharedDBName, bin->bNameW, bin->baseVA, bin->sizeOfImage, bin->timeDateStamp, hostID);

	ret = ExecuteInsert(gffSharedDBName, query, len, &result);
	//ignore duplicates
	if(ret != GENERIC_SUCCESS && ret != INSERT_ERROR_DUPLICATE){
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}


/////////////////////////////////////////////////////////////////////////////////////
//SELECTS
/////////////////////////////////////////////////////////////////////////////////////

int CheckIfExportExistsForLoadedModuleID(unsigned int loadedModuleID, unsigned int * exists){
	char query[200];
	char * fixedSelectStr;
	unsigned int len;
	int holder;

	fixedSelectStr = "SELECT id FROM Exports WHERE LoadedModuleID = %u LIMIT 1";
	len = sprintf_s(query, 200, fixedSelectStr, loadedModuleID);

	holder = SelectSingleUIntResult(gffTiresiasDBName, query, len, exists);
	if(holder != GENERIC_SUCCESS){
		printf("CheckIfExportExistsForLoadedModuleID: SelectSingleUIntResult returned %#x\n", holder);
	}

	return holder;
}


//The caller needs to have allocated MAX_EXPORT_NAME_LEN worth of space for entry->name before calling this
int SelectExportEntryByNameAndLoadedModuleID(char * exportName, unsigned int loadedModuleID, exportsEntry_t * entry){
	MYSQL * connection;
	MYSQL_RES * results = NULL;
	MYSQL_ROW row; //really a char **
	int holder;
	char query[200];
	char * fixedStr;
	unsigned int len;

	fixedStr = "SELECT * FROM Exports WHERE name = '%s' AND loadedModuleID = %u";
	len = sprintf_s(query, 200, fixedStr, exportName, loadedModuleID);

	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
		printf("SelectExportEntryByNameAndLoadedModuleID: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	connection = OpenDatabaseConnection(gffTiresiasDBName);
	if(connection == NULL){
		printf("SelectExportEntryByNameAndLoadedModuleID: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(connection, query, len)){
		printf("SelectExportEntryByNameAndLoadedModuleID: mysql_real_query() failed\n");
		holder = GENERIC_ERROR;
		goto cleanAndExit;
	}

	results = mysql_store_result(connection);
	if(results == NULL){
		printf("SelectExportEntryByNameAndLoadedModuleID: mysql_use_result failed\n");
		holder = GENERIC_ERROR;
		goto cleanAndExit;
	}

	if(mysql_num_rows(results) == 0){
		holder = NO_RESULTS_FOUND;
		goto cleanAndExit;
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectExportEntryByNameAndLoadedModuleID: mysql_fetch_row failed\n");
		holder = GENERIC_ERROR;
		goto cleanAndExit;
	}

	entry->id = strtoul(row[0], NULL, 10);
	entry->RVA = strtoul(row[1], NULL, 10);
	if(entry->name != NULL){
		//will still error out if the person didn't zero initialize the struct or didn't
		//allocate space for name
		strncpy_s(entry->name, MAX_EXPORT_NAME_LEN, row[2], MAX_EXPORT_NAME_LEN);
	}
	entry->ordinal = strtoul(row[3], NULL, 10);	
	entry->loadedModuleID = strtoul(row[4], NULL, 10);
	holder = GENERIC_SUCCESS;

	//////////////////////////////////
cleanAndExit:
	mysql_free_result(results);
	CloseDatabaseConnection(connection);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectExportEntryByNameAndLoadedModuleID: Couldn't release mutex.\n");
		return GENERIC_ERROR;
	}
	return holder;
}

//TODO: Ideally this could take a binID as input too, but don't need it for now
int SelectResolvedBinarySymbolRVAByNameAndHostID(char * symbolName, unsigned int hostID, unsigned int * symbolRVA){
	char query[200];
	char * fixedStr;
	unsigned int len, holder;

	fixedStr = "SELECT rva FROM ResolvedBinarySymbols WHERE name = '%s' AND hostID = %u";
	len = sprintf_s(query, 200, fixedStr, symbolName, hostID);

	holder = SelectSingleUIntResult(gffTiresiasDBName, query, len, symbolRVA);
	if(holder != GENERIC_SUCCESS){
		printf("SelectResolvedBinarySymbolRVAByNameAndHostID: SelectSingleUIntResult returned %#x\n", holder);
	}

	return holder;
}

int CheckError(MYSQL * connection, unsigned int error){
	switch(error){
		case INSERT_ERROR_DUPLICATE: //Allowed and ignored.
			return INSERT_ERROR_DUPLICATE;
			break;

		case TABLE_ALREADY_DEFINED: //Allowed and ignored.
			return TABLE_ALREADY_DEFINED;
			break;

		default:
			printf("unhandled mysql_real_query error: %s\n", mysql_error(connection));
			__asm{int 3};
			return GENERIC_ERROR;
			break;
	}
}

//Helper function to return the value when we expect to get back a single column and
//single row integer result (such as when looking up a single ID field)
int SelectSingleUIntResult(char * dbName, char * query, unsigned int len, unsigned int *value){
	MYSQL * connection;
	MYSQL_RES * results = NULL;
	MYSQL_ROW row; //really a char **
	int holder;
	*value = 0;

	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
		printf("SelectSingleUIntResult: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	connection = OpenDatabaseConnection(dbName);
	if(connection == NULL){
		printf("SelectSingleUIntResult: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(connection, query, len)){
		printf("SelectSingleUIntResult: mysql_real_query() failed\n");
		holder = GENERIC_ERROR;
		goto cleanAndExit;
	}

	results = mysql_store_result(connection);
	if(results == NULL){
		printf("SelectSingleUIntResult: mysql_use_result failed\n");
		holder = GENERIC_ERROR;
		goto cleanAndExit;
	}

	if(mysql_num_rows(results) == 0){
		holder = NO_RESULTS_FOUND;
		goto cleanAndExit;
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectSingleUIntResult: mysql_fetch_row failed\n");
		holder = GENERIC_ERROR;
		goto cleanAndExit;
	}

	POSSIBLE_NULL_ENTRY(*value, row[0]);
	holder = GENERIC_SUCCESS;

	//////////////////////////////////
cleanAndExit:
	mysql_free_result(results);
	CloseDatabaseConnection(connection);
	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectSingleUIntResult: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}
	return holder;
}


#define NUM_MULTI		3
#define NUM_BINARIES	3
#define NUM_SELF		2
#define NUM_NOTES		3
#define NUM_MISC		2

int CreateTables(MYSQL * connection){

	char * multi[NUM_MULTI];
	char * binaries[NUM_BINARIES];
	char * self[NUM_SELF];
	char * notes[NUM_NOTES];
	char * misc[NUM_MISC];
	unsigned int i = 0;


	//Multipurpose
	multi[0] = "CREATE TABLE notes (				\
			   note BLOB NOT NULL,					\
			   id INTEGER UNSIGNED AUTO_INCREMENT,	\
			   PRIMARY KEY(id))";

	multi[1] = "CREATE TABLE hosts (				\
			   hostname VARCHAR(255),				\
			   ip_str VARCHAR(15),					\
			   ip_netorder_int INTEGER UNSIGNED,	\
			   id INTEGER UNSIGNED AUTO_INCREMENT,	\
			   PRIMARY KEY(id),						\
			   UNIQUE KEY(hostname, ip_str, ip_netorder_int))";

	multi[2] =	"CREATE TABLE MeasurementEvents (				\
				id INTEGER UNSIGNED AUTO_INCREMENT,				\
				PRIMARY KEY(id),								\
				type INTEGER UNSIGNED NOT NULL,					\
				nonce INTEGER UNSIGNED NOT NULL,				\
				timeInSeconds INTEGER UNSIGNED NOT NULL,		\
				timeInMicroseconds INTEGER UNSIGNED NOT NULL,	\
				meRTTInMicroseconds INTEGER UNSIGNED NOT NULL,	\
				netRTTInMicroseconds INTEGER UNSIGNED,			\
				HostID INTEGER UNSIGNED NOT NULL,				\
				FOREIGN KEY(HostID) REFERENCES Hosts(id),		\
				UNIQUE KEY(type, nonce, timeInSeconds, timeInMicroseconds, meRTTInMicroseconds, netRTTInMicroseconds, HostID))";


	/////////////////////////////////////
	////For binary measurements
	/////////////////////////////////////
	////ORDER MATTERS!!!
	////Everything must be declared after the tables which it references by foreign key


	////I don't think I can make LoadedModuleID reference shared.LoadedModules
	////so I made this unofficially a foreign key to that
	binaries[0] =	"CREATE TABLE Exports (\
					id INTEGER UNSIGNED AUTO_INCREMENT, \
					PRIMARY KEY(id),					\
					rva INTEGER UNSIGNED NOT NULL,		\
					name VARCHAR(52),					\
					ordinal INTEGER UNSIGNED NOT NULL,	\
					LoadedModuleID INTEGER UNSIGNED NOT NULL, \
					UNIQUE KEY(rva, name, ordinal, LoadedModuleID))";

	binaries[1] =	"CREATE TABLE ExpectedBinarySymbols (	\
					id INTEGER UNSIGNED AUTO_INCREMENT,		\
					symbolName VARCHAR(128),				\
					moduleName VARCHAR(128),				\
					PRIMARY KEY(id))";

	binaries[2] =	"CREATE TABLE ResolvedBinarySymbols (		\
					id INTEGER UNSIGNED AUTO_INCREMENT,			\
					name VARCHAR(128),							\
					rva INTEGER UNSIGNED NOT NULL,				\
					BinID INTEGER UNSIGNED NOT NULL,			\
					HostID INTEGER UNSIGNED NOT NULL,			\
					FOREIGN KEY(HostID) REFERENCES Hosts(id),	\
					FOREIGN KEY(BinID) REFERENCES Binaries(id), \
					PRIMARY KEY(id))";

	//binaries[3] =	"CREATE TABLE ExpectedBinaryRVAs (			\
	//				id INTEGER UNSIGNED AUTO_INCREMENT,			\
	//				timeDateStamp INTEGER UNSIGNED NOT NULL,	\
	//				moduleName VARCHAR(128),					\
	//				rva INTEGER UNSIGNED NOT NULL,				\
	//				PRIMARY KEY(id))";


	///////////////////////////////////
	//For self measurements
	///////////////////////////////////
	self[0] =	"CREATE TABLE Checksums (				\
				id INTEGER UNSIGNED AUTO_INCREMENT,		\
				PRIMARY KEY(id),						\
				nonce INTEGER UNSIGNED NOT NULL,		\
				timeDateStamp INTEGER UNSIGNED NOT NULL,\
				baseVA INTEGER UNSIGNED NOT NULL,		\
				c0 INTEGER UNSIGNED NOT NULL,			\
				c1 INTEGER UNSIGNED NOT NULL,			\
				c2 INTEGER UNSIGNED NOT NULL,			\
				c3 INTEGER UNSIGNED NOT NULL,			\
				c4 INTEGER UNSIGNED NOT NULL,			\
				c5 INTEGER UNSIGNED NOT NULL,			\
				UNIQUE KEY(nonce, timeDateStamp, baseVA))";

	//Self Measurement Event
	self[1] =	"CREATE TABLE ChecksumMEs (							\
				id INTEGER UNSIGNED AUTO_INCREMENT,					\
				PRIMARY KEY(id),									\
				ChecksumID INTEGER UNSIGNED NOT NULL,				\
				FOREIGN KEY(ChecksumID) REFERENCES Checksums(id),	\
				MeasurementEventID INTEGER UNSIGNED NOT NULL,		\
				FOREIGN KEY(MeasurementEventID) REFERENCES MeasurementEvents(id), \
				HostID INTEGER UNSIGNED NOT NULL,					\
				FOREIGN KEY(HostID) REFERENCES Hosts(id))";

	///////////////////////////////////
	//For notes
	///////////////////////////////////

	notes[0] = "INSERT INTO notes VALUES (\"WHITELIST:IMPORTS\",NULL)";
	notes[1] = "INSERT INTO notes VALUES (\"WHITELIST:EXPORTS\",NULL)";
	notes[2] = "INSERT INTO notes VALUES (\"WHITELIST:IMPORTS:EXPORTS\",NULL)";

				//The prerequisites table (along with the associated message type)
				//is used to signal to the server that it needs to ask the client 
				//for a particular measurement type before tiresias can fully calculate
				//the current measurement which is being asked of it

	///////////////////////////////////
	//For misc
	///////////////////////////////////


	misc[0] =	"CREATE TABLE Prerequisites (		\
				id INTEGER UNSIGNED AUTO_INCREMENT, \
				PRIMARY KEY(id),					\
				type INTEGER UNSIGNED NOT NULL,		\
				name varchar(29),					\
				status INTEGER UNSIGNED,			\
				queryCount INTEGER UNSIGNED,		\
				hostID INTEGER UNSIGNED NOT NULL,	\
				UNIQUE KEY(type, name, status, hostID))";
				//type will be a msgType
				//name will be the binary name if the type is BINARY_SECTIONS
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
	misc[1] =	"CREATE TABLE LoadedModules (			\
				id INTEGER UNSIGNED AUTO_INCREMENT,		\
				PRIMARY KEY(id),						\
				name VARCHAR(29) NOT NULL,				\
				baseVA INTEGER UNSIGNED NOT NULL,		\
				sizeOfImage INTEGER UNSIGNED NOT NULL,	\
				timeDateStamp INTEGER UNSIGNED NOT NULL, \
				hostID INTEGER UNSIGNED NOT NULL)";

//////////////////////////////////////////////////////////////////////

	for(i = 0; i < NUM_MULTI; i++){
		if(0 != mysql_real_query(connection, multi[i], strlen(multi[i]))){
			if(CheckError(connection, mysql_errno(connection)) == GENERIC_ERROR){ 
				return GENERIC_ERROR;
			}
		}
	}
	
	for(i = 0; i < NUM_BINARIES; i++){
		if(0 != mysql_real_query(connection, binaries[i], strlen(binaries[i]))){
			if(CheckError(connection, mysql_errno(connection)) == GENERIC_ERROR){ 
				return GENERIC_ERROR; 
			}
		}
	}

	for(i = 0; i < NUM_SELF; i++){
		if(0 != mysql_real_query(connection, self[i], strlen(self[i]))){
			if(CheckError(connection, mysql_errno(connection)) == GENERIC_ERROR){ 
				return GENERIC_ERROR; 
			}
		}
	}

	for(i = 0; i < NUM_NOTES; i++){
		if(0 != mysql_real_query(connection, notes[i], strlen(notes[i]))){
			if(CheckError(connection, mysql_errno(connection)) == GENERIC_ERROR){ 
				return GENERIC_ERROR;
			}
		}
	}

	for(i = 0; i < NUM_MISC; i++){
		if(0 != mysql_real_query(connection, misc[i], strlen(misc[i]))){
			if(CheckError(connection, mysql_errno(connection)) == GENERIC_ERROR){ 
				return GENERIC_ERROR; 
			}
		}
	}

	return GENERIC_SUCCESS;
}

//Just assume it will work, since this won't be used in production
int DeleteAndRecreateDatabase(MYSQL * connection, char * databaseName){
	char buffer[50];
	char * str1 = "DROP DATABASE %s";
	char * str2 = "CREATE DATABASE %s";
	unsigned int len;

	len = sprintf_s(buffer, 50, str1, databaseName);
	mysql_real_query(connection, buffer, len);
	len = sprintf_s(buffer, 50, str2, databaseName);
	mysql_real_query(connection, buffer, len);

	return 0;
}

////int ExecuteUpdateOrDeleteOrLock(char * dbName, char * query, unsigned int length){
////	int holder;
////	MYSQL * conn;
////
////	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
////		printf("ExecuteUpdateOrDeleteOrLock(): Couldn't acquire mutex. Returning\n");
////		return GENERIC_ERROR;
////	}
////
////	conn = OpenDatabaseConnection(dbName);
////
////	if(0 != mysql_real_query(conn, query, length)){
////		holder = CheckError(conn,mysql_errno(conn));
////		CloseDatabaseConnection(conn);	
////		return ReleaseMutexAndReturnError(mysqlMutex, holder);
////	}
////
////	CloseDatabaseConnection(conn);	
////	
////	if(!ReleaseMutex(mysqlMutex)){
////		printf("ExecuteUpdateOrDeleteOrLock(): Couldn't release mutex. Returning\n");
////		return GENERIC_ERROR;
////	}
////
////	return GENERIC_SUCCESS;
////}

int ExecuteUpdateOrDeleteOrLock(unsigned int database, char * query, unsigned int length){
	int holder;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("ExecuteUpdateOrDeleteOrLock(): Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	if(database == TIRESIAS){
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

int ExecuteInsert(char * dbName, char * query, unsigned int length, unsigned int * result){
	int holder;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex, INFINITE) != WAIT_OBJECT_0){
		printf("ExecuteInsert: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(dbName);

	if(conn == NULL){
		printf("ExecuteInsert: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
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

//See if the given host has the given module loaded
//Useful for determining if other modules will be incfluencing a measurement (e.g. due to inline hooks)
int SelectLoadedModuleEntryByNameAndHostID(char * binName, unsigned int hostID, loadedModulesEntry_t * entry){
	MYSQL * conn;
	MYSQL_RES * results;
	MYSQL_ROW row; //really a char **
	int holder = 0;
	char query[100];
	char * fixedStr;
	unsigned int len;

	fixedStr = "SELECT * FROM LoadedModules WHERE hostID = %u AND name = '%s'";
	len = sprintf_s(query, 100, fixedStr, hostID, binName);

	// Acquire Mutex
	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
		printf("SelectLoadedModuleEntryByNameAndHostID: Couldn't acquire mutex.\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffSharedDBName);
	if(conn == NULL){
		printf("SelectLoadedModuleEntryByNameAndHostID: OpenDatabaseConnection(gffSharedDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectLoadedModuleEntryByNameAndHostID: mysql_real_query failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectLoadedModuleEntryByNameAndHostID: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		printf("SelectLoadedModuleEntryByNameAndHostID failed: mysql_num_rows(results) = %u\n", (unsigned int)mysql_num_rows(results));
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,NO_RESULTS_FOUND);
		//Will fail here if an empty set is returned
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectLoadedModuleEntryByNameAndHostID: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	entry->id = strtoul(row[0], NULL, 10);
	strncpy_s(entry->name, MAX_BIN_NAME_LEN, row[1], MAX_BIN_NAME_LEN);
	entry->baseVA = strtoul(row[2], NULL, 10);	
	entry->sizeOfImage = strtoul(row[3], NULL, 10);
	entry->timeDateStamp = strtoul(row[4], NULL, 10);
	entry->hostID = strtoul(row[5], NULL, 10);
	holder = GENERIC_SUCCESS;
	//////////////////////////////////
	CloseDatabaseConnection(conn);

	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectLoadedModuleEntryByNameAndHostID: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return holder;
}

//This select is used to look up module information when all you have is a prefix
//e.g. in forwarded exports, you will only be given something like "VIDEOPRT" or "HAL" or "NTOSKRNL"
//For one thing, it would be annoying to always be trying to tack on a .sys, and then a .dll to find things
//so instead we force the string to start at the beginning of the name with the carrot (^) symbol, and
//then we add in a literal . (as \.) and then at most 3 characters in order to prevent it from matching 
//multiple things which share the same starting sequence, and also to prevent it from matching hal.dll
//and hal.evil.dll
int SelectLoadedModuleEntryByRegexpNameAndHostID(char * binName, unsigned int hostID, loadedModulesEntry_t * entry){
	MYSQL * conn;
	MYSQL_RES * results;
	MYSQL_ROW row; //really a char **
	int holder = 0;
	char query[100];
	char * fixedStr;
	unsigned int len;

	//^ = beginning of name
	//\\. = \\ to get a single \, and then \. for mysql literal dot
	//... = 3 of any character
	//$ = end of name
	fixedStr = "SELECT * FROM LoadedModules WHERE hostID = %u AND name REGEXP '^%s\\....$'";
	len = sprintf_s(query, 100, fixedStr, hostID, binName);

	// Acquire Mutex
	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
		printf("SelectLoadedModuleEntryByNameAndHostID: Couldn't acquire mutex.\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffSharedDBName);
	if(conn == NULL){
		printf("SelectLoadedModuleEntryByNameAndHostID: OpenDatabaseConnection(gffSharedDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	//////////////////////////////////
	if(0 != mysql_real_query(conn, query, len)){
		printf("SelectLoadedModuleEntryByNameAndHostID: mysql_real_query failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	results = mysql_store_result(conn);
	if(results == NULL){
		printf("SelectLoadedModuleEntryByNameAndHostID: mysql_use_result failed\n");
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	if(mysql_num_rows(results) == 0){
		printf("SelectLoadedModuleEntryByNameAndHostID failed: mysql_num_rows(results) = %u\n", (unsigned int)mysql_num_rows(results));
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,NO_RESULTS_FOUND);
		//Will fail here if an empty set is returned
	}

	row = mysql_fetch_row(results);
	if(row == NULL){
		printf("SelectLoadedModuleEntryByNameAndHostID: mysql_fetch_row failed\n");
		mysql_free_result(results);
		CloseDatabaseConnection(conn);
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	entry->id = strtoul(row[0], NULL, 10);
	strncpy_s(entry->name, MAX_BIN_NAME_LEN, row[1], MAX_BIN_NAME_LEN);
	entry->baseVA = strtoul(row[2], NULL, 10);	
	entry->sizeOfImage = strtoul(row[3], NULL, 10);
	entry->timeDateStamp = strtoul(row[4], NULL, 10);
	entry->hostID = strtoul(row[5], NULL, 10);
	holder = GENERIC_SUCCESS;
	//////////////////////////////////
	CloseDatabaseConnection(conn);

	if(!ReleaseMutex(mysqlMutex)){
		printf("SelectLoadedModuleEntryByNameAndHostID: Couldn't release mutex. Exiting thread\n");
		return GENERIC_ERROR;
	}

	return holder;
}

//returns negative value on internal error, 0 on success, and positive value on possibly recoverable error
int InsertChecksum(st_msg_t * check, unsigned int * ChecksumID){
	MYSQL * connection = NULL;
	int ret = 0;
	char query[300];
	//TODO: support calculating the network RTT
	char * fixedStr = "INSERT INTO Checksums VALUES (NULL, %u, %u, %u, %u, %u, %u, %u, %u, %u)";
	unsigned int len = sprintf_s(query, 300, fixedStr, check->nonce, check->timeDateStamp, check->baseVA, check->checksum[0], check->checksum[1], check->checksum[2], check->checksum[3], check->checksum[4], check->checksum[5]);

	// Acquire Mutex
	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
	printf("InsertSection: Couldn't acquire mutex.\n");
		__asm{int 3};
	}

	connection = OpenDatabaseConnection(gffTiresiasDBName);
	if(connection == NULL){
		printf("InsertChecksum: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}	


	if(0 != mysql_real_query(connection, query, len)){
		ret = CheckError(connection, mysql_errno(connection));
		if(ret != INSERT_ERROR_DUPLICATE){
			CloseDatabaseConnection(connection);
			return ReleaseMutexAndReturnError(mysqlMutex,ret);
		}
		//When we already have this checksum, we instead have to lookup
		//the ID for the existing checksum
		CloseDatabaseConnection(connection);
		//Release Mutex
		if(!ReleaseMutex(mysqlMutex)){
			printf("PrintBinaryNames: Couldn't release mutex.\n");
			__asm{int 3};
		}
		return SelectChecksumIDByUniqueKey(check, ChecksumID);
	}

	*ChecksumID = (unsigned int)mysql_insert_id(connection);
	if(*ChecksumID == 0){
		printf("InsertChecksum: mysql_insert_id failed\n");
		CloseDatabaseConnection(connection);
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	CloseDatabaseConnection(connection);

	//Release Mutex
	if(!ReleaseMutex(mysqlMutex)){
		printf("PrintBinaryNames: Couldn't release mutex.\n");
		__asm{int 3};
	}

	return GENERIC_SUCCESS;
}

//returns negative value on error, checksum id on success
int SelectChecksumIDByUniqueKey(st_msg_t * check, unsigned int * ChecksumID){
	MYSQL * connection = NULL;
	int holder = 0;
	char query[200];
	char * fixedStr = "SELECT id FROM Checksums WHERE nonce = %u AND timeDateStamp = %u AND baseVA = %u";
	unsigned int len = sprintf_s(query, 200, fixedStr, check->nonce, check->timeDateStamp, check->baseVA);

	holder =  SelectSingleUIntResult(gffTiresiasDBName, query, len, ChecksumID);
	if(holder != GENERIC_SUCCESS){
		printf("SelectChecksumIDByUniqueKey: SelectSingleUIntResult returned %#x\n", holder);
	}

	return holder;

}
