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
#include "server_tiresias_protocol.h"
#include "server_client_protocol.h"

#include <windows.h>
#include <winsock.h>

#include <mysql.h>
#include <stdio.h>

#define INSERT_ERROR_DUPLICATE	1062
#define TABLE_ALREADY_DEFINED	1050

//These constants need to match being the element of the tiresias.notes array with id = the constant
#define PAGENOTE_NONE 0
#define PAGENOTE_IMPORT 1
#define PAGENOTE_EXPORT 2
#define PAGENOTE_IMPORT_EXPORT 3

#define		POSSIBLE_NULL_ENTRY(var,row)	\
	if(row == NULL){var = 0;}					\
	else{var = strtoul(row, NULL, 10);}		\

//STRUCTS

typedef struct expected_rva {
	int index;
	int rva;
	char *moduleName;
	int binID;
} expected_rva_t;

typedef struct expected_symbol {
	int index;
	char *symbolName;
	char *moduleName;
} expected_symbol_t;

typedef struct resolved_symbol {
	int index;
	int binID;
	int rva;
	int hostID;
	char * symbolName;
} resolved_symbol_t;

typedef struct expected_binary_symbol_entry {
	char *symbolName;
	char *moduleName;
} expected_binary_symbol_entry_t;

typedef struct binary_rva {
	unsigned int timeDateStamp;
	char * moduleName;
	unsigned int rva;
} binary_rva_t;

//Keep this in sync with the Binaries table definition in CreateTables
typedef struct binariesTableEntry{
	unsigned int id;
	char name[MAX_BIN_NAME_LEN];
	unsigned int timeDateStamp;
	unsigned int baseVA;
	unsigned int sizeOfImage;
	unsigned int numROSections;
	unsigned int measurementComplete;
	unsigned int hostID;
	unsigned int versionID;
	unsigned int noteID;
}binariesTableEntry_t;

//Keep this in sync with the LoadedModules table definition in CreateTables
typedef struct loadedModulesEntry{
	unsigned int id;
	char name[MAX_BIN_NAME_LEN];
	unsigned int baseVA;
	unsigned int sizeOfImage;
	unsigned int timeDateStamp;
	unsigned int hostID;
}loadedModulesEntry_t;

//Keep this in sync with the Exports table definition in CreateTables
typedef struct exportsEntry{
	unsigned int id;
	unsigned int RVA;
	char * name;
	unsigned int ordinal;
	unsigned int loadedModuleID;
}exportsEntry_t;


/////////////////////////////////////////////////////////////////////////////////////
//INSERTS
/////////////////////////////////////////////////////////////////////////////////////
int InsertChecksum(st_msg_t * check, unsigned int * ChecksumID);
int InsertLoadedModule(bin_data_t * bin, unsigned int hostID);

/////////////////////////////////////////////////////////////////////////////////////
//SELECTS
/////////////////////////////////////////////////////////////////////////////////////
int CheckIfExportExistsForLoadedModuleID(unsigned int loadedModuleID, unsigned int * exists);
int SelectChecksumIDByUniqueKey(st_msg_t * check, unsigned int * ChecksumID);
int SelectExportEntryByNameAndLoadedModuleID(char * exportName, unsigned int loadedModuleID, exportsEntry_t * entry);
int SelectLoadedModuleEntryByNameAndHostID(char * binName, unsigned int hostID, loadedModulesEntry_t * entry);
int SelectLoadedModuleEntryByRegexpNameAndHostID(char * binName, unsigned int hostID, loadedModulesEntry_t * entry);
int SelectResolvedBinarySymbolRVAByNameAndHostID(char * symbolName, unsigned int hostID, unsigned int * symbolRVA);

// Utilities
int CheckError(MYSQL * connection, unsigned int error);
int CloseDatabaseConnection(MYSQL * connection);
int CloseDatabaseConnection(MYSQL * connection);
int CreateTables(MYSQL * connection);
///int ExecuteUpdateOrDeleteOrLock(char * dbName, char * query, unsigned int length);
int ExecuteUpdateOrDeleteOrLock(unsigned int database, char * query, unsigned int length);
int ExecuteInsert(char * dbName, char * query, unsigned int length, unsigned int * result);
int DeleteAndRecreateDatabase(MYSQL * connection, char * databaseName);
int InitializeDatabaseConnection();
MYSQL * OpenDatabaseConnection(char * dbName);
int ReleaseMutexAndReturnError(HANDLE mutex,int err);
int SelectSingleUIntResult(char * dbName, char * query, unsigned int len, unsigned int *value);

#endif