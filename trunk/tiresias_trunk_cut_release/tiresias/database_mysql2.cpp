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
#include "global_includes.h"

extern "C"{
	//Defined in database_mysql.c
	extern char * gffSharedDBName;
	extern char * gffTiresiasDBName;
	extern char * gffMeasurementsDBName;
	extern char * gffDatabaseUsername;
	extern char * gffDatabasePassword;
	extern HANDLE mysqlMutex;
}

vector<expected_symbol_t> gExpectedBinarySymbols;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

int InsertExports(unsigned int loadedModuleID, vector<export_t *> * v){
	char query[300];
	char * fixedStr;
	unsigned int len, holder;
	export_t * tmp;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
		printf("InsertExports: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffTiresiasDBName);
	if(conn == NULL){
		printf("InsertExports: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	//////////////////////////////////
	for(unsigned int i=0; i < v->size(); i++){
		tmp = v->at(i);
		//Skip anything that's a special case and therefore the rva was set to 0
		//(like the VideoPortCheckForDeviceExistance->VIDEOPRT.VideoPortCheckForDeviceExistance)
		if(tmp->rva == 0)
			continue;
		fixedStr = "INSERT INTO Exports(rva,name,ordinal,loadedModuleID) VALUES (%u,'%s',%u,%u)";
		len = sprintf_s(query, 300, fixedStr, tmp->rva, tmp->name, tmp->ordinal, loadedModuleID);
		if(0 != mysql_real_query(conn, query, len)){
			holder = CheckError(conn,mysql_errno(conn));
			if(holder != INSERT_ERROR_DUPLICATE){ //allow duplicates

				CloseDatabaseConnection(conn);
				ReleaseMutex(mysqlMutex);
				
				printf("InsertModulesToMeasureForPolling: Couldn't release mutex. Returning\n");
				return GENERIC_ERROR;
			}
		}
	}


	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("InsertModulesToMeasureForPolling: Couldn't release mutex. Returning\n");
		//free outstanding resources
		//v->clear();
		__asm{int 3};	
		return GENERIC_ERROR;
	}
	
	return GENERIC_SUCCESS;
}

int InsertExpectedBinarySymbols(vector<expected_symbol_t> * v){
	char query[300];
	char * fixedStr;
	unsigned int len, holder;
	expected_symbol_t tmp;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
		printf("InsertExpectedBinarySymbols: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffTiresiasDBName);
	if(conn == NULL){
		printf("InsertExpectedBinarySymbols: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	//////////////////////////////////
	for(unsigned int i=0; i < v->size(); i++){
		tmp = v->at(i);
		fixedStr = "INSERT INTO ExpectedBinarySymbols(symbolName,moduleName) VALUES ('%s','%s')";
		len = sprintf_s(query, 300, fixedStr, tmp.symbolName, tmp.moduleName);
		if(0 != mysql_real_query(conn, query, len)){
			holder = CheckError(conn,mysql_errno(conn));
			if(holder != INSERT_ERROR_DUPLICATE){ //allow duplicates
				CloseDatabaseConnection(conn);
				ReleaseMutex(mysqlMutex);
				printf("InsertExpectedBinarySymbols: Couldn't release mutex. Returning\n");
				return GENERIC_ERROR;
			}
		}
	}
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("InsertExpectedBinarySymbols: Couldn't release mutex. Returning\n");
		__asm{int 3};	
		return GENERIC_ERROR;
	}
	
	return GENERIC_SUCCESS;
}

int InsertResolvedBinarySymbols(vector<resolved_symbol_t *> * v){
	char query[300];
	char * fixedStr;
	unsigned int len, holder;
	resolved_symbol_t *resolved_entry;
	MYSQL * conn;

	if(WaitForSingleObject(mysqlMutex,INFINITE) != WAIT_OBJECT_0){
		printf("InsertResolvedBinarySymbols: Couldn't acquire mutex. Returning\n");
		return GENERIC_ERROR;
	}

	conn = OpenDatabaseConnection(gffTiresiasDBName);
	if(conn == NULL){
		printf("InsertResolvedBinarySymbols: OpenDatabaseConnection(gffTiresiasDBName) failed\n");
		return ReleaseMutexAndReturnError(mysqlMutex,GENERIC_ERROR);
	}

	//////////////////////////////////
	for(unsigned int i=0; i < v->size(); i++){
		resolved_entry = v->at(i);
		fixedStr = "INSERT INTO ResolvedBinarySymbols(name,rva,binID,hostID) VALUES ('%s',%u,%u,%u)";
		len = sprintf_s(query, 300, fixedStr, resolved_entry->symbolName, resolved_entry->rva, resolved_entry->binID, resolved_entry->hostID);
		if(0 != mysql_real_query(conn, query, len)){
			holder = CheckError(conn,mysql_errno(conn));
			if(holder != INSERT_ERROR_DUPLICATE){ //allow duplicates
				CloseDatabaseConnection(conn);
				ReleaseMutex(mysqlMutex);
				printf("InsertResolvedBinarySymbols: Mysql Error code: %d\n",holder);
				return GENERIC_ERROR;
			}
		}
	}
	//////////////////////////////////
	CloseDatabaseConnection(conn);
	if(!ReleaseMutex(mysqlMutex)){
		printf("InsertResolvedBinarySymbols: Couldn't release mutex. Returning\n");
		__asm{int 3};	
		return GENERIC_ERROR;
	}
	
	return GENERIC_SUCCESS;
}