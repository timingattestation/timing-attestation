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

//This is where things that want to use some C++ containers 
//but still using the MySQL C API go


#ifndef DATABASE_MYSQL2_H
#define DATABASE_MYSQL2_H 

#include <queue>
#include <vector>
#include <list>
#include "global_includes.h"
extern "C"{
	#include "database_mysql.h"
}
#include "server_client_protocol.h"

using namespace std;

// Generic hostname and IP processor
// Resolves the hostname or IP if one is missing, Inserts or updates the Hosts table to latest host->ip mapping
// Inserts or updates the HostsToMeasure table if requested
int ProcessHost(string & hostName, string & ipStr, bool updateForPolling, int readinessState, unsigned int * hostID);

int SelectAllHostsToMeasure(queue<string> * q, queue<int> * r);
int SelectHostIDByName(string hostName, unsigned int * hostID);
int SelectAllHostsToMeasureForPolling(int tolerance, queue<int> * q);
int SelectModulesToMeasure(vector<string> * v);
int SelectTiresiasChecksumByNonceAndBaseAndTimedatestamp(self_check_t * selfCheckInput, self_check_t * selfCheckTiresias);
int SelectDataSetForLimitCalculations(unsigned int countFromTimeInSeconds, unsigned int count, queue<unsigned int> * q);
int SelectHostIPsByHostName(char * hostName, list<string> * v);
int SelectUnfinishedPendingSelfAttestationMeIds(unsigned int timeLimit, vector<int> * v);

int InsertModulesToMeasureForPolling(vector<string> * v);
int InsertHostsToMeasureForPolling(vector<string> * v);
int InsertServerPrerequisiteForMessageType(int msgType, vector<string> * v);
int InsertBrandStringLimits(vector<string> * v);
int InsertHostLimits(vector<string> * v);

int MovePendingMeasurementToFinalMeasurements(me_t * incomingME, me_t * pendingME, bool insert);
int CleanUpStaleMatchingPendingEvents(me_t * pendingME);

//PROTOTYPES
char * MsgTypeToString(msgType m);

#endif

