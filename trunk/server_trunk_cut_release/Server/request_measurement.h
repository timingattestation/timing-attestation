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

//This will be for sending each of the measurement request type packets
#ifndef _REQUEST_MEASUREMENT_H
#define _REQUEST_MEASUREMENT_H
#include <string>
#include <queue>
#include "server_client_protocol.h"
using namespace std;

////////////////////////////////////////////////////////
//STRUCTURES
////////////////////////////////////////////////////////


////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

//Function which can be used from anywhere to request any type of measurement
int RequestMeasurementByType(msgType t, wstring * nameW, unsigned int hostID);

//Common code across all requests
int RequestCommon(char * sourceIP, char * destinationIP, char * dstHostName, request_hdr_t * requestHeader, unsigned int requestSize, me_t * outboundPendingME, char * parentFuncName);

//The actual measurement functions that we care about
int BuildTimingTestRequestPacket(char * sourceIP, char * destinationIP, char * dstHostName, unsigned int numIterations);
int BuildTickStampAttestationRequestPacket(char * sourceIP, char * destinationIP, char * dstHostName, unsigned int numIterations);
int ToggleAttackRequestPacket(char * sourceIP, char * destinationIP, char * dstHostName);

// Hostname resolution support functions
int CheckHostIPValues(string & ipString, string & hostName, bool * ipExists, bool * nameExists);
int GetHostNameByIP(const char * ipAddress, char * hostName);
int GetIpByHostName(const char * hostName, char * ipAddress);
int ResolveIPsAndNames(string * srcIP, string * dstIP, string * srcHostName, string * dstHostName);
int IsHostName(char * str, bool * result);

//For sending a bunch of self-checks to baseline the timing
int GenerateUpperLowerControlLimitsOnHost(char * hostIP, char * hostName);
int getAverageWindowRTT(queue<unsigned int> * selfCheckTimingQueue, unsigned int * averageRTT);
int CalculateLimits(queue<unsigned int> * dataSet, unsigned int * LCL, unsigned int * UCL);


#endif