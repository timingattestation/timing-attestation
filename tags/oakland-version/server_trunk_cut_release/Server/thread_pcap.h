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

//This code is a modified version of the winpcap udpdump.c example code
//included with the winpcap developers pack 4.0.2
//4/5/09

/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _THREAD_PCAP_H
#define _THREAD_PCAP_H

#include "global_includes.h"

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////
#define ETH_HDR_SIZE 14

////////////////////////////////////////////////////////
//STRUCTURES
////////////////////////////////////////////////////////

//From the old send_packet_helpers.cpp - just wanted to have less files
struct DeviceInfo
{
	bool Exists;
	unsigned int IP; //In case IP spoofing is not supported, use real IP
	unsigned int DefaultGateway;   // Where the packet is first sent
	unsigned char GatewayPhysicalAddress[6]; //MAC of destination (gateway)
	unsigned char PhysicalAddress[6]; //Source MAC in case MAC spoofing is not supported
};

/* IPv4 header */
typedef struct ip_header
{
	unsigned char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	unsigned char	tos;			// Type of service 
	unsigned short tlen;			// Total length 
	unsigned short identification; // Identification
	unsigned short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	unsigned char	ttl;			// Time to live
	unsigned char	proto;			// Protocol
	unsigned short crc;			// Header checksum
	unsigned int	saddr;		// Source address
	unsigned int	daddr;		// Destination address
	unsigned int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	unsigned short sport;			// Source port
	unsigned short dport;			// Destination port
	unsigned short len;			// Datagram length
	unsigned short crc;			// Checksum
}udp_header;

////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
DWORD WINAPI PcapThread(LPVOID lpParam);

#endif