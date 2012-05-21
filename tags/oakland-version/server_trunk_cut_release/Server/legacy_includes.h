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

//Some code taken from the raw packet generation example:
//http://www.codeproject.com/KB/IP/UDPandWPCAP.aspx
//Copyright Emmanuel Herrera 2008, may be used in accordance with http://www.opensource.org/licenses/ms-pl.html
//Modified by Xeno Kovah - 4/5/2009

#ifndef _INCLUDES_H
#define _INCLUDES_H

#include <winsock2.h> // htons() htonl() and other helper functions
#pragma comment (lib,"WS2_32.lib") 
#include <windows.h> 
#include <Iphlpapi.h>// Used to find information about the device such as default gateway and hardware addresses
#pragma comment (lib,"Iphlpapi.lib") 
#include <pcap.h> // WinPCap
#pragma comment (lib,"wpcap.lib") // Link to pcap
#include <iostream> //sprintf()
using namespace std;

#endif