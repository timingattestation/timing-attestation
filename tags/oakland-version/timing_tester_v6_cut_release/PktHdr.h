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


//****************************************************************************//
//*                                                                           //
//* Copyright (C) 2003, James Antognini, antognini@mindspring.com.            //
//*                                                                           //
//****************************************************************************//
//http://www.wd-3.com/archive/ExtendingPassthru2.htm
//Companion Sample Code for the Article
//"Extending the Microsoft PassThru NDIS Intermediate Driver"
//
//Portions Copyright ©1992-2000 Microsoft Corporation; used by permission.
//Portions Copyright © 2003 Printing Communications Associates, Inc. (PCAUSA)
//
//The right to use this code in your own derivative works is granted so long as
//
//Your own derivative works include significant modifications of your own.
//You retain the above copyright notices and this paragraph in its entirety within sources derived from this code.
//This product includes software developed by PCAUSA. The name of PCAUSA may not be used to endorse or promote products derived from this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

#define htonl(a) (((a&0xFF)<<24) + ((a&0xFF00)<<8) + ((a&0xFF0000)>>8) + ((a&0xFF000000)>>24)
#define htons(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))

// Next 3 define's are from Snort 2.0.
#define IP_DF      0x4000   /* dont fragment flag */
#define IP_MF      0x2000   /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */

// Next 4 define's are from \network\ndis\netvmini\sys\miniport.h.  See also equivalents in \network\ndis\e100bex\e11_equ.h.
#define     ETH_HEADER_SIZE             14
#define     ETH_MAX_DATA_SIZE           1500
#define     ETH_MAX_PACKET_SIZE         ETH_HEADER_SIZE + ETH_MAX_DATA_SIZE
#define     ETH_MIN_PACKET_SIZE         60

#define lnEthHdr    14                                // Size of Ethernet header.           
#define lnIPHdr     20                                // Size of IP header.                 
#define lnTCPHdrMin 20                                // Minimum size of TCP header.        
#define lnUDPHdrMin 20                                // Minimum size of UDP header.        

#define MAX_IP_UDP_PAYLOAD	(ETH_MAX_DATA_SIZE - lnIPHdr - lnUDPHdrMin) //1460 bytes

typedef enum
  {
   EthHTypeIP   = 0x0800,
   EthHTypeARP  = 0x0806,
   EthHTypeRARP = 0x8035
  }
   EthHType;
//#define EthHTypeIP   0x0800
//#define EthHTypeARP  0x0806
//#define EthHTypeRARP 0x8035

typedef struct _EthHdr
  {
   char        DestMAC[6];
   char        SrcMAC[6];
   USHORT      Type;                                  // 0x0800 => IP.
  }
   EthHdr, * pEthHdr;


typedef struct _IPHdr
  {
   union
     {
      UCHAR HdrLenVer;
      struct
        {
         UCHAR    IPHdrLen         : 4;               // Length, in 4-byte multiples.
         UCHAR    IPVer            : 4;               // IP version.
        };
     };
   UCHAR          TypeOfService;
   USHORT         TotalLength;                        // Size of IP datagram.
   USHORT         Identification;
   union
     {
      USHORT      FragmentationSummary; //Prefer to use this and just specify the flags manually
      struct
        {
         USHORT   FragmentOffset1  : 5; //most significant 5 bits of fragmentation offset
         USHORT   MoreFragments    : 1; //MF bit
         USHORT   DoNotFragment    : 1;	//DF bit
         USHORT   padding          : 1;               // Reserved, must be zero.
         USHORT   FragmentOffset2  : 8; //least significant 8 bits of fragmentation offset
        };
     };
   UCHAR          TTL;
   UCHAR          Protocol;
   USHORT         Checksum;
   ULONG          SourceAddress;
   ULONG          DestinationAddress;
  }
   IPHdr, * pIPHdr;

typedef struct _UDPHeader
{
	USHORT Source;
	USHORT Dest; 
	USHORT Length;
	USHORT Checksum;
}UDPHeader, * pUDPHeader;

typedef struct _EncapPktHdr
  {
   ULONG    ulOrigPayload;
   ULONG    ulNewVA;
   UCHAR    stuff[16];
  }
    EncapPktHdr, * pEncapPktHdr;

// ++++++++++++++++++++ Begin section taken from winsock2.h ++++++++++++++++++++ //
    
/*
 * Constants and structures defined by the internet system,
 * Per RFC 790, September 1981, taken from the BSD file netinet/in.h.
 */

/*
 * Protocols
 */
#define IPPROTO_IP              0               /* dummy for IP */
#define IPPROTO_ICMP            1               /* control message protocol */
#define IPPROTO_IGMP            2               /* internet group management protocol */
#define IPPROTO_GGP             3               /* gateway^2 (deprecated) */
#define IPPROTO_TCP             6               /* tcp */
#define IPPROTO_PUP             12              /* pup */
#define IPPROTO_UDP             17              /* user datagram protocol */
#define IPPROTO_IDP             22              /* xns idp */
#define IPPROTO_IPV6            41              /* IPv6 */
#define IPPROTO_ND              77              /* UNOFFICIAL net disk proto */
#define IPPROTO_ICLFXBM         78

#define IPPROTO_RAW             255             /* raw IP packet */
#define IPPROTO_MAX             256

/*
 * Port/socket numbers: network standard functions
 */
#define IPPORT_ECHO             7
#define IPPORT_DISCARD          9
#define IPPORT_SYSTAT           11
#define IPPORT_DAYTIME          13
#define IPPORT_NETSTAT          15
#define IPPORT_FTP              21
#define IPPORT_TELNET           23
#define IPPORT_SMTP             25
#define IPPORT_TIMESERVER       37
#define IPPORT_NAMESERVER       42
#define IPPORT_WHOIS            43
#define IPPORT_MTP              57

/*
 * Port/socket numbers: host specific functions
 */
#define IPPORT_TFTP             69
#define IPPORT_RJE              77
#define IPPORT_FINGER           79
#define IPPORT_TTYLINK          87
#define IPPORT_SUPDUP           95

/*
 * UNIX TCP sockets
 */
#define IPPORT_EXECSERVER       512
#define IPPORT_LOGINSERVER      513
#define IPPORT_CMDSERVER        514
#define IPPORT_EFSSERVER        520

/*
 * UNIX UDP sockets
 */
#define IPPORT_BIFFUDP          512
#define IPPORT_WHOSERVER        513
#define IPPORT_ROUTESERVER      520

// ++++++++++++++++++++ End section taken from winsock2.h ++++++++++++++++++++ //     

// ++++++++++++++++++++ Begin section taken from offload.h +++++++++++++++++++ //     
 
// This section is taken from offload.h in the DDK src\network\ndis\e100bex. 
 
//
//  Define the maximum size of large TCP packets the driver can offload.
//  This sample driver uses shared memory to map the large packets, 
//  LARGE_SEND_OFFLOAD_SIZE is useless in this case, so we just define 
//  it as NIC_MAX_PACKET_SIZE. But shipping drivers should define
//  LARGE_SEND_OFFLOAD_SIZE if they support LSO, and use it as 
//  MaximumPhysicalMapping  when they call NdisMInitializeScatterGatherDma 
//  if they use ScatterGather method. If the drivers don't support
//  LSO, then MaximumPhysicalMapping is NIC_MAX_PACKET_SIZE.
//
#define LARGE_SEND_OFFLOAD_SIZE     NIC_MAX_PACKET_SIZE
//
// Definitions for header flags.
//
#define TCP_FLAG_FIN    0x00000100
#define TCP_FLAG_SYN    0x00000200
#define TCP_FLAG_RST    0x00000400
#define TCP_FLAG_PUSH   0x00000800
#define TCP_FLAG_ACK    0x00001000
#define TCP_FLAG_URG    0x00002000

//
// These are the maximum size of TCP and IP options
// 
#define TCP_MAX_OPTION_SIZE     40
#define IP_MAX_OPTION_SIZE      40

//
// Structure of a TCP packet header.
//
struct TCPHeader {
    USHORT    tcp_src;                // Source port.
    USHORT    tcp_dest;               // Destination port.
    int       tcp_seq;                // Sequence number.
    int       tcp_ack;                // Ack number.
    USHORT    tcp_flags;              // Flags and data offset.
    USHORT    tcp_window;             // Window offered.
    USHORT    tcp_xsum;               // Checksum.
    USHORT    tcp_urgent;             // Urgent pointer.
};

typedef struct TCPHeader TCPHeader;


//
// IP Header format.
//
typedef struct IPHeader {
    UCHAR     iph_verlen;             // Version and length.
    UCHAR     iph_tos;                // Type of service.
    USHORT    iph_length;             // Total length of datagram.
    USHORT    iph_id;                 // Identification.
    USHORT    iph_offset;             // Flags and fragment offset.
    UCHAR     iph_ttl;                // Time to live.
    UCHAR     iph_protocol;           // Protocol.
    USHORT    iph_xsum;               // Header checksum.
    UINT      iph_src;                // Source address.
    UINT      iph_dest;               // Destination address.
} IPHeader;

#define TCP_IP_MAX_HEADER_SIZE  TCP_MAX_OPTION_SIZE+IP_MAX_OPTION_SIZE \
                                +sizeof(TCPHeader)+sizeof(IPHeader)

#define LARGE_SEND_MEM_SIZE_OPTION       3

//
// Compute the checksum
// 
#define XSUM(_TmpXsum, _StartVa, _PacketLength, _Offset)                             \
{                                                                                    \
    PUSHORT  WordPtr = (PUSHORT)((PUCHAR)_StartVa + _Offset);                        \
    ULONG    WordCount = (_PacketLength) >> 1;                                       \
    BOOLEAN  fOddLen = (BOOLEAN)((_PacketLength) & 1);                               \
    while (WordCount--)                                                              \
    {                                                                                \
        _TmpXsum += *WordPtr;                                                        \
        WordPtr++;                                                                   \
    }                                                                                \
    if (fOddLen)                                                                     \
    {                                                                                \
        _TmpXsum += (USHORT)*((PUCHAR)WordPtr);                                      \
    }                                                                                \
    _TmpXsum = (((_TmpXsum >> 16) | (_TmpXsum << 16)) + _TmpXsum) >> 16;             \
}

// ++++++++++++++++++++ End section taken from offload.h +++++++++++++++++++++ //     

//#define net_short(s) ((s&0xFF00)>>8) + ((s&0x00ff)<<8)

// ++++++++++++++++++++ Begin section taken from offload.c +++++++++++++++++++ //     
 
#define PROTOCOL_TCP         6

//
// calculate the checksum for pseudo-header
//
// net_short replaced by RtlUshortByteSwap.  ja, 19 May 2003.
//
#define PHXSUM(s,d,p,l) (UINT)( (UINT)*(USHORT *)&(s) + \
                        (UINT)*(USHORT *)((char *)&(s) + sizeof(USHORT)) + \
                        (UINT)*(USHORT *)&(d) + \
                        (UINT)*(USHORT *)((char *)&(d) + sizeof(USHORT)) + \
                        (UINT)((USHORT)RtlUshortByteSwap((p))) + \
                        (UINT)((USHORT)RtlUshortByteSwap((USHORT)(l))) )


#define IP_HEADER_LENGTH(pIpHdr)   \
        ( (ULONG)((pIpHdr->iph_verlen & 0x0F) << 2) )

#define TCP_HEADER_LENGTH(pTcpHdr) \
        ( (USHORT)(((*((PUCHAR)(&(pTcpHdr->tcp_flags))) & 0xF0) >> 4) << 2) )

// ++++++++++++++++++++ End section taken from offload.c +++++++++++++++++++++ //     

typedef struct _easyMAC{
	unsigned int firstFour;
	unsigned short lastTwo;
} easyMAC, *pEasyMac;

#define EASYMACIFY(a) ((pEasyMac)&a)

ULONG gDstIP;
ULONG gSrcIP;
ULONG gSetInfoIP;
unsigned char gDstMAC[6];
unsigned char gSrcMAC[6];

VOID PtFreePacket( IN PNDIS_PACKET ndisPktPtr);
