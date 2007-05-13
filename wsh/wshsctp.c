/*
 * Copyright (c) 2007 KOZUKA Masahiro  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * $Id: wshsctp.c,v 1.1 2007/05/13 08:27:19 kozuka Exp $
 */

#define UNICODE

#include <stdio.h>
#include <devioctl.h>
#include <windows.h>

typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
	PWSTR  Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
#define UNICODE_NULL ((WCHAR)0) // winnt

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeStringToString (
    PUNICODE_STRING Destination,
    PUNICODE_STRING Source
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlIntegerToUnicodeString (
    ULONG Value,
    ULONG Base,
    PUNICODE_STRING String
    );


#if DBG
NTSYSAPI
VOID
NTAPI
RtlAssert(
    PVOID FailedAssertion,
    PVOID FileName,
    ULONG LineNumber,
    PCHAR Message
    );

#define ASSERT(exp) \
if (!(exp)) \
    RtlAssert(#exp, __FILE__, __LINE__, NULL)

#define ASSERTMSG(msg,exp) \
if (!(exp)) \
    RtlAssert(#exp, __FILE__, __LINE__, msg)

#else
#define ASSERT(exp)
#define ASSERTMSG(msg, exp)
#endif // DBG


#include <wchar.h>
#include <ctype.h>

#include <tdi.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <wsahelp.h>

#include <basetyps.h>
#include <nspapi.h>
#include <nspapip.h>


#define IPPROTO_SCTP			132

#define SCTP_RTOINFO                    0x00000001
#define SCTP_ASSOCINFO                  0x00000002
#define SCTP_INITMSG                    0x00000003
#define SCTP_NODELAY                    0x00000004
#define SCTP_AUTOCLOSE                  0x00000005
#define SCTP_SET_PEER_PRIMARY_ADDR      0x00000006
#define SCTP_PRIMARY_ADDR               0x00000007
#define SCTP_ADAPTATION_LAYER           0x00000008
#define SCTP_DISABLE_FRAGMENTS          0x00000009
#define SCTP_PEER_ADDR_PARAMS           0x0000000a
#define SCTP_DEFAULT_SEND_PARAM         0x0000000b
#define SCTP_EVENTS                     0x0000000c
#define SCTP_I_WANT_MAPPED_V4_ADDR      0x0000000d
#define SCTP_MAXSEG                     0x0000000e
#define SCTP_DELAYED_ACK_TIME           0x0000000f
#define SCTP_FRAGMENT_INTERLEAVE        0x00000010
#define SCTP_PARTIAL_DELIVERY_POINT     0x00000011
#define SCTP_AUTH_CHUNK                 0x00000012
#define SCTP_AUTH_KEY                   0x00000013
#define SCTP_HMAC_IDENT                 0x00000014
#define SCTP_AUTH_ACTIVE_KEY            0x00000015
#define SCTP_AUTH_DELETE_KEY            0x00000016

#define SCTP_NAME			L"Sctp"
#define DD_SCTP_ONE_TO_ONE_DEVICE_NAME L"\\Device\\SctpTcp"
#define DD_SCTP_ONE_TO_MANY_DEVICE_NAME L"\\Device\\SctpUdp"

#define DEFAULT_RECEIVE_BUFFER_SIZE	8192
#define DEFAULT_IP_TTL			256
#define DEFAULT_IP_TOS			0

typedef struct _MAPPING_TRIPLE {
	DWORD AddressFamily;
	DWORD SocketType;
	DWORD Protocol;
} MAPPING_TRIPLE, *PMAPPING_TRIPLE;

MAPPING_TRIPLE SctpMappingTriples[] = {
#if 0
	{AF_INET, SOCK_STREAM, IPPROTO_SCTP},
	{AF_INET6, SOCK_STREAM, IPPROTO_SCTP},
#endif
#if 0
	{AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP},
	{AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP},
#else
	{AF_INET, SOCK_DGRAM, IPPROTO_SCTP},
	{AF_INET6, SOCK_DGRAM, IPPROTO_SCTP},
#endif
};

PROTOCOL_INFO SctpProtocolInfos[] = {
#if 0
{
	XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
	XP1_IFS_HANDLES,
	AF_INET,
	sizeof(SOCKADDR_IN),
	sizeof(SOCKADDR_IN),
	SOCK_STREAM,
	IPPROTO_SCTP,
	0xFFFFFFFF,
	L"MSAFD Sctp(one-to-one) [SCTP/IPv4]"
},
{
	XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
	XP1_IFS_HANDLES,
	AF_INET,
	sizeof(SOCKADDR_IN6),
	sizeof(SOCKADDR_IN6),
	SOCK_STREAM,
	IPPROTO_SCTP,
	0xFFFFFFFF,
	L"MSAFD Sctp(one-to-one) [SCTP/IPv6]"
},
#endif
{
#if 0
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_GUARANTEED_DELIVERY |
	XP1_GUARANTEED_ORDER |
	XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA |
	XP1_DISCONNECT_DATA |
	XP1_SUPPORT_MULTIPOINT |
	XP1_FRAGMENTATION,
	XP1_IFS_HANDLES,
	XP1_CONNECTIONLESS | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
#endif
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_IFS_HANDLES,
	AF_INET,
	sizeof(SOCKADDR_IN),
	sizeof(SOCKADDR_IN),
#if 0
	SOCK_SEQPACKET,
#else
	SOCK_DGRAM,
#endif
	IPPROTO_SCTP,
	0xFFFFFFFF,
	L"MSAFD Sctp(one-to-many) [SCTP/IPv4]"
},
{
#if 0
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_GUARANTEED_DELIVERY |
	XP1_GUARANTEED_ORDER |
	XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA |
	XP1_DISCONNECT_DATA |
	XP1_SUPPORT_MULTIPOINT |
	XP1_IFS_HANDLES,
	XP1_CONNECTIONLESS | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
#endif
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_IFS_HANDLES,
	AF_INET6,
	sizeof(SOCKADDR_IN6),
	sizeof(SOCKADDR_IN6),
#if 0
	SOCK_SEQPACKET,
#else
	SOCK_DGRAM,
#endif
	IPPROTO_SCTP,
	0xFFFFFFFF,
	L"MSAFD Sctp(one-to-many) [SCTP/IPv6]"
}
};

#define NUM_SCTP_PROTOCOL_INFOS \
	(sizeof(SctpProtocolInfos) / sizeof(SctpProtocolInfos[0]))

WSAPROTOCOL_INFOW WsaSctpProtocolInfos[] = {
#if 0
    // one-to-one socket for SCTP/IPv4
{
	XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
	XP1_IFS_HANDLES,
	0,
	0,
	0,
	0,
	{
	    0, 0, 0,
	    {0, 0, 0, 0, 0, 0, 0, 0}
	},
	0,
	{
	    BASE_PROTOCOL,
	    {0, 0, 0, 0, 0, 0, 0}
	},
	0,
	AF_INET,
	sizeof(SOCKADDR_IN),
	sizeof(SOCKADDR_IN),
	SOCK_STREAM,
	IPPROTO_SCTP,
	0,
	BIGENDIAN,
	SECURITY_PROTOCOL_NONE,
	0xFFFFFFFF,
	0,
	L"MSAFD Sctp(one-to-one) [SCTP/IPv4]"
},

// one-to-one socket for SCTP/IPv6
{
	XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
	XP1_IFS_HANDLES,
	0,
	0,
	0,
	0,
	{
	    0, 0, 0,
	    {0, 0, 0, 0, 0, 0, 0, 0}
	},
	0,
	{
	    BASE_PROTOCOL,
	    {0, 0, 0, 0, 0, 0, 0}
	},
	0,
	AF_INET6,
	sizeof(SOCKADDR_IN6),
	sizeof(SOCKADDR_IN6),
	SOCK_STREAM,
	IPPROTO_SCTP,
	0,
	BIGENDIAN,
	SECURITY_PROTOCOL_NONE,
	0xFFFFFFFF,
	0,
	L"MSAFD Sctp(one-to-one) [SCTP/IPv6]"
},
#endif

// one-to-many socket for SCTP/IPv4
    {
#if 0
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_GUARANTEED_DELIVERY |
	XP1_GUARANTEED_ORDER |
	XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA |
	XP1_DISCONNECT_DATA |
	XP1_SUPPORT_MULTIPOINT |
	XP1_IFS_HANDLES,
	XP1_CONNECTIONLESS | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
#endif
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_IFS_HANDLES,
	0,
	0,
	0,
	PFL_MATCHES_PROTOCOL_ZERO,
	{
	    0, 0, 0,
	    {0, 0, 0, 0, 0, 0, 0, 0}
	},
	0,
	{
	    BASE_PROTOCOL,
	    {0, 0, 0, 0, 0, 0, 0}
	},
	2,
	AF_INET,
	sizeof(SOCKADDR_IN),
	sizeof(SOCKADDR_IN),
#if 0
	SOCK_SEQPACKET,
#else
	SOCK_DGRAM,
#endif
	IPPROTO_SCTP,
	0,
	BIGENDIAN,
	SECURITY_PROTOCOL_NONE,
	0xFFFFFFFF,
	0,
	L"MSAFD Sctp(one-to-many) [SCTP/IPv4]"
},
// one-to-many socket for SCTP/IPv6
{
#if 0
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_GUARANTEED_DELIVERY |
	XP1_GUARANTEED_ORDER |
	XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA |
	XP1_DISCONNECT_DATA |
	XP1_SUPPORT_MULTIPOINT |
	XP1_IFS_HANDLES,
	XP1_CONNECTIONLESS | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER |
	XP1_MESSAGE_ORIENTED | XP1_GRACEFUL_CLOSE |
	XP1_CONNECT_DATA | XP1_DISCONNECT_DATA |
#endif
	XP1_CONNECTIONLESS |
	XP1_MESSAGE_ORIENTED |
	XP1_IFS_HANDLES,
	0,
	0,
	0,
	PFL_MATCHES_PROTOCOL_ZERO,
	{
	    0, 0, 0,
	    {0, 0, 0, 0, 0, 0, 0, 0}
	},
	0,
	{
	    BASE_PROTOCOL,
	    {0, 0, 0, 0, 0, 0, 0}
	},
	2,
	AF_INET6,
	sizeof(SOCKADDR_IN6),
	sizeof(SOCKADDR_IN6),
#if 0
	SOCK_SEQPACKET,
#else
	SOCK_DGRAM,
#endif
	IPPROTO_SCTP,
	0,
	BIGENDIAN,
	SECURITY_PROTOCOL_NONE,
	0xFFFFFFFF,
	0,
	L"MSAFD Sctp(one-to-many) [SCTP/IPv6]"
},
};

#define NUM_WSA_SCTP_PROTOCOL_INFOS \
	(sizeof(WsaSctpProtocolInfos) / sizeof(WsaSctpProtocolInfos[0]))

// {E9BAC45A-85E4-4569-8B40-5532D722AFD4}
const GUID SctpProviderGuid = {
    0xe9bac45a,
    0x85e4,
    0x4569,
    {0x8b, 0x40, 0x55, 0x32, 0xd7, 0x22, 0xaf, 0xd4}
};

typedef struct _WSHSCTP_SOCKET_CONTEXT {
	DWORD AddressFamily;
	DWORD SocketType;
	DWORD Protocol;
	INT ReceiveBufferSize;
	DWORD Flags;
	UCHAR IpTtl;
	UCHAR IpTos;
	UCHAR IpDontFragment;
	UCHAR IpOptionsLength;
	UCHAR *IpOptions;
	BOOLEAN KeepAlive;
	BOOLEAN DontRoute;
	BOOLEAN NoDelay;
	BOOLEAN NoChecksum;
} WSHSCTP_SOCKET_CONTEXT, *PWSHSCTP_SOCKET_CONTEXT;
    
    
BOOLEAN
IsTripleInSctpTriple(
    IN INT AddressFamily,
    IN INT SocketType,
    IN INT Protocol)
{
	size_t i;

	for (i = 0; i < sizeof(SctpMappingTriples) / sizeof(SctpMappingTriples[0]); i++) {
		if (AddressFamily == SctpMappingTriples[i].AddressFamily &&
		    SocketType == SctpMappingTriples[i].SocketType &&
		    Protocol == SctpMappingTriples[i].Protocol) {
			return TRUE;
		}
	}

	return FALSE;
}


BOOLEAN
DllMain(
    IN PVOID DllHandle,
    IN ULONG Reason,
    IN PVOID Context OPTIONAL)
{
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(DllHandle);
		break;

	case DLL_THREAD_ATTACH:
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
	default:
		break;
	}
	return TRUE;
}


INT
WSHGetSockaddrType(
    IN PSOCKADDR Sockaddr,
    IN DWORD SockaddrLength,
    OUT PSOCKADDR_INFO SockaddrInfo)
{
	UNALIGNED SOCKADDR_IN *sin;
	UNALIGNED SOCKADDR_IN6 *sin6;

	if (Sockaddr->sa_family != AF_INET &&
	    Sockaddr->sa_family != AF_INET6) {
		return WSAEAFNOSUPPORT;
	}

	if ((Sockaddr->sa_family == AF_INET &&
	     SockaddrLength < sizeof(SOCKADDR_IN)) ||
	    (Sockaddr->sa_family == AF_INET6 &&
	     SockaddrLength < sizeof(SOCKADDR_IN6))) {
		return WSAEFAULT;
	}

	switch (Sockaddr->sa_family) {
	case AF_INET:
		sin = (PSOCKADDR_IN)Sockaddr;
		if (sin->sin_addr.s_addr == INADDR_ANY) {
			SockaddrInfo->AddressInfo = SockaddrAddressInfoWildcard;
		} else if (sin->sin_addr.s_addr == INADDR_BROADCAST) {
			SockaddrInfo->AddressInfo = SockaddrAddressInfoBroadcast;
		} else if (sin->sin_addr.s_addr == INADDR_LOOPBACK) {
			SockaddrInfo->AddressInfo = SockaddrAddressInfoLoopback;
		} else {
			SockaddrInfo->AddressInfo = SockaddrAddressInfoNormal;
		}

		if (sin->sin_port == 0) {
			SockaddrInfo->EndpointInfo = SockaddrEndpointInfoWildcard;
		} else if (ntohs(sin->sin_port) < 2000) {
			SockaddrInfo->EndpointInfo = SockaddrEndpointInfoReserved;
		} else {
			SockaddrInfo->EndpointInfo = SockaddrEndpointInfoNormal;
		}

		break;
	case AF_INET6:
		sin6 = (PSOCKADDR_IN6)Sockaddr;

		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			SockaddrInfo->AddressInfo = SockaddrAddressInfoWildcard;
		} else if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
			SockaddrInfo->AddressInfo = SockaddrAddressInfoBroadcast;
		} else {
			SockaddrInfo->AddressInfo = SockaddrAddressInfoNormal;
		}

		if (sin6->sin6_port == 0) {
			SockaddrInfo->EndpointInfo = SockaddrEndpointInfoWildcard;
		} else if (ntohs(sin6->sin6_port) < 2000) {
			SockaddrInfo->EndpointInfo = SockaddrEndpointInfoReserved;
		} else {
			SockaddrInfo->EndpointInfo = SockaddrEndpointInfoNormal;
		}

		break;
	}

	return NO_ERROR;
}


INT
WSHGetSocketInformation(
    IN PVOID HelperDllSocketContext,
    IN SOCKET SocketHandle,
    IN HANDLE TdiAddressObjectHandle,
    IN HANDLE TdiConnectionObjectHandle,
    IN INT Level,
    IN INT OptionName,
    OUT PCHAR OptionValue,
    OUT PINT OptionLength)
{
	PWSHSCTP_SOCKET_CONTEXT context = HelperDllSocketContext;

	UNREFERENCED_PARAMETER(SocketHandle);
	UNREFERENCED_PARAMETER(TdiAddressObjectHandle);
	UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);

	if (Level == SOL_INTERNAL && OptionName == SO_CONTEXT) {
		if (OptionValue != NULL) {
			if (*OptionLength < sizeof(*context)) {
				return WSAEFAULT;
			}

			CopyMemory(OptionValue, context, sizeof(*context));
		}
		*OptionLength = sizeof(*context);

		return NO_ERROR;
	}

	if (Level != SOL_SOCKET &&
	    Level != IPPROTO_SCTP &&
	    Level != IPPROTO_IP &&
	    Level != IPPROTO_IPV6) {
		return WSAEINVAL;
	}

	if (Level == IPPROTO_IPV6 && context->AddressFamily == AF_INET) {
		return WSAEINVAL;
	}
	if (*OptionLength < sizeof(INT)) {
		return WSAEINVAL;
	}

	if (Level == IPPROTO_SCTP) {
		switch (OptionName) {
		case SCTP_INITMSG:
			break;

		case SCTP_NODELAY:
			ZeroMemory(OptionValue, *OptionLength);

			*OptionValue = context->NoDelay;
	    		*OptionLength = sizeof(INT);
			break;

		case SCTP_AUTOCLOSE:
			break;

		case SCTP_ADAPTATION_LAYER:
			break;

		case SCTP_DISABLE_FRAGMENTS:
			break;

		case SCTP_EVENTS:
			break;

		case SCTP_I_WANT_MAPPED_V4_ADDR:
			break;

		case SCTP_MAXSEG:
			break;

		case SCTP_AUTH_CHUNK:
			break;

		case SCTP_HMAC_IDENT:
			break;

		case SCTP_AUTH_KEY:
			break;

		case SCTP_AUTH_ACTIVE_KEY:
			break;

		case SCTP_AUTH_DELETE_KEY:
			break;

		case SCTP_FRAGMENT_INTERLEAVE:
			break;

		case SCTP_PARTIAL_DELIVERY_POINT:
			break;
#if 0
		case SCTP_USE_EXT_RCVINFO:
			break;
#endif

		case SCTP_RTOINFO:
			break;

		case SCTP_ASSOCINFO:
			break;

		case SCTP_PEER_ADDR_PARAMS:
			break;

		case SCTP_DEFAULT_SEND_PARAM:
			break;

		default:
			break;
		}

		return NO_ERROR;
	}

	if (Level == IPPROTO_IP) {
		switch (OptionName) {
		case IP_DONTFRAGMENT:
			ZeroMemory(OptionValue, *OptionLength); 

			*OptionValue = (INT)context->IpDontFragment;
	   		*OptionLength = sizeof(INT);
			break;

		case IP_OPTIONS:
			if (*OptionLength < context->IpOptionsLength) {
				return WSAEINVAL;
			}

			ZeroMemory(OptionValue, *OptionLength);

			if (context->IpOptions != NULL) {
				MoveMemory(OptionValue, context->IpOptions, context->IpOptionsLength);
			}
			*OptionLength = context->IpOptionsLength;
			break;

		case IP_PKTINFO:
#if 0
			ZeroMemory(OptionValue, *OptionLength); 
			*OptionValue = (INT)context->PktInfo;
			*OptionLength = sizeof(INT);
#endif
			break;

		case IP_TOS:
			ZeroMemory(OptionValue, *OptionLength); 

			*OptionValue = (INT)context->IpTos;
			*OptionLength = sizeof(INT);
			break;

		case IP_TTL:
			ZeroMemory(OptionValue, *OptionLength); 

			*OptionValue = (INT)context->IpTtl;
			*OptionLength = sizeof(INT);
			break;

		default:
			return WSAENOPROTOOPT;
		}
		return NO_ERROR;
	}

	if (Level == IPPROTO_IPV6) {
		switch (OptionName) {
#if 0
		case IPV6_HOPLIMIT:
			ZeroMemory(OptionValue, *OptionLength); 

			*OptionValue = (INT)context->Ipv6Ttl;
			*OptionLength = sizeof(INT);
			break;
#endif

#if 0
		case IPV6_PKTINFO:
			ZeroMemory(OptionValue, *OptionLength); 

			*OptionValue = (INT)context->PktInfo;
			*OptionLength = sizeof(INT);
			break;
#endif

#if 0
		case IPV6_V6ONLY:
			ZeroMemory(OptionValue, *OptionLength); 

			*OptionValue = (INT)context->Ipv6Only;
			*OptionLength = sizeof(INT);
			break;
#endif

		default:
			return WSAENOPROTOOPT;
		}
		return NO_ERROR;
	}

	if (Level == SOL_SOCKET) {
		switch (OptionName) {
		case SO_ACCEPTCONN:
#if 0
		case SO_CONNECT_TIME:
#endif
		case SO_DEBUG:
		case SO_DONTLINGER:
		case SO_DONTROUTE:
		case SO_KEEPALIVE:
		case SO_LINGER:
		case SO_RCVBUF:
		case SO_RCVLOWAT:
		case SO_RCVTIMEO:
		case SO_REUSEADDR:
		case SO_SNDBUF:
		case SO_SNDLOWAT:
		case SO_SNDTIMEO:
		case SO_CONDITIONAL_ACCEPT:
		case SO_EXCLUSIVEADDRUSE:
#if 0
		case SO_PROTECT:
#endif
		default:
			return WSAENOPROTOOPT;
		}

		return NO_ERROR;
	}

	return WSAEINVAL;
}


INT
WSHGetWildcardSockaddr(
    IN PVOID HelperDllSocketContext,
    OUT PSOCKADDR Sockaddr,
    OUT PINT SockaddrLength)
{
	PWSHSCTP_SOCKET_CONTEXT context = HelperDllSocketContext;

	switch (context->AddressFamily) {
	case AF_INET:
		if (*SockaddrLength < sizeof(SOCKADDR_IN)) {
			return WSAEFAULT;
		}

		ZeroMemory(Sockaddr, sizeof(SOCKADDR_IN));
		Sockaddr->sa_family = AF_INET;

		*SockaddrLength = sizeof(SOCKADDR_IN);
		break;

	case AF_INET6:
		if (*SockaddrLength < sizeof(SOCKADDR_IN6)) {
			return WSAEFAULT;
		}

		ZeroMemory(Sockaddr, sizeof(SOCKADDR_IN6));
		Sockaddr->sa_family = AF_INET6;

		*SockaddrLength = sizeof(SOCKADDR_IN6);
		break;

	default:
		break;
	}

	return NO_ERROR;
}


DWORD
WSHGetWinsockMapping(
    OUT PWINSOCK_MAPPING Mapping,
    IN DWORD MappingLength)
{
	DWORD mappingLength;

	mappingLength = sizeof(WINSOCK_MAPPING) - sizeof(MAPPING_TRIPLE) + sizeof(SctpMappingTriples);

	if (mappingLength > MappingLength) {
		return mappingLength;
	}

	Mapping->Rows = sizeof(SctpMappingTriples) / sizeof(SctpMappingTriples[0]);
	Mapping->Columns = sizeof(MAPPING_TRIPLE) / sizeof(DWORD);
	MoveMemory(Mapping->Mapping, SctpMappingTriples, sizeof(SctpMappingTriples));

	return mappingLength;
}


INT
WSHOpenSocket(
    IN OUT PINT AddressFamily,
    IN OUT PINT SocketType,
    IN OUT PINT Protocol,
    OUT PUNICODE_STRING TransportDeviceName,
    OUT PVOID *HelperDllSocketContext,
    OUT PDWORD NotificationEvents)
{
	return WSHOpenSocket2(
	    AddressFamily,
	    SocketType,
	    Protocol,
	    0,
	    0,
	    TransportDeviceName,
	    HelperDllSocketContext,
	    NotificationEvents);
}


INT
WSHOpenSocket2(
    IN OUT PINT AddressFamily,
    IN OUT PINT SocketType,
    IN OUT PINT Protocol,
    IN GROUP Group,
    IN DWORD Flags,
    OUT PUNICODE_STRING TransportDeviceName,
    OUT PVOID *HelperDllSocketContext,
    OUT PDWORD NotificationEvents
    )
{
	PWSHSCTP_SOCKET_CONTEXT context;
	FILE *fp;

	fp = fopen("c:\\hoge.txt", "a");

	if (!IsTripleInSctpTriple(*AddressFamily, *SocketType, *Protocol)) {
		fprintf(fp, "IsTripleInSctpTriple failed\n");
		fflush(fp);
		fclose(fp);
		return WSAEINVAL;
	}

	if ((Flags & ~WSA_FLAG_OVERLAPPED) != 0) {
		fprintf(fp, "WSA_FLAG_OVERLAPPED\n");
		fflush(fp);
		fclose(fp);
		return WSAEINVAL;
	}

	if (*SocketType == SOCK_STREAM) {
		RtlInitUnicodeString(TransportDeviceName, DD_SCTP_ONE_TO_ONE_DEVICE_NAME);
		fprintf(fp, "%ws\n", DD_SCTP_ONE_TO_ONE_DEVICE_NAME);
		fflush(fp);
	} else { /* SOCK_SEQPACKET */
		RtlInitUnicodeString(TransportDeviceName, DD_SCTP_ONE_TO_MANY_DEVICE_NAME);
		fprintf(fp, "%ws\n", DD_SCTP_ONE_TO_MANY_DEVICE_NAME);
		fflush(fp);
	}

	context = HeapAlloc(GetProcessHeap(), 0, sizeof(*context)) ;
	if (context == NULL) {
		fprintf(fp, "HeapAlloc failed\n");
		fflush(fp);
		fclose(fp);
		return WSAENOBUFS;
	}
	fprintf(fp, "AddressFamily=%d,SocketType=%d,Protocol=%d\n", *AddressFamily, *SocketType, *Protocol);
	fflush(fp);
	fclose(fp);

	ZeroMemory(context, sizeof(*context));

	context->AddressFamily = *AddressFamily;
	context->SocketType = *SocketType;
	context->Protocol = *Protocol;
	context->ReceiveBufferSize = DEFAULT_RECEIVE_BUFFER_SIZE;
	context->Flags = Flags;

	context->IpTtl = DEFAULT_IP_TTL;
	context->IpTos = DEFAULT_IP_TOS;

	*NotificationEvents = WSH_NOTIFY_BIND | WSH_NOTIFY_CONNECT | WSH_NOTIFY_CLOSE | WSH_NOTIFY_CONNECT_ERROR;

	*HelperDllSocketContext = context;

	return NO_ERROR;
}


INT
WSHNotify(
    IN PVOID HelperDllSocketContext,
    IN SOCKET SocketHandle,
    IN HANDLE TdiAddressObjectHandle,
    IN HANDLE TdiConnectionObjectHandle,
    IN DWORD NotifyEvent)
{
	PWSHSCTP_SOCKET_CONTEXT context = HelperDllSocketContext;

	if (NotifyEvent == WSH_NOTIFY_BIND) {
	} else if (NotifyEvent == WSH_NOTIFY_CONNECT) {
	} else if (NotifyEvent == WSH_NOTIFY_CONNECT_ERROR) {
	} else if (NotifyEvent == WSH_NOTIFY_CLOSE) {
	} else {
		return WSAEINVAL;
	}

	return NO_ERROR;
}


INT
WSHSetSocketInformation(
    IN PVOID HelperDllSocketContext,
    IN SOCKET SocketHandle,
    IN HANDLE TdiAddressObjectHandle,
    IN HANDLE TdiConnectionObjectHandle,
    IN INT Level,
    IN INT OptionName,
    IN PCHAR OptionValue,
    IN INT OptionLength)
{
	PWSHSCTP_SOCKET_CONTEXT context = HelperDllSocketContext;
	PWSHSCTP_SOCKET_CONTEXT parentContext;
    
	INT error;
	INT optionValue;

	UNREFERENCED_PARAMETER(SocketHandle);
	UNREFERENCED_PARAMETER(TdiAddressObjectHandle);
	UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);

	if (Level == SOL_INTERNAL && OptionName == SO_CONTEXT) {
		if (OptionValue != NULL) {
			if (OptionLength < sizeof(*context)) {
				return WSAEINVAL;
			}

			if (HelperDllSocketContext == NULL) {
				context = HeapAlloc(GetProcessHeap(), 0, sizeof(*context));
				if (context == NULL) {
					return WSAENOBUFS;
				}
			}

			CopyMemory(context, OptionValue, sizeof(*context));

			*(PWSHSCTP_SOCKET_CONTEXT *)OptionValue = context;

			return NO_ERROR;
		} else {
			parentContext = (PWSHSCTP_SOCKET_CONTEXT)OptionValue;

			ASSERT(context->AddressFamily == parentContext->AddressFamily);
			ASSERT(context->SocketType == parentContext->SocketType);
			ASSERT(context->Protocol == parentContext->Protocol);

		}

		return NO_ERROR;
	}

	if (Level != SOL_SOCKET &&
	    Level != IPPROTO_SCTP &&
	    Level != IPPROTO_IP &&
	    Level != IPPROTO_IPV6) {
		return WSAEINVAL;
	}
	if (Level == IPPROTO_IPV6 && context->AddressFamily == AF_INET) {
		return WSAEINVAL;
	}
	if (OptionLength < sizeof(INT)) {
		return WSAEINVAL;
	}

	if (Level == IPPROTO_SCTP) {
		switch (OptionName) {
		case SCTP_INITMSG:
			break;

		case SCTP_NODELAY:
			break;

		case SCTP_AUTOCLOSE:
			break;

		case SCTP_ADAPTATION_LAYER:
			break;

		case SCTP_DISABLE_FRAGMENTS:
			break;

		case SCTP_EVENTS:
			break;

		case SCTP_I_WANT_MAPPED_V4_ADDR:
			break;

		case SCTP_MAXSEG:
			break;

		case SCTP_AUTH_CHUNK:
			break;

		case SCTP_HMAC_IDENT:
			break;

		case SCTP_AUTH_KEY:
			break;

		case SCTP_AUTH_ACTIVE_KEY:
			break;

		case SCTP_AUTH_DELETE_KEY:
			break;

		case SCTP_FRAGMENT_INTERLEAVE:
			break;

		case SCTP_PARTIAL_DELIVERY_POINT:
			break;

#if 0
		case SCTP_USE_EXT_RCVINFO:
			break;
#endif

		case SCTP_RTOINFO:
			break;

		case SCTP_ASSOCINFO:
			break;

		case SCTP_PEER_ADDR_PARAMS:
			break;

		case SCTP_DEFAULT_SEND_PARAM:
			break;

		default:
			return WSAENOPROTOOPT;
		}

		return NO_ERROR;
	}

	if (Level == IPPROTO_IP) {
		switch (OptionName) {
		case IP_DONTFRAGMENT:
			break;

		case IP_OPTIONS:
			break;

		case IP_PKTINFO:
			break;

		case IP_TOS:
			break;

		case IP_TTL:
			break;

		default:
			return WSAENOPROTOOPT;
		}
		return NO_ERROR;
	}

	if (Level == IPPROTO_IPV6) {
		switch (OptionName) {
		case IPV6_HOPLIMIT:
			break;

		case IPV6_PKTINFO:
			break;

#if 0
		case IPV6_V6ONLY:
			break;
#endif

		default:
			return WSAENOPROTOOPT;
		}
		return NO_ERROR;
	}

	if (Level == SOL_SOCKET) {
		switch (OptionName) {
		case SO_ACCEPTCONN:
#if 0
		case SO_CONNECT_TIME:
#endif
		case SO_DEBUG:
		case SO_DONTLINGER:
		case SO_DONTROUTE:
		case SO_KEEPALIVE:
		case SO_LINGER:
		case SO_RCVBUF:
		case SO_RCVLOWAT:
		case SO_RCVTIMEO:
		case SO_REUSEADDR:
		case SO_SNDBUF:
		case SO_SNDLOWAT:
		case SO_SNDTIMEO:
		case SO_CONDITIONAL_ACCEPT:
		case SO_EXCLUSIVEADDRUSE:
#if 0
		case SO_PROTECT:
#endif
		default:
			return WSAENOPROTOOPT;
		}

		return NO_ERROR;
	}

	return WSAEINVAL;
}


INT
WSHEnumProtocols(
    IN LPINT lpiProtocols,
    IN LPWSTR lpTransportKeyName,
    IN OUT LPVOID lpProtocolBuffer,
    IN OUT LPDWORD lpdwBufferLength)
{
	BOOLEAN useSctp = FALSE;
	ULONG i;
	FILE *fp;
    
	fp = fopen("c:\\hoge.txt", "a");
	if (lpiProtocols != NULL) {
		for (i = 0; lpiProtocols[i] != 0; i++) {
			if (lpiProtocols[i] == IPPROTO_SCTP) {
				useSctp = TRUE;
			}
		}
	} else {
		useSctp = TRUE;
	}

	if (!useSctp) {
		*lpdwBufferLength = 0;
		fprintf(fp, "!useSctp\n");
		fflush(fp);
		fclose(fp);
		return 0;
	}

	if (*lpdwBufferLength < sizeof(SctpProtocolInfos)) {
		*lpdwBufferLength = sizeof(SctpProtocolInfos);
		fprintf(fp, "*lpdwBufferLength=%d,sizeof(SctpProtocolInfos)=%d\n", *lpdwBufferLength, sizeof(SctpProtocolInfos));
		fflush(fp);
		fclose(fp);
		return -1;
	}

	fprintf(fp, "#2*lpdwBufferLength=%d,sizeof(SctpProtocolInfos)=%d\n", *lpdwBufferLength, sizeof(SctpProtocolInfos));
	fflush(fp);
	fclose(fp);
	CopyMemory(lpProtocolBuffer, SctpProtocolInfos, sizeof(SctpProtocolInfos));
	*lpdwBufferLength = sizeof(SctpProtocolInfos);
    
	return NUM_SCTP_PROTOCOL_INFOS;
}


INT
WINAPI
WSHGetWSAProtocolInfo(
    IN LPWSTR ProviderName,
    OUT LPWSAPROTOCOL_INFOW *ProtocolInfo,
    OUT LPDWORD ProtocolInfoEntries)
{
	FILE *fp;
    
	fp = fopen("c:\\hoge.txt", "a");
	if(_wcsicmp(ProviderName, SCTP_NAME) == 0) {
		*ProtocolInfo = WsaSctpProtocolInfos;
		*ProtocolInfoEntries = NUM_WSA_SCTP_PROTOCOL_INFOS;

		fprintf(fp, "*ProtocolInfoEntries=%d\n", *ProtocolInfoEntries);
		fflush(fp);
		fclose(fp);
		return NO_ERROR;
	}

	fprintf(fp, "WSHGetWSAProtocolInfo failed\n");
	fflush(fp);
	fclose(fp);
	return WSAEINVAL;
}


INT
WINAPI
WSHGetProviderGuid(
    IN LPWSTR ProviderName,
    OUT LPGUID ProviderGuid)
{
	if(_wcsicmp(ProviderName, SCTP_NAME) == 0) {
		CopyMemory(ProviderGuid, &SctpProviderGuid, sizeof(SctpProviderGuid));

		return NO_ERROR;
	}

	return WSAEINVAL;
}


INT
WINAPI
WSHIoctl(
    IN PVOID HelperDllSocketContext,
    IN SOCKET SocketHandle,
    IN HANDLE TdiAddressObjectHandle,
    IN HANDLE TdiConnectionObjectHandle,
    IN DWORD IoControlCode,
    IN LPVOID InputBuffer,
    IN DWORD InputBufferLength,
    IN LPVOID OutputBuffer,
    IN DWORD OutputBufferLength,
    OUT LPDWORD NumberOfBytesReturned,
    IN LPWSAOVERLAPPED Overlapped,
    IN LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine,
    OUT LPBOOL NeedsCompletion)
{
	INT err;

	if (HelperDllSocketContext == NULL || SocketHandle == INVALID_SOCKET ||
	    NumberOfBytesReturned == NULL || NeedsCompletion == NULL) {
		return WSAEINVAL;
	}


	*NeedsCompletion = TRUE;

	switch (IoControlCode) {
	default:
		err = WSAEINVAL;
		break;
	}

	return err;
}
