/*
 * Copyright (c) 2008 CO-CONV, Corp. All rights reserved.
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
 */
// {E9BAC45A-85E4-4569-8B40-5532D722AFD4}
#define SCTP_PROVIDER_GUID_INIT \
	{ 0xe9bac45a, 0x85e4, 0x4569, \
	  {0x8b, 0x40, 0x55, 0x32, 0xd7, 0x22, 0xaf, 0xd4}}

#define SCTP_SERVICE_PROVIDER_PATH	L"%SystemRoot%\\System32\\sctpsp.dll"

#define IPPROTO_SCTP			132

GUID SctpProviderGuid = SCTP_PROVIDER_GUID_INIT;


WSAPROTOCOL_INFOW SctpProtocolInfos[] = {
    // one-to-one socket for SCTP/IPv4
{
    XP1_GUARANTEED_DELIVERY |
    XP1_GUARANTEED_ORDER |
    XP1_GRACEFUL_CLOSE |
    XP1_MESSAGE_ORIENTED |
    XP1_IFS_HANDLES,
    0,
    0,
    0,
    0,
    SCTP_PROVIDER_GUID_INIT,
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
    L"Sctp(one-to-one) [SCTP/IPv4]"
},
{
    XP1_GUARANTEED_DELIVERY |
    XP1_GUARANTEED_ORDER |
    XP1_GRACEFUL_CLOSE |
    XP1_MESSAGE_ORIENTED |
    XP1_IFS_HANDLES,
    0,
    0,
    0,
    0,
    SCTP_PROVIDER_GUID_INIT,
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
    L"Sctp(one-to-one) [SCTP/IPv6]"
},
{
    XP1_CONNECTIONLESS |
    XP1_GUARANTEED_DELIVERY |
    XP1_GUARANTEED_ORDER |
    XP1_MESSAGE_ORIENTED |
    XP1_IFS_HANDLES,
    0,
    0,
    0,
    0,
    SCTP_PROVIDER_GUID_INIT,
    0,
    {
	BASE_PROTOCOL,
	{0, 0, 0, 0, 0, 0, 0}
    },
    0,
    AF_INET,
    sizeof(SOCKADDR_IN),
    sizeof(SOCKADDR_IN),
    SOCK_SEQPACKET,
    IPPROTO_SCTP,
    0,
    BIGENDIAN,
    SECURITY_PROTOCOL_NONE,
    0xFFFFFFFF,
    0,
    L"Sctp(one-to-many) [SCTP/IPv4]"
},
{
    XP1_CONNECTIONLESS |
    XP1_GUARANTEED_DELIVERY |
    XP1_GUARANTEED_ORDER |
    XP1_MESSAGE_ORIENTED |
    XP1_IFS_HANDLES,
    0,
    0,
    0,
    0,
    SCTP_PROVIDER_GUID_INIT,
    0,
    {
	BASE_PROTOCOL,
	{0, 0, 0, 0, 0, 0, 0}
    },
    0,
    AF_INET6,
    sizeof(SOCKADDR_IN6),
    sizeof(SOCKADDR_IN6),
    SOCK_SEQPACKET,
    IPPROTO_SCTP,
    0,
    BIGENDIAN,
    SECURITY_PROTOCOL_NONE,
    0xFFFFFFFF,
    0,
    L"Sctp(one-to-many) [SCTP/IPv6]"
},
{
    XP1_CONNECTIONLESS |
    XP1_GUARANTEED_DELIVERY |
    XP1_GUARANTEED_ORDER |
    XP1_MESSAGE_ORIENTED |
    XP1_IFS_HANDLES,
    0,
    0,
    0,
    0,
    SCTP_PROVIDER_GUID_INIT,
    0,
    {
	BASE_PROTOCOL,
	{0, 0, 0, 0, 0, 0, 0}
    },
    0,
    AF_INET,
    sizeof(SOCKADDR_IN),
    sizeof(SOCKADDR_IN),
    SOCK_DGRAM,
    IPPROTO_SCTP,
    0,
    BIGENDIAN,
    SECURITY_PROTOCOL_NONE,
    0xFFFFFFFF,
    0,
    L"Sctp(one-to-many) [SCTP/IPv4]"
},
{
    XP1_CONNECTIONLESS |
    XP1_GUARANTEED_DELIVERY |
    XP1_GUARANTEED_ORDER |
    XP1_MESSAGE_ORIENTED |
    XP1_IFS_HANDLES,
    0,
    0,
    0,
    0,
    SCTP_PROVIDER_GUID_INIT,
    0,
    {
	BASE_PROTOCOL,
	{0, 0, 0, 0, 0, 0, 0}
    },
    0,
    AF_INET6,
    sizeof(SOCKADDR_IN6),
    sizeof(SOCKADDR_IN6),
    SOCK_DGRAM,
    IPPROTO_SCTP,
    0,
    BIGENDIAN,
    SECURITY_PROTOCOL_NONE,
    0xFFFFFFFF,
    0,
    L"Sctp(one-to-many) [SCTP/IPv6]"
},
};

#define NUM_SCTP_PROTOCOL_INFOS \
	(sizeof(SctpProtocolInfos) / sizeof(SctpProtocolInfos[0]))
