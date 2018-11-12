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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <rpc.h>

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

#include <sctpsp.h>

int __cdecl
_tmain(
    int argc,
    TCHAR *argv[])
{
	WSADATA wsd;
	int ret, i;
	LPWSAPROTOCOL_INFOW lpProtocolInfo0 = NULL, lpProtocolInfo = NULL;
	LPWSANAMESPACE_INFOW lpNameInfo0 = NULL, lpNameInfo = NULL;
	DWORD dwProtocolInfoSize = 0;
	DWORD dwNameInfoSize = 0;
	TCHAR *szUuid = NULL;
	int iError = 0;

	if (argc < 2) {
		_ftprintf(stderr, TEXT("Usage: %ws [/Print] [/Install] [/Uninstall]\n"), argv[0]);
		return -1;
	}

	ret = WSAStartup(MAKEWORD(2, 2), &wsd);
	if (ret != 0) {
		_ftprintf(stderr, TEXT("WSAStartup=%u\n"), WSAGetLastError());
		return -1;
	}
	if (_tcscmp(argv[1], TEXT("/Print")) == 0) {
		ret = WSCEnumProtocols(NULL, lpProtocolInfo0, &dwProtocolInfoSize, &iError);
		if (ret == SOCKET_ERROR && iError != WSAENOBUFS) {
			_ftprintf(stderr, TEXT("WSCEnumProtocols=%u\n"), iError);
			return -1;
		}
		lpProtocolInfo0 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwProtocolInfoSize);
		if (lpProtocolInfo0 == NULL) {
			_ftprintf(stderr, TEXT("HeapAlloc=%u\n"), GetLastError());
			return -1;
		}
		ret = WSCEnumProtocols(NULL, lpProtocolInfo0, &dwProtocolInfoSize, &iError);
		if (ret == SOCKET_ERROR) {
			_ftprintf(stderr, TEXT("WSCEnumProtocols=%u\n"), iError);
			return -1;
		}
		for (i = 0; i < ret; i++) {
			lpProtocolInfo = &lpProtocolInfo0[i];

			_tprintf(_T("%ws\n"), lpProtocolInfo->szProtocol);
			UuidToString((UUID *)&lpProtocolInfo->ProviderId, &szUuid);
			_tprintf(_T("\t%s\n"), szUuid);
			RpcStringFree(&szUuid);
		}
	} else if (
	    _tcscmp(argv[1], TEXT("/PrintNS")) == 0) {
		ret = WSAEnumNameSpaceProviders(&dwNameInfoSize, lpNameInfo0);
		if (ret == SOCKET_ERROR && WSAGetLastError() != WSAEFAULT) {
			_ftprintf(stderr, TEXT("WSCEnumProtocols=%u\n"), WSAGetLastError());
			return -1;
		}
		lpNameInfo0 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNameInfoSize);
		if (lpNameInfo0 == NULL) {
			_ftprintf(stderr, TEXT("HeapAlloc=%u\n"), GetLastError());
			return -1;
		}
		ret = WSAEnumNameSpaceProviders(&dwNameInfoSize, lpNameInfo0);
		if (ret == SOCKET_ERROR) {
			_ftprintf(stderr, TEXT("WSCEnumProtocols=%u\n"), WSAGetLastError());
			return -1;
		}
		for (i = 0; i < ret; i++) {
			lpNameInfo = &lpNameInfo0[i];

			_tprintf(_T("%ws\n"), lpNameInfo->lpszIdentifier);
			UuidToString(&lpProtocolInfo->ProviderId, &szUuid);
			_tprintf(_T("\t%s\n"), szUuid);
			RpcStringFree(&szUuid);
		}
	} else if (
	    _tcscmp(argv[1], TEXT("/Install")) == 0) {
		ret = WSCInstallProvider(&SctpProviderGuid, SCTP_SERVICE_PROVIDER_PATH,
		    SctpProtocolInfos, NUM_SCTP_PROTOCOL_INFOS, &iError);
		if (ret == SOCKET_ERROR) {
			_ftprintf(stderr, TEXT("WSCInstallProvider=%u\n"), iError);
		}
	} else if (
	    _tcscmp(argv[1], TEXT("/Uninstall")) == 0) {
		ret = WSCDeinstallProvider(&SctpProviderGuid, &iError);
		if (ret == SOCKET_ERROR) {
			_ftprintf(stderr, TEXT("WSCDeinstallProvider=%u\n"), iError);
		}
	} else {
		_ftprintf(stderr, TEXT("Usage: %ws [/Print] [/Install] [/Uninstall]\n"), argv[0]);
		return -1;
	}
	return 0;
}
