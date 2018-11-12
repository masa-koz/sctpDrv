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
#include <WS2tcpip.h>
#include <netsh.h>

#include <wchar.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <netinet/sctp_constants.h>
#include <netinet/sctp_uio.h>

#define SCTPMON_GUID /* C559CBE3-48E7-49b7-9F77-439CDB1DD3CD */ \
    {0xc559cbe3,0x48e7,0x49b7,{0x9f,0x77,0x43,0x9c,0xdb,0x1d,0xd3,0xcd}}
static GUID g_SctpMonGuid = SCTPMON_GUID;

static
VOID
ShowSctpLog(
    IN struct sctp_log *sctp_log)
{
	unsigned int i;
	PrintMessage(L"number of entries=%1!d!\n", sctp_log->index);
	for (i = 0; i < sctp_log->index; i++) {
		PrintMessage(L"%1!I64d!: param0=0x%1!X!,param1=0x%2!X!,param2=0x%3!X!,param3=0x%4!X!,param4=0x%5!X!,param5=0x%6!X!\n",
		    sctp_log->entry[i].timestamp,
		    sctp_log->entry[i].params[0],
		    sctp_log->entry[i].params[1],
		    sctp_log->entry[i].params[2],
		    sctp_log->entry[i].params[3],
		    sctp_log->entry[i].params[4],
		    sctp_log->entry[i].params[5]);
	}
}

static
DWORD
WINAPI
HandleShowSysctl(
    IN LPCWSTR pwszMachine,
    __inout_ecount(dwArgCount) LPWSTR *ppwcArguments,
    IN DWORD dwCurrentIndex,
    IN DWORD dwArgCount,
    IN DWORD dwFlags,
    IN LPCVOID pvData,
    OUT BOOL* pbDone)
{
	TAG_TYPE tTags[1] = {
	{
	    L"name",
	    NS_REQ_ZERO,
	    FALSE,
	},
	};
	DWORD dwtTags[1];

	size_t countConverted;
	errno_t err;
	mbstate_t mbstate;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwError = NO_ERROR, dwSize = 0;
	struct sysctl_req req;
	int kind = 0;
	UCHAR name[256], nxt_name[256];
	char data[1024];
	struct sctp_log *sctp_log = NULL;

	*pbDone = FALSE;

	dwError = PreprocessCommand(NULL, ppwcArguments, 3, dwArgCount, (TAG_TYPE *)&tTags, 1, 0, 1, dwtTags);
	if (dwError != NO_ERROR) {
		return dwError;
	}

	memset(nxt_name, 0, sizeof(nxt_name));
	if (tTags[0].bPresent) {
		memset(&mbstate, 0, sizeof(mbstate));
		err = wcsrtombs_s(&countConverted, nxt_name, sizeof(nxt_name),
		    &ppwcArguments[3 + dwtTags[0]], _TRUNCATE, &mbstate);
		if (err != 0) {
			PrintMessage(L"Failed to convert to MBString: name=%1!s!\n", ppwcArguments[3 + dwtTags[0]]);
			return NO_ERROR;
		}
	}

	hFile = CreateFileW(WIN_SCTP_DEVICE_NAME,
	    GENERIC_READ | GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    NULL,
	    OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL,
	    NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		dwError = GetLastError();
		PrintMessage(L"Failed to open a device: code=%1!u!\n", dwError);
		return dwError;
	}

	if (strcmp(nxt_name, "sctp_log") == 0) {
		sctp_log = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct sctp_log));
	}

	/* Enumerate the entries */
	do {
		memset(&req, 0, sizeof(req));

		memset(name, 0, sizeof(name));
		if (strlen(nxt_name) > 0) {
			strcpy(name, nxt_name);
		}
		req.name = name;
		req.namelen = sizeof(name);

		if (strcmp(req.name, "sctp_log") == 0) {
			if (sctp_log != NULL) {
				memset(sctp_log, 0, sizeof(struct sctp_log));
				req.data = sctp_log;
				req.datalen = sizeof(struct sctp_log);
			} else {
				req.data = NULL;
				req.datalen = 0;
			}
		} else {
			memset(data, 0, sizeof(data));
			req.data = data;
			req.datalen = sizeof(data);
		}

		memset(nxt_name, 0, sizeof(nxt_name));
		req.nxt_name = nxt_name;
		req.nxt_namelen = sizeof(nxt_name);

		if (!DeviceIoControl(hFile,
			IOCTL_SCTP_SYSCTL,
			&req, sizeof(req),
			&req, sizeof(req), &dwSize,
			NULL)) {
			dwError = GetLastError();
			PrintMessage(L"Failed to execute I/O control: code=%1!u!\n", dwError);
			break;
		}

		if ((req.kind & CTLFLAG_RD) == 0) {
			continue;
		}
		switch (req.kind & CTLTYPE_MASK) {
		case CTLTYPE_INT:
			if (req.dataidx > 0) {
				PrintMessage(L"%1!S!: %2!d!\n", req.name, *(int *)req.data);
				break;
			}
			PrintMessage(L"%1!S!: \n", req.name);
			break;
		case CTLTYPE_STRUCT:
			if (strcmp(req.name, "sctp_log") == 0 &&
			    req.data != NULL && req.datalen > 0 && req.dataidx >= sizeof(struct sctp_log)) {
				ShowSctpLog((struct sctp_log *)req.data);
				break;
			}
			PrintMessage(L"%1!S!: \n", req.name);
			break;
		default:
			PrintMessage(L"%1!S!: \n", req.name);
			break;
		}

	} while (!tTags[0].bPresent && req.nxt_nameidx > 0);

	if (sctp_log != NULL) {
		HeapFree(GetProcessHeap(), 0, sctp_log);
		sctp_log = NULL;
	}

	CloseHandle(hFile);

	return NO_ERROR;
}

static
DWORD
WINAPI
HandleShowSysctlDesc(
    IN LPCWSTR pwszMachine,
    __inout_ecount(dwArgCount) LPWSTR *ppwcArguments,
    IN DWORD dwCurrentIndex,
    IN DWORD dwArgCount,
    IN DWORD dwFlags,
    IN LPCVOID pvData,
    OUT BOOL* pbDone)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwError = NO_ERROR, dwSize = 0;
	struct sysctl_req req;
	UCHAR name[256], nxt_name[256];
	UCHAR desc[256];

	*pbDone = FALSE;

	hFile = CreateFileW(WIN_SCTP_DEVICE_NAME,
	    GENERIC_READ | GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    NULL,
	    OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL,
	    NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		dwError = GetLastError();
		PrintMessage(L"Failed to open a device: code=%1!u!\n", dwError);
		return dwError;
	}

	if (dwArgCount <= 3) {
		/* Enumerate all the entries */

		memset(nxt_name, 0, sizeof(nxt_name));
		do {
			memset(&req, 0, sizeof(req));

			memset(name, 0, sizeof(name));
			if (strlen(nxt_name) > 0) {
				strcpy(name, nxt_name);
			}
			req.name = name;
			req.namelen = sizeof(name);

			memset(desc, 0, sizeof(desc));
			req.desc = desc;
			req.desclen = sizeof(desc);

			memset(nxt_name, 0, sizeof(nxt_name));
			req.nxt_name = nxt_name;
			req.nxt_namelen = sizeof(nxt_name);

			if (!DeviceIoControl(hFile,
				IOCTL_SCTP_SYSCTL,
				&req, sizeof(req),
				&req, sizeof(req), &dwSize,
				NULL)) {
				dwError = GetLastError();
				PrintMessage(L"Failed to execute I/O control: code=%1!u!\n", dwError);
				break;
			}
			PrintMessage(L"%1!S!: %2!S!\n", req.name, req.desc);
		} while (req.nxt_nameidx > 0);
	}

	CloseHandle(hFile);

	return NO_ERROR;
}

static
DWORD
WINAPI
HandleShowAssociation(
    IN LPCWSTR pwszMachine,
    __inout_ecount(dwArgCount) LPWSTR *ppwcArguments,
    IN DWORD dwCurrentIndex,
    IN DWORD dwArgCount,
    IN DWORD dwFlags,
    IN LPCVOID pvData,
    OUT BOOL* pbDone)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwError = NO_ERROR, dwSize = 0;
	struct sysctl_req req;
	UCHAR *name = "assoclist";
	char *data = NULL;
	int datalen = 0;
	int offset = 0;
	struct xsctp_inpcb *xinp = NULL;
	struct xsctp_tcb *xstcb = NULL;
	struct xsctp_laddr *xladdr = NULL;
	struct xsctp_raddr *xraddr = NULL;
	int addrlen;
	char hbuf[NI_MAXHOST];

	*pbDone = FALSE;

	hFile = CreateFileW(WIN_SCTP_DEVICE_NAME,
	    GENERIC_READ | GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    NULL,
	    OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL,
	    NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		dwError = GetLastError();
		PrintMessage(L"Failed to open a device: code=%1!u!\n", dwError);
		return dwError;
	}

	memset(&req, 0, sizeof(req));
	req.name = name;
	req.namelen = strlen(name) + 1;

	/* Retrieve the size of needed buffer. */
	if (!DeviceIoControl(hFile,
		IOCTL_SCTP_SYSCTL,
		&req, sizeof(req),
		&req, sizeof(req), &dwSize,
		NULL)) {
		dwError = GetLastError();
		PrintMessage(L"Failed to execute I/O control: code=%1!u!\n", dwError);
		goto done;
	}

	datalen = req.dataidx;
	data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, datalen);
	if (data == NULL) {
		dwError = GetLastError();
		PrintMessage(L"Failed to allocate memory: code=%1!u!\n", dwError);
		goto done;
	}

	memset(&req, 0, sizeof(req));
	req.name = name;
	req.namelen = strlen(name) + 1;
	req.data = data;
	req.datalen = datalen;

	/* Retrieve information of SCTP association. */
	if (!DeviceIoControl(hFile,
		IOCTL_SCTP_SYSCTL,
		&req, sizeof(req),
		&req, sizeof(req), &dwSize,
		NULL)) {
		dwError = GetLastError();
		PrintMessage(L"Failed to execute I/O control#2: code=%1!u!\n", dwError);
		goto done;
	}

	/* Enumerate */
	offset = 0;
	xinp = (struct xsctp_inpcb *)(data + offset);
	while (xinp->last == 0 && offset < datalen) {
		PrintMessage(L"\nEndpoint with port=%1!u!\n", xinp->local_port);
		offset += sizeof(struct xsctp_inpcb);
		PrintMessage(L"\tLocal addresses:");
		xladdr = (struct xsctp_laddr *)(data + offset);
		while (xladdr->last == 0) {
			switch (xladdr->address.sin.sin_family) {
			case AF_INET:
				addrlen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				addrlen = sizeof(struct sockaddr_in6);
				break;
			default:
				addrlen = 0;
				break;
			}

			memset(hbuf, 0, sizeof(hbuf));
			if (addrlen > 0) {
				getnameinfo((struct sockaddr *)&xladdr->address, addrlen,
				    hbuf, sizeof(hbuf), NULL, 0,
				    NI_NUMERICHOST);
			}
			PrintMessage(L" %1!S!", hbuf);
			offset += sizeof(struct xsctp_laddr);
			xladdr = (struct xsctp_laddr *)(data + offset);
		}
		offset += sizeof(struct xsctp_laddr);
		PrintMessage(L".\n");

		xstcb = (struct xsctp_tcb *)(data + offset);
		while (xstcb->last == 0) {
			xstcb = (struct xsctp_tcb *)(data + offset);
			PrintMessage(L"\tRemote port=%1!u!, state=%2!d!.\n",
			       xstcb->remote_port, xstcb->state);
			offset += sizeof(struct xsctp_tcb);

			PrintMessage(L"\t\tLocal addresses:");
			xladdr = (struct xsctp_laddr *)(data + offset);
			while (xladdr->last == 0) {
				switch (xladdr->address.sin.sin_family) {
				case AF_INET:
					addrlen = sizeof(struct sockaddr_in);
					break;
				case AF_INET6:
					addrlen = sizeof(struct sockaddr_in6);
					break;
				default:
					addrlen = 0;
					break;
				}
				memset(hbuf, 0, sizeof(hbuf));
				if (addrlen > 0) {
					getnameinfo((struct sockaddr *)&xladdr->address, addrlen,
					    hbuf, sizeof(hbuf), NULL, 0,
					    NI_NUMERICHOST);
				}
				PrintMessage(L" %1!S!", hbuf);
				offset += sizeof(struct xsctp_laddr);
				xladdr = (struct xsctp_laddr *)(data + offset);
			}
			offset += sizeof(struct xsctp_laddr);
			PrintMessage(L".\n");
			
			xraddr = (struct xsctp_raddr *)(data + offset);
			while (xraddr->last == 0) {
				switch (xraddr->address.sin.sin_family) {
				case AF_INET:
					addrlen = sizeof(struct sockaddr_in);
					break;
				case AF_INET6:
					addrlen = sizeof(struct sockaddr_in6);
					break;
				default:
					addrlen = 0;
					break;
				}
				memset(hbuf, 0, sizeof(hbuf));
				if (addrlen > 0) {
					getnameinfo((struct sockaddr *)&xraddr->address, addrlen,
					    hbuf, sizeof(hbuf), NULL, 0,
					    NI_NUMERICHOST);
				}
				PrintMessage(L"\t\tPath towards %1!S!.\n", hbuf);
				offset += sizeof(struct xsctp_raddr);
				xraddr = (struct xsctp_raddr *)(data + offset);
			}
			offset += sizeof(struct xsctp_raddr);
			xstcb = (struct xsctp_tcb *)(data + offset);
		}
		offset += sizeof(struct xsctp_tcb);
		xinp = (struct xsctp_inpcb *)(data + offset);
	}

done:
	if (data != NULL) {
		HeapFree(GetProcessHeap(), 0, data);
		data = NULL;
	}
	CloseHandle(hFile);
	return dwError;
}

static
DWORD
WINAPI
HandleSetSysctl(
    IN LPCWSTR pwszMachine,
    __inout_ecount(dwArgCount) LPWSTR *ppwcArguments,
    IN DWORD dwCurrentIndex,
    IN DWORD dwArgCount,
    IN DWORD dwFlags,
    IN LPCVOID pvData,
    OUT BOOL* pbDone)
{
	TAG_TYPE tTags[2] = {
	{
	    L"name",
	    NS_REQ_PRESENT,
	    FALSE,
	},
	{
	    L"value",
	    NS_REQ_PRESENT,

	    FALSE,
	},
	};
	DWORD dwtTags[2];

	size_t countConverted;
	errno_t err;
	mbstate_t mbstate;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwError = NO_ERROR, dwSize = 0;
	struct sysctl_req req;
	int kind = 0;
	UCHAR name[256];
	int intdata = 0, new_intdata = 0;

	*pbDone = FALSE;

	dwError = PreprocessCommand(NULL, ppwcArguments, 3, dwArgCount, (TAG_TYPE *)&tTags, 2, 2, 2, dwtTags);
	if (dwError != NO_ERROR) {
		return dwError;
	}

	memset(&mbstate, 0, sizeof(mbstate));
	err = wcsrtombs_s(&countConverted, name, sizeof(name),
	    &ppwcArguments[3 + dwtTags[0]], _TRUNCATE, &mbstate);
	if (err != 0) {
		PrintMessage(L"Failed to convert to MBString: name=%1!s!\n", ppwcArguments[3 + dwtTags[0]]);
	}

	hFile = CreateFileW(WIN_SCTP_DEVICE_NAME,
	    GENERIC_READ | GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    NULL,
	    OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL,
	    NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		dwError = GetLastError();
		PrintMessage(L"Failed to open a device: code=%1!u!\n", dwError);
		return dwError;
	}

	memset(&req, 0, sizeof(req));
	req.name = name;
	req.namelen = strlen(name) + 1;

	/* Get the kind */
	if (!DeviceIoControl(hFile,
		IOCTL_SCTP_SYSCTL,
		&req, sizeof(req),
		&req, sizeof(req), &dwSize,
		NULL)) {
		dwError = GetLastError();
		PrintMessage(L"Failed to execute I/O control: code=%1!u!\n", dwError);
		goto done;
	}

	kind = req.kind;

	memset(&req, 0, sizeof(req));
	req.name = name;
	req.namelen = strlen(name) + 1;
	switch (kind & CTLTYPE_MASK) {
	case CTLTYPE_INT:
		new_intdata = _wtoi(ppwcArguments[3 + dwtTags[1]]);
		req.data = (void *)&intdata;
		req.datalen = sizeof(intdata);
		req.new_data = (void *)&new_intdata;
		req.new_datalen = sizeof(new_intdata);
		break;
	default:
		PrintMessage(L"Not supported operation: Set %1!S!\n", name);
		goto done;
	}

	if (!DeviceIoControl(hFile,
		IOCTL_SCTP_SYSCTL,
		&req, sizeof(req),
		&req, sizeof(req), &dwSize,
		NULL)) {
		dwError = GetLastError();
		PrintMessage(L"Failed to execute I/O control: code=%1!u!\n", dwError);
		goto done;
	}
	switch (req.kind & CTLTYPE_MASK) {
	case CTLTYPE_INT:
		if (req.dataidx > 0 && req.new_dataidx > 0) {
			PrintMessage(L"%1!S!: %2!d! -> %3!d!\n", req.name, *(int *)req.data, *(int *)req.new_data);
			break;
		}
	default:
		PrintMessage(L"%1!S!: -> \n", req.name);
		break;
	}

done:
	CloseHandle(hFile);
	return dwError;
}

#define CMD_SCTPMON_SHOW_SYSCTL		L"sysctl"
#define HLP_SCTPMON_SHOW_SYSCTL		1001
#define HLP_SCTPMON_SHOW_SYSCTL_EX	1002
#define CMD_SCTPMON_SHOW_SYSCTL_DESC	L"sysctl_desc"
#define HLP_SCTPMON_SHOW_SYSCTL_DESC	1003
#define HLP_SCTPMON_SHOW_SYSCTL_DESC_EX	1004
#define CMD_SCTPMON_SHOW_ASSOC		L"association"
#define HLP_SCTPMON_SHOW_ASSOC		1005
#define HLP_SCTPMON_SHOW_ASSOC_EX	1006

#define CMD_SCTPMON_SET_SYSCTL		L"sysctl"
#define HLP_SCTPMON_SET_SYSCTL		2001
#define HLP_SCTPMON_SET_SYSCTL_EX	2002

static CMD_ENTRY g_SctpMonShowCmdTable[] = 
{
	CREATE_CMD_ENTRY(SCTPMON_SHOW_SYSCTL, HandleShowSysctl),
	CREATE_CMD_ENTRY(SCTPMON_SHOW_SYSCTL_DESC, HandleShowSysctlDesc),
	CREATE_CMD_ENTRY(SCTPMON_SHOW_ASSOC, HandleShowAssociation),
};

static CMD_ENTRY g_SctpMonSetCmdTable[] = 
{
	CREATE_CMD_ENTRY(SCTPMON_SET_SYSCTL, HandleSetSysctl),
};

#define CMD_SCTPMON_GROUP_SHOW		L"show"
#define HLP_SCTPMON_GROUP_SHOW		1000
#define CMD_SCTPMON_GROUP_SET		L"set"
#define HLP_SCTPMON_GROUP_SET		2000

static CMD_GROUP_ENTRY g_SctpMonGroupCmds[] = 
{
	CREATE_CMD_GROUP_ENTRY(SCTPMON_GROUP_SHOW, g_SctpMonShowCmdTable),
	CREATE_CMD_GROUP_ENTRY(SCTPMON_GROUP_SET, g_SctpMonSetCmdTable),
};


static
DWORD
WINAPI
NetshStartHelper(
    IN const GUID* pguidParent,
    IN DWORD dwVersion)
{
	DWORD dwErr;
	NS_CONTEXT_ATTRIBUTES contextAttr;

	ZeroMemory(&contextAttr, sizeof(contextAttr));

	contextAttr.pwszContext = L"sctp";
	contextAttr.guidHelper = g_SctpMonGuid;
	contextAttr.dwVersion = 1;
	contextAttr.dwFlags = 0;
	contextAttr.ulNumTopCmds = 0;
	contextAttr.pTopCmds = (CMD_ENTRY (*)[])NULL;
	contextAttr.ulNumGroups  = sizeof(g_SctpMonGroupCmds) / sizeof(g_SctpMonGroupCmds[0]);
	contextAttr.pCmdGroups = (CMD_GROUP_ENTRY (*)[])&g_SctpMonGroupCmds;
	contextAttr.pfnCommitFn = NULL;
	contextAttr.pfnDumpFn = NULL;
	contextAttr.pfnConnectFn = NULL;

	dwErr = RegisterContext(&contextAttr);
	return dwErr;
}

DWORD
WINAPI
InitHelperDll(
    IN DWORD dwNetshVersion,
    OUT PVOID pReserved)
{
	NS_HELPER_ATTRIBUTES helperAttr;

	ZeroMemory(&helperAttr, sizeof(helperAttr));

	helperAttr.guidHelper = g_SctpMonGuid;
	helperAttr.dwVersion = 1;
	helperAttr.pfnStart = NetshStartHelper;
	RegisterHelper(NULL, &helperAttr);
	return NO_ERROR;
}

