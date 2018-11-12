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
#define UNICODE

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <ws2spi.h>

#include <sctpsp.h>

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp.h>
#include <netinet/sctp_peeloff.h>

#include "_errno.h"

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG  Length;
    HANDLE  RootDirectory;
    PUNICODE_STRING  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
	NTSTATUS Status;
	PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef ULONG ACCESS_MASK;
typedef ACCESS_MASK *PACCESS_MASK;

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

#if defined(SCTP_PROVIDER_DEBUG)
#if _WIN32_WINNT < 0x0600
#define DBGPRINT DbgPrint
#else
__inline void
_DbgPrint(
    IN PCHAR  Format,
    ...)
{
	va_list va;
	va_start(va, Format);
	vDbgPrintEx(80, 0, Format, va);
        va_end(va);
}
#define DBGPRINT _DbgPrint

#endif
#else
__inline void
_DbgPrint(
    IN PCHAR  Format,
    ...)
{
}
#define DBGPRINT _DbgPrint
#endif

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString
    );

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer,
    IN ULONG EaLength
    );

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event,
    IN PIO_APC_ROUTINE  ApcRoutine,
    IN PVOID  ApcContext,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  IoControlCode,
    IN PVOID  InputBuffer,
    IN ULONG  InputBufferLength,
    OUT PVOID  OutputBuffer,
    IN ULONG  OutputBufferLength
    );
NTSYSAPI
NTSTATUS 
NTAPI
ZwClose(
    IN HANDLE  Handle
    );


WSPUPCALLTABLE Upcalls;
HMODULE hIPv4Dll = NULL;
HMODULE hIPv6Dll = NULL;


typedef struct _SOCKET_CONTEXT {
    SOCKET socket;
    WSAPROTOCOL_INFOW protocolInfo;
} SOCKET_CONTEXT, *PSOCKET_CONTEXT;

PSOCKET_CONTEXT ctxs = NULL;

SOCKET
WSPAPI
WSPAccept(
    SOCKET s,
    struct sockaddr FAR * addr,
    LPINT addrlen,
    LPCONDITIONPROC lpfnCondition,
    DWORD_PTR dwCallbackData,
    LPINT lpErrno)
{
	UNICODE_STRING devname;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statusBlock;
	SOCKET socket = INVALID_SOCKET;
	NTSTATUS status = 0x00000000L; /* STATUS_SUCCESS */
	SOCKET_ACCEPT_REQUEST acceptReq;
	WSAPROTOCOL_INFO protocolInfo;

	DBGPRINT("WSPAccept - enter\n");

	if (addr != NULL && addrlen == NULL) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPAccept - leave #1\n");
		goto done;
	}
	RtlInitUnicodeString(&devname, DD_SCTP_SOCKET_DEVICE_NAME);

	InitializeObjectAttributes(&attr,
	    &devname,
	    OBJ_CASE_INSENSITIVE,
	    NULL, NULL);

	status = ZwCreateFile((HANDLE *)&socket,
	    GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
	    &attr,
	    &statusBlock,
	    0L,
	    FILE_ATTRIBUTE_NORMAL,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    FILE_OPEN_IF,
	    0L,
	    NULL,
	    0);
	if (status != 0x00000000L) { /* != STATUS_SUCCESS */
		switch (status) {
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAENOBUFS;
			break;
		default:
			*lpErrno = WSAENETDOWN;
			break;
		}
		DBGPRINT("WSPAccept - leave #2\n");
		return socket;
	}

	if (addr != NULL && addrlen != NULL) {
		acceptReq.addr = addr;
		acceptReq.addrlen = *addrlen;
	}
	acceptReq.socket = (HANDLE)socket;

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_ACCEPT,
	    (PVOID)&acceptReq, sizeof(acceptReq),
	    (PVOID)&acceptReq, sizeof(acceptReq));
	DBGPRINT("IOCTL_SOCKET_ACCEPT: status=%08x\n", status);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		if (addrlen != NULL) {
			*addrlen = acceptReq.addrlen;
		}
	} else {
		ZwClose((HANDLE)socket);
		socket = INVALID_SOCKET;

		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAENOBUFS;
			break;
		case STATUS_SOCKET_ECONNABORTED:
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAECONNRESET;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		default:
			*lpErrno = WSAENETDOWN;
			break;
		}
		DBGPRINT("WSPAccept - leave#3\n");
		goto done;
	}

	RtlZeroMemory(&protocolInfo, sizeof(protocolInfo));
	status = NtDeviceIoControlFile((HANDLE)socket, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_GET_PROTOINFO,
	    NULL, 0,
	    (PVOID)&protocolInfo, sizeof(protocolInfo));
	DBGPRINT("IOCTL_SOCKET_GET_PROTOINFO: status=%08x,Information=%d\n", status, statusBlock.Information);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAENOBUFS;
			break;
		default:
			*lpErrno = WSAENETDOWN;
			break;
		}
		DBGPRINT("WSPAccept - leave#4\n");
		goto done;
	}
	if (Upcalls.lpWPUModifyIFSHandle(protocolInfo.dwCatalogEntryId, socket, lpErrno) == INVALID_SOCKET) {
		ZwClose((HANDLE)socket);
		DBGPRINT("WSPAccept - leave#5\n");
		goto done;
	}

	DBGPRINT("WSPAccept - leave\n");
done:
	return socket;
}

typedef INT (WINAPI *PWSH_ADDRESS_TO_STRING)(LPSOCKADDR,INT,LPWSAPROTOCOL_INFOW,LPWSTR,LPDWORD);
static PWSH_ADDRESS_TO_STRING WSHAddressToString = NULL;
static PWSH_ADDRESS_TO_STRING WSHAddressToStringIPv6 = NULL;

int
WSPAPI
WSPAddressToString(
    LPSOCKADDR lpsaAddress,
    DWORD dwAddressLength,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    LPWSTR lpszAddressString,
    LPDWORD lpdwAddressStringLength,
    LPINT lpErrno)
{
	int ret = 0;

	DBGPRINT("WSPAddressToString - enter\n");

	if (lpsaAddress->sa_family == AF_INET &&
	    WSHAddressToString != NULL) {
		*lpErrno = WSHAddressToString(lpsaAddress, dwAddressLength,
		    NULL, lpszAddressString, lpdwAddressStringLength);
	} else if (
	    lpsaAddress->sa_family == AF_INET6 &&
	    WSHAddressToStringIPv6!= NULL) {
		*lpErrno = WSHAddressToStringIPv6(lpsaAddress, dwAddressLength,
		    NULL, lpszAddressString, lpdwAddressStringLength);
	} else {
		*lpErrno = WSAEINVAL;
	}

	if (*lpErrno != 0) {
		ret = SOCKET_ERROR;
	}

	DBGPRINT("WSPAddressToString - leave\n");
	return ret;
}

int
WSPAPI
WSPAsyncSelect(
    SOCKET s,
    HWND hWnd,
    unsigned int wMsg,
    long lEvent,
    LPINT lpErrno)
{
	DBGPRINT("WSPAsyncSelect - enter\n");
	*lpErrno = WSAENETDOWN;
	DBGPRINT("WSPAsyncSelect - leave\n");
	return SOCKET_ERROR;
}

int
WSPAPI
WSPBind(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;

	DBGPRINT("WSPBind - enter\n");

	if (name == NULL || namelen <= 0) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPBind - leave#1\n");
		goto done;
	}

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_BIND,
	    (PVOID)name, (ULONG)namelen,
	    NULL, 0);
	DBGPRINT("IOCTL_SOCKET_BIND: status=%08x\n", status);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_EAFNOSUPPORT:
			*lpErrno = WSAEPFNOSUPPORT;
			break;
		case STATUS_SOCKET_EINVAL:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_EADDRINUSE:
			*lpErrno = WSAEADDRINUSE;
			break;
		case STATUS_SOCKET_EADDRNOTAVAIL:
			*lpErrno = WSAEADDRNOTAVAIL;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPBind - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPBind - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPCancelBlockingCall(
    LPINT lpErrno)
{
	DBGPRINT("WSPCancelBlockingCall - enter\n");
	*lpErrno = WSAEOPNOTSUPP;
	DBGPRINT("WSPCancelBlockingCall - leave\n");
	return SOCKET_ERROR;
}

int
WSPAPI
WSPCleanup(
    LPINT lpErrno)
{
	DBGPRINT("WSPCleanup - enter\n");

	if (hIPv4Dll != NULL) {
		FreeLibrary(hIPv4Dll);
	}
	if (hIPv6Dll != NULL) {
		FreeLibrary(hIPv6Dll);
	}

	*lpErrno = ERROR_SUCCESS;

	DBGPRINT("WSPCleanup - leave\n");
	return 0;
}

int
WSPAPI
WSPCloseSocket(
    SOCKET s,
    LPINT lpErrno)
{
	NTSTATUS status = 0x00000000L;
	int ret = SOCKET_ERROR;

	DBGPRINT("WSPCloseSocket - enter\n");
	status = ZwClose((HANDLE)s);
	DBGPRINT("ZwClose: status=%08x\n", status);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
		case 0xC000000DL: /* STATUS_INVALID_PARAMETER */
			*lpErrno = WSAENOTSOCK;
			break;
		default:
			*lpErrno = WSAENETDOWN;
			break;
		}
		DBGPRINT("WSPCloseSocket - leave#1\n");
		goto done;
	}
	ret = 0;
	DBGPRINT("WSPCloseSocket - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPConnect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;

	DBGPRINT("WSPConnect - enter\n");
	
	if (name == NULL || namelen <= 0) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPConnect - leave#1\n");
		goto done;
	}
	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_CONNECT,
	    (PVOID)name, (ULONG)namelen,
	    NULL, 0);
	DBGPRINT("IOCTL_SOCKET_CONNECT: status=%08x\n", status);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case 0x00000102L: /* STATUS_TIMEOUT */
			*lpErrno = WSAETIMEDOUT;
			break;
		case STATUS_SOCKET_EAFNOSUPPORT:
			*lpErrno = WSAEAFNOSUPPORT;
			break;
		case STATUS_SOCKET_EADDRNOTAVAIL:
			*lpErrno = WSAEADDRNOTAVAIL;
			break;
		case STATUS_SOCKET_EINVAL:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_EADDRINUSE:
			*lpErrno = WSAEADDRINUSE;
			break;
		case STATUS_SOCKET_EISCONN:
			*lpErrno = WSAEISCONN;
			break;
		case STATUS_SOCKET_EALREADY:
			*lpErrno = WSAEALREADY;
			break;
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAENETUNREACH;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPConnect - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPConnect - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPDuplicateSocket(
    SOCKET s,
    DWORD dwProcessId,
    LPWSAPROTOCOL_INFO lpProtocolInfo,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	WSAPROTOCOL_INFO protocolInfo;

	DBGPRINT("WSPDuplicateSocket - enter\n");

	if (lpProtocolInfo == NULL) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPDuplicateSocket - leave#1\n");
		goto done;
	}

	RtlZeroMemory(&protocolInfo, sizeof(protocolInfo));
	status = NtDeviceIoControlFile((HANDLE)socket, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_GET_PROTOINFO,
	    NULL, 0,
	    (PVOID)lpProtocolInfo, sizeof(WSAPROTOCOL_INFO));
	DBGPRINT("IOCTL_SOCKET_GET_PROTOINFO: status=%08x\n", status);

	if (status != 0x00000000) {
		ret = SOCKET_ERROR;
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPDuplicateSocket - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPDuplicateSocket - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPEnumNetworkEvents(
    SOCKET s,
    WSAEVENT hEventObject,
    LPWSANETWORKEVENTS lpNetworkEvents,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_ENUMNETWORKEVENTS_REQUEST enumEvents = {0};

	DBGPRINT("WSPEnumNetworkEvents - enter\n");

	if (lpNetworkEvents == NULL) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPEnumNetworkEvents - leave#1\n");
		goto done;
	}
	enumEvents.hEventObject = (HANDLE)hEventObject;

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_ENUMNETWORKEVENTS,
	    (PVOID)&enumEvents, sizeof(enumEvents),
	    (PVOID)&enumEvents, sizeof(enumEvents));

	DBGPRINT("IOCTL_SOCKET_ENUMNETWORKEVENTS: status=%08x\n", status);
	if (status == 0x00000000L) {/* STATUS_SUCCESS */
		RtlCopyMemory(lpNetworkEvents, &enumEvents.networkEvents, sizeof(WSANETWORKEVENTS));
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case 0xC000000DL: /* STATUS_INVALID_PARAMETER */
			*lpErrno = WSAEINVAL;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPEnumNetworkEvents - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPEnumNetworkEvents - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPEventSelect(
    SOCKET s,
    WSAEVENT hEventObject,
    long lNetworkEvents,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_EVENTSELECT_REQUEST eventSelect = {0};

	DBGPRINT("WSPEventSelect - enter\n");

	eventSelect.hEventObject = (HANDLE)hEventObject;
	eventSelect.lNetworkEvents = lNetworkEvents;
	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_EVENTSELECT,
	    (PVOID)&eventSelect, sizeof(eventSelect),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_EVENTSELECT: status=%08x\n", status);
	if (status != 0x00000000L) {/* STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case 0xC000000DL: /* STATUS_INVALID_PARAMETER */
			*lpErrno = WSAEINVAL;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPEventSelect - leave#1\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPEventSelect - leave\n");
done:
	return ret;
}

BOOL
WSPAPI
WSPGetOverlappedResult(
    SOCKET s,
    LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer,
    BOOL fWait,
    LPDWORD lpdwFlags,
    LPINT lpErrno)
{
	DBGPRINT("WSPGetOverlappedResult - enter\n");
	if (lpOverlapped == NULL || lpcbTransfer == NULL || lpdwFlags == NULL) {
		WSASetLastError(WSAEINVAL);
		DBGPRINT("WSPGetOverlappedResult - leave#1\n");
		return FALSE;
	}

	if (lpOverlapped->Internal == -1) {
		if (!fWait) {
			if (WaitForSingleObject(lpOverlapped->hEvent, 0) == WAIT_TIMEOUT) {
				WSASetLastError(WSA_IO_INCOMPLETE);
				DBGPRINT("WSPGetOverlappedResult - leave#2\n");
				return FALSE;
			}
		} else {
			WaitForSingleObject(lpOverlapped->hEvent, INFINITE);
		}
	}

	*lpcbTransfer = (DWORD)lpOverlapped->Internal;
	*lpdwFlags = (DWORD)lpOverlapped->InternalHigh;
	WSASetLastError(0);

	DBGPRINT("WSPGetOverlappedResult - leave\n");
	return TRUE;
}

int
WSPAPI
WSPGetPeerName(
    SOCKET s,
    struct sockaddr *name,
    LPINT namelen,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;

	DBGPRINT("WSPGetPeerName - enter\n");

	if (name == NULL || namelen == NULL || *namelen <= 0) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPGetPeerName - leave#1\n");
		goto done;
	}

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_GETPEERNAME,
	    NULL, 0,
	    (PVOID)name, *namelen);

	DBGPRINT("IOCTL_SOCKET_GETPEERNAME: status=%08x\n", status);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		*namelen = (UINT)statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAECONNRESET;
			break;
		case STATUS_SOCKET_ENOENT:
			*lpErrno = WSANO_DATA;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPGetPeerName - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPGetPeerName - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPGetSockName(
    SOCKET s,
    struct sockaddr *name,
    LPINT namelen,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;

	DBGPRINT("WSPGetSockName - enter\n");

	if (name == NULL || namelen == NULL || *namelen <= 0) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPGetSockName - leave#1\n");
		goto done;
	}

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_GETSOCKNAME,
	    NULL, 0,
	    (PVOID)name, *namelen);

	DBGPRINT("IOCTL_SOCKET_GETSOCKNAME: status=%08x\n", status);
	if (status == 0x00000000L) {/* STATUS_SUCCESS */
		*namelen = (UINT)statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAECONNRESET;
			break;
		case STATUS_SOCKET_ENOENT:
			*lpErrno = WSANO_DATA;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPGetSockName - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPGetSockName - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPGetSockOpt(
    SOCKET s,
    int level,
    int optname,
    char *optval,
    LPINT optlen,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_SOCKOPT_REQUEST optReq;

	DBGPRINT("WSPGetSockOpt - enter\n");

	if (optval == NULL || optlen == NULL || *optlen <= 0) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPGetSockOpt - leave#1\n");
		goto done;
	}
		
	if (level == IPPROTO_SCTP && optname == SCTP_PEELOFF) {
		struct sctp_peeloff_opt *peeloff = NULL;
		UNICODE_STRING devname;
		OBJECT_ATTRIBUTES attr;
		SOCKET socket = INVALID_SOCKET;
		SOCKET_PEELOFF_REQUEST peeloffReq;
		WSAPROTOCOL_INFO protocolInfo;

		DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - enter\n");

		if (*optlen < sizeof(struct sctp_peeloff_opt)) {
			*lpErrno = WSAEFAULT;
			DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - leave#1\n");
			goto done;
		}
		peeloff = (struct sctp_peeloff_opt *)optval;

		if ((HANDLE)s != peeloff->s) {
			*lpErrno = WSAEFAULT;
			DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - leave#2\n");
			goto done;
		}

		RtlInitUnicodeString(&devname, DD_SCTP_SOCKET_DEVICE_NAME);
		InitializeObjectAttributes(&attr,
		    &devname,
		    OBJ_CASE_INSENSITIVE,
		    NULL, NULL);
		memset(&statusBlock, 0, sizeof(statusBlock));

		status = ZwCreateFile((HANDLE *)&socket,
		    GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		    &attr,
		    &statusBlock,
		    0L,
		    FILE_ATTRIBUTE_NORMAL,
		    FILE_SHARE_READ | FILE_SHARE_WRITE,
		    FILE_OPEN_IF,
		    0L,
		    NULL,
		    0);
		if (status != 0x00000000L) { /* != STATUS_SUCCESS */
			switch (status) {
			case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
				*lpErrno = WSAENOBUFS;
				break;
			default:
				*lpErrno = WSAENETDOWN;
				break;
			}
			DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - leave #3\n");
			goto done;
		}

		peeloffReq.assoc_id = peeloff->assoc_id;
		peeloffReq.socket = (HANDLE)socket;

		status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
		    IOCTL_SOCKET_PEELOFF,
		    (PVOID)&peeloffReq, sizeof(peeloffReq),
		    (PVOID)&peeloffReq, sizeof(peeloffReq));
		DBGPRINT("IOCTL_SOCKET_SCTP_PEELOFF: status=%08x\n", status);
		if (status != 0x00000000L) { /* !STATUS_SUCCESS */
			ZwClose((HANDLE)socket);
			socket = INVALID_SOCKET;

			switch (status) {
			case 0xC0000008L: /* STATUS_INVALID_HANDLE */
			case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
				*lpErrno = WSAENOTSOCK;
				break;
			case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
				*lpErrno =  WSAENOBUFS;
				break;
			case STATUS_SOCKET_ECONNABORTED:
			case STATUS_SOCKET_ECONNRESET:
				*lpErrno = WSAECONNRESET;
				break;
			case STATUS_SOCKET_EOPNOTSUPP:
				*lpErrno = WSAEOPNOTSUPP;
				break;
			default:
				*lpErrno = WSAENETDOWN;
				break;
			}
			DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - leave#4\n");
			goto done;
		}

		RtlZeroMemory(&protocolInfo, sizeof(protocolInfo));
		status = NtDeviceIoControlFile((HANDLE)socket, NULL, NULL, NULL, &statusBlock,
		    IOCTL_SOCKET_GET_PROTOINFO,
		    NULL, 0,
		    (PVOID)&protocolInfo, sizeof(protocolInfo));
		DBGPRINT("IOCTL_SOCKET_GET_PROTOINFO: status=%08x,Information=%d\n", status, statusBlock.Information);
		if (status != 0x00000000L) { /* !STATUS_SUCCESS */
			ZwClose((HANDLE)socket);
			socket = INVALID_SOCKET;

			switch (status) {
			case 0xC0000008L: /* STATUS_INVALID_HANDLE */
			case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
				*lpErrno = WSAENOTSOCK;
				break;
			case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
				*lpErrno = WSAENOBUFS;
				break;
			default:
				*lpErrno = WSAENETDOWN;
				break;
			}
			DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - leave#5\n");
			goto done;
		}

		if (Upcalls.lpWPUModifyIFSHandle(protocolInfo.dwCatalogEntryId, socket, lpErrno) == INVALID_SOCKET) {
			ZwClose((HANDLE)socket);
			DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - leave#6\n");
			goto done;
		}

		peeloff->new_sd = (HANDLE)socket;
		*optlen = sizeof(struct sctp_peeloff_opt);
		ret = 0;
		DBGPRINT("WSPGetSockOpt:SCTP_PEELOFF - leave\n");
		goto done;
	}

	RtlZeroMemory(&optReq, sizeof(optReq));
	optReq.level = level;
	optReq.optname = optname;
	optReq.optval = optval;
	optReq.optlen = *optlen;

	RtlZeroMemory(&statusBlock, sizeof(statusBlock));
	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_GETSOCKOPT,
	    (PVOID)&optReq, sizeof(optReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_GETSOCKOPT: status=%08x,Information=%d\n", status, statusBlock.Information);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		*optlen = statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		case STATUS_SOCKET_ENOPROTOOPT:
			*lpErrno = WSAENOPROTOOPT;
			break;
		case STATUS_SOCKET_EINVAL:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_ENOENT:
			*lpErrno = WSANO_DATA;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPGetSockOpt - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPGetSockOpt - leave\n");
done:
	return ret;
}

BOOL
WSPAPI
WSPGetQOSByName(
    SOCKET s,
    LPWSABUF lpQOSName,
    LPQOS lpQOS,
    LPINT lpErrno)
{
	DBGPRINT("WSPGetQOSByName - enter\n");
	*lpErrno = WSAENETDOWN;
	DBGPRINT("WSPGetQOSByName - leave\n");
	return FALSE;
}

int
WSPAPI
WSARecvMsg(
    SOCKET s,
    LPWSAMSG lpMsg,
    LPDWORD lpdwNumberOfBytesRecvd,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

int
WSPAPI
_WSASendMsg(
    SOCKET s,
    LPWSAMSG lpMsg,
    DWORD dwFlags,
    LPDWORD lpNumberOfBytesSent,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#if _WIN32_WINNT < 0x0600
typedef
INT
(PASCAL FAR * LPFN_WSASENDMSG) (
    IN SOCKET s,
    IN LPWSAMSG lpMsg,
    IN DWORD dwFlags,
    __out_opt LPDWORD lpNumberOfBytesSent,
    IN LPWSAOVERLAPPED lpOverlapped OPTIONAL,
    IN LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine OPTIONAL);

#define WSAID_WSASENDMSG /* a441e712-754f-43ca-84a7-0dee44cf606d */ \
    {0xa441e712,0x754f,0x43ca,{0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}}
#endif

static GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
static GUID WSASendMsg_GUID = WSAID_WSASENDMSG;

int
WSPAPI
WSPIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;

	DBGPRINT("WSPIoctl - enter\n");

	switch (dwIoControlCode) {
	case SIO_GET_EXTENSION_FUNCTION_POINTER:
		if (lpvInBuffer == NULL || lpvOutBuffer == NULL ||
		    cbInBuffer < sizeof(GUID)) {
			*lpErrno = WSAEFAULT;
			DBGPRINT("WSPIoctl - leave#1\n");
			goto done;
		}
		if (IsEqualGUID((GUID *)lpvInBuffer, &WSARecvMsg_GUID)) {
			if (cbOutBuffer < sizeof(LPFN_WSARECVMSG)) {
				*lpErrno = WSAEFAULT;
				DBGPRINT("WSPIoctl - leave#2\n");
				goto done;
			}

			*(LPFN_WSARECVMSG *)lpvOutBuffer = &WSARecvMsg;
		} else if (
		    IsEqualGUID((GUID *)lpvInBuffer, &WSASendMsg_GUID)) {
			if (cbOutBuffer < sizeof(LPFN_WSASENDMSG)) {
				*lpErrno = WSAEFAULT;
				DBGPRINT("WSPIoctl - leave#2\n");
				goto done;
			}

			*(LPFN_WSASENDMSG *)lpvOutBuffer = &_WSASendMsg;
		} else {
			*lpErrno = WSAEOPNOTSUPP;
			DBGPRINT("WSPIoctl - leave#3\n");
			goto done;
		}

		break;
	default:
		*lpErrno = WSAEINVAL;
		DBGPRINT("WSPIoctl - leave#4\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPIoctl - leave\n");
done:
	return ret;
}

SOCKET
WSPAPI
WSPJoinLeaf(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    DWORD dwFlags,
    LPINT lpErrno)
{
	DBGPRINT("WSPJoinLeaf - enter\n");
	*lpErrno = WSAENETDOWN;
	DBGPRINT("WSPJoinLeaf - leave\n");
	return SOCKET_ERROR;
}

int
WSPAPI
WSPListen(
    SOCKET s,
    int backlog,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;

	DBGPRINT("WSPListen - enter\n");

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_LISTEN,
	    (PVOID)&backlog, sizeof(backlog),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_LISTEN: status=%08x\n", status);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_EAFNOSUPPORT:
			*lpErrno = WSAEPFNOSUPPORT;
			break;
		case STATUS_SOCKET_EADDRINUSE:
			*lpErrno = WSAEADDRINUSE;
			break;
		case STATUS_SOCKET_EADDRNOTAVAIL:
			*lpErrno = WSAEADDRNOTAVAIL;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPListen - leave#1\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPListen - leave\n");
done:
	return ret;
}

VOID
NTAPI
WSPRecvCompletion(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved)
{
	LPWSAOVERLAPPED lpOverlapped = NULL;
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine = NULL;

	DBGPRINT("WSPRecvCompletion - enter\n");

	lpOverlapped = (LPWSAOVERLAPPED)ApcContext;
	lpCompletionRoutine = (LPWSAOVERLAPPED_COMPLETION_ROUTINE)lpOverlapped->Pointer;
	
	if (lpCompletionRoutine != NULL) {
		lpCompletionRoutine(IoStatusBlock->Status, (DWORD)lpOverlapped->Internal,
		    lpOverlapped, (DWORD)lpOverlapped->InternalHigh);
	}
	DBGPRINT("WSPRecvCompletion - leave\n");
}

int
WSPAPI
WSPRecv(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_RECV_REQUEST recvReq;
	HANDLE hEvent = NULL;

	DBGPRINT("WSPRecv - enter\n");

	if (lpBuffers == NULL || lpNumberOfBytesRecvd == NULL || lpFlags == NULL) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPRecv - leave#1\n");
		goto done;
	}

	if (lpOverlapped != NULL) {
		lpOverlapped->Internal = -1;
		lpOverlapped->InternalHigh = -1;
		if (lpCompletionRoutine != NULL) {
			lpOverlapped->Pointer = lpCompletionRoutine;
		} else {
			hEvent = lpOverlapped->hEvent;
		}
	}

	RtlZeroMemory(&recvReq, sizeof(recvReq));
	recvReq.lpBuffers = (PSOCKET_WSABUF)lpBuffers;
	recvReq.dwBufferCount = dwBufferCount;
	recvReq.lpFlags = lpFlags;
	recvReq.lpOverlapped = (PSOCKET_OVERLAPPED)lpOverlapped;
	
	RtlZeroMemory(&statusBlock, sizeof(statusBlock));

	status = NtDeviceIoControlFile((HANDLE)s,
	    hEvent,
	    lpCompletionRoutine != NULL ? WSPRecvCompletion : NULL,
	    hEvent == NULL ? lpOverlapped : NULL,
	    &statusBlock,
	    IOCTL_SOCKET_RECV,
	    (PVOID)&recvReq, sizeof(recvReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_RECV: status=%08x,Information=%d\n", status, statusBlock.Information);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		*lpNumberOfBytesRecvd = (DWORD)statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			*lpErrno = WSAEFAULT;
			break;
		case 0x00000103L: /* STATUS_PENDING */
			*lpErrno = WSA_IO_PENDING;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		case STATUS_SOCKET_EINVAL:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			*lpErrno = WSAEWOULDBLOCK;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			*lpErrno = WSAECONNREFUSED;
			break;
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAENETRESET;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPRecv - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPRecv - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPRecvDisconnect(
    SOCKET s,
    LPWSABUF lpInboundDisconnectData,
    LPINT lpErrno)
{
	DBGPRINT("WSPRecvDisconnect - enter\n");
	*lpErrno = WSAEOPNOTSUPP;
	DBGPRINT("WSPRecvDisconnect - leave\n");
	return SOCKET_ERROR;
}

int
WSPAPI
WSPRecvFrom(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    struct sockaddr* lpFrom,
    LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_RECV_REQUEST recvReq;
	HANDLE hEvent = NULL;

	DBGPRINT("WSPRecvFrom - enter\n");

	if (lpBuffers == NULL || lpNumberOfBytesRecvd == NULL || lpFlags == NULL || lpFrom == NULL || lpFromlen == NULL) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPRecvFrom - leave#1\n");
		goto done;
	}

	if (lpOverlapped != NULL) {
		lpOverlapped->Internal = -1;
		lpOverlapped->InternalHigh = -1;
		if (lpCompletionRoutine != NULL) {
			lpOverlapped->Pointer = lpCompletionRoutine;
		} else {
			hEvent = lpOverlapped->hEvent;
		}
	}

	RtlZeroMemory(&recvReq, sizeof(recvReq));
	recvReq.lpBuffers = (PSOCKET_WSABUF)lpBuffers;
	recvReq.dwBufferCount = dwBufferCount;
	recvReq.lpFrom = lpFrom;
	recvReq.lpFromlen = lpFromlen;
	recvReq.lpFlags = lpFlags;
	recvReq.lpOverlapped = (PSOCKET_OVERLAPPED)lpOverlapped;
	
	RtlZeroMemory(&statusBlock, sizeof(statusBlock));

	status = NtDeviceIoControlFile((HANDLE)s,
	    hEvent,
	    lpCompletionRoutine != NULL ? WSPRecvCompletion : NULL,
	    hEvent == NULL ? lpOverlapped : NULL,
	    &statusBlock,
	    IOCTL_SOCKET_RECVFROM,
	    (PVOID)&recvReq, sizeof(recvReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_RECVFROM: status=%08x,Information=%d\n", status, statusBlock.Information);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		*lpNumberOfBytesRecvd = (DWORD)statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			*lpErrno = WSAEFAULT;
			break;
		case 0x00000103L: /* STATUS_PENDING */
			*lpErrno = WSA_IO_PENDING;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		case STATUS_SOCKET_EINVAL:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			*lpErrno = WSAEWOULDBLOCK;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			*lpErrno = WSAECONNREFUSED;
			break;
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAENETRESET;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPRecvFrom - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPRecvFrom - leave\n");
done:
	return ret;
}

int
WSPAPI
WSARecvMsg(
    SOCKET s,
    LPWSAMSG lpMsg,
    LPDWORD lpdwNumberOfBytesRecvd,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_RECVMSG_REQUEST recvMsgReq;
	HANDLE hEvent = NULL;

	DBGPRINT("WSARecvMsg - enter\n");

	if (lpMsg == NULL || lpdwNumberOfBytesRecvd == NULL) {
		WSASetLastError(WSAEFAULT);
		DBGPRINT("WSARecvMsg - leave#1\n");
		goto done;
	}

	RtlZeroMemory(&recvMsgReq, sizeof(recvMsgReq));
	recvMsgReq.lpMsg = (PSOCKET_WSAMSG)lpMsg;
	recvMsgReq.lpOverlapped = (PSOCKET_OVERLAPPED)lpOverlapped;
	
	if (lpOverlapped != NULL) {
		lpOverlapped->Internal = -1;
		lpOverlapped->InternalHigh = -1;
		if (lpCompletionRoutine != NULL) {
			lpOverlapped->Pointer = lpCompletionRoutine;
		} else {
			hEvent = lpOverlapped->hEvent;
		}
	}

	RtlZeroMemory(&statusBlock, sizeof(statusBlock));

	status = NtDeviceIoControlFile((HANDLE)s,
	    hEvent,
	    lpCompletionRoutine != NULL ? WSPRecvCompletion : NULL,
	    hEvent == NULL ? lpOverlapped : NULL,
	    &statusBlock,
	    IOCTL_SOCKET_RECVMSG,
	    (PVOID)&recvMsgReq, sizeof(recvMsgReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_RECVMSG: status=%08x,Information=%d\n", status, statusBlock.Information);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		*lpdwNumberOfBytesRecvd = (DWORD)statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			WSASetLastError(WSAENOTSOCK);
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			WSASetLastError(WSAEMFILE);
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			WSASetLastError(WSAEFAULT);
			break;
		case 0x00000103L: /* STATUS_PENDING */
			WSASetLastError(WSA_IO_PENDING);
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			WSASetLastError(WSAEOPNOTSUPP);
			break;
		case STATUS_SOCKET_EINVAL:
			WSASetLastError(WSAEINVAL);
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			WSASetLastError(WSAEWOULDBLOCK);
			break;
		case STATUS_SOCKET_ENOTCONN:
			WSASetLastError(WSAENOTCONN);
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			WSASetLastError(WSAECONNREFUSED);
			break;
		case STATUS_SOCKET_ECONNRESET:
			WSASetLastError(WSAENETRESET);
			break;
		default:
			WSASetLastError(WSAENETDOWN);
		}
		DBGPRINT("WSARecvMsg - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSARecvMsg - leave\n");
done:
	return ret;
}

ssize_t
sctp_generic_recvmsg(
    SOCKET s,
    char *data,
    size_t len,
    struct sockaddr *from,
    socklen_t *fromlen,
    struct sctp_sndrcvinfo *sinfo,
    int *msg_flags)
{
	ssize_t ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_SCTPRECV_REQUEST sctpRecvReq;

	DBGPRINT("sctp_generic_recvmsg - enter\n");

	RtlZeroMemory(&sctpRecvReq, sizeof(sctpRecvReq));
	if (data == NULL || len <= 0 ||
	    (from != NULL && (fromlen == NULL || *fromlen == 0))
	    ) {
		WSASetLastError(WSAEFAULT);
		DBGPRINT("sctp_generic_recvmsg - leave#1\n");
		goto done;
	}
	sctpRecvReq.data = data;
	sctpRecvReq.len = len;
	sctpRecvReq.from = from;
	sctpRecvReq.fromlen = fromlen;
	sctpRecvReq.sinfo = sinfo;
	sctpRecvReq.msg_flags = msg_flags;

	RtlZeroMemory(&statusBlock, sizeof(statusBlock));

	status = NtDeviceIoControlFile((HANDLE)s, NULL,
	    NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_SCTPRECV,
	    (PVOID)&sctpRecvReq, sizeof(sctpRecvReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_SCTPRECV: status=%08x,Information=%d\n", status, statusBlock.Information);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		ret = (ssize_t)statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			WSASetLastError(WSAENOTSOCK);
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			WSASetLastError(WSAEMFILE);
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			WSASetLastError(WSAEFAULT);
			break;
		case 0x00000103L: /* STATUS_PENDING */
			WSASetLastError(WSA_IO_PENDING);
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			WSASetLastError(WSAEOPNOTSUPP);
			break;
		case STATUS_SOCKET_EINVAL:
			WSASetLastError(WSAEINVAL);
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			WSASetLastError(WSAEWOULDBLOCK);
			break;
		case STATUS_SOCKET_ENOTCONN:
			WSASetLastError(WSAENOTCONN);
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			WSASetLastError(WSAECONNREFUSED);
			break;
		case STATUS_SOCKET_ECONNRESET:
			WSASetLastError(WSAENETRESET);
			break;
		default:
			WSASetLastError(WSAENETDOWN);
		}
		DBGPRINT("sctp_generic_recvmsg - leave#2\n");
		goto done;
	}

	DBGPRINT("sctp_generic_recvmsg - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPSelect(
    int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    const struct timeval* timeout,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET s = INVALID_SOCKET;
	unsigned int i;
	SOCKET_SELECT_REQUEST selectReq;

	DBGPRINT("WSPSelect - enter\n");

#define getsocket(fds) do { \
	if (fds != NULL && s == INVALID_SOCKET) { \
		for (i = 0; i < fds->fd_count && i < FD_SETSIZE; i++) { \
			if (fds->fd_array[i] != INVALID_SOCKET) { \
				s = fds->fd_array[i]; \
				break; \
			} \
		} \
	} \
} while (0)
	getsocket(readfds);
	getsocket(writefds);
	getsocket(exceptfds);
#undef getsocket

	RtlZeroMemory(&selectReq, sizeof(selectReq));
	selectReq.fd_setsize = FD_SETSIZE;
	selectReq.readfds = (PSOCKET_FD_SET)readfds;
	selectReq.writefds = (PSOCKET_FD_SET)writefds;
	selectReq.exceptfds = (PSOCKET_FD_SET)exceptfds;
	if (timeout != NULL) {
		*((struct timeval *)&selectReq.timeout) = *timeout;
	} else {
		selectReq.infinite = TRUE;
	}
	
	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_SELECT,
	    (PVOID)&selectReq, sizeof(selectReq),
	    (PVOID)&selectReq, sizeof(selectReq));

	DBGPRINT("IOCTL_SOCKET_SELECT: status=%08x,selectReq.nfds=%d\n", status, selectReq.nfds);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		ret = selectReq.nfds;
	} else if (
	    status == 0x00000102L) { /* STATUS_TIMEOUT*/
		ret = 0;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT:
			*lpErrno = WSAEFAULT;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPSelect - leave#1\n");
		goto done;
	}

	DBGPRINT("WSPSelect - leave\n");
done:
	return ret;
}

VOID
NTAPI
WSPSendCompletion(
    IN PVOID apcContext,
    IN PIO_STATUS_BLOCK statusBlock,
    IN ULONG reserved)
{
	LPWSAOVERLAPPED lpOverlapped = NULL;
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine = NULL;

	DBGPRINT("WSPSendCompletion- enter\n");

	lpOverlapped = (LPWSAOVERLAPPED)apcContext;
	lpCompletionRoutine = (LPWSAOVERLAPPED_COMPLETION_ROUTINE)lpOverlapped->Pointer;

	if (lpCompletionRoutine != NULL) {
		lpCompletionRoutine(statusBlock->Status, (DWORD)lpOverlapped->Internal,
		    lpOverlapped, (DWORD)lpOverlapped->InternalHigh);
	}
	DBGPRINT("WSPSendCompletion - leave\n");
}

int
WSPAPI
WSPSend(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	HANDLE hEvent = NULL;
	SOCKET_SEND_REQUEST sendReq;

	DBGPRINT("WSPSend - enter\n");

	if (lpNumberOfBytesSent == NULL && lpOverlapped == NULL) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPSend - leave#1\n");
		goto done;
	}

	if (lpOverlapped != NULL) {
		lpOverlapped->Internal = -1;
		lpOverlapped->InternalHigh = -1;
		if (lpCompletionRoutine != NULL) {
			lpOverlapped->Pointer = lpCompletionRoutine;
		} else {
			hEvent = lpOverlapped->hEvent;
		}
	}

	RtlZeroMemory(&sendReq, sizeof(sendReq));
	sendReq.lpBuffers = (PSOCKET_WSABUF)lpBuffers;
	sendReq.dwBufferCount = dwBufferCount;
	sendReq.dwFlags = dwFlags;
	sendReq.lpOverlapped = (PSOCKET_OVERLAPPED)lpOverlapped;
	
	status = NtDeviceIoControlFile((HANDLE)s,
	    hEvent,
	    lpCompletionRoutine != NULL ? WSPSendCompletion : NULL,
	    hEvent == NULL ? lpOverlapped : NULL,
	    &statusBlock,
	    IOCTL_SOCKET_SEND,
	    (PVOID)&sendReq, sizeof(sendReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_SEND: status=%08x\n", status);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		if (lpNumberOfBytesSent != NULL) {
			*lpNumberOfBytesSent = (DWORD)statusBlock.Information;
		}
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
		case STATUS_SOCKET_ENOMEM:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			*lpErrno = WSAEFAULT;
			break;
		case 0x00000103L: /* STATUS_PENDING */
			*lpErrno = WSA_IO_PENDING;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		case STATUS_SOCKET_EINVAL:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_ENOENT:
			*lpErrno = WSANO_DATA;
			break;
		case STATUS_SOCKET_EMSGSIZE:
			*lpErrno = WSAEMSGSIZE;
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			*lpErrno = WSAEWOULDBLOCK;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			*lpErrno = WSAECONNREFUSED;
			break;
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAENETRESET;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPSend - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPSend - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPSendDisconnect(
    SOCKET s,
    LPWSABUF lpOutboundDisconnectData,
    LPINT lpErrno)
{
	DBGPRINT("WSPSendDisconnect - enter\n");
	*lpErrno = WSAEOPNOTSUPP;
	DBGPRINT("WSPSendDisconnect - leave\n");
	return SOCKET_ERROR;
}

int
WSPAPI
WSPSendTo(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr* lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_SEND_REQUEST sendReq;
	HANDLE hEvent = NULL;

	DBGPRINT("WSPSendTo - enter\n");

	if (lpNumberOfBytesSent == NULL && lpOverlapped == NULL) {
		ret = SOCKET_ERROR;
		*lpErrno = WSAEFAULT;
		goto done;
		DBGPRINT("WSPSendTo - leave#1\n");
	}

	if (lpOverlapped != NULL) {
		lpOverlapped->Internal = -1;
		lpOverlapped->InternalHigh = -1;
		if (lpCompletionRoutine != NULL) {
			lpOverlapped->Pointer = lpCompletionRoutine;
		} else {
			hEvent = lpOverlapped->hEvent;
		}
	}

	RtlZeroMemory(&sendReq, sizeof(sendReq));
	sendReq.lpBuffers = (PSOCKET_WSABUF)lpBuffers;
	sendReq.dwBufferCount = dwBufferCount;
	sendReq.dwFlags = dwFlags;
	sendReq.lpTo = (struct sockaddr *)lpTo;
	sendReq.iTolen = iTolen;
	
	status = NtDeviceIoControlFile((HANDLE)s,
	    hEvent,
	    lpCompletionRoutine != NULL ? WSPSendCompletion : NULL,
	    hEvent == NULL ? lpOverlapped : NULL,
	    &statusBlock,
	    IOCTL_SOCKET_SENDTO,
	    (PVOID)&sendReq, sizeof(sendReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_SEND: status=%08x\n", status);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		if (lpNumberOfBytesSent != NULL) {
			*lpNumberOfBytesSent = (DWORD)statusBlock.Information;
		}
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
		case STATUS_SOCKET_ENOMEM:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			*lpErrno = WSAEFAULT;
			break;
		case 0x00000103L: /* STATUS_PENDING */
			*lpErrno = WSA_IO_PENDING;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		case STATUS_SOCKET_EINVAL:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_ENOENT:
			*lpErrno = WSANO_DATA;
			break;
		case STATUS_SOCKET_EMSGSIZE:
			*lpErrno = WSAEMSGSIZE;
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			*lpErrno = WSAEWOULDBLOCK;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			*lpErrno = WSAECONNREFUSED;
			break;
		case STATUS_SOCKET_ECONNRESET:
			*lpErrno = WSAENETRESET;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPSendTo - leave#1\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPSendTo - leave\n");
done:
	return ret;
}

int
WSPAPI
_WSASendMsg(
    SOCKET s,
    LPWSAMSG lpMsg,
    DWORD dwFlags,
    LPDWORD lpNumberOfBytesSent,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_SENDMSG_REQUEST sendMsgReq;
	HANDLE hEvent = NULL;

	DBGPRINT("WSASendMsg - enter\n");

	if (lpMsg == NULL || (lpNumberOfBytesSent == NULL && lpOverlapped == NULL)) {
		ret = SOCKET_ERROR;
		WSASetLastError(WSAEFAULT);
		DBGPRINT("WSASendMsg - leave#1\n");
		goto done;
        }

	if (lpOverlapped != NULL) {
		lpOverlapped->Internal = -1;
		lpOverlapped->InternalHigh = -1;
		if (lpCompletionRoutine != NULL) {
			lpOverlapped->Pointer = lpCompletionRoutine;
		} else {
			hEvent = lpOverlapped->hEvent;
		}
	}

	RtlZeroMemory(&sendMsgReq, sizeof(sendMsgReq));
	sendMsgReq.lpMsg = (PSOCKET_WSAMSG)lpMsg;
	sendMsgReq.dwFlags = dwFlags;
	sendMsgReq.lpOverlapped = (PSOCKET_OVERLAPPED)lpOverlapped;
	
	status = NtDeviceIoControlFile((HANDLE)s,
	    hEvent,
	    lpCompletionRoutine != NULL ? WSPSendCompletion : NULL,
	    hEvent == NULL ? lpOverlapped : NULL,
	    &statusBlock,
	    IOCTL_SOCKET_SENDMSG,
	    (PVOID)&sendMsgReq, sizeof(sendMsgReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_SENDMSG: status=%08x\n", status);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		if (lpNumberOfBytesSent != NULL) {
			*lpNumberOfBytesSent = (DWORD)statusBlock.Information;
		}
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			WSASetLastError(WSAENOTSOCK);
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
		case STATUS_SOCKET_ENOMEM:
			WSASetLastError(WSAEMFILE);
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			WSASetLastError(WSAEFAULT);
			break;
		case 0x00000103L: /* STATUS_PENDING */
			WSASetLastError(WSA_IO_PENDING);
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			WSASetLastError(WSAEOPNOTSUPP);
			break;
		case STATUS_SOCKET_EINVAL:
			WSASetLastError(WSAEINVAL);
			break;
		case STATUS_SOCKET_ENOENT:
			WSASetLastError(WSANO_DATA);
			break;
		case STATUS_SOCKET_EMSGSIZE:
			WSASetLastError(WSAEMSGSIZE);
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			WSASetLastError(WSAEWOULDBLOCK);
			break;
		case STATUS_SOCKET_ENOTCONN:
			WSASetLastError(WSAENOTCONN);
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			WSASetLastError(WSAECONNREFUSED);
			break;
		case STATUS_SOCKET_ECONNRESET:
			WSASetLastError(WSAENETRESET);
			break;
		default:
			WSASetLastError(WSAENETDOWN);
		}
		DBGPRINT("WSPSendMsg - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPSendMsg - leave\n");
done:
	return ret;
}

int
sctp_generic_sendmsg(
    SOCKET s,
    const void *data,
    size_t len,
    const struct sockaddr *to,
    int tolen,
    const struct sctp_sndrcvinfo *sinfo,
    int flags)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_SCTPSEND_REQUEST sctpSendReq;

	DBGPRINT("sctp_generic_sendmsg - enter\n");

	RtlZeroMemory(&sctpSendReq, sizeof(sctpSendReq));
	if (data == NULL || len <= 0 ||
	    (to == NULL && tolen > 0)) {
		ret = SOCKET_ERROR;
		WSASetLastError(WSAEFAULT);
		DBGPRINT("sctp_generic_sendmsg - leave#1\n");
		goto done;
        }

	sctpSendReq.data = (void *)data;
	sctpSendReq.len = len;
	sctpSendReq.to = (struct sockaddr *)to;
	sctpSendReq.tolen = tolen;
	sctpSendReq.sinfo = (struct sctp_sndrcvinfo *)sinfo;
	sctpSendReq.flags = flags;
	
	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_SCTPSEND,
	    (PVOID)&sctpSendReq, sizeof(sctpSendReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_SCTPSEND: status=%08x,Information=%d\n", status, statusBlock.Information);
	if (status == 0x00000000L) { /* STATUS_SUCCESS */
		ret = (ssize_t)statusBlock.Information;
	} else {
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			WSASetLastError(WSAENOTSOCK);
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOBUFS:
		case STATUS_SOCKET_ENOMEM:
			WSASetLastError(WSAEMFILE);
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
		case STATUS_SOCKET_EFAULT: /* XXX */
			WSASetLastError(WSAEFAULT);
			break;
		case 0x00000103L: /* STATUS_PENDING */
			WSASetLastError(WSA_IO_PENDING);
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			WSASetLastError(WSAEOPNOTSUPP);
			break;
		case STATUS_SOCKET_EINVAL:
			WSASetLastError(WSAEINVAL);
			break;
		case STATUS_SOCKET_EMSGSIZE:
			WSASetLastError(WSAEMSGSIZE);
			break;
		case STATUS_SOCKET_EWOULDBLOCK:
			WSASetLastError(WSAEWOULDBLOCK);
			break;
		case STATUS_SOCKET_ENOENT:
		case STATUS_SOCKET_ENOTCONN:
			WSASetLastError(WSAENOTCONN);
			break;
		case STATUS_SOCKET_ECONNREFUSED:
			WSASetLastError(WSAECONNREFUSED);
			break;
		case STATUS_SOCKET_ECONNRESET:
			WSASetLastError(WSAENETRESET);
			break;
		default:
			WSASetLastError(WSAENETDOWN);
		}
		DBGPRINT("sctp_generic_sendmsg - leave#2\n");
		goto done;
	}

	DBGPRINT("sctp_generic_sendmsg - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPSetSockOpt(
  SOCKET s,
  int level,
  int optname,
  const char* optval,
  int optlen,
  LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	SOCKET_SOCKOPT_REQUEST optReq;

	DBGPRINT("WSPSetSockOpt - enter\n");

	if ((optval == NULL && optlen != 0) ||
	    optlen < 0) {
		*lpErrno = WSAEFAULT;
		DBGPRINT("WSPSetSockOpt - leave#1\n");
	}

	RtlZeroMemory(&optReq, sizeof(optReq));
	optReq.level = level;
	optReq.optname = optname;
	optReq.optval = (char *)optval;
	optReq.optlen = optlen;

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_SETSOCKOPT,
	    (PVOID)&optReq, sizeof(optReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_SETSOCKOPT: status=%08x\n", status);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOMEM:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		case STATUS_SOCKET_ENOPROTOOPT:
			*lpErrno = WSAENOPROTOOPT;
			break;
		case STATUS_SOCKET_EINVAL:
		case STATUS_SOCKET_EDOM:
			*lpErrno = WSAEINVAL;
			break;
		case STATUS_SOCKET_ENOTCONN:
			*lpErrno = WSAENOTCONN;
			break;
		case STATUS_SOCKET_EALREADY:
			*lpErrno = WSAEALREADY;
			break;
		case STATUS_SOCKET_ENOENT:
			*lpErrno = WSANO_DATA;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPSetSockOpt - leave#2\n");
		goto done;
	}
	ret = 0;

	DBGPRINT("WSPSetSockOpt - leave\n");
done:
	return ret;
}

int
WSPAPI
WSPShutdown(
    SOCKET s,
    int how,
    LPINT lpErrno)
{
	int ret = SOCKET_ERROR;
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;

	DBGPRINT("WSPShutdown - enter\n");

	if (how != SD_RECEIVE && how != SD_SEND && how != SD_BOTH) {
		*lpErrno = WSAEINVAL;
		DBGPRINT("WSPShutdown - leave#1\n");
		goto done;
	}

	status = NtDeviceIoControlFile((HANDLE)s, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_SHUTDOWN,
	    &how, sizeof(how),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_SHUTDOWN: status=%08x\n", status);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
		case STATUS_SOCKET_ENOMEM:
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPShutdown - leave#2\n");
		goto done;
	}

	DBGPRINT("WSPShutdown - leave\n");
done:
	return ret;
}

SOCKET
WSPAPI
WSPSocket(
    int af,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFO lpProtocolInfo,
    GROUP g,
    DWORD dwFlags,
    LPINT lpErrno)
{
	SOCKET socket = INVALID_SOCKET;
	SOCKET_OPEN_REQUEST openReq;
	UNICODE_STRING devname;
	OBJECT_ATTRIBUTES attr;
	char eaBuf[sizeof(FILE_FULL_EA_INFORMATION) + sizeof(ProtocolInfo) + sizeof(WSAPROTOCOL_INFO)];
	PFILE_FULL_EA_INFORMATION eaInfo = NULL;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS status = 0x00000000L; /* STATUS_SUCCESS */

	DBGPRINT("WSPSocket - enter\n");

	RtlInitUnicodeString(&devname, DD_SCTP_SOCKET_DEVICE_NAME);

	RtlZeroMemory(eaBuf, sizeof(eaBuf));
	eaInfo = (PFILE_FULL_EA_INFORMATION)eaBuf;

	eaInfo->EaNameLength = sizeof(ProtocolInfo) - 1;
	RtlCopyMemory(eaInfo->EaName, ProtocolInfo, sizeof(ProtocolInfo));

	eaInfo->EaValueLength = sizeof(WSAPROTOCOL_INFO);
	RtlCopyMemory(eaInfo->EaName + sizeof(ProtocolInfo), lpProtocolInfo, sizeof(WSAPROTOCOL_INFO));

	InitializeObjectAttributes(&attr,
	    &devname,
	    OBJ_CASE_INSENSITIVE,
	    NULL, NULL);

	status = ZwCreateFile((HANDLE *)&socket,
	    GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
	    &attr,
	    &statusBlock,
	    0L,
	    FILE_ATTRIBUTE_NORMAL,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    FILE_OPEN_IF,
	    0L,
	    eaBuf,
	    sizeof(eaBuf));
	if (status != 0x00000000L) {
		socket = INVALID_SOCKET;
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPSocket - leave#1\n");
		goto done;
	}

	RtlZeroMemory(&openReq, sizeof(openReq));
	openReq.af = af;
	openReq.type = type;
	openReq.protocol = protocol;

	status = NtDeviceIoControlFile((HANDLE)socket, NULL, NULL, NULL, &statusBlock,
	    IOCTL_SOCKET_OPEN,
	    (PVOID)&openReq, sizeof(openReq),
	    NULL, 0);

	DBGPRINT("IOCTL_SOCKET_OPEN: status=%08x\n", status);
	if (status != 0x00000000L) { /* !STATUS_SUCCESS */
		socket = INVALID_SOCKET;
		switch (status) {
		case 0xC0000008L: /* STATUS_INVALID_HANDLE */
		case 0xC0000010L: /* STATUS_INVALID_DEVICE_REQUEST */
			*lpErrno = WSAENOTSOCK;
			break;
		case 0xC000009AL: /* STATUS_INSUFFICIENT_RESOURCES */
			*lpErrno = WSAEMFILE;
			break;
		case 0xC0000005L: /* STATUS_ACCESS_VIOLATION */
			*lpErrno = WSAEFAULT;
			break;
		case STATUS_SOCKET_EOPNOTSUPP:
			*lpErrno = WSAEOPNOTSUPP;
			break;
		default:
			*lpErrno = WSAENETDOWN;
		}
		DBGPRINT("WSPSocket - leave #2\n");
		goto done;
	}

	if (Upcalls.lpWPUModifyIFSHandle(lpProtocolInfo->dwCatalogEntryId, socket, lpErrno) == INVALID_SOCKET) {
		ZwClose((HANDLE)socket);
		socket = INVALID_SOCKET;
		DBGPRINT("WSPSocket - leave #3\n");
		goto done;
	}

	DBGPRINT("WSPSocket - leave\n");
done:
	return socket;
}

typedef INT (WINAPI *PWSH_STRING_TO_ADDRESS)(LPWSTR,DWORD,LPWSAPROTOCOL_INFOW,LPSOCKADDR,LPDWORD);
static PWSH_STRING_TO_ADDRESS WSHStringToAddress = NULL;
static PWSH_STRING_TO_ADDRESS WSHStringToAddressIPv6 = NULL;

int
WSPAPI
WSPStringToAddress(
    LPWSTR AddressString,
    INT AddressFamily,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    LPSOCKADDR lpAddress,
    LPINT lpAddressLength,
    LPINT lpErrno)
{
	int ret = 0;
	DBGPRINT("WSPStringToAddress - enter\n");
	switch (AddressFamily) {
	case AF_INET:
		*lpErrno = WSHStringToAddress(AddressString, AddressFamily,
		    NULL, lpAddress, lpAddressLength);
		break;
	case AF_INET6:
		*lpErrno = WSHStringToAddressIPv6(AddressString, AddressFamily,
		    NULL, lpAddress, lpAddressLength);
		break;
	default:
		*lpErrno = WSAEINVAL;
	}
	if (*lpErrno != 0) {
		ret = SOCKET_ERROR;
	}

	DBGPRINT("WSPStringToAddress - leave\n");
	return ret;
}

int
WSPAPI
WSPStartup(
    WORD wVersionRequested,
    LPWSPDATA lpWSPData,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    WSPUPCALLTABLE UpcallTable,
    LPWSPPROC_TABLE lpProcTable)
{
	int ret = 0;
	DBGPRINT("WSPStartup - enter\n");

	Upcalls = UpcallTable;
	
	lpProcTable->lpWSPAccept = WSPAccept;
	lpProcTable->lpWSPAddressToString = WSPAddressToString;
	lpProcTable->lpWSPAsyncSelect = WSPAsyncSelect;
	lpProcTable->lpWSPBind = WSPBind;
	lpProcTable->lpWSPCancelBlockingCall = WSPCancelBlockingCall;
	lpProcTable->lpWSPCleanup = WSPCleanup;
	lpProcTable->lpWSPCloseSocket = WSPCloseSocket;
	lpProcTable->lpWSPConnect = WSPConnect;
	lpProcTable->lpWSPDuplicateSocket = WSPDuplicateSocket;
	lpProcTable->lpWSPEnumNetworkEvents = WSPEnumNetworkEvents;
	lpProcTable->lpWSPEventSelect = WSPEventSelect;
	lpProcTable->lpWSPGetOverlappedResult = WSPGetOverlappedResult;
	lpProcTable->lpWSPGetPeerName = WSPGetPeerName;
	lpProcTable->lpWSPGetSockName = WSPGetSockName;
	lpProcTable->lpWSPGetSockOpt = WSPGetSockOpt;
	lpProcTable->lpWSPGetQOSByName = WSPGetQOSByName;
	lpProcTable->lpWSPIoctl = WSPIoctl;
	lpProcTable->lpWSPJoinLeaf = WSPJoinLeaf;
	lpProcTable->lpWSPListen = WSPListen;
	lpProcTable->lpWSPRecv = WSPRecv;
	lpProcTable->lpWSPRecvDisconnect = WSPRecvDisconnect;
	lpProcTable->lpWSPRecvFrom = WSPRecvFrom;
	lpProcTable->lpWSPSelect = WSPSelect;
	lpProcTable->lpWSPSend = WSPSend;
	lpProcTable->lpWSPSendDisconnect = WSPSendDisconnect;
	lpProcTable->lpWSPSendTo = WSPSendTo;
	lpProcTable->lpWSPSetSockOpt = WSPSetSockOpt;
	lpProcTable->lpWSPShutdown = WSPShutdown;
	lpProcTable->lpWSPSocket = WSPSocket;
	lpProcTable->lpWSPStringToAddress = WSPStringToAddress;

	lpWSPData->wVersion = MAKEWORD(2, 2);
	lpWSPData->wHighVersion = MAKEWORD(2, 2);

	hIPv4Dll = LoadLibrary(TEXT("wship"));
	if (hIPv4Dll != NULL) {
		WSHAddressToString = (PWSH_ADDRESS_TO_STRING)GetProcAddress(hIPv4Dll, "WSHAddressToString");
		WSHStringToAddress = (PWSH_STRING_TO_ADDRESS)GetProcAddress(hIPv4Dll, "WSHStringToAddress");
	}

	hIPv6Dll = LoadLibrary(TEXT("wship6"));
	if (hIPv6Dll != NULL) {
		WSHAddressToStringIPv6 = (PWSH_ADDRESS_TO_STRING)GetProcAddress(hIPv6Dll, "WSHAddressToString");
		WSHStringToAddressIPv6 = (PWSH_STRING_TO_ADDRESS)GetProcAddress(hIPv6Dll, "WSHStringToAddress");
	}

	DBGPRINT("WSPStartup - leave\n");
	return ret;
}

BOOLEAN
WINAPI
DllMain(
    IN PVOID DllHandle,
    IN ULONG Reason,
    IN PVOID Context OPTIONAL)
{
	DBGPRINT("DllMain - enter\n");

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

	DBGPRINT("DllMain - leave\n");
	return TRUE;
}
