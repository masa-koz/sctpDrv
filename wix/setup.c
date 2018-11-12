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
#include <stdlib.h>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <tchar.h>

#include <sctpsp.h>

typedef unsigned long MSIHANDLE;

#define	SCTP_OS_VERSION_XP32_SP2	_T("Windows XP 32bit Service Pack 2")
#define	SCTP_OS_VERSION_XP32_SP3	_T("Windows XP 32bit Service Pack 3")
#define	SCTP_OS_VERSION_VISTA32		_T("Windows Vista 32bit")

BOOLEAN
SctpGetOSVersion(
    OUT PTCHAR szVersion,
    IN ULONG ulMax)
{
	BOOLEAN ret = FALSE;
	OSVERSIONINFOEX osvi;
	SYSTEM_INFO si;

	memset(&osvi, 0, sizeof(osvi));
	memset(&si, 0, sizeof(si));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (!GetVersionEx((OSVERSIONINFO *)&osvi)) {
		return FALSE;
	}
   	GetSystemInfo(&si);

	if (osvi.dwPlatformId != VER_PLATFORM_WIN32_NT) {
		/* Not supported OS */
		return FALSE;
	}
	if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 &&
	    si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL) {
		/* not supported CPU */
		return FALSE;
	}

	switch (osvi.dwMajorVersion) {
	case 5:
		/* Windows 2k, XP or Server 2003 */
		if (osvi.dwMinorVersion == 2) {
			/* Server 2003 */
			_sntprintf(szVersion, ulMax, _T("Windows Server 2003 %s %s"), 
			    si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ?
				_T("64bit") : _T("32bit"),
			    osvi.szCSDVersion);
			ret = TRUE;
		} else if (
		    osvi.dwMinorVersion == 1) {
			/* XP */
			_sntprintf(szVersion, ulMax, _T("Windows XP %s %s"), 
			    si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ?
				_T("64bit") : _T("32bit"),
			    osvi.szCSDVersion);
			ret = TRUE;
		} else if (
		    osvi.dwMinorVersion == 0) {
			/* 2k, not supported */
		} else {
			/* Unknown, not supported */
		}
		break;
	case 6:
		/* Vista or Server 2008 */
		if (osvi.dwMinorVersion == 0 &&
		    osvi.wProductType == VER_NT_WORKSTATION) {
			/* Vista */
			_sntprintf(szVersion, ulMax, _T("Windows Vista %s %s"), 
			    si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ?
				_T("64bit") : _T("32bit"),
			    osvi.szCSDVersion);
			ret = TRUE;
		} else if (
		    osvi.dwMinorVersion == 0 &&
		    osvi.wProductType == VER_NT_WORKSTATION) {
			/* Server 2008 */
			_sntprintf(szVersion, ulMax, _T("Windows Server 2008 %s %s"), 
			    si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ?
				_T("64bit") : _T("32bit"),
			    osvi.szCSDVersion);
			ret = TRUE;
		} else {
			/* Unknown, not supported */
		}
		break;
	default:
		break;
	}

	return ret;
}

UINT
__stdcall
SctpInstallDriver(
    IN MSIHANDLE hInstall)
{
	UINT ret = ERROR_SUCCESS;
	TCHAR szVersion[MAX_PATH];
	TCHAR szError[128];
	SC_HANDLE shManager = NULL;
	SC_HANDLE shService = NULL;
	DWORD dwStartType = SERVICE_SYSTEM_START;
	TCHAR *lpLoadOrderGroup = _T("PNP_TDI");
	TCHAR *lpDependencies = NULL;
	TCHAR *lpServiceArgVectors = NULL;

	memset(szError, 0, sizeof(szError));

	if (!SctpGetOSVersion(szVersion, _countof(szVersion))) {
		MessageBox(NULL, _T("Failed to determine version of OS.\n"),
		    _T("Sctp Driver Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		goto done;
	}

	shManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (shManager == NULL) {
		goto done;
	}

	if (_tcscmp(szVersion, SCTP_OS_VERSION_XP32_SP2) == 0 ||
	    _tcscmp(szVersion, SCTP_OS_VERSION_XP32_SP3) == 0) {
		/* Windows XP SP2 later: check whether the target has IPv6 stack installed */
		shService = OpenService(shManager, _T("TCPIP6"), SERVICE_ALL_ACCESS);
		if (shService != NULL) {
			lpDependencies = _T("TCPIP\0TCPIP6\0IpFilterDriver\0");
			CloseServiceHandle(shService);
		} else {
			lpDependencies = _T("TCPIP\0IpFilterDriver\0");
		}

		/* Change StartType of IpFilterDriver to "SYSTEM_START" */
		shService = OpenService(shManager, _T("IpFilterDriver"), SERVICE_ALL_ACCESS);
		if (shService == NULL) {
			_sntprintf(szError, _countof(szError),
			    _T("Failed to change configuration of IpFilterDriver, OpenService=%u\n"), GetLastError());
			MessageBox(NULL, szError,
			    _T("Sctp Driver Install Error"),
			    MB_OK | MB_ICONINFORMATION);
			goto done;
		}
		if (!ChangeServiceConfig(shService,
			SERVICE_NO_CHANGE,	/* TYPE */
			SERVICE_SYSTEM_START,	/* START_TYPE */
			SERVICE_NO_CHANGE,	/* ERROR_CONTROL */
			NULL,			/* BINARY_PATH_NAME */
			_T("PNP_TDI"),	/* LOAD_ORDER_GROUP */
			NULL,			/* TAG */
			NULL,			/* DEPENDENCIES */
			NULL,			/* SERVICE_START_NAME */
			NULL,			/* lpPassword */
			NULL			/* DISPLAY_NAME */
		    )) {
			_sntprintf(szError, _countof(szError),
			    _T("Failed to change configuration of IpFilterDriver, ChangeService=%u\n"), GetLastError());
			MessageBox(NULL, szError,
			    _T("Sctp Driver Install Error"),
			    MB_OK | MB_ICONINFORMATION);
			goto done;
		}
		CloseServiceHandle(shService);
	} else if (
	    _tcsncmp(szVersion, SCTP_OS_VERSION_VISTA32, _countof(SCTP_OS_VERSION_VISTA32) - 1) == 0) {
		dwStartType = SERVICE_AUTO_START;
		lpLoadOrderGroup = _T("NetworkProvider");
		lpDependencies = _T("TCPIP\0BFE\0");
	}

	shService = CreateService(shManager,
	    _T("Sctp"),
	    _T("Sctp Driver"),
	    SERVICE_ALL_ACCESS,
	    SERVICE_KERNEL_DRIVER,
	    dwStartType,
	    SERVICE_ERROR_NORMAL,
	    _T("System32\\drivers\\sctp.sys"),
	    lpLoadOrderGroup,
	    NULL,
	    lpDependencies,
	    NULL,
	    NULL);
	if (shService == NULL) {
		ret = GetLastError();
		_sntprintf(szError, _countof(szError), _T("Failed to install Sctp Driver into system, CreateService=%u\n"), ret);
		MessageBox(NULL, szError,
		    _T("Sctp Driver Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		goto done;
	}
	lpServiceArgVectors = _T("Sctp");
	if (!StartService(shService, 1, &lpServiceArgVectors)) {
		ret = GetLastError();
		_sntprintf(szError, _countof(szError), _T("Failed to install Sctp Driver into system, StartService=%u\n"), ret);
		MessageBox(NULL, szError,
		    _T("Sctp Driver Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		DeleteService(shService);
		goto done;
	}

done:
	if (shService != NULL) {
		CloseServiceHandle(shService);
	}
	if (shManager != NULL) {
		CloseServiceHandle(shManager);
	}
	return ret;
}

UINT
__stdcall
SctpUnInstallDriver(
    IN MSIHANDLE hInstall)
{
	UINT ret = ERROR_SUCCESS;
	TCHAR szError[128];
	SC_HANDLE shManager = NULL;
	SC_HANDLE shService = NULL;
	SERVICE_STATUS serviceStatus;

	memset(szError, 0, sizeof(szError));

	shManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (shManager == NULL) {
		goto done;
	}

	shService = OpenService(shManager, _T("Sctp"), SERVICE_ALL_ACCESS);
	if (shService == NULL) {
		_sntprintf(szError, _countof(szError), _T("Can't un-install Sctp Driver from system, OpenService=%u\n"), GetLastError());
		MessageBox(NULL, szError,
		    _T("Sctp Driver Un-Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		goto done;
	}
	ControlService(shService, SERVICE_CONTROL_STOP, &serviceStatus);
	if (!DeleteService(shService)) {
		_sntprintf(szError, _countof(szError), _T("Can't un-install Sctp Driver from system, DeleteService=%u\n"), ret);
		MessageBox(NULL, szError,
		    _T("Sctp Driver Un-Install Error"),
		    MB_OK | MB_ICONINFORMATION);
	}
	CloseServiceHandle(shService);
	shService = NULL;

	/* XXX Should we revert the configuration of IpFilterDriver? */
#if 0
	/* Stop IpFilterDriver and change the configuration. */
	shService = OpenService(shManager, _T("IpFilterDriver"), SERVICE_ALL_ACCESS);
	if (shService != NULL) {
		ControlService(shService, SERVICE_CONTROL_STOP, &serviceStatus);

		if (!ChangeServiceConfig(shService,
			SERVICE_NO_CHANGE,	/* TYPE */
			SERVICE_DEMAND_START,	/* START_TYPE */
			SERVICE_NO_CHANGE,	/* ERROR_CONTROL */
			NULL,			/* BINARY_PATH_NAME */
			_T(""),			/* LOAD_ORDER_GROUP */
			NULL,			/* TAG */
			NULL,			/* DEPENDENCIES */
			NULL,			/* SERVICE_START_NAME */
			NULL,			/* lpPassword */
			NULL			/* DISPLAY_NAME */
		    )) {
			_sntprintf(szError, _countof(szError),
			    _T("Can't change configuration of IpFilterDriver, ChangeService=%u\n"), GetLastError());
			MessageBox(NULL, szError,
			    _T("Sctp Driver UnInstall Error"),
			    MB_OK | MB_ICONINFORMATION);
			goto done;
		}
	}
#endif
done:
	if (shService != NULL) {
		CloseServiceHandle(shService);
	}
	if (shManager != NULL) {
		CloseServiceHandle(shManager);
	}
	return ret;
}

UINT
__stdcall
SctpInstallProvider(
    IN MSIHANDLE hInstall)
{
	UINT ret = ERROR_SUCCESS;
	TCHAR szError[128];
	int wsaRet = 0;
	WSADATA wsd;
	int iError = 0;

	wsaRet = WSAStartup(MAKEWORD(2, 2), &wsd);
	if (wsaRet != 0) {
		ret = WSAGetLastError();
		_sntprintf(szError, _countof(szError), _T("Can't install Sctp Provider into system, WSAStartup=%u\n"), ret);
		MessageBox(NULL, szError,
		    _T("Sctp Provider Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		goto done;
	}

	wsaRet = WSCInstallProvider(&SctpProviderGuid,
	    SCTP_SERVICE_PROVIDER_PATH,
	    SctpProtocolInfos,
	    NUM_SCTP_PROTOCOL_INFOS,
	    &iError);
	if (wsaRet == SOCKET_ERROR) {
		ret = iError;
		_sntprintf(szError, _countof(szError), _T("Can't install Sctp Provider into system, WSCInstallProvider=%u\n"), ret);
		MessageBox(NULL, szError,
		    _T("Sctp Provider Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		goto done;
	}

done:
	return ret;
}

UINT
__stdcall
SctpUnInstallProvider(
    IN MSIHANDLE hInstall)
{
	UINT ret = ERROR_SUCCESS;
	TCHAR szError[128];
	int wsaRet = 0;
	WSADATA wsd;
	int iError = 0;

	wsaRet = WSAStartup(MAKEWORD(2, 2), &wsd);
	if (wsaRet != 0) {
		ret = WSAGetLastError();
		_sntprintf(szError, _countof(szError), _T("Can't un-install Sctp Provider from system, WSAStartup=%u\n"), ret);
		MessageBox(NULL, szError,
		    _T("Sctp Provider Un-Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		goto done;
	}

	wsaRet = WSCDeinstallProvider(&SctpProviderGuid, &iError);
	if (wsaRet == SOCKET_ERROR) {
		ret = iError;
		_sntprintf(szError, _countof(szError), _T("Can't un-install Sctp Provider from system, WSCDeinstallProvider=%u\n"), ret);
		MessageBox(NULL, szError,
		    _T("Sctp Provider Un-Install Error"),
		    MB_OK | MB_ICONINFORMATION);
		goto done;
	}

done:
	return ret;
}

BOOLEAN
WINAPI
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
