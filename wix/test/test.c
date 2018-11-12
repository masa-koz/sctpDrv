#include <stdlib.h>

#include <windows.h>
#include <tchar.h>

#define	SCTP_OS_VERSION_XP32_SP2	_T("Windows XP 32bit Service Pack 2")
#define	SCTP_OS_VERSION_XP32_SP3	_T("Windows XP 32bit Service Pack 3")
#define	SCTP_OS_VERSION_VISTA32		_T("Windows Vista 32bit")

BOOLEAN SctpGetOSVersion(OUT PTCHAR, IN ULONG);

int
__cdecl
_tmain(
    int argc,
    TCHAR *argv[])
{
	TCHAR szVersion[MAX_PATH];

	memset(szVersion, 0, sizeof(szVersion));
	if (SctpGetOSVersion(szVersion, _countof(szVersion))) {
		if (_tcscmp(szVersion, SCTP_OS_VERSION_XP32_SP2) == 0 ||
		    _tcscmp(szVersion, SCTP_OS_VERSION_XP32_SP3) == 0 ||
		    _tcsncmp(szVersion, SCTP_OS_VERSION_VISTA32, _countof(SCTP_OS_VERSION_VISTA32) - 1) == 0) {
			_tprintf(_T("%s: OK\n"), szVersion);
		} else {
			_tprintf(_T("%s: NG\n"), szVersion);
		}
	}
	return 0;
}

