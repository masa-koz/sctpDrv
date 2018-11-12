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
#ifndef _SYS_SYSTM_H_
#define _SYS_SYSTM_H_

#include <stdarg.h>

#include <sys/atomic.h>

#define hz		1000
#define tick		(1000000 / hz)

static __inline int imin(int a, int b) { return (a < b ? a : b); }

#if !defined(_KERNEL)
NTSYSAPI
ULONG
NTAPI
DbgPrint(
    IN PCHAR  Format,
    ...);

NTSYSAPI
ULONG
NTAPI
vDbgPrintEx(
    __in ULONG ComponentId,
    __in ULONG Level,
    __in PCCH Format,
    __in va_list arglist
    );

#define DPFLTR_IHVNETWORK_ID	80
#define DPFLTR_ERROR_LEVEL	0

VOID
NTAPI
DbgBreakPoint(
    VOID
    );

#endif
#define printf		DbgPrint

#define	bzero		RtlZeroMemory
#define bcopy(a, b, c)	RtlCopyMemory(b, a, c)
#define bcmp(a, b, c)	((RtlCompareMemory((a), (b), (c)) == (c)) ? 0 : 1)

#if !defined(_KERNEL)
#define malloc(size)			HeapAlloc(GetProcessHeap(), 0, (size))
#define calloc(size, count)		malloc((size) * (count))
#define free(buf)			HeapFree(GetProcessHeap(), 0, (buf))
#endif


#if defined(_KERNEL)
int 	copyin(void *uaddr, void *kaddr, size_t len);
int 	copyout(void *kaddr, void *uaddr, size_t len);
PVOID	LockRequest(IN PIRP irp, IN PIO_STACK_LOCATION irpSp);
VOID	UnlockRequest(IN PIRP irp, IN PIO_STACK_LOCATION irpSp);
NTSTATUS LockBuffer(IN void *uaddr, IN size_t len, IN LOCK_OPERATION operation, OUT PMDL *mdl0);
VOID	UnlockBuffer(IN PMDL mdl);
PFILE_FULL_EA_INFORMATION FindEAInfo(IN PFILE_FULL_EA_INFORMATION start, IN CHAR *target, IN USHORT length);
#endif


#if defined(_KERNEL)
__inline void
panic(char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vDbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, fmt, va);
	va_end(va);
	KeBugCheck(0);
}

#if defined(DBG)
#define DEBUG_GENERIC_ERROR	0x00000001
#define DEBUG_GENERIC_WARN	0x00000002
#define DEBUG_GENERIC_INFO	0x00000004
#define DEBUG_GENERIC_VERBOSE	0x00000008
#define DEBUG_GENERIC_ALL	0x0000000f
#define DEBUG_LOCK_ERROR	0x00000010
#define DEBUG_LOCK_WARN		0x00000020
#define DEBUG_LOCK_INFO		0x00000040
#define DEBUG_LOCK_VERBOSE	0x00000080
#define DEBUG_LOCK_ALL		0x000000f0
#define DEBUG_KERN_ERROR	0x00000100
#define DEBUG_KERN_WARN		0x00000200
#define DEBUG_KERN_INFO		0x00000400
#define DEBUG_KERN_VERBOSE	0x00000800
#define DEBUG_KERN_ALL		0x00000f00
#define DEBUG_NET_ERROR		0x00001000
#define DEBUG_NET_WARN		0x00002000
#define DEBUG_NET_INFO		0x00004000
#define DEBUG_NET_VERBOSE	0x00008000
#define DEBUG_NET_ALL		0x0000f000

extern uint32_t debug_on;
__inline void
DebugPrint(uint32_t level, char *format, ...)
{
	va_list va;
	va_start(va, format);
	if (debug_on & level) {
		vDbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, format, va);
	}
	va_end(va);
}
#else
#define DebugPrint(level, format, ...)
#endif
#endif


#endif	/* _SYS_SYSTM_H_ */
