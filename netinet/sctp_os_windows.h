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
 * $Id: sctp_os_windows.h,v 1.1 2007/03/08 19:12:22 kozuka Exp $
 */
#ifndef __sctp_os_windows_h__
#define __sctp_os_windows_h__
/*
 * includes
 */
#include "globals.h"

#if defined(HAVE_SCTP_PEELOFF_SOCKOPT)
#include <sys/file.h>
#include <sys/filedesc.h>
#endif

#if defined(__FreeBSD__)
#ifndef in6pcb
#define in6pcb		inpcb
#endif
#endif



/*
 *
 */
#define USER_ADDR_NULL	(NULL)		/* FIX ME: temp */
#define SCTP_LIST_EMPTY(list)	LIST_EMPTY(list)

/*
 * Local address and interface list handling
 */
#define SCTP_MAX_VRF_ID 0
#define SCTP_SIZE_OF_VRF_HASH 3
#define SCTP_IFNAMSIZ IFNAMSIZ
#define SCTP_DEFAULT_VRFID 0

#define SCTP_IFN_IS_IFT_LOOP(ifn) ((ifn)->ifn_type == IFT_LOOP)

/*
 * Access to IFN's to help with src-addr-selection
 */
/* This could return VOID if the index works but for BSD we provide both. */
#define SCTP_GET_IFN_VOID_FROM_ROUTE(ro) (void *)ro->ro_rt->rt_ifp
#define SCTP_GET_IF_INDEX_FROM_ROUTE(ro) ro->ro_rt->rt_ifp->if_index

/*
 * general memory allocation
 */
#define SCTP_MALLOC(var, type, size, name) \
    do { \
	var = (type)ExAllocatePool(NonPagedPool, size); \
    } while (0)

#define SCTP_FREE(var)	ExFreePool(var)

#define SCTP_MALLOC_SONAME(var, type, size) \
    do { \
	var = (type)ExAllocatePool(NonPagedPool, size); \
	if (var != NULL) { \
		RtlZeroMemory(var, size); \
	} \
    } while (0)

#define SCTP_FREE_SONAME(var)	ExFreePool(var)

#define SCTP_PROCESS_STRUCT struct proc *

/*
 * zone allocation functions
 */

/* SCTP_ZONE_INIT: initialize the zone */
typedef NPAGED_LOOKASIDE_LIST *sctp_zone_t;
#define UMA_ZFLAG_FULL	0x0020
#define SCTP_ZONE_INIT(zone, name, size, number) \
	do { \
		ExInitializeNPagedLookasideList(zone, NULL, NULL, 0, size, \
		    0x64657246, 0);\
	} while (0) \
}

/* SCTP_ZONE_GET: allocate element from the zone */
#define SCTP_ZONE_GET(zone, type) \
	(type *)ExAllocateFromNPagedLookasideList(zone);

/* SCTP_ZONE_FREE: free element from the zone */
#define SCTP_ZONE_FREE(zone, element) \
	ExFreeToNPagedLookasideList(zone, element);

void *sctp_hashinit_flags(int elements, struct malloc_type *type, 
                    u_long *hashmask, int flags);

#define HASH_NOWAIT 0x00000001
#define HASH_WAITOK 0x00000002

#define SCTP_HASH_INIT(size, hashmark) sctp_hashinit_flags(size, M_PCB, hashmark, HASH_NOWAIT)
#define SCTP_HASH_FREE(table, hashmark) hashdestroy(table, M_PCB, hashmark)


/*
 * timers
 */
struct sctp_os_timer_t {
	KTIMER tmr;
	KDPC dpc;
	PKDEFERRED_ROUTINE func;
	PVOID arg;
};

#define SCTP_OS_TIMER_INIT(tmr) do { \
	KeInitializeDpc(&tmr->dpc, tmr->func, tmr->arg); \
	KeInitializeTimer(&tmr->tmr); \
} while(0)

#define SCTP_OS_TIMER_START(tmr, ticks, func, arg) do { \
	LARGE_INTEGER InitialWakeUp; \
	InitialWakeUp.QuadPart = -(LONGLONG) MS_PER_TICK * 10000; \
	KeSetTimerEx(&tmr->tmr, InitialWakeUp, ticks, &tmr->dpc); \
} while (0)

#define SCTP_OS_TIMER_STOP(tmr) do { \
	while (KeCancelTimer(&tmr->tmr) == TRUE) { \
		KeFlushQueuedDpcs(); \
	} \
} while (0)

#define SCTP_OS_TIMER_PENDING(tmr)	FALSE
#define SCTP_OS_TIMER_ACTIVE(tmr)	FALSE
#define SCTP_OS_TIMER_DEACTIVATE(tmr)


NDIS_HANDLE SctpBufferPool;
KMUTEX SctpBufferMutex;

struct m_ext {
	UCHAR	*ext_buf;
	ULONG	ext_size;
	ULONG	ref_cnt;
};

struct mbuf {
	struct mbuf	*m_next;
	struct m_ext	m_ext;
	UCHAR		*m_data;
	NDIS_BUFFER	*ndis_buffer;
};

#define M_COPYALL	1000000000

/*
 * Functions
 */
/* Mbuf manipulation and access macros  */
#define SCTP_BUF_INIT() do { \
	NTSTATUS _status; \
	NdisAllocateBufferPool(&_status, &SctpBufferPool, 100); \
	KeInitializeMutex(&SctpBufferMutex, 0); \
} while (0)

#define SCTP_BUF_ALLOC(m, size) do { \
	NTSTATUS _status; \
	(m) = ExAllocatePool(NonPagedPool, sizeof(*(m))); \
	if (m != NULL) { \
		(m)->m_ext.ext_size = (size); \
		(m)->m_ext.ref_cnt = 1; \
		(m)->m_ext.ext_buf = ExAllocatePool(NonPagedPool, (size)); \
		if ((m)->m_ext.ext_buf != NULL) { \
			NdisAllocateBuffer(&_status, &(m)->ndis_buffer, \
			    SctpBufferPool, (m)->m_ext.ext_buf, (size)); \
			(m)->m_data = (m)->m_ext.ext_buf; \
			if (_status != NDIS_STATUS_SUCCESS) { \
				ExFreePool((m)->m_ext.ext_buf); \
				ExFreePool((m)); \
				(m) = NULL; \
			} \
		} else { \
			ExFreePool((m)); \
			(m) = NULL; \
		} \
	} \
} while (0)

#define SCTP_BUF_FREE(m) do { \
	NdisFreeBuffer((m)->ndis_buffer); \
	KeWaitForMutexObject(&SctpBufferMutex, Executive, KernelMode, \
	    FALSE, NULL); \
	(m)->m_ext.ref_cnt--; \
	if ((m)->m_ext.ref_cnt == 0) { \
		ExFreePool((m)->m_ext.ext_buf); \
	} \
	KeReleaseMutex(&SctpBufferMutex, FALSE); \
	ExFreePool((m)); \
} while (0)

#define SCTP_BUF_REFCOPY(n, m, offset, len, how) do { \
	NTSTATUS _status; \
	(n) = ExAllocatePool(NonPagedPool, sizeof(*(n))); \
	if ((n) != NULL) { \
		KeWaitForMutexObject(&SctpBufferMutex, Executive, KernelMode, \
		    FALSE, NULL); \
		(m)->m_ext.ref_cnt++; \
		KeReleaseMutex(&SctpBufferMutex, FALSE); \
		(n)->m_ext = (m)->m_ext; \
		(n)->m_data = (m)->m_ext.ext_buf + (offset); \
		NdisAllocateBuffer(&_status, &(n)->ndis_buffer, \
		    SctpBufferPool, (n)->m_data, \
		    ((len) == M_COPYALL) ? (n)->m_ext.ext_size - (offset) : (len)); \
		if (_status != NDIS_STATUS_SUCCESS) { \
			KeWaitForMutexObject(&SctpBufferMutex, \
			    Executive, KernelMode, FALSE, NULL); \
			(n)->m_ext.ref_cnt--; \
			KeReleaseMutex(&SctpBufferMutex, FALSE); \
			ExFreePool((n)); \
		} \
	} \
} while (0)

#define SCTP_BUF_ADJUST_LEN(m, len) do { \
	NdisAdjustBufferLength((m)->ndis_buffer, (len)); \
} while (0)

#define SCTP_BUF_SET_NEXT(m, n) do { \
	(m)->m_next = (n); \
	NDIS_BUFFER_LINKAGE((m)->ndis_buffer) = (n)->ndis_buffer; \
} while (0)

#define SCTP_BUF_LEN(m) NdisBufferLength((m)->ndis_buffer)
#define SCTP_BUF_NEXT(m) (m)->m_next
#define SCTP_BUF_NEXT_PKT(m)
#define SCTP_BUF_RESV_UF(m, size) (m)->m_data += size
#define SCTP_BUF_AT(m, size) ((m)->m_data + size)
#define SCTP_BUF_IS_EXTENDED(m) (1)
#define SCTP_BUF_EXTEND_SIZE(m) (m->m_ext.ext_size)
#define SCTP_BUF_TYPE(m)
#define SCTP_BUF_RECVIF(m)
#define SCTP_BUF_PREPEND(m)

/*************************/
/* These are for logging */
/*************************/
/* return the base ext data pointer */
#define SCTP_BUF_EXTEND_BASE(m) (m->m_ext.ext_buf)
 /* return the refcnt of the data pointer */
#define SCTP_BUF_EXTEND_REFCNT(m) (*m->m_ext.ref_cnt)
/* return any buffer related flags, this is
 * used beyond logging for apple only.
 */
#define SCTP_BUF_GET_FLAGS(m) (m->m_flags)

/* For BSD this just accesses the M_PKTHDR length
 * so it operates on an mbuf with hdr flag. Other
 * O/S's may have seperate packet header and mbuf
 * chain pointers.. thus the macro.
 */
#define SCTP_HEADER_TO_CHAIN(m) (m)
#define SCTP_HEADER_LEN(m) (m->m_pkthdr.len)
#define SCTP_GET_HEADER_FOR_OUTPUT(len) sctp_get_mbuf_for_msg(len, 1, M_DONTWAIT, 1, MT_DATA)

/* Attach the chain of data into the sendable packet. */
#define SCTP_ATTACH_CHAIN(pak, m, packet_length) do { \
                                                 pak->m_next = m; \
                                                 pak->m_pkthdr.len = packet_length; \
                         } while(0)

/* Other m_pkthdr type things */
#define SCTP_IS_IT_BROADCAST(dst, m) in_broadcast(dst, m->m_pkthdr.rcvif)
#define SCTP_IS_IT_LOOPBACK(m) ((m->m_pkthdr.rcvif == NULL) ||(m->m_pkthdr.rcvif->if_type == IFT_LOOP))


/* This converts any input packet header
 * into the chain of data holders, for BSD
 * its a NOP.
 */
#define SCTP_PAK_TO_BUF(i_pak) (i_pak)

/* Macro's for getting length from V6/V4 header */
#define SCTP_GET_IPV4_LENGTH(iph) (iph->ip_len)
#define SCTP_GET_IPV6_LENGTH(ip6) (ntohs(ip6->ip6_plen))

/* is the endpoint v6only? */
#define SCTP_IPV6_V6ONLY(inp)	(((struct inpcb *)inp)->inp_flags & IN6P_IPV6_V6ONLY)
/* is the socket non-blocking? */
#define SCTP_SO_IS_NBIO(so)	((so)->so_state & SS_NBIO)
#define SCTP_SET_SO_NBIO(so)	((so)->so_state |= SS_NBIO)
#define SCTP_CLEAR_SO_NBIO(so)	((so)->so_state &= ~SS_NBIO)
/* get the socket type */
#define SCTP_SO_TYPE(so)	((so)->so_type)

/*
 * SCTP AUTH
 */
#define HAVE_SHA2

#if (__FreeBSD_version < 500000)
#define SCTP_READ_RANDOM(buf, len)	read_random_unlimited(buf, len)
#else
#define SCTP_READ_RANDOM(buf, len)	read_random(buf, len)
#endif

#include <netinet/sctp_sha1.h>

#endif
