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
#ifndef __sctp_os_windows_h__
#define __sctp_os_windows_h__

#include <ntifs.h>

#include <ndis.h>

#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>

#include <stddef.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/poll.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/sctp_constants.h>
#include <netinet6/in6.h>


struct proc {
	uint8_t dummy;
};

#define SCTP_PROCESS_STRUCT struct proc *

#define SCTP_BASE_INFO(__m) system_base_info.sctppcbinfo.__m
#define SCTP_BASE_STATS system_base_info.sctpstat
#define SCTP_BASE_STAT(__m)     system_base_info.sctpstat.__m
#define SCTP_BASE_SYSCTL(__m) system_base_info.sctpsysctl.__m
#define SCTP_BASE_VAR(__m) system_base_info.__m



#define SCTP_UNUSED

#define USER_ADDR_NULL	(NULL)		/* FIX ME: temp */
#define SCTP_LIST_EMPTY(list)	LIST_EMPTY(list)

#if defined(SCTP_DEBUG)
extern uint32_t *sctp_debug_on;
__inline void
SCTPDBG(uint32_t level, char *format, ...)
{
	va_list va;
	va_start(va, format);
	if (*sctp_debug_on & level) {
		vDbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, format, va);
	}
	va_end(va);
}
#define SCTPDBG_ADDR(level, addr) \
{ \
	do { \
		if (*sctp_debug_on & level) { \
			sctp_print_address(addr); \
		} \
	} while (0); \
}
#define SCTPDBG_PKT(level, iph, sh) \
{ \
	do { \
		if (*sctp_debug_on & level) { \
			sctp_print_address_pkt(iph, sh); \
		} \
	} while (0); \
}
#else
#define SCTPDBG(x, ...)
#define SCTPDBG_ADDR(level, addr)
#define SCTPDBG_PKT(level, iph, sh)
#endif
__inline void
SCTP_PRINTF(char *format, ...)
{
	va_list va;
	va_start(va, format);
	vDbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, format, va);
	va_end(va);
}

/* Empty ktr statement for win */

#if defined(SCTP_LOCAL_TRACE_BUF)
__inline uint64_t
get_cyclecount(void)
{
	LARGE_INTEGER tickCount;
	KeQueryTickCount(&tickCount);
	return (uint64_t)tickCount.QuadPart;
}
#define SCTP_GET_CYCLECOUNT get_cyclecount()
#define SCTP_CTR6 sctp_log_trace
#else
#define SCTP_CTR6 CTR6
#endif

#define CTR6(m, d, p1, p2, p3, p4, p5, p6)
#define SCTP_LTRACE_CHK(a, b, c, d)
#define SCTP_LTRACE_ERR(a, b, c, d)
#define SCTP_LTRACE_ERR_RET_PKT(m, inp, stcb, net, file, err)
#define SCTP_LTRACE_ERR_RET(inp, stcb, net, file, err)


/*
 * Local address and interface list handling
 */
#define SCTP_MAX_VRF_ID		0
#define SCTP_SIZE_OF_VRF_HASH	3
#define SCTP_IFNAMSIZ		255
#define SCTP_DEFAULT_VRFID	0
#define SCTP_VRF_ADDR_HASH_SIZE	16
#define SCTP_VRF_IFN_HASH_SIZE	3
#define	SCTP_INIT_VRF_TABLEID(vrf)

#define SCTP_IFN_IS_IFT_LOOP(ifn)	((ifn)->ifn_type == IFT_LOOP)
#define SCTP_ROUTE_IS_REAL_LOOP(ro) ((ro)->ro_rt && (ro)->ro_rt->rt_ifa && (ro)->ro_rt->rt_ifa->ifa_ifp && (ro)->ro_rt->rt_ifa->ifa_ifp->if_type == IFT_LOOP)

/*
 * Access to IFN's to help with src-addr-selection
 */
/* This could return VOID if the index works but for BSD we provide both. */
#define SCTP_GET_IFN_VOID_FROM_ROUTE(ro) \
	((ro)->ro_rt != NULL ? (ro)->ro_rt->rt_ifp : NULL)
#define SCTP_GET_IF_INDEX_FROM_ROUTE(ro) \
	((ro)->ro_rt != NULL ? ((ro)->ro_rt->rt_ifp != NULL ? (ro)->ro_rt->rt_ifp->if_index : -1): -1)
#define SCTP_ROUTE_HAS_VALID_IFN(ro) \
	((ro)->ro_rt && (ro)->ro_rt->rt_ifp)

/* Declare all the malloc names for all the various mallocs */
MALLOC_DECLARE(SCTP_M_MAP);
MALLOC_DECLARE(SCTP_M_STRMI);
MALLOC_DECLARE(SCTP_M_STRMO);
MALLOC_DECLARE(SCTP_M_ASC_ADDR);
MALLOC_DECLARE(SCTP_M_ASC_IT);
MALLOC_DECLARE(SCTP_M_AUTH_CL);
MALLOC_DECLARE(SCTP_M_AUTH_KY);
MALLOC_DECLARE(SCTP_M_AUTH_HL);
MALLOC_DECLARE(SCTP_M_AUTH_IF);
MALLOC_DECLARE(SCTP_M_STRESET);
MALLOC_DECLARE(SCTP_M_CMSG);
MALLOC_DECLARE(SCTP_M_COPYAL);
MALLOC_DECLARE(SCTP_M_VRF);
MALLOC_DECLARE(SCTP_M_IFA);
MALLOC_DECLARE(SCTP_M_IFN);
MALLOC_DECLARE(SCTP_M_TIMW);
MALLOC_DECLARE(SCTP_M_MVRF);
MALLOC_DECLARE(SCTP_M_ITER);
MALLOC_DECLARE(SCTP_M_SOCKOPT);

#define SCTP_MALLOC(var, type, size, name) \
	MALLOC(var, type, size, name, 0)
#define SCTP_FREE	FREE

#define SCTP_MALLOC_SONAME(var, type, size) \
	MALLOC(var, type, size, M_SONAME, M_ZERO)
#define SCTP_FREE_SONAME(var) FREE(var, M_SONAME)

typedef NPAGED_LOOKASIDE_LIST sctp_zone_t;
#define UMA_ZFLAG_FULL	0x0020
#define SCTP_ZONE_INIT(zone, name, size, number) do { \
	ExInitializeNPagedLookasideList(&(zone), NULL, NULL, 0, (size), \
	    0x64657246, 0); \
} while (0)

/* SCTP_ZONE_GET: allocate element from the zone */
#define SCTP_ZONE_GET(zone, type) \
	(type *)ExAllocateFromNPagedLookasideList(&(zone))

/* SCTP_ZONE_FREE: free element from the zone */
#define SCTP_ZONE_FREE(zone, element) \
	ExFreeToNPagedLookasideList(&(zone), (element))

#define	SCTP_ZONE_DESTROY(zone) do { \
	ExDeleteNPagedLookasideList(&(zone)); \
} while(0)

void *sctp_hashinit_flags(int, struct malloc_type *, u_long *, int);
	
#define HASH_NOWAIT 0x00000001
#define HASH_WAITOK 0x00000002

#define SCTP_HASH_INIT(size, hashmark) sctp_hashinit_flags(size, M_PCB, hashmark, HASH_NOWAIT)
#if 0 /* XXX */
#define SCTP_HASH_FREE(table, hashmark) hashdestroy(table, M_PCB, hashmark)
#else
#define SCTP_HASH_FREE(table, hashmark)
#endif

#define SCTP_M_COPYM	m_copym

#define SCTP_BUF_LEN(m)			(m->m_len)
#define SCTP_BUF_NEXT(m)		(m->m_next)
#define SCTP_BUF_NEXT_PKT(m)		(m->m_nextpkt)
#define SCTP_BUF_RESV_UF(m, size) 	m->m_data += size
#define SCTP_BUF_AT(m, size)		(m->m_data + size)
#define SCTP_BUF_IS_EXTENDED(m)		(m->m_flags & M_EXT)
#define SCTP_BUF_EXTEND_SIZE(m)		(m->m_ext.ext_size)
#define SCTP_BUF_TYPE(m)		(m->m_type)
#define SCTP_BUF_RECVIF(m)		(m->m_pkthdr.rcvif)
#define SCTP_BUF_PREPEND		M_PREPEND

#define SCTP_ALIGN_TO_END(m, len) if(m->m_flags & M_PKTHDR) { \
	MH_ALIGN(m, len); \
	} else if ((m->m_flags & M_EXT) == 0) { \
	M_ALIGN(m, len); \
}

/* We make it so if you have up to 4 threads
 * writting based on the default size of
 * the packet log 65 k, that would be
 * 4 16k packets before we would hit
 * a problem.
 */
#define SCTP_PKTLOG_WRITERS_NEED_LOCK 3

/*************************/
/*      MTU              */
/*************************/
#define SCTP_GATHER_MTU_FROM_IFN_INFO(ifn, ifn_index, af) ((struct ifnet *)ifn)->if_mtu
#define SCTP_GATHER_MTU_FROM_ROUTE(sctp_ifa, sa, rt) ((rt != NULL) ? rt->rt_mtu : 0)
#define SCTP_GATHER_MTU_FROM_INTFC(sctp_ifn) ((sctp_ifn->ifn_p != NULL) ? ((struct ifnet *)(sctp_ifn->ifn_p))->if_mtu : 0)
#define SCTP_SET_MTU_OF_ROUTE(sa, rt, mtu) do { \
	if (rt != NULL) \
		rt->rt_mtu = mtu; \
	} while(0) 

/* (de-)register interface event notifications */
#define SCTP_REGISTER_INTERFACE(ifhandle, af)
#define SCTP_DEREGISTER_INTERFACE(ifhandle, af)

/* return the base ext data pointer */
#define SCTP_BUF_EXTEND_BASE(m)		(caddr_t)(m->m_ext.ext_buf)
 /* return the refcnt of the data pointer */
#define SCTP_BUF_EXTEND_REFCNT(m)	(*(m->m_ext.ref_cnt))
/* return any buffer related flags, this is
 * used beyond logging for apple only.
 */
#define SCTP_BUF_GET_FLAGS(m)		(m->m_flags)

/* For BSD this just accesses the M_PKTHDR length
 * so it operates on an mbuf with hdr flag. Other
 * O/S's may have seperate packet header and mbuf
 * chain pointers.. thus the macro.
 */
#define SCTP_HEADER_TO_CHAIN(m)		(m)
#define SCTP_DETACH_HEADER_FROM_CHAIN(m)
#define SCTP_HEADER_LEN(m)		(m->m_pkthdr.len)
#define SCTP_GET_HEADER_FOR_OUTPUT(o_pak) 0
#define SCTP_RELEASE_HEADER(m)
#define SCTP_RELEASE_PKT(m)	sctp_m_freem(m)
#define SCTP_ENABLE_UDP_CSUM(m)

#define SCTP_GET_PKT_VRFID(m, vrf_id)  ((vrf_id = SCTP_DEFAULT_VRFID) != SCTP_DEFAULT_VRFID)

/* Attach the chain of data into the sendable packet. */
#define SCTP_ATTACH_CHAIN(pak, m, packet_length) do { \
	pak = m; \
	pak->m_pkthdr.len = packet_length; \
} while(0)

/* XXX */
__inline int
in_broadcast(struct in_addr in, struct ifnet *ifp)
{
	return 0;
}
/* Other m_pkthdr type things */
#define SCTP_IS_IT_BROADCAST(dst, m) \
	((m->m_flags & M_PKTHDR) ? in_broadcast(dst, m->m_pkthdr.rcvif) : 0)
#define SCTP_IS_IT_LOOPBACK(m) \
	((m->m_flags & M_PKTHDR) && ((m->m_pkthdr.rcvif == NULL) || (m->m_pkthdr.rcvif->if_type == IFT_LOOP)))

/* Macro's for getting length from V6/V4 header */
#define SCTP_GET_IPV4_LENGTH(iph) (iph->ip_len)
#define SCTP_GET_IPV6_LENGTH(ip6) (ntohs(ip6->ip6_plen))

/* get the v6 hop limit */
#define SCTP_GET_HLIM(inp, ro) 128 /* XXX */

/*
 * timers
 */

#include <sys/callout.h>
typedef struct callout sctp_os_timer_t;


#define	SCTP_OS_TIMER_INIT(tmr)	callout_init(tmr, 1)
#define	SCTP_OS_TIMER_START	callout_reset
#define	SCTP_OS_TIMER_STOP	callout_stop
#define	SCTP_OS_TIMER_STOP_DRAIN callout_drain
#define	SCTP_OS_TIMER_PENDING	callout_pending
#define	SCTP_OS_TIMER_ACTIVE	callout_active
#define	SCTP_OS_TIMER_DEACTIVATE callout_deactivate

__inline uint64_t
sctp_get_tick_count(void)
{
	LARGE_INTEGER tickCount;
	KeQueryTickCount(&tickCount);
	return tickCount.QuadPart;
}


/* is the endpoint v6only? */
#define SCTP_IPV6_V6ONLY(in6p)	(((struct in6pcb *)in6p)->in6p_flags & IN6P_IPV6_V6ONLY)
/* is the socket non-blocking? */
#define SCTP_SO_IS_NBIO(so)	((so)->so_state & SS_NBIO)
#define SCTP_SET_SO_NBIO(so)	((so)->so_state |= SS_NBIO)
#define SCTP_CLEAR_SO_NBIO(so)	((so)->so_state &= ~SS_NBIO)
/* get the socket type */
#define SCTP_SO_TYPE(so)	((so)->so_type)
/* reserve sb space for a socket */
#define SCTP_SORESERVE(so, send, recv)	soreserve(so, send, recv)
/* wakeup a socket */
#define SCTP_SOWAKEUP(so)	KeSetEvent(&(so)->so_waitEvent, 0, FALSE)
/* clear the socket buffer state */
#define SCTP_SB_CLEAR(sb) do { \
	(sb).sb_cc = 0; \
	(sb).sb_mb = NULL; \
	(sb).sb_mbcnt = 0; \
} while (0)

#define SCTP_SB_LIMIT_RCV(so)	so->so_rcv.sb_hiwat
#define SCTP_SB_LIMIT_SND(so)	so->so_snd.sb_hiwat

/*
 * routes, output, etc.
 */
typedef struct route	sctp_route_t;
typedef struct rtentry	sctp_rtentry_t;
#define SCTP_RTALLOC(ro, vrf_id) rtalloc((struct route *)ro)

/* Future zero copy wakeup/send  function */
#define SCTP_ZERO_COPY_EVENT(inp, so)
/* This is re-pulse ourselves for sendbuf */  
#define SCTP_ZERO_COPY_SENDQ_EVENT(inp, so)


/*
 * IP output routines
 */
extern uint16_t ip_id;
#define SCTP_IP_ID(inp) (ip_id)

NTSTATUS IPOutput(IN struct mbuf *, IN struct route *);
#define SCTP_IP_OUTPUT(result, o_pak, ro, stcb, vrf_id) \
{ \
	NTSTATUS status; \
	status = IPOutput(o_pak, ro); \
	if (status == STATUS_SUCCESS || status == STATUS_PENDING) { \
		result = 0; \
	} else { \
		result = EINVAL; \
	} \
}

NTSTATUS IP6Output(IN struct mbuf *, IN struct route *);
#define SCTP_IP6_OUTPUT(result, o_pak, ro, ifp, stcb, vrf_id) \
{ \
	NTSTATUS status; \
	status = IP6Output(o_pak, (struct route *)ro); \
	if (status == STATUS_SUCCESS || status == STATUS_PENDING) { \
		result = 0; \
	} else { \
		result = EINVAL; \
	} \
}

struct mbuf *
sctp_get_mbuf_for_msg(unsigned int space_needed, int want_header, int how, int allonebuf, int type);

/*
 * SCTP AUTH
 */

void read_random(uint8_t *, unsigned int);
#define SCTP_READ_RANDOM(buf, len)	read_random(buf, len)

#include <netinet/sctp_sha1.h>

#include <sys/md5.h>
#define	MD5_Init	MD5Init
#define	MD5_Update	MD5Update
#define	MD5_Final	MD5Final

#define SCTP_DECREMENT_AND_CHECK_REFCOUNT(addr)	(atomic_fetchadd_int(addr, -1) == 1)

#if defined(INVARIANTS)
#define SCTP_SAVE_ATOMIC_DECREMENT(addr, val) \
{ \
	int32_t oldval; \
	oldval = atomic_fetchadd_int(addr, -val); \
	if (oldval < val) { \
		panic("Counter goes negative"); \
	} \
}
#else
#define SCTP_SAVE_ATOMIC_DECREMENT(addr, val) \
{ \
	int32_t oldval; \
	oldval = atomic_fetchadd_int(addr, -val); \
	if (oldval < val) { \
		*addr = 0; \
	} \
}
#endif

#endif
