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
#ifndef _NET_ROUTE_H_
#define _NET_ROUTE_H_

#include <ipinfo.h>

#include <net/radix.h>

#include <netinet/in.h>
#include <netinet6/in6.h>

struct _sockaddr {
	unsigned char sa_len;
	unsigned char padding[7];
	struct sockaddr sa;
};

struct _sockaddr_in {
	unsigned char sin_len;
	unsigned char padding[7];
	struct sockaddr_in sin;
};

struct _sockaddr_in6 {
	unsigned char sin6_len;
	unsigned char padding[7];
	struct sockaddr_in6 sin6;
};

struct _sockaddr_storage {
	unsigned char ss_len;
	unsigned char padding[7];
	struct sockaddr_storage ss;
};

struct rtentry {
	struct radix_node rt_nodes[2];
#define rt_key(r)	(*((struct _sockaddr **)(&(r)->rt_nodes->rn_key)))
#define rt_mask(r)	(*((struct _sockaddr **)(&(r)->rt_nodes->rn_mask)))
	union {
		struct _sockaddr _sa;
		struct _sockaddr_in _sin;
		struct _sockaddr_in6 _sin6;
	} _rt_dst;
	union {
		struct _sockaddr _sa;
		struct _sockaddr_in _sin;
		struct _sockaddr_in6 _sin6;
	} _rt_netmask;
#define rt_dst		_rt_dst._sa.sa
#define rt_netmask	_rt_netmask._sa.sa
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} _rt_gateway;
#define rt_gateway	_rt_gateway.sa
	struct ifnet *rt_ifp;
	struct ifaddr *rt_ifa;
	uint32_t rt_mtu;
	uint16_t rt_flags;
	uint32_t rt_refcnt;
	KSPIN_LOCK rt_spinlock;
};
#define	RTF_UP		0x0001
#define	RTF_HOST	0x0002
#define	RTF_GATEWAY	0x0004
#define	RTF_MPATH	0x0008

#define	RT_LOCK_INIT(rt) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "RT_LOCK_INIT: %s[%d]\n", __FILE__, __LINE__); \
	KeInitializeSpinLock(&(rt)->rt_spinlock); \
} while (0)

#define	RT_LOCK(rt) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "RT_LOCK: rt=%p,cpu=%u,thr=%p @ %s[%d]\n", (rt), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
	KeAcquireSpinLockAtDpcLevel(&(rt)->rt_spinlock); \
} while (0)
#define	RT_UNLOCK(rt) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "RT_UNLOCK: rt=%p,cpu=%u,thr=%p %s[%d]\n", (rt), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
	KeReleaseSpinLockFromDpcLevel(&(rt)->rt_spinlock); \
} while(0)
#define	RT_LOCK_DESTROY(rt) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "RT_LOCK_DESTROY: rt=%p,cpu=%u,thr=%p %s[%d]\n", (rt), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
} while (0)
#define	RT_ADDREF(rt) do { \
	(rt)->rt_refcnt++; \
} while (0)
#define	RT_REMREF(rt) do { \
	(rt)->rt_refcnt--; \
} while (0)
#define RTFREE_LOCKED(rt) do { \
	if ((rt)->rt_refcnt <= 1) { \
		rtfree((rt)); \
	} else { \
		RT_REMREF((rt)); \
		RT_UNLOCK((rt)); \
	} \
	(rt) = NULL; \
} while (0)
#define RTFREE(rt) do { \
	RT_LOCK((rt)); \
	RTFREE_LOCKED((rt)); \
} while (0)

struct route {
	struct rtentry *ro_rt;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} _ro_dst;
#define ro_dst _ro_dst.sa
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} ro_src;
};
#define route_in6 route

#define	RTM_ADD		0x01
#define	RTM_DELETE	0x02

typedef struct {
	struct ifnet *ifp;
	struct ifaddr *ifa;
} RouteInterface;

typedef struct {
	ULONG dwNumEntries;
	IPRouteEntry table[1];
} IPRouteTable;

typedef struct IPv6QueryRouteEntry {
	struct in6_addr	i6qre_addr;
	ULONG		i6qre_prefix;
	ULONG		i6qre_index;
	ULONG		i6qre_unk1;	/* 0x00000000 */
	ULONG		i6qre_unk2;	/* 0x0006FD08 */
	ULONG		i6qre_unk3;	/* 0x00000004 */
	ULONG		i6qre_unk4;	/* 0x00000000 */
	struct in6_addr	i6qre_gw;
} IPv6QueryRouteEntry;

typedef struct IPv6RouteEntry {
	IPv6QueryRouteEntry i6re_query;
	ULONG		i6re_siteprefix;
	ULONG		i6re_expire;
	ULONG		i6re_expire2;
	ULONG		i6re_metric;
	ULONG		i6re_type;	/* 0: System, 2: Autoconf, 3: Manual */
	ULONG		i6re_publish;	/* 0: no, 1: yes or age */
	ULONG		i6re_publish2;	/* 0: age, 1: yes */
} IPv6RouteEntry;

typedef struct IPv6RouteTable {
	ULONG		ulNumEntries;
	ULONG		ulNumActiveEntries;
	IPv6RouteEntry	Entries[1];
} IPv6RouteTable;

void rtalloc(struct route *);
struct rtentry *rtalloc1(struct _sockaddr *);
void rtfree(struct rtentry *);
void route_init(void);
void route_destroy(void);

#if NTDDI_VERSION < NTDDI_LONGHORN
struct radix_node * route_ipv6_add(IPv6RouteEntry *);
void route_ipv6_del(IPv6RouteEntry *);
int route_ipv4_reload(void);
int route_ipv6_reload(void);
#endif

#endif	/* _NET_ROUTE_H_ */
