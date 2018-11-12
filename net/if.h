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
#ifndef __if_h__
#define __if_h__

#include <ifdef.h>

#if NTDDI_VERSION < NTDDI_LONGHORN
#include <ipinfo.h>

#define MAX_PHYSADDR_SIZE   8
typedef struct IFEntry {
	unsigned long if_index;
	unsigned long if_type;
	unsigned long if_mtu;
	unsigned long if_speed;
	unsigned long if_physaddrlen;
	unsigned char if_physaddr[MAX_PHYSADDR_SIZE];
	unsigned long if_adminstatus;
	unsigned long if_operstatus;
	unsigned long if_lastchange;
	unsigned long if_inoctets;
	unsigned long if_inucastpkts;
	unsigned long if_innucastpkts;
	unsigned long if_indiscards;
	unsigned long if_inerrors;
	unsigned long if_inunknownprotos;
	unsigned long if_outoctets;
	unsigned long if_outucastpkts;
	unsigned long if_outnucastpkts;
	unsigned long if_outdiscards;
	unsigned long if_outerrors;
	unsigned long if_outqlen;
	unsigned long if_descrlen;
	unsigned char if_descr[1];
} IFEntry;

typedef struct {
	unsigned long dwNumEntries;
	IPAddrEntry table[0];
} IPAddrTable;


typedef struct ipv6_query_interface {
    unsigned int Index;
    GUID guid;
} IPV6_QUERY_INTERFACE;

typedef struct ipv6_info_interface {
    IPV6_QUERY_INTERFACE NextQuery;
    IPV6_QUERY_INTERFACE Query;
    UCHAR Unknown1[4];
    unsigned int LinkLevelAddressLength;
    UCHAR Unknown2[48];
    unsigned int Index0;
    unsigned int Index1;
    unsigned int Index2;
    unsigned int Site0;
    unsigned int Site1;
    unsigned int Site2;
    UCHAR Unknown3[40];
    unsigned int TrueMTU;
    unsigned int MTU;
    unsigned int HopLimit;
    unsigned int BaseReachableTime;
    unsigned int ReachableTime;
    unsigned int RetransTimer;
    unsigned int DupAddrDetectTransmits;
    unsigned int Preference;
    UCHAR Unknown4[4];
    unsigned int PrefixLength;
    UCHAR LinkLevelAddress[0];
} IPV6_INFO_INTERFACE;

typedef struct ipv6_query_address {
    IPV6_QUERY_INTERFACE IF;
    struct in6_addr Address;
} IPV6_QUERY_ADDRESS;

typedef struct ipv6_info_address {
    IPV6_QUERY_ADDRESS NextQuery;
    IPV6_QUERY_ADDRESS Query;
    unsigned int Type;
    UCHAR Unknown0[4];
    unsigned int Scope;
    unsigned int DADState; /* preferred == 4 */
    UCHAR Unknown1[4];
    unsigned int Temporary; /* temporary == 5, public == 4, manual == 1(?) */
    unsigned int ValidLifetime;
    unsigned int PreferredLifetime;
} IPV6_INFO_ADDRESS;
#endif


TAILQ_HEAD(ifnethead, ifnet);
TAILQ_HEAD(ifaddrhead, ifaddr);

#define IF_XNAMESIZE		0xff

#define IFT_OTHER		1
#define IFT_ETHER		6
#define IFT_ISO88025		9
#define	IFT_FDDI		15
#define IFT_PPP			23
#define	IFT_LOOP		24
#define IFT_SLIP		28
#define IFT_ATM			37
#define IFT_IEEE80211		71
#define IFT_TUNNEL		131
#define IFT_IEEE1394		144

struct ifnet {
	TAILQ_ENTRY(ifnet)	if_link;
	KSPIN_LOCK		if_spinlock;
	int			if_index;
	int			refcount;
	char			if_xname[IF_XNAMESIZE + 1];
	u_short			if_family;
	GUID			if_guid;
	struct ifaddrhead	if_addrhead;
	uint8_t			if_type;
	uint16_t		if_flags;
	int			if_mtu;
	int			if_ifIndex;
};

#define if_addrlist     	if_addrhead
#define if_list         	if_link

#define	IF_FLAG_LOOPBACK	0x0001

struct ifaddr {
	TAILQ_ENTRY(ifaddr)	ifa_link;
	KSPIN_LOCK		ifa_spinlock;
	struct ifnet		*ifa_ifp;
	int			refcount;
	int			ifa_flags;
	struct sockaddr		*ifa_addr;
};
#define ifa_list         	ifa_link

struct in_ifaddr {
	struct ifaddr		ia_ifa;
};
struct in6_ifaddr {
	int     		ia6_flags;
	struct			ifaddr ia_ifa;
};
#define ia_ifp          	ia_ifa.ifa_ifp
#define ia_flags        	ia_ifa.ifa_flags


extern struct ifnethead ifnet;
extern KSPIN_LOCK ifnet_lock;


#define IFNET_LOCK_INIT() do { \
	KeInitializeSpinLock(&ifnet_lock); \
} while (0)

#define IFNET_LOCK_DESTROY() do { \
} while (0)

#define IFNET_WLOCK() do { \
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) { \
		panic("IFNET_WLOCK: cpu=%u,thr=%p,irql=%d @ %s[%d]\n", KeGetCurrentProcessorNumber(), KeGetCurrentThread(), KeGetCurrentIrql(), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&ifnet_lock); \
} while (0)
#define IFNET_RLOCK IFNET_WLOCK

#define IFNET_WUNLOCK() do { \
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) { \
		panic("IFNET_WUNLOCK: cpu=%u,thr=%p,irql=%d @ %s[%d]\n", KeGetCurrentProcessorNumber(), KeGetCurrentThread(), KeGetCurrentIrql(), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&ifnet_lock); \
} while (0)
#define IFNET_RUNLOCK IFNET_WUNLOCK

#define IF_LOCK_INIT(_ifp) \
	KeInitializeSpinLock(&(_ifp)->if_spinlock)

#define IF_LOCK_DESTROY(_ifp) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "IF_LOCK_DESTROY: ifp=%p,cpu=%u,thr=%p @ %s[%d]\n", (_ifp), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
} while (0)

#define IF_LOCK(_ifp) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "IF_LOCK: ifp=%p,cpu=%u,thr=%p @ %s[%d]\n", (_ifp), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) { \
		panic("IF_LOCK: ifp=%p,cpu=%u,thr=%p,irql=%d @ %s[%d]\n", (_ifp), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), KeGetCurrentIrql(), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_ifp)->if_spinlock); \
} while (0)

#define IF_UNLOCK(_ifp) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "IF_UNLOCK(%p),cpu=%u,thr=%p @ %s[%d]\n", (_ifp), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) { \
		panic("IF_UNLOCK: ifp=%p,cpu=%u,thr=%p,irql=%d @ %s[%d]\n", (_ifp), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), KeGetCurrentIrql(), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_ifp)->if_spinlock); \
} while (0)

#define IFREF(_ifp) do { \
	IF_LOCK((_ifp)); \
	(_ifp)->refcount++; \
	IF_UNLOCK((_ifp)); \
} while (0)

#define IFFREE_LOCKED(_ifp) do { \
	if (--(_ifp)->refcount == 0) { \
		TAILQ_REMOVE(&ifnet, (_ifp), if_link); \
		IF_LOCK_DESTROY((_ifp)); \
		ExFreePool((_ifp)); \
		(_ifp) = NULL; \
	} else {\
		IF_UNLOCK((_ifp)); \
	} \
} while (0)

#define IFFREE(_ifp) do { \
	IF_LOCK((_ifp)); \
	IFFREE_LOCKED((_ifp)); \
} while (0)

#define IFA_LOCK_INIT(_ifa) \
	KeInitializeSpinLock(&(_ifa)->ifa_spinlock)

#define IFA_LOCK_DESTROY(_ifa) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "IFA_LOCK_DESTROY: ifa=%p,cpu=%u,thr=%p @ %s[%d]\n", (_ifa), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
} while (0)

#define IFA_LOCK(_ifa) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "IFA_LOCK: ifa=%p,cpu=%u,thr=%p @ %s[%d]\n", (_ifa), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) { \
		panic("IFA_LOCK: ifa=%p,cpu=%u,thr=%p,irql=%d @ %s[%d]\n", (_ifa), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), KeGetCurrentIrql(), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_ifa)->ifa_spinlock); \
} while (0)

#define IFA_UNLOCK(_ifa) do { \
	DebugPrint(DEBUG_LOCK_VERBOSE, "IFA_UNLOCK: ifa=%p,cpu=%u,thr=%p @ %s[%d]\n", (_ifa), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), __FILE__, __LINE__); \
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) { \
		panic("IFA_UNLOCK: ifa=%p,cpu=%u,thr=%p,irql=%d @ %s[%d]\n", (_ifa), KeGetCurrentProcessorNumber(), KeGetCurrentThread(), KeGetCurrentIrql(), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_ifa)->ifa_spinlock); \
} while (0)

#define IFAREF(_ifa) do { \
	IFA_LOCK((_ifa)); \
	(_ifa)->refcount++; \
	IFA_UNLOCK((_ifa)); \
} while (0)

#define IFAFREE(_ifa) do { \
	IFA_LOCK((_ifa)); \
	if (--(_ifa)->refcount == 0) { \
		IFA_LOCK_DESTROY((_ifa)); \
		ExFreePool((_ifa)); \
		(_ifa) = NULL; \
	} else {\
		IFA_UNLOCK((_ifa)); \
	} \
} while (0)


int if_init(void);
void if_destroy(void);
#if NTDDI_VERSION < NTDDI_LONGHORN
struct ifnet * ifnet_create_by_in_addr(struct in_addr *);
struct ifnet * ifnet_create_by_index(ADDRESS_FAMILY, ULONG);
#else
struct ifnet * ifnet_create_by_index(ADDRESS_FAMILY, NET_IFINDEX);
#endif
struct ifaddr * ifnet_append_address(struct ifnet *, struct sockaddr *);

#endif
