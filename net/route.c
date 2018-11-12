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

#include <ntifs.h>

#include <stddef.h>
#include <stdarg.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/radix.h>
#ifdef RADIX_MPATH
#include <net/radix_mpath.h>
#endif
#include <net/route.h>

#include <netinet/in.h>
#include <netinet6/in6.h>

#include <netinet/sctp_os.h>
#include <netinet/sctp_constants.h>

#if NTDDI_VERSION >= NTDDI_LONGHORN
#include <netioapi.h>
#else
#define IOCTL_TCP_QUERY_INFORMATION_EX 1179651
#define IOCTL_TCP_SET_INFORMATION_EX 1179688
#endif


void sctp_print_address(struct sockaddr *);
void sctp_addr_change(struct ifaddr *ifa, int cmd);

static void route_ipv4_init(void);
static void route_ipv6_init(void);

int route_ipv4_initialized = 0;
struct radix_node_head *rnh_ipv4 = NULL;
int route_ipv6_initialized = 0;
struct radix_node_head *rnh_ipv6 = NULL;

int ipmultipath = 1;
int ip6_multipath = 1;

#if NTDDI_VERSION < NTDDI_LONGHORN
extern HANDLE SctpRawHandle;
extern HANDLE TpIP6Handle;

PFILE_OBJECT ReloadThrObj;
KEVENT ReloadThrStop;

IPRouteTable *ipRouteTablePtr[2];
unsigned int ipRoutePtrTableCount = 0;
unsigned int ipRoutePtrTableInitialized = 0;
IPv6RouteTable *ip6RouteTablePtr[2];
unsigned int ip6RoutePtrTableCount = 0;
unsigned int ip6RoutePtrTableInitialized = 0;

static void route_reload_thread(void *);
#else
static void route_load(ADDRESS_FAMILY, struct radix_node_head *);
static void route_change(PVOID, PMIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE);

HANDLE NotifyRouteV4Handle;
HANDLE NotifyRouteV6Handle;

#endif

void
rtalloc(struct route *ro)
{	
	struct rtentry *rt = NULL;
	struct _sockaddr_storage dst;
	int i;

	DebugPrint(DEBUG_NET_VERBOSE, "rtalloc - enter\n");

	RtlZeroMemory(&dst, sizeof(dst));
	switch (ro->ro_dst.sa_family) {
	case AF_INET:
		dst.ss_len = sizeof(struct _sockaddr_in);
		RtlCopyMemory(&dst.ss, &ro->ro_dst, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		dst.ss_len = sizeof(struct _sockaddr_in6);
		RtlCopyMemory(&dst.ss, &ro->ro_dst, sizeof(struct sockaddr_in6));
		break;
	default:
		DebugPrint(DEBUG_NET_VERBOSE, "rtalloc - leave#1\n");
		return;
	}

	rt = ro->ro_rt;
	if (rt != NULL) {
		if (rt->rt_ifp != NULL && (rt->rt_flags & RTF_UP) != 0) {
			DebugPrint(DEBUG_NET_VERBOSE, "rtalloc - leave#2\n");
			return;
		}
		RTFREE(rt);
		ro->ro_rt = NULL;
	}
	ro->ro_rt = rtalloc1((struct _sockaddr *)&dst);
	if (ro->ro_rt) {
		RT_UNLOCK(ro->ro_rt);
	}
	DebugPrint(DEBUG_NET_VERBOSE, "rtalloc - leave\n");
}

struct rtentry *
rtalloc1(struct _sockaddr *dst)
{
	struct radix_node_head *rnh = NULL;
	struct radix_node *rn = NULL;
	struct rtentry *rt = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "rtalloc1 - enter\n");

	switch (dst->sa.sa_family) {
	case AF_INET:
		rnh = rnh_ipv4;
		break;
	case AF_INET6:
		rnh = rnh_ipv6;
		break;
	default:
		DebugPrint(DEBUG_NET_VERBOSE, "rtalloc1 - leave#1\n");
		return NULL;
	}

	RADIX_NODE_HEAD_LOCK(rnh);
	rn = rnh->rnh_matchaddr(dst, rnh);
	if (rn != NULL && (rn->rn_flags & RNF_ROOT) == 0) {
		rt = (struct rtentry *)rn;
		RT_LOCK(rt);
		RT_ADDREF(rt);
	}
	RADIX_NODE_HEAD_UNLOCK(rnh);

	DebugPrint(DEBUG_NET_VERBOSE, "rtalloc1 - leave\n");

	return rt;
}

void
rtfree(struct rtentry *rt)
{
	struct radix_node_head *rnh = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "rtfree - enter\n");

	if (rt == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "rtfree - leave#1\n");
		return;
	}

	RT_REMREF(rt);
	if (rt->rt_refcnt > 0) {
		RT_UNLOCK(rt);
		DebugPrint(DEBUG_NET_VERBOSE, "rtfree - leave#2\n");
		return;
	}
	switch ((rt_key(rt))->sa.sa_family) {
	case AF_INET:
		rnh = rnh_ipv4;
		break;
	case AF_INET6:
		rnh = rnh_ipv6;
		break;
	}

	if ((rt->rt_flags & RTF_UP) == 0) {
		RT_LOCK_DESTROY(rt);
		ExFreePool(rt);
	} else {
		RT_UNLOCK(rt);
	}
	DebugPrint(DEBUG_NET_VERBOSE, "rtfree - leave\n");
	return;
}


void
route_init(void)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE reloadThrHandle;

	DebugPrint(DEBUG_NET_VERBOSE, "route_init - enter\n");

	max_keylen = sizeof(struct _sockaddr_in6);
	rn_init();
	route_ipv4_init();
	route_ipv6_init();
	
#if NTDDI_VERSION < NTDDI_LONGHORN
	KeInitializeEvent(&ReloadThrStop, SynchronizationEvent, FALSE);
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = PsCreateSystemThread(&reloadThrHandle,
	    0, &objectAttributes, NULL, NULL,
	    route_reload_thread, NULL);
	if (status == STATUS_SUCCESS) {
		ObReferenceObjectByHandle(reloadThrHandle,
		    THREAD_ALL_ACCESS, NULL, KernelMode,
		    (PVOID *)&ReloadThrObj, NULL);
		ZwClose(reloadThrHandle);
	}
#endif
	DebugPrint(DEBUG_NET_VERBOSE, "route_init - leave\n");
}

void
route_destroy(void)
{
#if NTDDI_VERSION < NTDDI_LONGHORN
	NTSTATUS status = STATUS_SUCCESS;
#endif
	DebugPrint(DEBUG_NET_VERBOSE, "route_destroy - enter\n");
#if NTDDI_VERSION < NTDDI_LONGHORN
	if (ReloadThrObj != NULL) {
		KeSetEvent(&ReloadThrStop, IO_NO_INCREMENT, FALSE);
		status = KeWaitForSingleObject(ReloadThrObj, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(ReloadThrObj);
	}
#else
	if (NotifyRouteV4Handle != NULL) {
		CancelMibChangeNotify2(NotifyRouteV4Handle);
	}
	if (NotifyRouteV6Handle != NULL) {
		CancelMibChangeNotify2(NotifyRouteV6Handle);
	}
#endif
	DebugPrint(DEBUG_NET_VERBOSE, "route_destroy - leave\n");
}


static
struct radix_node *
route_add(
    struct radix_node_head *rnh,
#if NTDDI_VERSION < NTDDI_LONGHORN
    IPRouteEntry *routeV4Entry,
    IPv6RouteEntry *routeV6Entry
#else
    PMIB_IPFORWARD_ROW2 routeEntry
#endif
    )
{
	KIRQL oldIrql;
	struct rtentry *rt = NULL;
	struct radix_node *rn = NULL;
	ULONG i;
	struct ifnet *ifp = NULL;
	struct ifaddr *ifa = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "route_add - enter\n");

#if NTDDI_VERSION < NTDDI_LONGHORN
	if ((routeV4Entry != NULL && routeV6Entry != NULL) ||
	    (routeV4Entry == NULL && routeV6Entry == NULL)) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_add - leave#1\n");
		return NULL;
	}
#endif

	ifp = NULL;

#if NTDDI_VERSION < NTDDI_LONGHORN
	if (routeV4Entry != NULL &&
	    routeV4Entry->ire_nexthop == ntohl(INADDR_LOOPBACK) &&
	    *((unsigned char *)&routeV4Entry->ire_dest) != 127) {

		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		IFNET_WLOCK();

		TAILQ_FOREACH(ifp, &ifnet, if_link) {
			IF_LOCK(ifp);
			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				if (ifa->ifa_addr->sa_family != AF_INET) {
					continue;
				}
				if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr ==
					routeV4Entry->ire_dest) {
					break;
				}
			}
			if (ifa != NULL) {
				IF_UNLOCK(ifp);
				IFREF(ifp);
				break;
			}
			IF_UNLOCK(ifp);
		}
		IFNET_WUNLOCK();
		KeLowerIrql(oldIrql);

		if (ifp == NULL) {
			ifp = ifnet_create_by_in_addr((struct in_addr *)&routeV4Entry->ire_dest);
		}

	} else
#endif
	{
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		IFNET_WLOCK();

		TAILQ_FOREACH(ifp, &ifnet, if_link) {
#if NTDDI_VERSION < NTDDI_LONGHORN
			if (ifp->if_family == AF_INET && routeV4Entry != NULL &&
			    ifp->if_ifIndex == routeV4Entry->ire_index) {
				break;
			}
			if (ifp->if_family == AF_INET6 && routeV6Entry != NULL &&
			    ifp->if_ifIndex == routeV6Entry->i6re_query.i6qre_index) {
				break;
			}
#else
			if (ifp->if_family != routeEntry->NextHop.si_family) {
				continue;
			}
			if (ifp->if_ifIndex == routeEntry->InterfaceIndex) {
				break;
			}
#endif
		}
		if (ifp != NULL) {
			IFREF(ifp);
		}
		IFNET_WUNLOCK();
		KeLowerIrql(oldIrql);

		if (ifp == NULL) {
#if NTDDI_VERSION < NTDDI_LONGHORN
			if (routeV4Entry != NULL) {
				ifp = ifnet_create_by_index(AF_INET, routeV4Entry->ire_index);
				if (ifp != NULL && routeV4Entry->ire_index == 1) {
#else
			if (routeEntry->NextHop.si_family == AF_INET) {
				ifp = ifnet_create_by_index(routeEntry->NextHop.si_family, routeEntry->InterfaceIndex);
				if (ifp != NULL && routeEntry->InterfaceIndex == 1) {
#endif
					struct sockaddr_in sin;

					RtlZeroMemory(&sin, sizeof(sin));
					sin.sin_family = AF_INET;
					((unsigned char *)&sin.sin_addr)[0] = 127;
					((unsigned char *)&sin.sin_addr)[1] = 0;
					((unsigned char *)&sin.sin_addr)[2] = 0;
					((unsigned char *)&sin.sin_addr)[3] = 1;
					KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
					IFNET_WLOCK();
					IF_LOCK(ifp);
					ifa = ifnet_append_address(ifp, (struct sockaddr *)&sin);
					IF_UNLOCK(ifp);
					IFNET_WUNLOCK();
					if (ifa != NULL) {
						sctp_addr_change(ifa, RTM_ADD);
					}
					KeLowerIrql(oldIrql);
				}
			} else {
#if NTDDI_VERSION < NTDDI_LONGHORN
				ifp = ifnet_create_by_index(AF_INET6, routeV6Entry->i6re_query.i6qre_index);
				if (ifp != NULL) {
					IPv6RouteEntry routeV6Entry1;

					RtlZeroMemory(&routeV6Entry1, sizeof(routeV6Entry1));
					routeV6Entry1.i6re_query.i6qre_addr.s6_addr[0] = 0xfe;
					routeV6Entry1.i6re_query.i6qre_addr.s6_addr[1] = 0x80;
					routeV6Entry1.i6re_query.i6qre_prefix = 64;
					routeV6Entry1.i6re_query.i6qre_index = routeV6Entry->i6re_query.i6qre_index;

					route_add(rnh, NULL, &routeV6Entry1);
				}
#else
				ifp = ifnet_create_by_index(routeEntry->NextHop.si_family, routeEntry->InterfaceIndex);
#endif
			}
		}
	}

	if (ifp == NULL) {
#ifdef SCTP_DEBUG
#if NTDDI_VERSION < NTDDI_LONGHORN
		if (routeV4Entry != NULL &&
		    *sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
			uchar *dest = (uchar *)&routeV4Entry->ire_dest;
			uchar *mask = (uchar *)&routeV4Entry->ire_mask;
			uchar *nexthop = (uchar *)&routeV4Entry->ire_nexthop;
			
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_add: failed IF=%d,"
			    "DEST=%ld.%ld.%ld.%ld,MASK=%ld.%ld.%ld.%ld,NEXTHOP=%ld.%ld.%ld.%ld\n",
			    routeV4Entry->ire_index,
			    dest[0], dest[1], dest[2], dest[3],
			    mask[0], mask[1], mask[2], mask[3],
			    nexthop[0], nexthop[1], nexthop[2], nexthop[3]);
		} else {
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_add: failed IF=%d,"
			    "DEST=%s,PREFIXLEN=%d,",
			    routeV6Entry->i6re_query.i6qre_index,
			    ip6_sprintf(&routeV6Entry->i6re_query.i6qre_addr),
			    routeV6Entry->i6re_query.i6qre_prefix);
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "NEXTHOP=%s\n",
			    ip6_sprintf(&routeV6Entry->i6re_query.i6qre_gw));
		}
#else
		SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_add: failed IF=%d\n\tDEST=",
		    routeEntry->InterfaceIndex);
		SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4,
		    (struct sockaddr *)&routeEntry->DestinationPrefix.Prefix);
		SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tPREFIXLEN=%d\n",
		    routeEntry->DestinationPrefix.PrefixLength);
		SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tNEXTHOP=");
		SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4,
		    (struct sockaddr *)&routeEntry->NextHop);
#endif
#endif
		DebugPrint(DEBUG_NET_VERBOSE, "route_add - leave#2\n");
		return NULL;
	}

#ifdef SCTP_DEBUG
#if NTDDI_VERSION < NTDDI_LONGHORN
	if (*sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
		if (routeV4Entry != NULL) {
			uchar *dest = (uchar *)&routeV4Entry->ire_dest;
			uchar *mask = (uchar *)&routeV4Entry->ire_mask;
			uchar *nexthop = (uchar *)&routeV4Entry->ire_nexthop;
				
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_add: IF=%d,ifp=%p "
			    "DEST=%ld.%ld.%ld.%ld,MASK=%ld.%ld.%ld.%ld,NEXTHOP=%ld.%ld.%ld.%ld\n",
			    routeV4Entry->ire_index,
			    ifp,
			    dest[0], dest[1], dest[2], dest[3],
			    mask[0], mask[1], mask[2], mask[3],
			    nexthop[0], nexthop[1], nexthop[2], nexthop[3]);
		} else {
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_add: IF=%d,ifp=%p "
			    "DEST=%s,PREFIXLEN=%d,",
			    routeV6Entry->i6re_query.i6qre_index,
			    ifp,
			    ip6_sprintf(&routeV6Entry->i6re_query.i6qre_addr),
			    routeV6Entry->i6re_query.i6qre_prefix);
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "NEXTHOP=%s\n",
			    ip6_sprintf(&routeV6Entry->i6re_query.i6qre_gw));
		}
	}
#else
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_add: IF=%d,ifp=%p\n\tDEST=",
	    routeEntry->InterfaceIndex, ifp);
	SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4,
	    (struct sockaddr *)&routeEntry->DestinationPrefix.Prefix);
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tPREFIXLEN=%d\n",
	    routeEntry->DestinationPrefix.PrefixLength);
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tNEXTHOP=");
	SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4,
	    (struct sockaddr *)&routeEntry->NextHop);
#endif
#endif

	rt = ExAllocatePool(NonPagedPool, sizeof(struct rtentry));
	RtlZeroMemory(rt, sizeof(struct rtentry));
	RT_LOCK_INIT(rt);

#if NTDDI_VERSION < NTDDI_LONGHORN
	if (routeV4Entry != NULL) {
		rt->_rt_dst._sa.sa_len = sizeof(struct _sockaddr_in);
		rt->rt_dst.sa_family = AF_INET;
		RtlCopyMemory(&((struct sockaddr_in *)&rt->rt_dst)->sin_addr, &routeV4Entry->ire_dest,
		    sizeof(struct in_addr));

		if (routeV4Entry->ire_mask != IN_CLASSD_HOST) {
			rt->_rt_netmask._sa.sa_len = sizeof(struct _sockaddr_in);
			rt->rt_netmask.sa_family = AF_INET;
			RtlCopyMemory(&((struct sockaddr_in *)&rt->rt_netmask)->sin_addr, &routeV4Entry->ire_mask,
			    sizeof(struct in_addr));
			rt->rt_flags |= RTF_GATEWAY;
		} else {
			rt->rt_flags |= RTF_HOST;
		}

		rt->rt_gateway.sa_family = AF_INET;
		if ((rt->rt_flags & RTF_HOST) != 0 ||
		    (routeV4Entry->ire_nexthop & routeV4Entry->ire_mask) != routeV4Entry->ire_dest) {
			RtlCopyMemory(&((struct sockaddr_in *)&rt->rt_gateway)->sin_addr, &routeV4Entry->ire_nexthop,
			    sizeof(struct in_addr));
		}
	} else {
		struct in6_addr masked_nexthop;

		rt->_rt_dst._sa.sa_len = sizeof(struct _sockaddr_in6);
		rt->rt_dst.sa_family = AF_INET6;
		RtlCopyMemory(&((struct sockaddr_in6 *)&rt->rt_dst)->sin6_addr, &routeV6Entry->i6re_query.i6qre_addr,
		    sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&rt->rt_dst)->sin6_scope_id = routeV6Entry->i6re_query.i6qre_index;
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		in6_embedscope(&((struct sockaddr_in6 *)&rt->rt_dst)->sin6_addr,
		    (struct sockaddr_in6 *)&rt->rt_dst);
		KeLowerIrql(oldIrql);
		((struct sockaddr_in6 *)&rt->rt_dst)->sin6_scope_id = 0;

		if (routeV6Entry->i6re_query.i6qre_prefix < 128) {
			rt->_rt_netmask._sa.sa_len = sizeof(struct _sockaddr_in6);
			rt->rt_netmask.sa_family = AF_INET6;

			RtlZeroMemory(&masked_nexthop, sizeof(masked_nexthop));
			for (i = 0; i < routeV6Entry->i6re_query.i6qre_prefix; i++) {
				((struct sockaddr_in6 *)&rt->rt_netmask)->sin6_addr.s6_addr[(i / 8)] |= (0x80 >> (i % 8));
				masked_nexthop.s6_addr[(i / 8)] |=
				    routeV6Entry->i6re_query.i6qre_gw.s6_addr[(i / 8)] & (0x80 >> (i % 8));
			}
			rt->rt_flags |= RTF_GATEWAY;

		} else {
			rt->rt_flags |= RTF_HOST;
		}

		rt->rt_gateway.sa_family = AF_INET6;
		if ((rt->rt_flags & RTF_HOST) != 0 ||
		    !IN6_ADDR_EQUAL(&routeV6Entry->i6re_query.i6qre_addr, &masked_nexthop)) {
			RtlCopyMemory(&((struct sockaddr_in6 *)&rt->rt_gateway)->sin6_addr,
			    &routeV6Entry->i6re_query.i6qre_gw,
			    sizeof(struct in6_addr));
		}
	}
#else
	if (routeEntry->DestinationPrefix.Prefix.si_family == AF_INET) {
		rt->_rt_dst._sa.sa_len = sizeof(struct _sockaddr_in);
		RtlCopyMemory(&rt->rt_dst, &routeEntry->DestinationPrefix.Prefix.Ipv4,
		    sizeof(struct sockaddr_in));

		if (routeEntry->DestinationPrefix.PrefixLength < 32) {
			rt->_rt_netmask._sa.sa_len = sizeof(struct _sockaddr_in);
			rt->rt_netmask.sa_family = AF_INET;
			for (i = 0; i < routeEntry->DestinationPrefix.PrefixLength; i++) {
				((UCHAR *)&((struct sockaddr_in *)&rt->rt_netmask)->sin_addr)[(i / 8)] |= (0x80 >> (i % 8));
			}
			rt->rt_flags |= RTF_GATEWAY;
		} else {
			rt->rt_flags |= RTF_HOST;
		}

		RtlCopyMemory(&rt->rt_gateway, &routeEntry->NextHop.Ipv4,
		    sizeof(struct sockaddr_in));
	} else {
		rt->_rt_dst._sa.sa_len = sizeof(struct _sockaddr_in6);
		RtlCopyMemory(&rt->rt_dst, &routeEntry->DestinationPrefix.Prefix.Ipv6,
		    sizeof(struct sockaddr_in6));

		((struct sockaddr_in6 *)&rt->rt_dst)->sin6_scope_id = routeEntry->InterfaceIndex;
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		in6_embedscope(&((struct sockaddr_in6 *)&rt->rt_dst)->sin6_addr,
		    (struct sockaddr_in6 *)&rt->rt_dst);
		KeLowerIrql(oldIrql);
		((struct sockaddr_in6 *)&rt->rt_dst)->sin6_scope_id = 0;

		if (routeEntry->DestinationPrefix.PrefixLength < 128) {
			rt->_rt_netmask._sa.sa_len = sizeof(struct _sockaddr_in6);
			rt->rt_netmask.sa_family = AF_INET6;
			for (i = 0; i < routeEntry->DestinationPrefix.PrefixLength; i++) {
				((struct sockaddr_in6 *)&rt->rt_netmask)->sin6_addr.s6_addr[(i / 8)] |= (0x80 >> (i % 8));
			}
			rt->rt_flags |= RTF_GATEWAY;
		} else {
			rt->rt_flags |= RTF_HOST;
		}

		RtlCopyMemory(&rt->rt_gateway, &routeEntry->NextHop.Ipv6,
		    sizeof(struct sockaddr_in6));
	}
#endif
	rt->rt_flags |= RTF_UP;

	rt->rt_ifp = ifp;

	rt_key(rt) = &rt->_rt_dst._sa;
	if ((rt->rt_flags & RTF_HOST) == 0) {
		rt_mask(rt) = &rt->_rt_netmask._sa;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	RADIX_NODE_HEAD_LOCK(rnh);

#ifdef RADIX_MPATH
	if (rn_mpath_capable(rnh)) {
		if (rt_mpath_conflict(rnh, rt, rt_mask(rt), 1)) {
			ExFreePool(rt);
			DebugPrint(DEBUG_NET_VERBOSE, "route_add - leave#3\n");
			goto done;
		}
	}
#endif

	rn = rnh->rnh_addaddr(rt_key(rt), rt_mask(rt), rnh, rt->rt_nodes);
	if (rn == NULL) {
		ExFreePool(rt);
		DebugPrint(DEBUG_NET_VERBOSE, "route_add - leave#4\n");
		goto done;
	}

#ifdef RADIX_MPATH
	if (rn_mpath_capable(rnh)) {
		rn = rnh->rnh_lookup(rt_key(rt), rt_mask(rt), rnh);
		if (rn != NULL) {
			rt = (struct rtentry *)rn;
			if (rn_mpath_next(rn) != NULL) {
				rt->rt_flags |= RTF_MPATH;
			} else {
				rt->rt_flags &= ~RTF_MPATH;
			}
		}
	}
#endif

	DebugPrint(DEBUG_NET_VERBOSE, "route_add - leave\n");

done:
	RADIX_NODE_HEAD_UNLOCK(rnh);
	KeLowerIrql(oldIrql);

	return rn;
}
    
static
void
route_del(
    struct radix_node_head *rnh,
#if NTDDI_VERSION < NTDDI_LONGHORN
    IPRouteEntry *routeV4Entry,
    IPv6RouteEntry *routeV6Entry
#else
    PMIB_IPFORWARD_ROW2 routeEntry
#endif
    )
{
	KIRQL oldIrql;
	struct rtentry *rt = NULL;
	struct radix_node *rn = NULL;
	ULONG i;
	struct _sockaddr *dst = NULL, *netmask = NULL;
	struct _sockaddr_in in_dst, in_netmask;
	struct _sockaddr_in6 in6_dst, in6_netmask;
	struct sockaddr *nexthop = NULL;
	struct sockaddr_in in_nexthop;
	struct sockaddr_in6 in6_nexthop;

	DebugPrint(DEBUG_NET_VERBOSE, "route_del - enter\n");

#if NTDDI_VERSION < NTDDI_LONGHORN
	if ((routeV4Entry != NULL && routeV6Entry != NULL) ||
	    (routeV4Entry == NULL && routeV6Entry == NULL)) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_del - leave#1\n");
		return;
	}
#endif

#ifdef SCTP_DEBUG
#if NTDDI_VERSION < NTDDI_LONGHORN
	if (*sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
		if (routeV4Entry != NULL) {
			uchar *dest = (uchar *)&routeV4Entry->ire_dest;
			uchar *mask = (uchar *)&routeV4Entry->ire_mask;
			uchar *nexthop = (uchar *)&routeV4Entry->ire_nexthop;
				
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_del: IF=%d,"
			    "DEST=%ld.%ld.%ld.%ld,MASK=%ld.%ld.%ld.%ld,NEXTHOP=%ld.%ld.%ld.%ld\n",
			    routeV4Entry->ire_index,
			    dest[0], dest[1], dest[2], dest[3],
			    mask[0], mask[1], mask[2], mask[3],
			    nexthop[0], nexthop[1], nexthop[2], nexthop[3]);
		} else {
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_del: IF=%d,"
			    "DEST=%s,PREFIXLEN=%d,",
			    routeV6Entry->i6re_query.i6qre_index,
			    ip6_sprintf(&routeV6Entry->i6re_query.i6qre_addr),
			    routeV6Entry->i6re_query.i6qre_prefix);
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "NEXTHOP=%s\n",
			    ip6_sprintf(&routeV6Entry->i6re_query.i6qre_gw));
		}
	}
#else
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_del: IF=%d\n\tDEST=",
	    routeEntry->InterfaceIndex);
	SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4,
	    (struct sockaddr *)&routeEntry->DestinationPrefix.Prefix);
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tPREFIXLEN=%d\n",
	    routeEntry->DestinationPrefix.PrefixLength);
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tNEXTHOP=");
	SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4,
	    (struct sockaddr *)&routeEntry->NextHop);
#endif
#endif

#if NTDDI_VERSION < NTDDI_LONGHORN
	if (routeV4Entry != NULL) {
		RtlZeroMemory(&in_dst, sizeof(in_dst));
		in_dst.sin_len = sizeof(struct _sockaddr_in);
		in_dst.sin.sin_family = AF_INET;
		RtlCopyMemory(&in_dst.sin.sin_addr, &routeV4Entry->ire_dest,
		    sizeof(struct in_addr));
		dst = (struct _sockaddr *)&in_dst;

		if (routeV4Entry->ire_mask != IN_CLASSD_HOST) {
			RtlZeroMemory(&in_netmask, sizeof(in_netmask));
			in_netmask.sin_len = sizeof(struct _sockaddr_in);
			in_netmask.sin.sin_family = AF_INET;
			RtlCopyMemory(&in_netmask.sin.sin_addr, &routeV4Entry->ire_mask,
			    sizeof(struct in_addr));
			netmask = (struct _sockaddr *)&in_netmask;
		} else {
			netmask = NULL;
		}

		RtlZeroMemory(&in_nexthop, sizeof(in_nexthop));
		in_nexthop.sin_family = AF_INET;
		RtlCopyMemory(&in_nexthop.sin_addr, &routeV4Entry->ire_nexthop,
		    sizeof(struct in_addr));
		nexthop = (struct sockaddr *)&in_nexthop;
	} else {
		RtlZeroMemory(&in6_dst, sizeof(in6_dst));
		in6_dst.sin6_len = sizeof(struct _sockaddr_in6);
		in6_dst.sin6.sin6_family = AF_INET;
		RtlCopyMemory(&in6_dst.sin6.sin6_addr, &routeV6Entry->i6re_query.i6qre_addr,
		    sizeof(struct in6_addr));

		in6_dst.sin6.sin6_scope_id = routeV6Entry->i6re_query.i6qre_index;
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		in6_embedscope(&in6_dst.sin6.sin6_addr, &in6_dst.sin6);
		KeLowerIrql(oldIrql);
		in6_dst.sin6.sin6_scope_id = 0;

		dst = (struct _sockaddr *)&in6_dst;

		if (routeV6Entry->i6re_query.i6qre_prefix < 128) {
			RtlZeroMemory(&in6_netmask, sizeof(in6_netmask));
			in6_netmask.sin6_len = sizeof(struct _sockaddr_in6);
			in6_netmask.sin6.sin6_family = AF_INET6;
			for (i = 0; i < routeV6Entry->i6re_query.i6qre_prefix; i++) {
				in6_netmask.sin6.sin6_addr.s6_addr[(i / 8)] |= (0x80 >> (i % 8));
			}
			netmask = (struct _sockaddr *)&in6_netmask;
		} else {
			netmask = NULL;
		}

		RtlZeroMemory(&in6_nexthop, sizeof(in6_nexthop));
		in6_nexthop.sin6_family = AF_INET6;
		RtlCopyMemory(&in6_nexthop.sin6_addr, &routeV6Entry->i6re_query.i6qre_gw,
		    sizeof(struct in6_addr));
		nexthop = (struct sockaddr *)&in6_nexthop;
	}
#else
	if (routeEntry->NextHop.si_family == AF_INET) {
		RtlZeroMemory(&in_dst, sizeof(in_dst));
		in_dst.sin_len = sizeof(struct _sockaddr_in);
		RtlCopyMemory(&in_dst.sin, &routeEntry->DestinationPrefix.Prefix.Ipv4, sizeof(struct sockaddr_in));
		dst = (struct _sockaddr *)&in_dst;

		if (routeEntry->DestinationPrefix.PrefixLength < 32) {
			RtlZeroMemory(&in_netmask, sizeof(in_netmask));
			in_netmask.sin_len = sizeof(struct _sockaddr_in);
			in_netmask.sin.sin_family = AF_INET;
			for (i = 0; i < routeEntry->DestinationPrefix.PrefixLength; i++) {
				((UCHAR *)&in_netmask.sin.sin_addr)[(i / 8)] |= (0x80 >> (i % 8));
			}
			netmask = (struct _sockaddr *)&in_netmask;
		} else {
			netmask = NULL;
		}

		nexthop = (struct sockaddr *)&routeEntry->NextHop;
	} else {
		RtlZeroMemory(&in6_dst, sizeof(in6_dst));
		in6_dst.sin6_len = sizeof(struct _sockaddr_in6);
		RtlCopyMemory(&in6_dst.sin6, &routeEntry->DestinationPrefix.Prefix.Ipv6, sizeof(struct sockaddr_in6));

		in6_dst.sin6.sin6_scope_id = routeEntry->InterfaceIndex;
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		in6_embedscope(&in6_dst.sin6.sin6_addr, &in6_dst.sin6);
		KeLowerIrql(oldIrql);
		in6_dst.sin6.sin6_scope_id = 0;

		dst = (struct _sockaddr *)&in6_dst;

		if (routeEntry->DestinationPrefix.PrefixLength < 128) {
			RtlZeroMemory(&in6_netmask, sizeof(in6_netmask));
			in6_netmask.sin6_len = sizeof(struct _sockaddr_in6);
			in6_netmask.sin6.sin6_family = AF_INET6;
			for (i = 0; i < routeEntry->DestinationPrefix.PrefixLength; i++) {
				in6_netmask.sin6.sin6_addr.s6_addr[(i / 8)] |= (0x80 >> (i % 8));
			}
			netmask = (struct _sockaddr *)&in6_netmask;
		} else {
			netmask = NULL;
		}

		nexthop = (struct sockaddr *)&routeEntry->NextHop;
	}
#endif

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	RADIX_NODE_HEAD_LOCK(rnh);

	rn = rnh->rnh_lookup(dst, netmask, rnh);
	if (rn == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_del - leave#2\n");
		goto done;
	}
	rt = (struct rtentry *)rn;

#ifdef RADIX_MPATH
	if (rn_mpath_capable(rnh)) {
		rt = rt_mpath_matchgate(rt, nexthop);
		if (rt == NULL) {
			DebugPrint(DEBUG_NET_VERBOSE, "route_del - leave#3\n");
			goto done;
		}
		rn = (struct radix_node *)rt;
	}
#endif

	rn = rnh->rnh_deladdr(dst, netmask, rnh, rn);
	if (rn == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_del - leave#4\n");
		goto done;
	}
	rt = (struct rtentry *)rn;
	RT_LOCK(rt);
	RT_ADDREF(rt);
	rt->rt_flags &= ~RTF_UP;
	RTFREE_LOCKED(rt);

#ifdef RADIX_MPATH
	if (rn_mpath_capable(rnh)) {
		rn = rnh->rnh_lookup(dst, netmask, rnh);
		if (rn != NULL && rn_mpath_next(rn) == NULL) {
			rt = (struct rtentry *)rn;
			rt->rt_flags &= ~RTF_MPATH;
		}
	}
#endif

done:
	RADIX_NODE_HEAD_UNLOCK(rnh);
	KeLowerIrql(oldIrql);

	DebugPrint(DEBUG_NET_VERBOSE, "route_del - leave\n");
}

void
route_ipv4_init(void)
{
	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_init - enter\n");

#ifdef RADIX_MPATH
	rn_mpath_inithead(&rnh_ipv4, offsetof(struct _sockaddr_in, sin.sin_addr) << 3);
#else
	rn_inithead(&rnh_ipv4, offsetof(struct _sockaddr_in, sin.sin_addr) << 3);
#endif

#if NTDDI_VERSION < NTDDI_LONGHORN
	RtlZeroMemory(ipRouteTablePtr, sizeof(ipRouteTablePtr));
	ipRoutePtrTableCount = 0;
#else
	route_load(AF_INET, rnh_ipv4);
	NotifyRouteChange2(AF_INET, route_change, rnh_ipv4, FALSE, &NotifyRouteV4Handle);
#endif

	route_ipv4_initialized++;

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_init - leave\n");
}

void
route_ipv6_init(void)
{
	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_init - enter\n");

#ifdef RADIX_MPATH
	rn_mpath_inithead(&rnh_ipv6, offsetof(struct _sockaddr_in6, sin6.sin6_addr) << 3);
#else
	rn_inithead(&rnh_ipv6, offsetof(struct _sockaddr_in6, sin6.sin6_addr) << 3);
#endif

#if NTDDI_VERSION < NTDDI_LONGHORN
	RtlZeroMemory(ip6RouteTablePtr, sizeof(ip6RouteTablePtr));
	ip6RoutePtrTableCount = 0;
#else
	route_load(AF_INET6, rnh_ipv6);
	NotifyRouteChange2(AF_INET6, route_change, rnh_ipv6, FALSE, &NotifyRouteV6Handle);
#endif

	route_ipv6_initialized++;

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_init - leave\n");
}

#if NTDDI_VERSION < NTDDI_LONGHORN
static int
route_ipv4_check(
    IPRouteTable **ipRouteTable_ptr,
    IPRouteTable *ipRouteTable1)
{
	KIRQL oldIrql;	
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	TCP_REQUEST_QUERY_INFORMATION_EX tcp_req;

	IPSNMPInfo ipSnmpInfo;

	IPRouteTable *ipRouteTable;
	ULONG ipRouteTableSize = 0;

	ULONG i, ii;

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_check - enter\n");

	if (SctpRawHandle == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_check - leave#1\n");
		return -1;
	}

	if (ipRouteTable_ptr == NULL || ipRouteTable1 == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_check - leave#2\n");
		return -1;
	}

	RtlZeroMemory(&tcp_req, sizeof(tcp_req));
	tcp_req.ID.toi_entity.tei_entity = CL_NL_ENTITY;
	tcp_req.ID.toi_entity.tei_instance = 0;
	tcp_req.ID.toi_class = INFO_CLASS_PROTOCOL;
	tcp_req.ID.toi_type = INFO_TYPE_PROVIDER;
	tcp_req.ID.toi_id = 1; //IP_MIB_STATS_ID

	RtlZeroMemory(&ipSnmpInfo, sizeof(ipSnmpInfo));

	status = ZwDeviceIoControlFile(SctpRawHandle,
	    NULL,
	    NULL,
	    NULL,
	    &statusBlock,
	    IOCTL_TCP_QUERY_INFORMATION_EX,
	    &tcp_req,
	    sizeof(tcp_req),
	    &ipSnmpInfo,
	    sizeof(ipSnmpInfo));
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_check - leave#3,status=%d\n", status);
		return -1;
	}

	if (*ipRouteTable_ptr == NULL || (*ipRouteTable_ptr)->dwNumEntries < ipSnmpInfo.ipsi_numroutes) {
		if (*ipRouteTable_ptr != NULL) {
			ExFreePool(*ipRouteTable_ptr);
			*ipRouteTable_ptr = NULL;
		}
		ipRouteTableSize = sizeof(ULONG) + sizeof(IPRouteEntry) * ipSnmpInfo.ipsi_numroutes;
		*ipRouteTable_ptr = ExAllocatePool(PagedPool, ipRouteTableSize);
		if (*ipRouteTable_ptr == NULL) {
			return -1;
			DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_check - leave#4\n");
		}
		RtlZeroMemory(*ipRouteTable_ptr, ipRouteTableSize);
	}
	ipRouteTable = *ipRouteTable_ptr;
	ipRouteTable->dwNumEntries = ipSnmpInfo.ipsi_numroutes;

	tcp_req.ID.toi_id = 0x101; //IP_MIB_ROUTETABLE_ENTRY_ID
	status = ZwDeviceIoControlFile(SctpRawHandle,
	    NULL,
	    NULL,
	    NULL,
	    &statusBlock,
	    IOCTL_TCP_QUERY_INFORMATION_EX,
	    &tcp_req,
	    sizeof(tcp_req),
	    ipRouteTable->table,
	    sizeof(IPRouteEntry) * ipRouteTable->dwNumEntries);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_check - leave#5,status=%08x\n", status);
		return -1;
	}

#ifdef SCTP_DEBUG
	for (i = 0; i < ipRouteTable->dwNumEntries; i++) {
		if (*sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
			uchar *dest = (uchar *)&ipRouteTable->table[i].ire_dest;
			uchar *mask = (uchar *)&ipRouteTable->table[i].ire_mask;
			uchar *nexthop = (uchar *)&ipRouteTable->table[i].ire_nexthop;
			SCTPDBG(SCTP_DEBUG_OUTPUT4,
			    "route_ipv4_check: IF=%d,DEST=%ld.%ld.%ld.%ld,MASK=%ld.%ld.%ld.%ld,NEXTHOP=%ld.%ld.%ld.%ld\n",
			    ipRouteTable->table[i].ire_index,
			    dest[0], dest[1], dest[2], dest[3],
			    mask[0], mask[1], mask[2], mask[3],
			    nexthop[0], nexthop[1], nexthop[2], nexthop[3]);
		}
	}
#endif

	for (i = 0; i < ipRouteTable1->dwNumEntries; i++) {
		for (ii = 0; ii < ipRouteTable->dwNumEntries; ii++) {
			if (ipRouteTable1->table[i].ire_dest == ipRouteTable->table[ii].ire_dest &&
			    ipRouteTable1->table[i].ire_mask == ipRouteTable->table[ii].ire_mask &&
			    ipRouteTable1->table[i].ire_nexthop == ipRouteTable->table[ii].ire_nexthop) {
				break;
			}
		}
		if (ii < ipRouteTable->dwNumEntries) {
			continue;
		}

		route_del(rnh_ipv4, &ipRouteTable1->table[i], NULL);
	}

	for (i = 0; i < ipRouteTable->dwNumEntries; i++) {
		for (ii = 0; ii < ipRouteTable1->dwNumEntries; ii++) {
			if (ipRouteTable->table[i].ire_dest == ipRouteTable1->table[ii].ire_dest &&
			    ipRouteTable->table[i].ire_mask == ipRouteTable1->table[ii].ire_mask &&
			    ipRouteTable->table[i].ire_nexthop == ipRouteTable1->table[ii].ire_nexthop) {
				break;
			}
		}
		if (ii < ipRouteTable1->dwNumEntries) {
			continue;
		}
		route_add(rnh_ipv4, &ipRouteTable->table[i], NULL);
	}

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_load - leave\n");
	return 0;
}

static int
route_ipv6_check(
    IPv6RouteTable **ip6RouteTable_ptr,
    IPv6RouteTable *ip6RouteTable1)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statusBlock;
	IPv6QueryRouteEntry qroute;
	IPv6RouteEntry route;
	IPv6RouteTable *ip6RouteTable;
	size_t ip6RouteTableSize = 0;

	ULONG ulNumEntries, ulNumActiveEntries;
	unsigned int i, ii;

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_check - enter\n");

	if (TpIP6Handle == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_check - leave#1\n");
		return -1;
	}

	if (ip6RouteTable_ptr == NULL || ip6RouteTable1 == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_check - leave#2\n");
		return -1;
	}

	ip6RouteTable = *ip6RouteTable_ptr;
	if (ip6RouteTable != NULL) {
		ip6RouteTable->ulNumActiveEntries = 0;
	}

	RtlZeroMemory(&qroute, sizeof(qroute));
	RtlZeroMemory(&route, sizeof(route));

	ulNumActiveEntries = 0;
	route.i6re_query.i6qre_index = 0;
	do {
		RtlCopyMemory(&qroute, &route.i6re_query, sizeof(IPv6QueryRouteEntry));

		status = ZwDeviceIoControlFile(TpIP6Handle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    1179700,// 1212472 for add 1212472 for delete (Type is needed?)
		    &qroute,
		    sizeof(qroute),
		    &route,
		    sizeof(route));
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_check - leave#3, status=%08x\n", status);
			return -1;
		}

		if (qroute.i6qre_index != 0) {
			if (ip6RouteTable == NULL || ip6RouteTable->ulNumActiveEntries + 1 > ip6RouteTable->ulNumEntries) {
				if (ip6RouteTable == NULL) {
					ulNumEntries = 256;
				} else {
					ulNumEntries = ip6RouteTable->ulNumEntries * 2;
				}

				ip6RouteTableSize = sizeof(IPv6RouteTable) +
					sizeof(IPv6RouteEntry) * (ulNumEntries - 1);
				ip6RouteTable = ExAllocatePool(NonPagedPool, ip6RouteTableSize);
				if (ip6RouteTable == NULL) {
					return -1;
				}
				RtlZeroMemory(ip6RouteTable, ip6RouteTableSize);

				if (*ip6RouteTable_ptr != NULL) {
					RtlCopyMemory(&ip6RouteTable->Entries, &(*ip6RouteTable_ptr)->Entries,
					    sizeof(IPv6RouteEntry) * (*ip6RouteTable_ptr)->ulNumActiveEntries);
					ip6RouteTable->ulNumActiveEntries = (*ip6RouteTable_ptr)->ulNumActiveEntries;
				} else {
					ip6RouteTable->ulNumActiveEntries = 0;
				}
				ip6RouteTable->ulNumEntries = ulNumEntries;

				if (*ip6RouteTable_ptr != NULL) {
					ExFreePool(*ip6RouteTable_ptr);
				}
				*ip6RouteTable_ptr = ip6RouteTable;
			}

			SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_ipv6_check: IF=%d,DEST=%s,PREFIXLEN=%d,",
			    qroute.i6qre_index,
			    ip6_sprintf(&qroute.i6qre_addr),
			    qroute.i6qre_prefix);
			SCTPDBG(SCTP_DEBUG_OUTPUT4, "NEXTHOP=%s\n",
			    ip6_sprintf(&qroute.i6qre_gw));

			RtlCopyMemory(&ip6RouteTable->Entries[ip6RouteTable->ulNumActiveEntries], &route,
			    sizeof(IPv6RouteEntry));
			RtlCopyMemory(&ip6RouteTable->Entries[ip6RouteTable->ulNumActiveEntries].i6re_query, &qroute,
			    sizeof(IPv6QueryRouteEntry));
			ip6RouteTable->ulNumActiveEntries++;
		}
	} while (route.i6re_query.i6qre_index != 0);

	if(ip6RouteTable == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_check- leave#4\n");
		return -1;
	}

	for (i = 0; i < ip6RouteTable1->ulNumActiveEntries; i++) {
		for (ii = 0; ii < ip6RouteTable->ulNumActiveEntries; ii++) {
			if (IN6_ADDR_EQUAL(&ip6RouteTable1->Entries[i].i6re_query.i6qre_addr,
				&ip6RouteTable->Entries[ii].i6re_query.i6qre_addr) &&
			    ip6RouteTable1->Entries[i].i6re_query.i6qre_prefix ==
				ip6RouteTable->Entries[ii].i6re_query.i6qre_prefix &&
			    ip6RouteTable1->Entries[i].i6re_query.i6qre_index ==
				ip6RouteTable->Entries[ii].i6re_query.i6qre_index &&
			    IN6_ADDR_EQUAL(&ip6RouteTable1->Entries[i].i6re_query.i6qre_gw,
				&ip6RouteTable->Entries[ii].i6re_query.i6qre_gw)) {
				break;
			}
		}
		if (ii < ip6RouteTable->ulNumActiveEntries) {
			continue;
		}
		route_del(rnh_ipv6, NULL, &ip6RouteTable1->Entries[i]);
	}

	for (i = 0; i < ip6RouteTable->ulNumActiveEntries; i++) {
		for (ii = 0; ii < ip6RouteTable1->ulNumActiveEntries; ii++) {
			if (IN6_ADDR_EQUAL(&ip6RouteTable->Entries[i].i6re_query.i6qre_addr,
				&ip6RouteTable1->Entries[ii].i6re_query.i6qre_addr) &&
			    ip6RouteTable->Entries[i].i6re_query.i6qre_prefix ==
				ip6RouteTable1->Entries[ii].i6re_query.i6qre_prefix &&
			    ip6RouteTable->Entries[i].i6re_query.i6qre_index ==
				ip6RouteTable1->Entries[ii].i6re_query.i6qre_index &&
			    IN6_ADDR_EQUAL(&ip6RouteTable->Entries[i].i6re_query.i6qre_gw,
				&ip6RouteTable1->Entries[ii].i6re_query.i6qre_gw)) {
				break;
			}
		}
		if (ii < ip6RouteTable1->ulNumActiveEntries) {
			continue;
		}
		route_add(rnh_ipv6, NULL, &ip6RouteTable->Entries[i]);
	}

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_check - leave\n");
	return 0;
}

struct radix_node *
route_ipv6_add(
    IPv6RouteEntry *routeV6Entry)
{
	struct radix_node *ret = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_add - enter\n");

	ret = route_add(rnh_ipv6, NULL, routeV6Entry);

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_add - leave\n");
	return ret;
}

void
route_ipv6_del(
    IPv6RouteEntry *routeV6Entry)
{
	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_del - enter\n");

	route_del(rnh_ipv6, NULL, routeV6Entry);

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_del - leave\n");
}

int
route_ipv4_reload(void)
{
	int ret = 0;

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_reload - enter\n");

	if (ipRoutePtrTableInitialized == 0) {
		IPRouteTable ipRouteTable1;

		RtlZeroMemory(&ipRouteTable1, sizeof(ipRouteTable1));
		ret = route_ipv4_check(&ipRouteTablePtr[ipRoutePtrTableCount % 2], &ipRouteTable1);
		if (ret == 0) {
			ipRoutePtrTableCount++;
			ipRoutePtrTableInitialized++;
		}
	} else {
		ret = route_ipv4_check(&ipRouteTablePtr[ipRoutePtrTableCount % 2],
		    ipRouteTablePtr[(ipRoutePtrTableCount - 1) % 2]);
		if (ret == 0) {
			ipRoutePtrTableCount++;
		}
	}

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv4_reload - leave\n");
	return ret;
}

int
route_ipv6_reload(void)
{
	int ret = 0;

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_reload - enter\n");

	if (ip6RoutePtrTableInitialized == 0) {
		IPv6RouteTable ip6RouteTable1;

		RtlZeroMemory(&ip6RouteTable1, sizeof(ip6RouteTable1));
		ret = route_ipv6_check(&ip6RouteTablePtr[ip6RoutePtrTableCount % 2], &ip6RouteTable1);
		if (ret == 0) {
			ip6RoutePtrTableCount++;
			ip6RoutePtrTableInitialized++;
		}
	} else {
		ret = route_ipv6_check(&ip6RouteTablePtr[ip6RoutePtrTableCount % 2],
		    ip6RouteTablePtr[(ip6RoutePtrTableCount - 1) % 2]);
		if (ret == 0) {
			ip6RoutePtrTableCount++;
		}
	}

	DebugPrint(DEBUG_NET_VERBOSE, "route_ipv6_reload - leave\n");
	return ret;
}

static
void
route_reload_thread(void *v)
{
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER timeout;

	DebugPrint(DEBUG_NET_VERBOSE, "route_reload_thread - enter\n");
	timeout.QuadPart = - 10000000 * 60;
	for (;;) {
		status = KeWaitForSingleObject(&ReloadThrStop, Executive, KernelMode, FALSE, &timeout);
		if (status == STATUS_SUCCESS) {
			break;
		}
		if (SctpRawHandle != NULL) {
			route_ipv4_reload();
		}
		if (TpIP6Handle != NULL) {
			route_ipv6_reload();
		}
	}

	DebugPrint(DEBUG_NET_VERBOSE, "route_reload_thread - leave\n");
}

#else
static void
route_load(
    ADDRESS_FAMILY family,
    struct radix_node_head *rnh)
{
	NTSTATUS status;
	PMIB_IPFORWARD_TABLE2 ipForwardTable = NULL;
	ULONG i;
	struct radix_node *rn = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "route_load - enter\n");

	status = GetIpForwardTable2(family, &ipForwardTable);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_load - leave#1,status=%08x\n", status);
		return;
	}

#ifdef SCTP_DEBUG
	for (i = 0; i < ipForwardTable->NumEntries; i++) {
		SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_load:IF=%d\n\tDEST=", ipForwardTable->Table[i].InterfaceIndex);
		SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4, (struct sockaddr *)&ipForwardTable->Table[i].DestinationPrefix.Prefix);
		SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tPREFIXLEN=%d\n", ipForwardTable->Table[i].DestinationPrefix.PrefixLength);
		SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tNEXTHOP=");
		SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4, (struct sockaddr *)&ipForwardTable->Table[i].NextHop);
	}
#endif

	for (i = 0; i < ipForwardTable->NumEntries; i++) {
		route_add(rnh, &ipForwardTable->Table[i]);
	}

	if (ipForwardTable != NULL) {
		FreeMibTable(ipForwardTable);
	}

	DebugPrint(DEBUG_NET_VERBOSE, "route_load - leave\n");
}

static void
route_change(
    PVOID context,
    PMIB_IPFORWARD_ROW2 routeEntry,
    MIB_NOTIFICATION_TYPE type)
{
	struct radix_node_head *rnh = (struct radix_node_head *)context;

	DebugPrint(DEBUG_NET_VERBOSE, "route_change - enter\n");

	if (routeEntry == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "route_change - leave#1\n");
		return;
	}
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "route_change:type=%d\n\tDEST=", type);
	SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4, (struct sockaddr *)&routeEntry->DestinationPrefix.Prefix);
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tPREFIXLEN=%d\n", routeEntry->DestinationPrefix.PrefixLength);
	SCTPDBG(SCTP_DEBUG_OUTPUT4, "\tNEXTHOP=");
	SCTPDBG_ADDR(SCTP_DEBUG_OUTPUT4, (struct sockaddr *)&routeEntry->NextHop);

	switch (type) {
	case MibAddInstance:
		route_add(rnh, routeEntry);
		break;
	case MibDeleteInstance:
		route_del(rnh, routeEntry);
		break;
	}

	DebugPrint(DEBUG_NET_VERBOSE, "route_change - leave\n");
}
#endif
