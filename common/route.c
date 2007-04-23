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
 * $Id: route.c,v 1.1 2007/04/23 15:50:03 kozuka Exp $
 */

#include "globals.h"
#include "if.h"
#include "route.h"

#define IP6Device L"\\Device\\Ip6"


extern HANDLE TpHandle;


struct radix_node_head *rnh_ipv4 = NULL, *rnh_ipv6 = NULL;


void route_ipv4_init(void);
void route_ipv6_init(void);


void
rtalloc(struct route *ro)
{
	struct radix_node_head *rnh = NULL;
	struct radix_node *rn;
	struct rtentry *rt;

	if (ro->ro_dst.sa.sa_family != AF_INET &&
	    ro->ro_dst.sa.sa_family != AF_INET6) {
		return;
	}

	switch (ro->ro_dst.sa.sa_family) {
	case AF_INET:
		rnh = rnh_ipv4;
		break;
	case AF_INET6:
		rnh = rnh_ipv6;
		break;
	}

	RADIX_NODE_HEAD_LOCK(rnh);
	rn = rnh->rnh_matchaddr(&ro->ro_dst.sa, rnh);
	if (rn != NULL && (rn->rn_flags & RNF_ROOT) == 0) {
		rt = (struct rtentry *)rn;
		RT_LOCK(rt);
		RT_ADDREF(rt);
		RT_UNLOCK(rt);

		ro->ro_rt = rt;
	}
	RADIX_NODE_HEAD_UNLOCK(rnh);
}

void
rtfree(struct rtentry *rt)
{
	struct radix_node_head *rnh = NULL;

	if (rt == NULL) {
		return;
	}

	RT_REMREF(rt);
	if (rt->rt_refcnt > 0) {
		RT_UNLOCK(rt);
		return;
	}
	switch ((rt_key(rt))->sa_family) {
	case AF_INET:
		rnh = rnh_ipv4;
		break;
	case AF_INET6:
		rnh = rnh_ipv6;
		break;
	}

	if (rnh->rnh_close) {
		rnh->rnh_close((struct radix_node *)rt, rnh);
	}

	if ((rt->rt_flags & RT_FLAG_UP) == 0) {
		RT_LOCK_DESTROY(rt);
		ExFreePool(rt);
	} else {
		RT_UNLOCK(rt);
	}
	return;
}

void
route_init(void)
{
	rn_init();
	route_ipv4_init();
	route_ipv6_init();
}


void
route_ipv4_init(void)
{
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	TCP_REQUEST_QUERY_INFORMATION_EX tcp_req;
	IPSNMPInfo ipSnmpInfo;
	IPAddrEntry *ipAddr;
	ULONG ipAddrSize = 0;
	IPRouteEntry *ipRoute;
	ULONG ipRouteSize = 0;
	ULONG i, j;
	struct rtentry *rt;
	struct radix_node *rn;
	struct ifnet *ifn;
	struct ifaddr *ifa;

	rn_inithead(&rnh_ipv4, offsetof(struct sockaddr_in, sin_addr));

	RtlZeroMemory(&tcp_req, sizeof(tcp_req));
	tcp_req.ID.toi_entity.tei_entity = CL_NL_ENTITY;
	tcp_req.ID.toi_entity.tei_instance = 0;
	tcp_req.ID.toi_class = INFO_CLASS_PROTOCOL;
	tcp_req.ID.toi_type = INFO_TYPE_PROVIDER;
	tcp_req.ID.toi_id = 1; //IP_MIB_STATS_ID

	RtlZeroMemory(&ipSnmpInfo, sizeof(ipSnmpInfo));

	status = ZwDeviceIoControlFile(TpHandle,
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
		DbgPrint("ZwDeviceIoControlFile failed, error=%08x\n", status);
		return;
	}

	tcp_req.ID.toi_id = 0x102; //IP_MIB_ADDRTABLE_ENTRY_ID;
	DbgPrint("ipsi_numaddr=>%u\n", ipSnmpInfo.ipsi_numaddr);
	ipAddrSize = sizeof(IPAddrEntry) * ipSnmpInfo.ipsi_numaddr;
	ipAddr = ExAllocatePool(PagedPool, ipAddrSize);
	if (ipAddr == NULL) {
		return;
	}
	RtlZeroMemory(ipAddr, ipAddrSize);
	status = ZwDeviceIoControlFile(TpHandle,
	    NULL,
	    NULL,
	    NULL,
	    &statusBlock,
	    IOCTL_TCP_QUERY_INFORMATION_EX,
	    &tcp_req,
	    sizeof(tcp_req),
	    ipAddr,
	    ipAddrSize);
	if (status != STATUS_SUCCESS) {
		DbgPrint("ZwDeviceIoControlFile failed, error=%08x\n", status);
		return;
	}

	for (i = 0; i < ipSnmpInfo.ipsi_numaddr; i++) {
		uchar *addr = (uchar *)&ipAddr[i].iae_addr;
		uchar *mask = (uchar *)&ipAddr[i].iae_mask;
		uchar *broad = (uchar *)&ipAddr[i].iae_bcastaddr;

		DbgPrint("ADDR: %ld.%ld.%ld.%ld, MASK: %ld.%ld.%ld.%ld, BROAD: %ld.%ld.%ld.%ld, ifidx: %d\n",
		    addr[0], addr[1], addr[2], addr[3],
		    mask[0], mask[1], mask[2], mask[3],
		    broad[0], broad[1], broad[2], broad[3],
		    ipAddr[i].iae_index);
	}

	DbgPrint("ipsi_numroutes=>%u\n", ipSnmpInfo.ipsi_numroutes);
	tcp_req.ID.toi_id = 0x101; //IP_MIB_ROUTETABLE_ENTRY_ID

	ipRouteSize = sizeof(IPRouteEntry) * ipSnmpInfo.ipsi_numroutes;
	ipRoute = ExAllocatePool(PagedPool, ipRouteSize);
	if (ipRoute == NULL) {
		ExFreePool(ipAddr);
		return;
	}
	RtlZeroMemory(ipRoute, ipRouteSize);
	status = ZwDeviceIoControlFile(TpHandle,
	    NULL,
	    NULL,
	    NULL,
	    &statusBlock,
	    IOCTL_TCP_QUERY_INFORMATION_EX,
	    &tcp_req,
	    sizeof(tcp_req),
	    ipRoute,
	    ipRouteSize);
	if (status != STATUS_SUCCESS) {
		DbgPrint("ZwDeviceIoControlFile failed, error=%08x\n", status);
		ExFreePool(ipAddr);
		ExFreePool(ipRoute);
		return;
	}

	for (i = 0; i < ipSnmpInfo.ipsi_numroutes; i++) {
		uchar *addr = (uchar *)&ipRoute[i].ire_addr;
		uchar *mask = (uchar *)&ipRoute[i].ire_mask;
		uchar *gw = (uchar *)&ipRoute[i].ire_gw;
		uchar _ifaddr[4] = {0x00, 0x00, 0x00, 0x00};
		uchar *ifaddr = _ifaddr;

		for (j = 0; j < ipSnmpInfo.ipsi_numroutes; j++) {
			if (ipAddr[j].iae_index == ipRoute[i].ire_index) {
				ifaddr = (uchar *)&ipAddr[j].iae_addr;
				break;
			}
		}
		DbgPrint("NEXTHOP: %ld.%ld.%ld.%ld, MASK: %ld.%ld.%ld.%ld, GW: %ld.%ld.%ld.%ld, IF: %ld.%ld.%ld.%ld\n",
		    addr[0], addr[1], addr[2], addr[3],
		    mask[0], mask[1], mask[2], mask[3],
		    gw[0], gw[1], gw[2], gw[3],
		    ifaddr[0], ifaddr[1], ifaddr[2], ifaddr[3]);

		rt = ExAllocatePool(NonPagedPool, sizeof(*rt));
		RtlZeroMemory(rt, sizeof(*rt));

		RT_LOCK_INIT(rt);
		rt->rt_dst.sin.sin_family = AF_INET;
		rt->rt_dst.sin.sin_len = sizeof(struct sockaddr_in);
		RtlCopyMemory(&rt->rt_dst.sin.sin_addr, &ipRoute[i].ire_addr, sizeof(struct in_addr));
		rt->rt_netmask.sin.sin_family = AF_INET;
		rt->rt_netmask.sin.sin_len = sizeof(struct sockaddr_in);
		RtlCopyMemory(&rt->rt_netmask.sin.sin_addr, &ipRoute[i].ire_mask, sizeof(struct in_addr));
		rt->rt_gateway.sin.sin_family = AF_INET;
		rt->rt_gateway.sin.sin_len = sizeof(struct sockaddr_in);
		RtlCopyMemory(&rt->rt_gateway.sin.sin_addr, &ipRoute[i].ire_gw, sizeof(struct in_addr));

		rt->rt_flags |= RT_FLAG_UP;

		IFNET_WLOCK();
		TAILQ_FOREACH(ifn, &ifnet, if_link) {
			IF_LOCK(ifn);
			TAILQ_FOREACH(ifa, &ifn->if_addrhead, ifa_link) {
				if (ifa->ifa_addr.ss_family != AF_INET) {
					continue;
				}
				if (((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr == ipAddr[j].iae_addr) {
					break;
				}
			}
			IF_UNLOCK(ifn);
			if (ifa != NULL) {
				break;
			}
		}
		IFNET_WUNLOCK();
		if (ifn != NULL && ifa != NULL) {
			IF_INCR_REF(ifn);
			IFA_INCR_REF(ifa);
			rt->rt_ifp = ifn;
			rt->rt_ifa = ifa;
		}

		rt_key(rt) = &rt->rt_dst.sa;
		rt_mask(rt) = &rt->rt_netmask.sa;

		rn = rnh_ipv4->rnh_addaddr(rt_key(rt), rt_mask(rt), rnh_ipv4, rt->rt_nodes);
	}

	ExFreePool(ipAddr);
	ExFreePool(ipRoute);
}

void
route_ipv6_init(void)
{
	NTSTATUS status;
	UNICODE_STRING devname;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statusBlock;
	HANDLE IPv6Handle = NULL;
	IPv6QueryRouteEntry qroute;
	IPv6RouteEntry route;

	struct radix_node *rn;
	struct rtentry *rt;
	unsigned int i;
	struct ifnet *ifn;
	struct ifaddr *ifa;

	RtlInitUnicodeString(&devname, IP6Device);

	InitializeObjectAttributes(&attr,
	    &devname,
	    OBJ_CASE_INSENSITIVE,
	    NULL,
	    NULL);

	status = ZwCreateFile(&IPv6Handle,
	    GENERIC_READ | GENERIC_WRITE,
	    &attr,
	    &statusBlock,
	    0L,
	    FILE_ATTRIBUTE_NORMAL,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    FILE_OPEN_IF,
	    0L,
	    NULL,
	    0);

	if (status != STATUS_SUCCESS) {
		DbgPrint( "ZwCreateFile failed, code=%d\n", status);
		return;
	}

	rn_inithead(&rnh_ipv6, offsetof(struct sockaddr_in6, sin6_addr));

	qroute.i6qre_index = 0;
	for (;;) {
		status = ZwDeviceIoControlFile(IPv6Handle,
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
			DbgPrint("ZwDeviceIoControlFile for 1179700 failed, code=%x\n", status);
			ZwClose(IPv6Handle);
			return;
		}
		if (qroute.i6qre_index != 0) {
			DbgPrint("%s/%d => ", ip6_sprintf(&qroute.i6qre_addr), qroute.i6qre_prefix);
			DbgPrint("%d/%s, metric=%d\n",
			    qroute.i6qre_index,
			    ip6_sprintf(&qroute.i6qre_gw),
			    route.i6re_metric);

			rt = ExAllocatePool(NonPagedPool, sizeof(*rt));
			RtlZeroMemory(rt, sizeof(*rt));

			RT_LOCK_INIT(rt);

			rt->rt_dst.sin6.sin6_family = AF_INET6;
			rt->rt_dst.sin6.sin6_len = sizeof(struct sockaddr_in6);
			RtlCopyMemory(&rt->rt_dst.sin6.sin6_addr, &qroute.i6qre_addr, sizeof(struct in6_addr));
			if (IN6_IS_ADDR_LINKLOCAL(&rt->rt_dst.sin6.sin6_addr) ||
			    IN6_IS_ADDR_MULTICAST(&rt->rt_dst.sin6.sin6_addr)) {
				rt->rt_dst.sin6.sin6_scope_id = qroute.i6qre_index;
			}
			rt->rt_netmask.sin6.sin6_family = AF_INET6;
			rt->rt_netmask.sin6.sin6_len = sizeof(struct sockaddr_in6);
			for (i = 0; i < qroute.i6qre_prefix; i++) {
				rt->rt_netmask.sin6.sin6_addr.s6_addr[(i / 8)] |= (0x80 >> (i % 8));
			}
			rt->rt_gateway.sin6.sin6_family = AF_INET6;
			rt->rt_gateway.sin6.sin6_len = sizeof(struct sockaddr_in6);
			RtlCopyMemory(&rt->rt_gateway.sin6.sin6_addr, &qroute.i6qre_gw, sizeof(struct in6_addr));
			if (IN6_IS_ADDR_LINKLOCAL(&rt->rt_gateway.sin6.sin6_addr)) {
				rt->rt_gateway.sin6.sin6_scope_id = qroute.i6qre_index;
			}

			rt->rt_flags |= RT_FLAG_UP;

			IFNET_WLOCK();
			TAILQ_FOREACH(ifn, &ifnet, if_link) {
				IF_LOCK(ifn);
				TAILQ_FOREACH(ifa, &ifn->if_addrhead, ifa_link) {
					if (ifa->ifa_addr.ss_family != AF_INET6) {
						continue;
					}
					if (((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id == qroute.i6qre_index) {
						break;
					}
				}
				IF_UNLOCK(ifn);
				if (ifa != NULL) {
					break;
				}
			}
			IFNET_WUNLOCK();
			if (ifn != NULL && ifa != NULL) {
				IF_INCR_REF(ifn);
				IFA_INCR_REF(ifa);
				rt->rt_ifp = ifn;
				rt->rt_ifa = ifa;
			}

			rt_key(rt) = &rt->rt_dst.sa;
			rt_mask(rt) = &rt->rt_netmask.sa;
			rn = rnh_ipv6->rnh_addaddr(rt_key(rt), rt_mask(rt), rnh_ipv6, rt->rt_nodes);
		}

		if (route.i6re_query.i6qre_index == 0) {
			break;
		}
		RtlCopyMemory(&qroute, &route.i6re_query, sizeof(IPv6QueryRouteEntry));
	}

	ZwClose(IPv6Handle);
}
