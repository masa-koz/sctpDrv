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

#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>

#if NTDDI_VERSION >= NTDDI_LONGHORN
#include <netioapi.h>
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet6/in6.h>


#define IOCTL_TCP_QUERY_INFORMATION_EX 1179651

#define PREFIX_TCPIP		L"\\DEVICE\\TCPIP_"
#define PREFIX_TCPIP6		L"\\DEVICE\\TCPIP6_"
#define PREFIX_TCPIP_SIZE	(sizeof(PREFIX_TCPIP) - sizeof(WCHAR))
#define PREFIX_TCPIP6_SIZE	(sizeof(PREFIX_TCPIP6) - sizeof(WCHAR))
#define PREFIX_TCPIP_LEN	((sizeof(PREFIX_TCPIP) / sizeof(WCHAR)) - 1)
#define PREFIX_TCPIP6_LEN	((sizeof(PREFIX_TCPIP6) / sizeof(WCHAR)) - 1)

NTSTATUS ClientPnPPowerChange(IN PUNICODE_STRING, IN PNET_PNP_EVENT, IN PTDI_PNP_CONTEXT, IN PTDI_PNP_CONTEXT);
VOID ClientPnPBindingChange(IN TDI_PNP_OPCODE, IN PUNICODE_STRING, IN PWSTR);
VOID ClientPnPAddNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);
VOID ClientPnPDelNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);
static struct ifnet *ifnet_craete_common(void);
#if NTDDI_VERSION < NTDDI_LONGHORN
static struct ifnet *ifnet_create_by_ipaddr(PTDI_ADDRESS_IP, GUID *);
static struct ifnet *ifnet_create_by_guid(GUID *);
#else
static struct ifnet *ifnet_create_by_guid(ADDRESS_FAMILY, GUID *);
#endif

void sctp_addr_change(struct ifaddr *ifa, int cmd);

extern HANDLE SctpRawHandle;
extern HANDLE TpIP6Handle;

HANDLE BindingHandle;
int if_index = 0;
struct ifnethead ifnet;
KSPIN_LOCK ifnet_lock;


int
if_init(void)
{
	NTSTATUS status;
	UNICODE_STRING clientName;
	TDI_CLIENT_INTERFACE_INFO ClientInterfaceInfo;

	DebugPrint(DEBUG_NET_VERBOSE, "if_init - enter\n");

	TAILQ_INIT(&ifnet);
	IFNET_LOCK_INIT();

	RtlInitUnicodeString(&clientName, L"HKLM\\System\\CCS\\Services\\Sctp");

	RtlZeroMemory(&ClientInterfaceInfo, sizeof(ClientInterfaceInfo));
	ClientInterfaceInfo.MajorTdiVersion = TDI_CURRENT_MAJOR_VERSION;
	ClientInterfaceInfo.MinorTdiVersion = TDI_CURRENT_MINOR_VERSION;
	ClientInterfaceInfo.ClientName = &clientName;
	ClientInterfaceInfo.PnPPowerHandler = ClientPnPPowerChange;
	ClientInterfaceInfo.BindingHandler = ClientPnPBindingChange;
	ClientInterfaceInfo.AddAddressHandlerV2 = ClientPnPAddNetAddress;
	ClientInterfaceInfo.DelAddressHandlerV2 = ClientPnPDelNetAddress;

	status = TdiRegisterPnPHandlers(&ClientInterfaceInfo, sizeof(ClientInterfaceInfo), &BindingHandle);
	if (status != STATUS_SUCCESS) {
		BindingHandle = NULL;
		DebugPrint(DEBUG_NET_VERBOSE, "if_init - leave#1\n");
		return -1;
	}

	DebugPrint(DEBUG_NET_VERBOSE, "if_init - leave\n");
	return 0;
}

void
if_destroy(void)
{
	DebugPrint(DEBUG_NET_VERBOSE, "if_destroy - enter\n");

	if (BindingHandle != NULL) {
		TdiDeregisterPnPHandlers(BindingHandle);
	}

	DebugPrint(DEBUG_NET_VERBOSE, "if_destroy - leave\n");
}


NTSTATUS
ClientPnPPowerChange(
    IN PUNICODE_STRING deviceName,
    IN PNET_PNP_EVENT powerEvent,
    IN PTDI_PNP_CONTEXT context1,
    IN PTDI_PNP_CONTEXT context2)
{
	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPPowerChange - enter\n");
	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPPowerChange: powerEvent->NetEvent=%d,powerEvent->Buffer=%d\n",
	    powerEvent->NetEvent, PtrToLong(powerEvent->Buffer));
	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPPowerChange - leave\n");
	return STATUS_SUCCESS;
}


VOID
ClientPnPBindingChange(
    IN TDI_PNP_OPCODE pnpOpcode,
    IN PUNICODE_STRING deviceName,
    IN PWSTR multiSZBindList)
{
	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPBindingChange - enter\n");
	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPBindingChange - leave\n");
}


VOID
ClientPnPAddNetAddress(
    IN PTA_ADDRESS Address,
    IN PUNICODE_STRING DeviceName,
    IN PTDI_PNP_CONTEXT Context)
{
	KIRQL oldIrql;
	NTSTATUS status;
	UNICODE_STRING guidStr;
	GUID guid;
	int i, len;
	unsigned char *p;
	struct ifnet *ifp, *ifp1;
	struct ifaddr *ifa;
	struct sockaddr_storage addr;

	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPAddNetAddress - enter\n");

	DebugPrint(DEBUG_NET_INFO, "ClientPnPAddNetAddress: DeviceName=\"%ws\"\n", DeviceName->Buffer);
	if (DeviceName->Length > PREFIX_TCPIP6_LEN &&
	    RtlCompareMemory(DeviceName->Buffer, PREFIX_TCPIP6, PREFIX_TCPIP6_SIZE) == PREFIX_TCPIP6_SIZE) {
		RtlInitUnicodeString(&guidStr, &DeviceName->Buffer[PREFIX_TCPIP6_LEN]);
	} else if (
	    DeviceName->Length > PREFIX_TCPIP_LEN &&
	    RtlCompareMemory(DeviceName->Buffer, PREFIX_TCPIP, PREFIX_TCPIP_SIZE) == PREFIX_TCPIP_SIZE) {
		RtlInitUnicodeString(&guidStr, &DeviceName->Buffer[PREFIX_TCPIP_LEN]);
	} else {
		return;
	}

	status = RtlGUIDFromString(&guidStr, &guid);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPAddNetAddress - leave#1\n");
		return;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (IsEqualGUID(&guid, &ifp->if_guid) && ifp->if_family == Address->AddressType) {
			break;
		}
	}
	if (ifp == NULL) {
		IFNET_WUNLOCK();
		KeLowerIrql(oldIrql);
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP)) {
#if NTDDI_VERSION < NTDDI_LONGHORN
			ifp = ifnet_create_by_ipaddr((PTDI_ADDRESS_IP)Address->Address, &guid);
#else
			ifp = ifnet_create_by_guid(AF_INET, &guid);
#endif
		} else {
#if NTDDI_VERSION < NTDDI_LONGHORN
			ifp = ifnet_create_by_guid(&guid);
			if (ifp != NULL) {
				IPv6RouteEntry routeV6Entry1;

				RtlZeroMemory(&routeV6Entry1, sizeof(routeV6Entry1));
				routeV6Entry1.i6re_query.i6qre_addr.s6_addr[0] = 0xfe;
				routeV6Entry1.i6re_query.i6qre_addr.s6_addr[1] = 0x80;
				routeV6Entry1.i6re_query.i6qre_prefix = 64;
				routeV6Entry1.i6re_query.i6qre_index = ifp->if_ifIndex;

				route_ipv6_add(&routeV6Entry1);
			}
#else
			ifp = ifnet_create_by_guid(AF_INET6, &guid);
#endif
		}
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		if (ifp == NULL) {
			DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPAddNetAddress - leave#2\n");
			goto done;
		}
		IFNET_WLOCK();
		IFFREE(ifp);
		IF_LOCK(ifp);
		IFNET_WUNLOCK();
	} else {
		IF_LOCK(ifp);
		IFNET_WUNLOCK();
	}

	DebugPrint(DEBUG_NET_INFO, "ClientPnPAddNetAddress: if_index=%d,if_ifIndex=%d,if_type=%d,if_mtu=%d\n",
	    ifp->if_index, ifp->if_ifIndex, ifp->if_type, ifp->if_mtu);

	RtlZeroMemory(&addr, sizeof(addr));
	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		addr.ss_family = AF_INET;
		RtlCopyMemory(&((struct sockaddr_in *)&addr)->sin_addr, &((PTDI_ADDRESS_IP)Address->Address)->in_addr,
		    sizeof(struct in_addr));
		break;
	case TDI_ADDRESS_TYPE_IP6:
		addr.ss_family = AF_INET6;
		RtlCopyMemory(&((struct sockaddr_in6 *)&addr)->sin6_addr, &((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
		    sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&addr)->sin6_scope_id = ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id;
		in6_embedscope(&((struct sockaddr_in6 *)&addr)->sin6_addr,
		    ((struct sockaddr_in6 *)&addr));
		break;
	}

	ifa = ifnet_append_address(ifp, (struct sockaddr *)&addr);
	IF_UNLOCK(ifp);
	if (ifa == NULL) {
		goto done;
	}

#if NTDDI_VERSION < NTDDI_LONGHORN
	KeLowerIrql(oldIrql);
	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		route_ipv4_reload();
		break;
	case TDI_ADDRESS_TYPE_IP6:
		route_ipv6_reload();
		break;
	}
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif

	sctp_addr_change(ifa, RTM_ADD);
done:
	KeLowerIrql(oldIrql);
}


VOID
ClientPnPDelNetAddress(
    IN PTA_ADDRESS Address,
    IN PUNICODE_STRING DeviceName,
    IN PTDI_PNP_CONTEXT Context)
{
	KIRQL oldIrql;
	UNICODE_STRING guidStr;
	NTSTATUS status;
	GUID guid;
	int i, len;
	unsigned char *p;
	struct ifnet *ifp;
	struct ifaddr *ifa;

	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPDelNetAddress - enter\n");

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	DebugPrint(DEBUG_NET_INFO, "ClientPnPDelNetAddress: DeviceName=\"%ws\"\n", DeviceName->Buffer);

	if (DeviceName->Length > PREFIX_TCPIP6_LEN &&
	    RtlCompareMemory(DeviceName->Buffer, PREFIX_TCPIP6, PREFIX_TCPIP6_SIZE) == PREFIX_TCPIP6_SIZE) {
		RtlInitUnicodeString(&guidStr, &DeviceName->Buffer[PREFIX_TCPIP6_LEN]);
	} else if (
	    DeviceName->Length > PREFIX_TCPIP_LEN &&
	    RtlCompareMemory(DeviceName->Buffer, PREFIX_TCPIP, PREFIX_TCPIP_SIZE) == PREFIX_TCPIP_SIZE) {
		RtlInitUnicodeString(&guidStr, &DeviceName->Buffer[PREFIX_TCPIP_LEN]);
	} else {
		goto done;
	}

	status = RtlGUIDFromString(&guidStr, &guid);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPDelNetAddress - leave#1\n");
		goto done;
	}

	IFNET_RLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (IsEqualGUID(&guid, &ifp->if_guid) && ifp->if_family == Address->AddressType) {
			break;
		}
	}
	if (ifp == NULL) {
		IFNET_RUNLOCK();
		DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPDelNetAddress - leave#2\n");
		goto done;
	}

	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		p = (unsigned char *)&((PTDI_ADDRESS_IP)Address->Address)->in_addr;
		DebugPrint(DEBUG_NET_INFO, "ClientPnPDelNetAddress: Del Address=%u.%u.%u.%u\n", p[0], p[1], p[2], p[3]);
		break;
	case TDI_ADDRESS_TYPE_IP6:
		DebugPrint(DEBUG_NET_INFO, "ClientPnPDelNetAddress: Del Address=%s%%%d\n",
		    ip6_sprintf((struct in6_addr *)&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr),
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id);
		break;
	}

	IF_LOCK(ifp);
	IFNET_RUNLOCK();

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ifa->ifa_addr->sa_family == AF_INET &&
		    ((PTDI_ADDRESS_IP)Address->Address)->in_addr == ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr)) {
			break;
		} else if (
		    (Address->AddressType == TDI_ADDRESS_TYPE_IP6 &&
		    ifa->ifa_addr->sa_family == AF_INET6 &&
		    RtlCompareMemory(&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
			&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == sizeof(struct in6_addr) &&
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id ==
		    ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_scope_id)) {
			break;
		}
	}
	if (ifa == NULL) {
		IF_UNLOCK(ifp);
		DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPDelNetAddress - leave#3\n");
		goto done;
	}

	TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);

	if (TAILQ_EMPTY(&ifp->if_addrhead)) {
#if NTDDI_VERSION < NTDDI_LONGHORN
		if (Address->AddressType == TDI_ADDRESS_TYPE_IP6) {
			IPv6RouteEntry routeV6Entry1;

			RtlZeroMemory(&routeV6Entry1, sizeof(routeV6Entry1));
			routeV6Entry1.i6re_query.i6qre_addr.s6_addr[0] = 0xfe;
			routeV6Entry1.i6re_query.i6qre_addr.s6_addr[1] = 0x80;
			routeV6Entry1.i6re_query.i6qre_prefix = 64;
			routeV6Entry1.i6re_query.i6qre_index = ifp->if_ifIndex;

			route_ipv6_del(&routeV6Entry1);
		}
#endif
		IFFREE_LOCKED(ifp);
	} else {
		IF_UNLOCK(ifp);
	}

#if NTDDI_VERSION < NTDDI_LONGHORN
	KeLowerIrql(oldIrql);
	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		route_ipv4_reload();
		break;
	case TDI_ADDRESS_TYPE_IP6:
		route_ipv6_reload();
		break;
	}
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif

	sctp_addr_change(ifa, RTM_DELETE);
	IFAFREE(ifa);

	KeLowerIrql(oldIrql);

	DebugPrint(DEBUG_NET_VERBOSE, "ClientPnPDelNetAddress - leave\n");
	return;
done:
	KeLowerIrql(oldIrql);
}


static
struct ifnet *
ifnet_create_common(void)
{
	struct ifnet *ifp = NULL, *ifp1 = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_common - enter\n");

	ifp = ExAllocatePool(NonPagedPool, sizeof(*ifp));
	if (ifp == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_common - leave#1\n");
		return NULL;
	}
	RtlZeroMemory(ifp, sizeof(*ifp));

	TAILQ_INIT(&ifp->if_addrhead);
	IF_LOCK_INIT(ifp);

	ifp->refcount = 1;

	for (ifp->if_index = 0; ifp->if_index <= if_index; ifp->if_index++) {
		TAILQ_FOREACH(ifp1, &ifnet, if_link) {
			if (ifp1->if_index == ifp->if_index) {
				break;
			}
		}
		if (ifp1 == NULL) {
			break;
		}
	}
	if (ifp->if_index > if_index) {
		if_index = ifp->if_index;
	}

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_common - leave\n");
	return ifp;
}

#if NTDDI_VERSION < NTDDI_LONGHORN
static
struct ifnet *
ifnet_create_by_ipaddr(
    PTDI_ADDRESS_IP address,
    GUID *guid)
{
	KIRQL oldIrql;
	NTSTATUS status;
	int i;
	IO_STATUS_BLOCK statusBlock;

	TCP_REQUEST_QUERY_INFORMATION_EX tcp_req;
	IPSNMPInfo ipSnmpInfo;

	IPAddrEntry *ipAddr = NULL;
	size_t ipAddr_size = 0;
	unsigned long if_index = 0;

	IFEntry *ifEntry = NULL;
	size_t ifEntry_size = sizeof(IFEntry) + IF_XNAMESIZE;
	int fail_cnt = 0;
	struct ifnet *ifp = NULL;
	int no_guid = 0;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - enter\n");

	if (SctpRawHandle == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#1\n");
		goto done;
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
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#2,status=%08x\n", status);
		goto done;
	}

	ipAddr_size = sizeof(IPAddrEntry) * ipSnmpInfo.ipsi_numaddr;
	ipAddr = ExAllocatePool(NonPagedPool, ipAddr_size);
	if (ipAddr == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#3\n");
		goto done;
	}
	RtlZeroMemory(ipAddr, ipAddr_size);

	tcp_req.ID.toi_id = 0x102; //IP_MIB_ADDRTABLE_ENTRY_ID;
	status = ZwDeviceIoControlFile(SctpRawHandle,
	    NULL,
	    NULL,
	    NULL,
	    &statusBlock,
	    IOCTL_TCP_QUERY_INFORMATION_EX,
	    &tcp_req,
	    sizeof(tcp_req),
	    ipAddr,
	    ipAddr_size);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#4,status=%08x\n", status);
		goto done;
	}

	for (i = 0; i < ipSnmpInfo.ipsi_numaddr; i++) {
		if (ipAddr[i].iae_addr == address->in_addr) {
			if_index = ipAddr[i].iae_index;
			break;
		}
	}
	if (i == ipSnmpInfo.ipsi_numaddr) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	ifEntry = ExAllocatePool(NonPagedPool, ifEntry_size);
	if (ifEntry == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	tcp_req.ID.toi_entity.tei_entity = IF_ENTITY;
	tcp_req.ID.toi_class = INFO_CLASS_PROTOCOL;
	tcp_req.ID.toi_type = INFO_TYPE_PROVIDER;
	tcp_req.ID.toi_id = 1;//IF_MIB_STATS_ID

	for (i = 0; i - fail_cnt < ipSnmpInfo.ipsi_numif; i++) {
		tcp_req.ID.toi_entity.tei_instance = i;

		status = ZwDeviceIoControlFile(SctpRawHandle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    IOCTL_TCP_QUERY_INFORMATION_EX,
		    &tcp_req,
		    sizeof(tcp_req),
		    ifEntry,
		    ifEntry_size);
		if (status != STATUS_SUCCESS) {
			fail_cnt++;
			continue;
		}

		if (if_index != ifEntry->if_index) {
			continue;
		}

		if (ifEntry->if_descrlen > IF_XNAMESIZE) {
			ifEntry->if_descrlen = 0;
		}
		ifEntry->if_descr[ifEntry->if_descrlen] = '\0';
		break;
	}
	if (i - fail_cnt == ipSnmpInfo.ipsi_numif) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#5\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_family == AF_INET &&
		    IsEqualGUID(&ifp->if_guid, guid) &&
		    ifp->if_ifIndex == ifEntry->if_index) {
			break;
		}
		if (ifp->if_family == AF_INET &&
		    ifp->if_ifIndex == ifEntry->if_index) {
			no_guid++;
			break;
		}
	}
	if (ifp != NULL && no_guid != 0) {
		RtlCopyMemory(&ifp->if_guid, guid, sizeof(GUID));
	} else if (
	    ifp == NULL) {
		ifp = ifnet_create_common();
		if (ifp == NULL) {
			IFNET_WUNLOCK();
			KeLowerIrql(oldIrql);
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#6\n");
			goto done;
		}
		ifp->if_family = AF_INET;
		RtlCopyMemory(&ifp->if_guid, guid, sizeof(GUID));
		ifp->if_ifIndex = ifEntry->if_index;

		ifp->if_type = ifEntry->if_type;
		ifp->if_mtu = ifEntry->if_mtu;
		RtlCopyMemory(ifp->if_xname, ifEntry->if_descr, ifEntry->if_descrlen);

		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFREF(ifp);
	IFNET_WUNLOCK();

	KeLowerIrql(oldIrql);
	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave\n");
done:
	if (ipAddr != NULL) {
		ExFreePool(ipAddr);
	}
	if (ifEntry != NULL) {
		ExFreePool(ifEntry);
	}
	return ifp;
}

struct ifnet *
ifnet_create_by_in_addr(
    struct in_addr *in_addr)
{
	KIRQL oldIrql;
	NTSTATUS status;
	int i;
	IO_STATUS_BLOCK statusBlock;

	TCP_REQUEST_QUERY_INFORMATION_EX tcp_req;
	IPSNMPInfo ipSnmpInfo;

	IPAddrEntry *ipAddr = NULL;
	size_t ipAddr_size = 0;
	unsigned long if_index = 0;

	IFEntry *ifEntry = NULL;
	size_t ifEntry_size = sizeof(IFEntry) + IF_XNAMESIZE;
	int fail_cnt = 0;
	struct ifnet *ifp = NULL;
	int no_guid = 0;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - enter\n");

	if (SctpRawHandle == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#1\n");
		goto done;
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
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#2,status=%08x\n", status);
		goto done;
	}

	ipAddr_size = sizeof(IPAddrEntry) * ipSnmpInfo.ipsi_numaddr;
	ipAddr = ExAllocatePool(NonPagedPool, ipAddr_size);
	if (ipAddr == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#3\n");
		goto done;
	}
	RtlZeroMemory(ipAddr, ipAddr_size);

	tcp_req.ID.toi_id = 0x102; //IP_MIB_ADDRTABLE_ENTRY_ID;
	status = ZwDeviceIoControlFile(SctpRawHandle,
	    NULL,
	    NULL,
	    NULL,
	    &statusBlock,
	    IOCTL_TCP_QUERY_INFORMATION_EX,
	    &tcp_req,
	    sizeof(tcp_req),
	    ipAddr,
	    ipAddr_size);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#4,status=%08x\n", status);
		goto done;
	}

	for (i = 0; i < ipSnmpInfo.ipsi_numaddr; i++) {
		if (ipAddr[i].iae_addr == in_addr->s_addr) {
			if_index = ipAddr[i].iae_index;
			break;
		}
	}
	if (i == ipSnmpInfo.ipsi_numaddr) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	ifEntry = ExAllocatePool(NonPagedPool, ifEntry_size);
	if (ifEntry == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	tcp_req.ID.toi_entity.tei_entity = IF_ENTITY;
	tcp_req.ID.toi_class = INFO_CLASS_PROTOCOL;
	tcp_req.ID.toi_type = INFO_TYPE_PROVIDER;
	tcp_req.ID.toi_id = 1;//IF_MIB_STATS_ID

	for (i = 0; i - fail_cnt < ipSnmpInfo.ipsi_numif; i++) {
		tcp_req.ID.toi_entity.tei_instance = i;

		status = ZwDeviceIoControlFile(SctpRawHandle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    IOCTL_TCP_QUERY_INFORMATION_EX,
		    &tcp_req,
		    sizeof(tcp_req),
		    ifEntry,
		    ifEntry_size);
		if (status != STATUS_SUCCESS) {
			fail_cnt++;
			continue;
		}

		if (if_index != ifEntry->if_index) {
			continue;
		}

		if (ifEntry->if_descrlen > IF_XNAMESIZE) {
			ifEntry->if_descrlen = 0;
		}
		ifEntry->if_descr[ifEntry->if_descrlen] = '\0';
		break;
	}
	if (i - fail_cnt == ipSnmpInfo.ipsi_numif) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_in_addr - leave#5\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_family == AF_INET &&
		    ifp->if_ifIndex == ifEntry->if_index) {
			break;
		}
	}
	if (ifp != NULL) {
		IFREF(ifp);
		IFNET_WUNLOCK();
		KeLowerIrql(oldIrql);
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_in_addr - leave#6\n");
		goto done;
	}

	ifp = ifnet_create_common();
	if (ifp == NULL) {
		IFNET_WUNLOCK();
		KeLowerIrql(oldIrql);
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_in_addr - leave#7\n");
		goto done;
	}
	ifp->if_family = AF_INET;
	ifp->if_ifIndex = ifEntry->if_index;
	ifp->if_type = ifEntry->if_type;
	ifp->if_mtu = ifEntry->if_mtu;
	RtlCopyMemory(ifp->if_xname, ifEntry->if_descr, ifEntry->if_descrlen);

	TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	IFREF(ifp);
	IFNET_WUNLOCK();

	KeLowerIrql(oldIrql);
	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_in_addr - leave\n");
done:
	if (ipAddr != NULL) {
		ExFreePool(ipAddr);
	}
	if (ifEntry != NULL) {
		ExFreePool(ifEntry);
	}
	return ifp;
}

static
struct ifnet *
ifnet_create_by_guid(
    GUID *guid)
{
	KIRQL oldIrql;
	NTSTATUS status;
	int i;
	IO_STATUS_BLOCK statusBlock;

	IPV6_QUERY_INTERFACE ifQuery;
	IPV6_INFO_INTERFACE *ifInfo = NULL;
	size_t ifInfo_size = sizeof(IPV6_INFO_INTERFACE) + MAX_PHYSADDR_SIZE;
	int found = 0;

	struct ifnet *ifp = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - enter\n");

	if (TpIP6Handle == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#1\n");
		goto done;
	}

	ifInfo = ExAllocatePool(NonPagedPool, ifInfo_size);
	if (ifInfo == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#2\n");
		goto done;
	}

	ifQuery.Index = 0xFFFFFFFF;

	for (;;) {
		RtlZeroMemory(ifInfo, ifInfo_size);

		status = ZwDeviceIoControlFile(TpIP6Handle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    1179652,
		    &ifQuery, sizeof(ifQuery),
		    ifInfo, ifInfo_size);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#3,status=%08x\n", status);
			goto done;
		}

		if (ifQuery.Index != 0xFFFFFFFF && IsEqualGUID(&ifInfo->Query.guid, guid)) {
			found++;
			break;
		}

		ifQuery = ifInfo->NextQuery;
		if (ifQuery.Index == 0xFFFFFFFF) {
			break;
		}
	}

	if (found == 0) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#4\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_family == AF_INET6 &&
		    IsEqualGUID(&ifp->if_guid, guid) &&
		    ifp->if_ifIndex == ifInfo->Index0) {
			break;
		}
	}
	if (ifp == NULL) {
		ifp = ifnet_create_common();
		if (ifp == NULL) {
			IFNET_WUNLOCK();
			KeLowerIrql(oldIrql);
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#5\n");
			goto done;
		}
		ifp->if_family = AF_INET6;
		RtlCopyMemory(&ifp->if_guid, guid, sizeof(GUID));
		ifp->if_ifIndex = ifInfo->Index0;

		ifp->if_type = IFT_OTHER;
		ifp->if_mtu = ifInfo->MTU;

		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFREF(ifp);
	IFNET_WUNLOCK();

	KeLowerIrql(oldIrql);
	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave\n");
done:

	if (ifInfo != NULL) {
		ExFreePool(ifInfo);
	}
	return ifp;
}

struct ifnet *
ifnet_create_by_index(
    ADDRESS_FAMILY family,
    ULONG interfaceIndex)
{
	KIRQL oldIrql;
	NTSTATUS status;
	int i;
	IO_STATUS_BLOCK statusBlock;
	TCP_REQUEST_QUERY_INFORMATION_EX tcp_req;
	IPSNMPInfo ipSnmpInfo;

	IFEntry *ifEntry = NULL;
	size_t ifEntry_size = sizeof(IFEntry) + IF_XNAMESIZE;
	int fail_cnt = 0;

	IPV6_QUERY_INTERFACE ifQuery;
	IPV6_INFO_INTERFACE *ifInfo = NULL;
	size_t ifInfo_size = sizeof(IPV6_INFO_INTERFACE) + MAX_PHYSADDR_SIZE;
	int found = 0;

	struct ifnet *ifp = NULL;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - enter\n");

	if ((family == AF_INET && SctpRawHandle == NULL) ||
	    (family == AF_INET6 && TpIP6Handle == NULL)) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#1\n");
		goto done;
	}

	if (family != AF_INET && family != AF_INET6) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#2\n");
		goto done;
	}

	if (family == AF_INET) {
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
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#3,status=%08x\n", status);
			goto done;
		}

		ifEntry = ExAllocatePool(NonPagedPool, ifEntry_size);
		if (ifEntry == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}

		tcp_req.ID.toi_entity.tei_entity = IF_ENTITY;
		tcp_req.ID.toi_class = INFO_CLASS_PROTOCOL;
		tcp_req.ID.toi_type = INFO_TYPE_PROVIDER;
		tcp_req.ID.toi_id = 1;//IF_MIB_STATS_ID

		for (i = 0; i - fail_cnt < ipSnmpInfo.ipsi_numif; i++) {
			tcp_req.ID.toi_entity.tei_instance = i;

			status = ZwDeviceIoControlFile(SctpRawHandle,
			    NULL,
			    NULL,
			    NULL,
			    &statusBlock,
			    IOCTL_TCP_QUERY_INFORMATION_EX,
			    &tcp_req,
			    sizeof(tcp_req),
			    ifEntry,
			    ifEntry_size);
			if (status != STATUS_SUCCESS) {
				fail_cnt++;
				continue;
			}

			if (ifEntry->if_index != interfaceIndex) {
				continue;
			}

			if (ifEntry->if_descrlen > IF_XNAMESIZE) {
				ifEntry->if_descrlen = 0;
			}
			ifEntry->if_descr[ifEntry->if_descrlen] = '\0';
			break;
		}
		if (i - fail_cnt == ipSnmpInfo.ipsi_numif) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#4\n");
			goto done;
		}
	} else {
		ifInfo = ExAllocatePool(NonPagedPool, ifInfo_size);
		if (ifInfo == NULL) {
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#5\n");
			goto done;
		}

		ifQuery.Index = 0xFFFFFFFF;

		for (;;) {
			RtlZeroMemory(ifInfo, ifInfo_size);

			status = ZwDeviceIoControlFile(TpIP6Handle,
			    NULL,
			    NULL,
			    NULL,
			    &statusBlock,
			    1179652,
			    &ifQuery, sizeof(ifQuery),
			    ifInfo, ifInfo_size);
			if (status != STATUS_SUCCESS) {
				DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#6,status=%08x\n", status);
				goto done;
			}

			if (ifQuery.Index == interfaceIndex) {
				found++;
				break;
			}

			ifQuery = ifInfo->NextQuery;
			if (ifQuery.Index == 0xFFFFFFFF) {
				break;
			}
		}

		if (found == 0) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#7\n");
			goto done;
		}
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_family != family) {
			continue;
		}
		if (ifp->if_family == AF_INET &&
		    ifp->if_ifIndex == ifEntry->if_index) {
			break;
		}
		if (ifp->if_family == AF_INET6 &&
		    IsEqualGUID(&ifp->if_guid, &ifInfo->Query.guid) &&
		    ifp->if_ifIndex == ifInfo->Index0) {
			break;
		}
	}
	if (ifp == NULL) {
		ifp = ifnet_create_common();
		if (ifp == NULL) {
			IFNET_WUNLOCK();
			KeLowerIrql(oldIrql);
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_ipaddr - leave#8\n");
			goto done;
		}
		ifp->if_family = family;
		if (family == AF_INET) {
			ifp->if_ifIndex = ifEntry->if_index;
			ifp->if_type = ifEntry->if_type;
			ifp->if_mtu = ifEntry->if_mtu;
			RtlCopyMemory(ifp->if_xname, ifEntry->if_descr, ifEntry->if_descrlen);
		} else {
			RtlCopyMemory(&ifp->if_guid, &ifInfo->Query.guid, sizeof(GUID));
			ifp->if_ifIndex = ifInfo->Index0;
			ifp->if_type = IFT_OTHER;
			ifp->if_mtu = ifInfo->MTU;
		}

		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFREF(ifp);
	IFNET_WUNLOCK();

	KeLowerIrql(oldIrql);
	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave\n");
done:

	if (ifInfo != NULL) {
		ExFreePool(ifInfo);
	}
	return ifp;
}
#else
static
struct ifnet *
ifnet_create_by_guid(
    ADDRESS_FAMILY family,
    GUID *guid)
{
	KIRQL oldIrql;
	NTSTATUS status;
	int i;
	PMIB_IF_TABLE2 pIfTable = NULL;
	PMIB_IF_ROW2 pIfEntry = NULL;
	struct ifnet *ifp = NULL;
	UNICODE_STRING usGuid;
	ANSI_STRING asGuid;
	size_t sz;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - enter\n");

	status = GetIfTable2(&pIfTable);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#1\n");
		goto done;
	}

	for (i = 0; i < pIfTable->NumEntries; i++) {
		if (IsEqualGUID(&pIfTable->Table[i].InterfaceGuid, guid)) {
			break;
		}
	}
	if (i == pIfTable->NumEntries) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#2\n");
		goto done;
	}
	pIfEntry = &pIfTable->Table[i];
	//DbgPrint("pIfEntry->Description=%ws,pIfEntry->Alias=%ws\n", pIfEntry->Description, pIfEntry->Alias);

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (IsEqualGUID(&pIfEntry->InterfaceGuid, &ifp->if_guid) &&
		    ifp->if_family == family) {
			break;
		}
	}
	if (ifp == NULL) {
		ifp = ifnet_create_common();
		if (ifp == NULL) {
			IFNET_WUNLOCK();
			KeLowerIrql(oldIrql);
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave#3\n");
			goto done;
		}
		ifp->if_family = family;
		RtlCopyMemory(&ifp->if_guid, &pIfEntry->InterfaceGuid, sizeof(GUID));
		ifp->if_ifIndex = pIfEntry->InterfaceIndex;

		ifp->if_type = pIfEntry->Type;
		ifp->if_mtu = pIfEntry->Mtu;

		status = RtlStringFromGUID(guid, &usGuid);
		if (status == STATUS_SUCCESS) {
			status = RtlUnicodeStringToAnsiString(&asGuid, &usGuid, TRUE);
			if (status == STATUS_SUCCESS) {
				sz = asGuid.Length < IF_XNAMESIZE ? asGuid.Length : IF_XNAMESIZE;
				RtlCopyMemory(ifp->if_xname, asGuid.Buffer, sz);
				RtlFreeAnsiString(&asGuid);
			}
			RtlFreeUnicodeString(&usGuid);
		}
		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFREF(ifp);
	IFNET_WUNLOCK();
	KeLowerIrql(oldIrql);
	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_guid - leave\n");
done:
	if (pIfTable != NULL) {
		FreeMibTable(pIfTable);
	}
	return ifp;
}

struct ifnet *
ifnet_create_by_index(
    ADDRESS_FAMILY family,
    NET_IFINDEX interfaceIndex)
{
	KIRQL oldIrql;
	NTSTATUS status;
	MIB_IF_ROW2 ifEntry;
	struct ifnet *ifp = NULL;
	UNICODE_STRING usGuid;
	ANSI_STRING asGuid;
	size_t sz;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - enter\n");

	RtlZeroMemory(&ifEntry, sizeof(ifEntry));
	ifEntry.InterfaceIndex = interfaceIndex;

	status = GetIfEntry2(&ifEntry);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#1,status=%08x\n", status);
		return NULL;
	}
	//DbgPrint("ifEntry.Description=%ws,ifEntry.Alias=%ws\n", ifEntry.Description, ifEntry.Alias);

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (IsEqualGUID(&ifEntry.InterfaceGuid, &ifp->if_guid) &&
		    ifp->if_ifIndex == interfaceIndex &&
		    ifp->if_family == family) {
			break;
		}
	}
	if (ifp == NULL) {
		ifp = ifnet_create_common();
		if (ifp == NULL) {
			IFNET_WUNLOCK();
			KeLowerIrql(oldIrql);
			DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave#2\n");
			return NULL;
		}
		ifp->if_family = family;
		RtlCopyMemory(&ifp->if_guid, &ifEntry.InterfaceGuid, sizeof(ifEntry.InterfaceGuid));
		ifp->if_ifIndex = interfaceIndex;

		ifp->if_type = ifEntry.Type;
		ifp->if_mtu = ifEntry.Mtu;

		status = RtlStringFromGUID(&ifEntry.InterfaceGuid, &usGuid);
		if (status == STATUS_SUCCESS) {
			status = RtlUnicodeStringToAnsiString(&asGuid, &usGuid, TRUE);
			if (status == STATUS_SUCCESS) {
				sz = asGuid.Length < IF_XNAMESIZE ? asGuid.Length : IF_XNAMESIZE;
				RtlCopyMemory(ifp->if_xname, asGuid.Buffer, sz);
				RtlFreeAnsiString(&asGuid);
			}
			RtlFreeUnicodeString(&usGuid);
		}
		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFREF(ifp);
	IFNET_WUNLOCK();
	KeLowerIrql(oldIrql);

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_create_by_index - leave\n");
	return ifp;
}
#endif

struct ifaddr *
ifnet_append_address(
    struct ifnet *ifp,
    struct sockaddr *addr)
{
	unsigned char *p = NULL;
	struct ifaddr *ifa;
	int ifasize;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_append_address - enter\n");

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if ((addr->sa_family == AF_INET &&
		    ifa->ifa_addr->sa_family == AF_INET &&
		    ((struct sockaddr_in *)addr)->sin_addr.s_addr == ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr)) {
			ifasize = sizeof(struct sockaddr_in);
			break;
		} else if (
		    (addr->sa_family == AF_INET6 &&
		    ifa->ifa_addr->sa_family == AF_INET6 &&
		    RtlCompareMemory(&((struct sockaddr_in6 *)addr)->sin6_addr,
			&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == sizeof(struct in6_addr) &&
		    ((struct sockaddr_in6 *)addr)->sin6_scope_id == ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_scope_id)) {
			ifasize = sizeof(struct sockaddr_in6);
			break;
		}
	}
	if (ifa != NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_append_address - leave#1\n");
		return NULL;
	}

	switch (addr->sa_family) {
	case AF_INET:
		ifasize = sizeof(struct in_ifaddr) + sizeof(struct sockaddr_in);
		p = (unsigned char *)&((struct sockaddr_in *)addr)->sin_addr;
		DebugPrint(DEBUG_NET_INFO, "ifnet_append_address: new Address=%u.%u.%u.%u\n", p[0], p[1], p[2], p[3]);
		break;
	case AF_INET6:
		ifasize = sizeof(struct in6_ifaddr) + sizeof(struct sockaddr_in6);
		DebugPrint(DEBUG_NET_INFO, "ClientPnPAddNetAddress: new Address=%s%%%d\n",
		    ip6_sprintf(&((struct sockaddr_in6 *)addr)->sin6_addr),
		    ((struct sockaddr_in6 *)addr)->sin6_scope_id);
		break;
	}

	ifa = ExAllocatePool(NonPagedPool, ifasize);
	if (ifa == NULL) {
		DebugPrint(DEBUG_NET_VERBOSE, "ifnet_append_address - leave#2\n");
		return NULL;
	}
	RtlZeroMemory(ifa, ifasize);

	IFA_LOCK_INIT(ifa);
	ifa->ifa_ifp = ifp;
	ifa->refcount = 1;

	switch (addr->sa_family) {
	case AF_INET:
		RtlCopyMemory(ifa + 1, addr, sizeof(struct sockaddr_in));
		ifa->ifa_addr = (struct sockaddr *)(ifa + 1);
		break;
	case AF_INET6:
		RtlCopyMemory(ifa + 1, addr, sizeof(struct sockaddr_in6));
		ifa->ifa_addr = (struct sockaddr *)(ifa + 1);
		break;
	}
	TAILQ_INSERT_TAIL(&ifp->if_addrhead, ifa, ifa_link);

	DebugPrint(DEBUG_NET_VERBOSE, "ifnet_append_address - leave\n");
	return ifa;
}
