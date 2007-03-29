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
 * $Id: ntinit.c,v 1.6 2007/03/29 07:40:23 kozuka Exp $
 */
#pragma data_seg("NONPAGE")

#include "globals.h"

#include <netinet/sctp_os_windows.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_addr.h>

#if 1
int sctp_attach(struct socket *);
int sctp_bind(struct socket *, struct sockaddr *);
int sctp_detach(struct socket *);
#endif

#define RawIPDeviceWithSCTP L"\\Device\\RawIP\\132"
#define RawIP6DeviceWithSCTP L"\\Device\\RawIp6\\132"

#define DD_SCTP_ONE_TO_ONE_DEVICE_NAME L"\\Device\\SctpTcp"
#define DD_SCTP_ONE_TO_MANY_DEVICE_NAME L"\\Device\\SctpUdp"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT, IN PUNICODE_STRING);
VOID Unload(IN PDRIVER_OBJECT);

NTSTATUS OpenRawSctp(IN UCHAR, OUT HANDLE *, OUT PFILE_OBJECT *);
NTSTATUS SCTPReceiveDatagram(IN PVOID, IN LONG, IN PVOID, IN LONG,
    IN PVOID, IN ULONG, IN ULONG, IN ULONG, OUT ULONG *, IN PVOID, OUT PIRP *);
NTSTATUS SCTPReceiveDatagram6(IN PVOID, IN LONG, IN PVOID, IN LONG,
    IN PVOID, IN ULONG, IN ULONG, IN ULONG, OUT ULONG *, IN PVOID, OUT PIRP *);
NTSTATUS SCTPSendDatagram(IN struct mpkt *, IN struct in_addr *);
NTSTATUS SendDatagram6(IN UCHAR *, IN struct in6_addr *, IN ULONG);
VOID SCTPReceiveThread(IN PVOID);
VOID ClientPnPAddNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);
VOID ClientPnPDelNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);
VOID RetrieveRoute(VOID);
VOID SetRoute(VOID);

NTSTATUS SCTPCreate(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPCleanup(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPClose(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatchDeviceControl(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatch(IN PDEVICE_OBJECT, IN PIRP);

struct RcvContext {
	BOOLEAN		bActive;
	KEVENT		event;
} *RcvContext, *Rcv6Context;

struct ifqueue {
	struct mpkt	*head;
	struct mpkt	*tail;
	KMUTEX		mtx;
} *inq, *in6q;

PDEVICE_OBJECT SctpTcpDeviceObject = NULL, SctpUdpDeviceObject = NULL;
PFILE_OBJECT TpObject, Tp6Object, RcvObject;
HANDLE TpHandle, Tp6Handle, RcvHandle, BindingHandle;

KSPIN_LOCK atomic_spinlock;
KLOCK_QUEUE_HANDLE atomic_lockqueue;

NPAGED_LOOKASIDE_LIST ExtBufLookaside;
NDIS_HANDLE SctpBufferPool;
NDIS_HANDLE SctpPacketPool;

int if_index = 0;
struct ifnethead ifnet;
KSPIN_LOCK ifnet_spinlock;
KLOCK_QUEUE_HANDLE ifnet_lockqueue;

struct socket *so = NULL;

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING devname;
	PIRP irp;
	KEVENT kCompleteEvent;
	IO_STATUS_BLOCK statusBlock;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	TDI_CLIENT_INTERFACE_INFO ClientInterfaceInfo;
	UNICODE_STRING clientName;
	KIRQL oldIrql;
	
	int i;
	int *test = NULL;

	DbgPrint("Enter into DriverEntry\n");

	oldIrql = KeGetCurrentIrql();

	SCTP_BUF_INIT();
	SCTP_HEADER_INIT();

	TAILQ_INIT(&ifnet);
	IFNET_LOCK_INIT();

	RtlZeroMemory(&ClientInterfaceInfo, sizeof(ClientInterfaceInfo));
	RtlInitUnicodeString(&clientName, L"HKLM\\System\\CCS\\Services\\Sctp");
	ClientInterfaceInfo.MajorTdiVersion = TDI_CURRENT_MAJOR_VERSION;
	ClientInterfaceInfo.MinorTdiVersion = TDI_CURRENT_MINOR_VERSION;
	ClientInterfaceInfo.ClientName = &clientName;
	ClientInterfaceInfo.AddAddressHandlerV2 = ClientPnPAddNetAddress;
	ClientInterfaceInfo.DelAddressHandlerV2 = ClientPnPDelNetAddress;

	status = TdiRegisterPnPHandlers(&ClientInterfaceInfo,
	    sizeof(ClientInterfaceInfo),
	    &BindingHandle);
	if (status != STATUS_SUCCESS) {
		BindingHandle = NULL;
		goto error;
	}

	sctp_init();
	status = OpenRawSctp(AF_INET, &TpHandle, &TpObject);
	if (status != STATUS_SUCCESS) {
		DbgPrint("OpenRawSCTP(AF_INET) failed, code=%d\n", status);
	}

	status = OpenRawSctp(AF_INET6, &Tp6Handle, &Tp6Object);
	if (status != STATUS_SUCCESS) {
		DbgPrint("OpenRawSCTP(AF_INET6) failed, code=%d\n", status);
	}

	if (TpObject == NULL && Tp6Object == NULL) {
		DbgPrint("No active IP!\n");
		goto error;
	}

	RcvContext = ExAllocatePool(NonPagedPool, sizeof(*RcvContext));
	RtlZeroMemory(RcvContext, sizeof(*RcvContext));
	KeInitializeEvent(&RcvContext->event, SynchronizationEvent, FALSE);
	RcvContext->bActive = TRUE;

	inq = ExAllocatePool(NonPagedPool, sizeof(*inq));
	RtlZeroMemory(inq, sizeof(*inq));
	KeInitializeMutex(&inq->mtx, 0);

	InitializeObjectAttributes(&ObjectAttributes,
	    NULL,
	    OBJ_KERNEL_HANDLE,
	    NULL,
	    NULL);
	status = PsCreateSystemThread(&RcvHandle,
	    0,
	    &ObjectAttributes,
	    NULL,
	    NULL,
	    SCTPReceiveThread,
	    RcvContext);
	if (status == STATUS_SUCCESS) {
		ObReferenceObjectByHandle(RcvHandle,
		    GENERIC_READ | GENERIC_WRITE,
		    NULL,
		    KernelMode,
		    (PVOID *)&RcvObject,
		    NULL);
		ZwClose(RcvHandle);
	}

	RtlInitUnicodeString(&devname, DD_SCTP_ONE_TO_MANY_DEVICE_NAME);
	status = IoCreateDevice(DriverObject, 0, &devname, FILE_DEVICE_NETWORK,
	    0, FALSE, &SctpUdpDeviceObject);
	if (status != STATUS_SUCCESS) {
		DbgPrint("IoCreateDevice failed, code=%d\n", status);
		goto error;
	}
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = SCTPDispatch;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SCTPCreate;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = SCTPCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SCTPClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SCTPDispatchDeviceControl;
	DriverObject->DriverUnload = Unload;

	/* XXX */
	if (oldIrql > KeGetCurrentIrql()) {
		KeLowerIrql(oldIrql);
	}

	if (1) {
		struct sockaddr_in sin;
		int error = 0;

		RtlZeroMemory(&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(sin);
		sin.sin_port = htons(80);

		so = ExAllocatePool(NonPagedPool, sizeof(*so));
		RtlZeroMemory(so, sizeof(*so));
		so->so_type = SOCK_SEQPACKET;
		so->so_qlimit = 1;

		error = sctp_attach(so);
		if (error == 0) {
			error = sctp_bind(so, (struct sockaddr *)&sin);
			DbgPrint("sctp_bind: error=%d\n", error);
		} else {
			DbgPrint("sctp_attach: error=%d\n", error);
		}
	}

	SetRoute();
	RetrieveRoute();

	DbgPrint("Leave from DriverEntry#1\n");
	return STATUS_SUCCESS;
error:
	Unload(DriverObject);
	DbgPrint("Leave from DriverEntry#2\n");
	return status;
}

VOID
Unload(
    IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	int error = 0;

	DbgPrint("Enter into Unload\n");

	if (so != NULL) {
		error = sctp_detach(so);
		DbgPrint("sctp_detach: error=%d\n", error);
	}
	sctp_finish();

	if (SctpTcpDeviceObject != NULL) {
		IoDeleteDevice(SctpTcpDeviceObject);	
	}
	if (SctpUdpDeviceObject != NULL) {
		IoDeleteDevice(SctpUdpDeviceObject);	
	}

	if (BindingHandle != NULL) {
		TdiDeregisterPnPHandlers(BindingHandle);
	}
	{
		struct ifnet *ifn;
		struct ifaddr *ifa;

		IFNET_WLOCK();
		ifn = TAILQ_FIRST(&ifnet);
		while (ifn != NULL) {
			IF_LOCK(ifn);
			TAILQ_REMOVE(&ifnet, ifn, if_link);
			ifa = TAILQ_FIRST(&ifn->if_addrhead);
			while (ifa != NULL) {
				TAILQ_REMOVE(&ifn->if_addrhead, ifa, ifa_link);
				ExFreePool(ifa);
				ifa = TAILQ_FIRST(&ifn->if_addrhead);
			}
			ExFreePool(ifn);
			ifn = TAILQ_FIRST(&ifnet);
		}
		IFNET_WUNLOCK();
	}
	if (RcvContext != NULL) {
		RcvContext->bActive = FALSE;
		KeSetEvent(&RcvContext->event, IO_NO_INCREMENT, FALSE);
		status = KeWaitForSingleObject(RcvObject,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		ObDereferenceObject(RcvObject);
	}

	if (TpObject != NULL) {
		ObDereferenceObject(TpObject);
	}
	if (TpHandle != NULL) {
		status = ZwClose(TpHandle);
		DbgPrint("ZwClose#1, status=%d\n", status);
	}

	if (Tp6Object != NULL) {
		ObDereferenceObject(Tp6Object);
	}
	if (Tp6Handle != NULL) {
		ZwClose(Tp6Handle);
		DbgPrint("ZwClose#2, status=%d\n", status);
	}

	IFNET_LOCK_DESTROY();

	SCTP_HEADER_DESTROY();
	SCTP_BUF_DESTROY();

	DbgPrint("Left from Unload\n");
}


VOID
ClientPnPAddNetAddress(
    IN PTA_ADDRESS Address,
    IN PUNICODE_STRING DeviceName,
    IN PTDI_PNP_CONTEXT Context)
{
	unsigned char *p;
	struct ifnet *ifp, *ifp1;
	struct ifaddr *ifa;

	DbgPrint("ClientPnPAddNetAddress: DeviceName=%ws\n", DeviceName->Buffer);

	if (Address->AddressType != TDI_ADDRESS_TYPE_IP &&
	    Address->AddressType != TDI_ADDRESS_TYPE_IP6) {
		return;
	}

	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		p = (unsigned char *)&((PTDI_ADDRESS_IP)Address->Address)->in_addr;
		DbgPrint("IPv4 address: %u.%u.%u.%u\n",
		    p[0], p[1], p[2], p[3]);
		break;
	case TDI_ADDRESS_TYPE_IP6:
		DbgPrint("IPv6 address: %s%%%d\n",
		    ip6_sprintf((struct in6_addr *)&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr),
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id);
		break;
	}

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (RtlCompareUnicodeString(DeviceName, &ifp->if_xname, TRUE) == 0) {
			break;
		}
	}
	if (ifp == NULL) {
		/* New interface */
		ifp = ExAllocatePool(NonPagedPool, sizeof(*ifp));
		if (ifp == NULL) {
			DbgPrint("ClientPnPAddNetAddress: Resource unavailable\n");
			IFNET_WUNLOCK();
			return;
		}
		RtlZeroMemory(ifp, sizeof(*ifp));
		RtlInitUnicodeString(&ifp->if_xname, DeviceName->Buffer);
		TAILQ_INIT(&ifp->if_addrhead);
		IF_LOCK_INIT(ifp);
		ifp->refcount = 2;

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
		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFNET_WUNLOCK();
	IF_LOCK(ifp);
	ifp->refcount--;

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ifa->ifa_addr.ss_family == AF_INET &&
		    ((PTDI_ADDRESS_IP)Address->Address)->in_addr == ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr) ||
		    (Address->AddressType == TDI_ADDRESS_TYPE_IP6 &&
		    ifa->ifa_addr.ss_family == AF_INET6 &&
		    RtlCompareMemory(&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
			&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == sizeof(struct in6_addr) &&
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id ==
		    ((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id)) {
			break;
		}
	}
	if (ifa != NULL) {
		DbgPrint("Already exists....\n");
		IF_UNLOCK(ifp);
		return;
	}

	ifa = ExAllocatePool(NonPagedPool, sizeof(*ifa));
	if (ifa == NULL) {
		DbgPrint("ClientPnPAddNetAddress: Resource unavailable#2\n");
		IF_UNLOCK(ifp);
		return;
	}
	RtlZeroMemory(ifa, sizeof(*ifa));
	IFA_LOCK_INIT(ifa);
	ifa->ifa_ifp = ifp;
	ifa->refcount = 1;

	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		ifa->ifa_addr.ss_family = AF_INET;
		RtlCopyMemory(&((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr,
		    &((PTDI_ADDRESS_IP)Address->Address)->in_addr,
		    sizeof(struct in_addr));
		break;
	case TDI_ADDRESS_TYPE_IP6:
		ifa->ifa_addr.ss_family = AF_INET6;
		RtlCopyMemory(&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr,
		    &((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
		    sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id = 
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id;
		break;
	}
	TAILQ_INSERT_TAIL(&ifp->if_addrhead, ifa, ifa_link);
	IF_UNLOCK(ifp);
}

VOID
ClientPnPDelNetAddress(
    IN PTA_ADDRESS Address,
    IN PUNICODE_STRING DeviceName,
    IN PTDI_PNP_CONTEXT Context)
{
	unsigned char *p;
	struct ifnet *ifp;
	struct ifaddr *ifa;

	DbgPrint("ClientPnPDelNetAddress: DeviceName=%ws\n", DeviceName->Buffer);

	if (Address->AddressType != TDI_ADDRESS_TYPE_IP &&
	    Address->AddressType != TDI_ADDRESS_TYPE_IP6) {
		return;
	}

	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		p = (unsigned char *)&((PTDI_ADDRESS_IP)Address->Address)->in_addr;
		DbgPrint("IPv4 address: %u.%u.%u.%u\n",
		    p[0], p[1], p[2], p[3]);
		break;
	case TDI_ADDRESS_TYPE_IP6:
		DbgPrint("IPv6 address: %s%%%d\n",
		    ip6_sprintf((struct in6_addr *)&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr),
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id);
		break;
	}

	IFNET_RLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (RtlCompareUnicodeString(DeviceName, &ifp->if_xname, TRUE) == 0) {
			break;
		}
	}
	if (ifp != NULL) {
		IF_INCR_REF(ifp);
	}
	if (ifp == NULL) {
		DbgPrint("No such device....\n");
		IFNET_RUNLOCK();
		return;
	}
	IFNET_RUNLOCK();
	IF_LOCK(ifp);
	ifp->refcount--;

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
#if 0
	switch (ifa->ifa_addr.ss_family) {
	case AF_INET:
		p = (unsigned char *)&((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr;
		DbgPrint("IPv4 address: %u.%u.%u.%u\n",
		    p[0], p[1], p[2], p[3]);
		break;
	case TDI_ADDRESS_TYPE_IP6:
		DbgPrint("IPv6 address: %s%%%d\n",
		    ip6_sprintf((struct in6_addr *)&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr),
		    ((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id);
		break;
	}
#endif
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ifa->ifa_addr.ss_family == AF_INET &&
		    ((PTDI_ADDRESS_IP)Address->Address)->in_addr == ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr) ||
		    (Address->AddressType == TDI_ADDRESS_TYPE_IP6 &&
		    ifa->ifa_addr.ss_family == AF_INET6 &&
		    RtlCompareMemory(&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
			&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == sizeof(struct in6_addr) &&
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id ==
		    ((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id)) {
			break;
		}
	}
	if (ifa == NULL) {
		IF_UNLOCK(ifp);
		DbgPrint("No such address....\n");
		return;
	}

	TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);
	IFAFREE(ifa);
	IF_UNLOCK(ifp);
#if 0
	if (TAILQ_EMPTY(&ifp->if_addrhead)) {
		TAILQ_REMOVE(&ifnet, ifp, if_link);
	}
#endif
}

typedef struct {
	unsigned long ipsi_forwarding;
	unsigned long ipsi_defaultttl;
	unsigned long ipsi_inreceives;
	unsigned long ipsi_inhdrerrors;
	unsigned long ipsi_inaddrerrors;
	unsigned long ipsi_forwdatagrams;
	unsigned long ipsi_inunknownprotos;
	unsigned long ipsi_indiscards;
	unsigned long ipsi_indelivers;
	unsigned long ipsi_outrequests;
	unsigned long ipsi_routingdiscards;
	unsigned long ipsi_outdiscards;
	unsigned long ipsi_outnoroutes;
	unsigned long ipsi_reasmtimeout;
	unsigned long ipsi_reasmreqds;
	unsigned long ipsi_reasmoks;
	unsigned long ipsi_reasmfails;
	unsigned long ipsi_fragoks;
	unsigned long ipsi_fragfails;
	unsigned long ipsi_fragcreates;
	unsigned long ipsi_numif;
	unsigned long ipsi_numaddr;
	unsigned long ipsi_numroutes;
} IPSNMPInfo;

typedef struct {
	unsigned long iae_addr;
	unsigned long iae_index;
	unsigned long iae_mask;
	unsigned long iae_bcastaddr;
	unsigned long iae_reasmsize;
	unsigned short iae_context;
	unsigned short iae_pad;
} IPAddrEntry;

typedef struct IPRouteEntry {
	ulong ire_addr;
	ulong ire_index;
	ulong ire_metric;
	ulong ire_unk1;
	ulong ire_unk2;
	ulong ire_unk3;
	ulong ire_gw;
	ulong ire_unk4;
	ulong ire_unk5;
	ulong ire_unk6;
	ulong ire_mask;
	ulong ire_unk7;
	ulong ire_unk8;
} IPRouteEntry;

VOID
RetrieveRoute(VOID)
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

	// InputBufferLength=>36, OutputBufferLength=>92
	// getInformation: tei_entity => 769, toi_class => 512, toi_type =>256, toi_id=>1
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
	}
	ExFreePool(ipAddr);
	ExFreePool(ipRoute);
}

VOID
SetRoute(VOID)
{
	NTSTATUS status;
	IO_STATUS_BLOCK statusBlock;
	uchar data[] = {
	    0x01,0x03,0x00,0x00,
	    0x00,0x00,0x00,0x00,
	    0x00,0x02,0x00,0x00,
	    0x00,0x01,0x00,0x00,
	    0x01,0x01,0x00,0x00,
	    0x34,0x00,0x00,0x00,
	    0x82,0x36,0x0E,0x01, // 130.54.14.1
	    0x03,0x00,0x01,0x00, // IF
	    0xFE,0xFF,0xFF,0xFF, // Metric1
	    0xFD,0xFF,0xFF,0xFF, // Metric2
	    0xFC,0xFF,0xFF,0xFF, // Metric3
	    0xFB,0xFF,0xFF,0xFF, // Metric4
	    0xC0,0xA8,0x92,0x02, // 192.168.146.2
#if 0
	    0x04,0x00,0x00,0x00, // dwForwardType
#else
	    0x02,0x00,0x00,0x00, // dwForwardType
#endif
	    0x16,0x27,0x00,0x00, // dwForwardProto
	    0x14,0x00,0x00,0x00, // dwForwardAge
	    0xFF,0xFF,0xFF,0xFF, // Netmask
	    0xFA,0xFF,0xFF,0xFF, // Metric5
	    0x00,0x00,0x00,0x00,
	    0x00,0x00,0x00,
	};

	status = ZwDeviceIoControlFile(TpHandle,
	    NULL,
	    NULL,
	    NULL,
	    &statusBlock,
	    1212420,
	    &data,
	    sizeof(data),
	    NULL,
	    0);
	if (status != STATUS_SUCCESS) {
		DbgPrint("ZwDeviceIoControlFile failed, error=%08x\n", status);
		return;
	}
}

NTSTATUS
OpenRawSctp(
    IN UCHAR Family,
    OUT HANDLE *pHandle,
    OUT PFILE_OBJECT *ppObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFILE_FULL_EA_INFORMATION eaInfo = NULL;
	int eaLength;

	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statusBlock;
	UNICODE_STRING devname;

	TCP_REQUEST_SET_INFORMATION_EX *tcp_req = NULL;
	ULONG hdrIncl = 1;
	ULONG Pktinfo = 1;
	ULONG ProtocolLevel = 10; /* PROTECTION_LEVEL_UNRESTRICTED */

	PTA_IP_ADDRESS taAddress;
	PTA_IP6_ADDRESS taAddress6;

	PDEVICE_OBJECT deviceObject;
	PIRP irp;

	DbgPrint("Enter into OpenRawSctp\n");

	tcp_req = (TCP_REQUEST_SET_INFORMATION_EX *)ExAllocatePool(NonPagedPool,
	    sizeof(*tcp_req) + sizeof(hdrIncl));
	if (tcp_req == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	RtlZeroMemory(tcp_req, sizeof(*tcp_req) + sizeof(hdrIncl));

	switch (Family) {
	case AF_INET:
		DbgPrint("AF_INET\n");
		eaLength = sizeof(FILE_FULL_EA_INFORMATION) +
		    sizeof(TdiTransportAddress) + sizeof(TA_IP_ADDRESS);
		eaInfo = (PFILE_FULL_EA_INFORMATION)ExAllocatePool(NonPagedPool, eaLength);
		if (eaInfo == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		RtlZeroMemory(eaInfo, eaLength);

		eaInfo->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
		RtlCopyMemory(eaInfo->EaName, TdiTransportAddress, sizeof(TdiTransportAddress));
		eaInfo->EaValueLength = sizeof(TA_IP_ADDRESS);

		taAddress = (PTA_IP_ADDRESS)(eaInfo->EaName + sizeof(TdiTransportAddress));
		taAddress->TAAddressCount = 1;
		taAddress->Address[0].AddressLength = sizeof(TDI_ADDRESS_IP);
		taAddress->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

		RtlInitUnicodeString(&devname, RawIPDeviceWithSCTP);

		break;
	case AF_INET6:
		DbgPrint("AF_INET6\n");
		eaLength = sizeof(FILE_FULL_EA_INFORMATION) +
		    sizeof(TdiTransportAddress) +
		    sizeof(TA_IP6_ADDRESS);
		eaInfo = (PFILE_FULL_EA_INFORMATION)ExAllocatePool(NonPagedPool, eaLength);
		if (eaInfo == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(eaInfo, eaLength);

		eaInfo->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
		RtlCopyMemory(eaInfo->EaName, TdiTransportAddress, sizeof(TdiTransportAddress));
		eaInfo->EaValueLength = sizeof(TA_IP6_ADDRESS);

		taAddress6 = (PTA_IP6_ADDRESS)(eaInfo->EaName +
		    sizeof(TdiTransportAddress));
		taAddress6->TAAddressCount = 1;
		taAddress6->Address[0].AddressLength = sizeof(TDI_ADDRESS_IP6);
		taAddress6->Address[0].AddressType = TDI_ADDRESS_TYPE_IP6;

		RtlInitUnicodeString(&devname, RawIP6DeviceWithSCTP);

		break;
	default:
		DbgPrint("Unknown Family: %d\n", Family);
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	InitializeObjectAttributes(&attr,
	    &devname,
	    OBJ_CASE_INSENSITIVE,
	    NULL,
	    NULL);

	status = ZwCreateFile(pHandle,
	    GENERIC_READ | GENERIC_WRITE,
	    &attr,
	    &statusBlock,
	    0L,
	    FILE_ATTRIBUTE_NORMAL,
	    FILE_SHARE_READ | FILE_SHARE_WRITE,
	    FILE_OPEN_IF,
	    0L,
	    eaInfo,
	    eaLength);
	if (status != STATUS_SUCCESS) {
		DbgPrint( "ZwCreateFile failed, code=%d\n", status);
		goto done;
	}

	status = ObReferenceObjectByHandle(*pHandle,
	    GENERIC_READ | GENERIC_WRITE,
	    NULL,
	    KernelMode,
	    ppObject,
	    NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint( "ObReferenceObjectByHandle failed, code=%d\n", status);
		ZwClose(*pHandle);
		goto done;
	}

	switch (Family) {
	case AF_INET:
		tcp_req->ID.toi_entity.tei_entity = CL_TL_ENTITY;
		tcp_req->ID.toi_entity.tei_instance = 0;
		tcp_req->ID.toi_class = INFO_CLASS_PROTOCOL;
		tcp_req->ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;

		tcp_req->ID.toi_id = 12; /* IP_HDRINCL */
		RtlCopyMemory(&tcp_req->Buffer, &hdrIncl, sizeof(hdrIncl));
		tcp_req->BufferSize = sizeof(hdrIncl);

		status = ZwDeviceIoControlFile(*pHandle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    IOCTL_TCP_SET_INFORMATION_EX,
		    tcp_req,
		    sizeof(*tcp_req) + sizeof(hdrIncl),
		    NULL,
		    0);
		if (status != STATUS_SUCCESS) {
			DbgPrint("ZwDeviceIoControlFile for IP_HDRINCL failed, code=%d\n", status);
			ObDereferenceObject(*ppObject);
			ZwClose(*pHandle);
			goto done;
		}

		deviceObject = IoGetRelatedDeviceObject(*ppObject);
		irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER,
		    deviceObject,
		    *ppObject,
		    NULL,
		    NULL);
		TdiBuildSetEventHandler(irp,
		    deviceObject,
		    *ppObject,
		    NULL,
		    NULL,
		    TDI_EVENT_RECEIVE_DATAGRAM,
		    SCTPReceiveDatagram,
		    NULL);

		status = IoCallDriver(deviceObject, irp);
		if (status != STATUS_SUCCESS) {
			DbgPrint("IoCallDriver for registering SCTPReceiveDatagra failed, code=%d\n", status);
			ObDereferenceObject(*ppObject);
			ZwClose(*pHandle);
			goto done;
		}
		break;

	case AF_INET6:
		tcp_req->ID.toi_entity.tei_entity = CL_TL_ENTITY;
		tcp_req->ID.toi_entity.tei_instance = 0;
		tcp_req->ID.toi_class = INFO_CLASS_PROTOCOL;
		tcp_req->ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;

		tcp_req->ID.toi_id = 12; /* IPV6_HDRINCL */
		RtlCopyMemory(&tcp_req->Buffer, &hdrIncl, sizeof(hdrIncl));
		tcp_req->BufferSize = sizeof(hdrIncl);

		status = ZwDeviceIoControlFile(*pHandle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    IOCTL_TCP_SET_INFORMATION_EX,
		    tcp_req,
		    sizeof(*tcp_req) + sizeof(hdrIncl),
		    NULL,
		    0);
		if (status != STATUS_SUCCESS) {
			DbgPrint("ZwDeviceIoControlFile for IPV6_HDRINCL failed, code=%d\n", status);
			ObDereferenceObject(*ppObject);
			ZwClose(*pHandle);
			goto done;
		}

		tcp_req->ID.toi_id = 27; /* IPV6_PKTINFO */
		RtlCopyMemory(&tcp_req->Buffer, &Pktinfo, sizeof(Pktinfo));
		tcp_req->BufferSize = sizeof(Pktinfo);

		status = ZwDeviceIoControlFile(*pHandle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    IOCTL_TCP_SET_INFORMATION_EX,
		    tcp_req,
		    sizeof(*tcp_req) + sizeof(hdrIncl),
		    NULL,
		    0);
		if (status != STATUS_SUCCESS) {
			DbgPrint("ZwDeviceIoControlFile for IPV6_PKTINFO failed, code=%d\n", status);
			ObDereferenceObject(*ppObject);
			ZwClose(*pHandle);
			goto done;
		}

		tcp_req->ID.toi_id = 38; /* IPV6_PROTECTION_LEVEL */
		RtlCopyMemory(&tcp_req->Buffer, &ProtocolLevel, sizeof(ProtocolLevel));
		tcp_req->BufferSize = sizeof(ProtocolLevel);

		status = ZwDeviceIoControlFile(*pHandle,
		    NULL,
		    NULL,
		    NULL,
		    &statusBlock,
		    IOCTL_TCP_SET_INFORMATION_EX,
		    tcp_req,
		    sizeof(*tcp_req) + sizeof(hdrIncl),
		    NULL,
		    0);
		if (status != STATUS_SUCCESS) {
			DbgPrint("ZwDeviceIoControlFile for IPV6_PROTECTION_LEVEL failed, code=%d\n", status);
			ObDereferenceObject(*ppObject);
			ZwClose(*pHandle);
			goto done;
		}

		deviceObject = IoGetRelatedDeviceObject(*ppObject);
		irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER,
		    deviceObject,
		    *ppObject,
		    NULL,
		    NULL);
		TdiBuildSetEventHandler(irp,
		    deviceObject,
		    *ppObject,
		    NULL,
		    NULL,
		    TDI_EVENT_RECEIVE_DATAGRAM,
		    SCTPReceiveDatagram6,
		    NULL);

		status = IoCallDriver(deviceObject, irp);
		if (status != STATUS_SUCCESS) {
			DbgPrint("IoCallDriver for registering SCTP6ReceiveDatagra failed, code=%d\n", status);
			ObDereferenceObject(*ppObject);
			ZwClose(*pHandle);
			goto done;
		}
		break;

	default:
		break;
	}

done:
	if (tcp_req != NULL) {
		ExFreePool(tcp_req);
	}
	if (eaInfo != NULL) {
		ExFreePool(eaInfo);
	}
	DbgPrint("Leave from OpenRawSctp\n");
	return status;
}


NTSTATUS
SCTPSendDatagram(
    IN struct mpkt *pkt,
    IN struct in_addr *dest)
{
	PTDI_CONNECTION_INFORMATION connectInfo;
	PTA_IP_ADDRESS taAddress;
	PDEVICE_OBJECT deviceObject;
	PIRP irp;
	KEVENT event;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS status;
	PNDIS_BUFFER buffer = NULL, firstBuffer, nextBuffer, failedBuffer;
	ULONG packetLength = 0;

	DbgPrint("Enter into SCTPSendDatagram\n");

	NdisQueryPacket(pkt->ndis_packet, NULL, NULL, &firstBuffer, &packetLength);

	DbgPrint("buffer => %p, packetLength => %d\n",
	    buffer, packetLength);
	connectInfo = (PTDI_CONNECTION_INFORMATION)ExAllocatePool(NonPagedPool,
	    sizeof(TDI_CONNECTION_INFORMATION) +
	    sizeof(TA_IP_ADDRESS));
	if (connectInfo == NULL) {
		DbgPrint("No memory for PTDI_CONNECTION_INFORMATION\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	RtlZeroMemory(connectInfo,
	    sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));
	connectInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
	connectInfo->RemoteAddress = (PUCHAR)connectInfo +
	    sizeof(TDI_CONNECTION_INFORMATION);
	taAddress = (PTA_IP_ADDRESS)connectInfo->RemoteAddress;
	taAddress->TAAddressCount = 1;
	taAddress->Address[0].AddressLength = sizeof(TDI_ADDRESS_IP);
	taAddress->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	RtlCopyMemory(&((PTDI_ADDRESS_IP)taAddress->Address[0].Address)->in_addr,
	    dest, sizeof(struct in_addr));

	deviceObject = IoGetRelatedDeviceObject(TpObject);

	irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM,
	    deviceObject,
	    TpObject,
	    NULL,
	    NULL);
	if (irp == NULL) {
		DbgPrint("TdiBuildInternalDeviceControlIrp failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	for (buffer = firstBuffer; buffer != NULL; buffer = nextBuffer) {
		NdisGetNextBuffer(buffer, &nextBuffer);
		try {
			MmProbeAndLockPages((PMDL)buffer, KernelMode, IoModifyAccess);
		} except ( EXCEPTION_EXECUTE_HANDLER ) {
			goto error;
		}
	}

	TdiBuildSendDatagram(irp,
	    deviceObject,
	    TpObject,
	    NULL,
	    NULL,
	    (PMDL)firstBuffer,
	    packetLength,
	    connectInfo);

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	irp->UserEvent = &event;
	irp->UserIosb = &statusBlock;

	status = IoCallDriver(deviceObject, irp);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
	}
	status = statusBlock.Status;
	if (status != STATUS_SUCCESS) {
		DbgPrint("IoCallDriver failed, code=%d\n", status);
	}

	NdisFreePacket(pkt->ndis_packet);
	ExFreePool(pkt);

	ExFreePool(connectInfo);
	DbgPrint("Leave from SCTPSendDatagram\n");
	return status;
error:
	SCTP_HEADER_FREE(pkt);
	if (buffer != NULL) {
		failedBuffer = buffer;
		for (buffer = firstBuffer; buffer != NULL && buffer != failedBuffer; buffer = nextBuffer) {
			NdisGetNextBuffer(buffer, &nextBuffer);
			MmUnlockPages((PMDL)buffer);
		}
	}

	ExFreePool(connectInfo);
	DbgPrint("Leave from SCTPSendDatagram#2\n");
	return status;
}


NTSTATUS
SCTPSendDatagram6(
    IN struct mpkt *pkt,
    IN struct in6_addr *dest,
    IN ULONG scopeId)
{
	PTDI_CONNECTION_INFORMATION connectInfo;
	PTA_IP6_ADDRESS taAddress6;
	PDEVICE_OBJECT deviceObject;
	PIRP irp;
	KEVENT event;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS status;
	PNDIS_BUFFER buffer = NULL, firstBuffer, nextBuffer, failedBuffer;
	ULONG packetLength = 0;

	DbgPrint("Enter into SCTPSendDatagram6\n");

	NdisQueryPacket(pkt->ndis_packet, NULL, NULL, &firstBuffer, &packetLength);

	connectInfo = (PTDI_CONNECTION_INFORMATION)ExAllocatePool(NonPagedPool,
	    sizeof(TDI_CONNECTION_INFORMATION) +
	    sizeof(TA_IP6_ADDRESS));
	if (connectInfo == NULL) {
		DbgPrint("No memory for PTDI_CONNECTION_INFORMATION\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	RtlZeroMemory(connectInfo,
	    sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP6_ADDRESS));
	connectInfo->RemoteAddressLength = sizeof(TA_IP6_ADDRESS);
	connectInfo->RemoteAddress = (PUCHAR)connectInfo +
	    sizeof(TDI_CONNECTION_INFORMATION);
	taAddress6 = (PTA_IP6_ADDRESS)connectInfo->RemoteAddress;
	taAddress6->TAAddressCount = 1;
	taAddress6->Address[0].AddressLength = sizeof(TDI_ADDRESS_IP6);
	taAddress6->Address[0].AddressType = TDI_ADDRESS_TYPE_IP6;
	RtlCopyMemory(&((PTDI_ADDRESS_IP6)taAddress6->Address[0].Address)->sin6_addr,
	    dest, sizeof(struct in6_addr));
	((PTDI_ADDRESS_IP6)taAddress6->Address[0].Address)->sin6_scope_id = scopeId;
	
	deviceObject = IoGetRelatedDeviceObject(Tp6Object);

	irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM,
	    deviceObject,
	    Tp6Object,
	    NULL,
	    NULL);
	if (irp == NULL) {
		DbgPrint("TdiBuildInternalDeviceControlIrp failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	for (buffer = firstBuffer; buffer != NULL; buffer = nextBuffer) {
		NdisGetNextBuffer(buffer, &nextBuffer);
		try {
			MmProbeAndLockPages((PMDL)buffer, KernelMode, IoModifyAccess);
		} except ( EXCEPTION_EXECUTE_HANDLER ) {
			goto error;
		}
	}

	TdiBuildSendDatagram(irp,
	    deviceObject,
	    Tp6Object,
	    NULL,
	    NULL,
	    (PMDL)firstBuffer,
	    packetLength,
	    connectInfo);

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	irp->UserEvent = &event;
	irp->UserIosb = &statusBlock;

	status = IoCallDriver(deviceObject, irp);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
	}
	status = statusBlock.Status;
	if (status != STATUS_SUCCESS) {
		DbgPrint("IoCallDriver failed, code=%d\n", status);
	}

	NdisFreePacket(pkt->ndis_packet);
	ExFreePool(pkt);

	ExFreePool(connectInfo);
	DbgPrint("Leave from SCTPSendDatagram6\n");
	return status;
error:
	SCTP_HEADER_FREE(pkt);
	if (buffer != NULL) {
		failedBuffer = buffer;
		for (buffer = firstBuffer; buffer != NULL && buffer != failedBuffer; buffer = nextBuffer) {
			NdisGetNextBuffer(buffer, &nextBuffer);
			MmUnlockPages((PMDL)buffer);
		}
	}

	ExFreePool(connectInfo);
	DbgPrint("Leave from SCTPSendDatagram6#2\n");
	return status;
}


NTSTATUS
SCTPReceiveDatagram(
    IN PVOID TdiEventContext,
    IN LONG SourceAddressLength,
    IN PVOID SourceAddress,
    IN LONG OptionsLength,
    IN PVOID Options,
    IN ULONG ReceiveDatagramFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket)
{
	unsigned int i;
	struct mpkt *pkt;
	struct mbuf *m;

	DbgPrint("SCTPReceiveDatagram( BytesAvailable => %d ):\n", BytesAvailable);
	DbgPrint("SCTPReceiveDatagram( OptionsLength => %d ):\n", OptionsLength);
	
	for (i = 0; i < BytesAvailable; i++) {
		DbgPrint("%0.2X", ((UCHAR *)Tsdu)[i]);
		if (i % 2 != 0)
			DbgPrint(" ");
		if (i % 8 == 7)
			DbgPrint("\n");
	}
	DbgPrint("\n");

	pkt = SCTP_GET_HEADER_FOR_OUTPUT(BytesAvailable);
	if (pkt == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	m = SCTP_HEADER_TO_CHAIN(pkt);
	RtlCopyMemory(SCTP_BUF_AT(m, 0), Tsdu, BytesAvailable);
	SCTP_BUF_SET_LEN(m, BytesAvailable);

	KeWaitForMutexObject(&inq->mtx, Executive, KernelMode, FALSE, NULL);
	if (inq->tail == NULL) {
		inq->head = pkt;
	} else {
		inq->tail->pkt_next = pkt;
	}
	inq->tail = pkt;
	KeReleaseMutex(&inq->mtx, 0);
	KeSetEvent(&RcvContext->event, IO_NO_INCREMENT, FALSE);

	return STATUS_SUCCESS;
}

NTSTATUS
SCTPReceiveDatagram6(
    IN PVOID TdiEventContext,
    IN LONG SourceAddressLength,
    IN PVOID SourceAddress,
    IN LONG OptionsLength,
    IN PVOID Options,
    IN ULONG ReceiveDatagramFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket)
{
	struct mpkt *pkt;
	struct mbuf *m;
	unsigned int i;
	struct ip6_hdr *ip6h;

	PTA_IP6_ADDRESS taAddr;
	struct in6_pktinfo_option *pkt6info;

	DbgPrint("SCTPReceiveDatagram6( BytesAvailable => %d ):\n", BytesAvailable);
	DbgPrint("SCTPReceiveDatagram6( OptionsLength => %d ):\n", OptionsLength);
	
	for (i = 0; i < BytesAvailable; i++) {
		DbgPrint("%0.2X", ((UCHAR *)Tsdu)[i]);
		if (i % 2 != 0)
			DbgPrint(" ");
		if (i % 8 == 7)
			DbgPrint("\n");
	}
	DbgPrint("\n");

	if (SourceAddressLength >= sizeof(TA_IP6_ADDRESS)) {
		taAddr = SourceAddress;
		if (taAddr->Address[0].AddressType == TDI_ADDRESS_TYPE_IP6) {
			DbgPrint("From: ");
			for (i = 0; i < sizeof(taAddr->Address[0].Address[0].sin6_addr); i++) {
				DbgPrint("%0.2x", ((UCHAR *)&taAddr->Address[0].Address[0].sin6_addr)[i]);
				if (i > 0 && i % 2 == 1 && i != sizeof(taAddr->Address[0].Address[0].sin6_addr) - 1) {
					DbgPrint(":");
				}
			}
			DbgPrint("%%%d\n", taAddr->Address[0].Address[0].sin6_scope_id);
		}
	}
	if (OptionsLength == sizeof(*pkt6info)) {
		pkt6info = Options;
		DbgPrint("To: ");
		for (i = 0; i < sizeof(pkt6info->ipi6_addr); i++) {
			DbgPrint("%0.2x", ((UCHAR *)&pkt6info->ipi6_addr)[i]);
			if (i > 0 && i % 2 == 1 && i != sizeof(pkt6info->ipi6_addr) - 1) {
				DbgPrint(":");
			}
		}
		DbgPrint("%%%d\n", pkt6info->ipi6_ifindex);
	}

	pkt = SCTP_GET_HEADER_FOR_OUTPUT(BytesAvailable + sizeof(*ip6h));
	if (pkt == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	m = SCTP_HEADER_TO_CHAIN(pkt);

	ip6h = mtod(m, struct ip6_hdr *);
	RtlZeroMemory(ip6h, sizeof(*ip6h));
	ip6h->ip6_vfc = (IPV6_VERSION & IPV6_VERSION_MASK);
	ip6h->ip6_hlim = 255;
	ip6h->ip6_plen = htons((USHORT)BytesAvailable);
	ip6h->ip6_nxt = IPPROTO_SCTP;
	RtlCopyMemory(&ip6h->ip6_src, &((PTA_IP6_ADDRESS)SourceAddress)->Address[0].Address[0].sin6_addr,
	    sizeof(struct in6_addr));
	RtlCopyMemory(&ip6h->ip6_dst, &((struct in6_pktinfo_option *)Options)->ipi6_addr,
	    sizeof(struct in6_addr));
	
	RtlCopyMemory(SCTP_BUF_AT(m, sizeof(*ip6h)), Tsdu, BytesAvailable);
	SCTP_BUF_SET_LEN(m, BytesAvailable);

	KeWaitForMutexObject(&inq->mtx, Executive, KernelMode, FALSE, NULL);
	if (inq->tail == NULL) {
		inq->head = pkt;
	} else {
		inq->tail->pkt_next = pkt;
	}
	inq->tail = pkt;
	KeReleaseMutex(&inq->mtx, 0);
	KeSetEvent(&RcvContext->event, IO_NO_INCREMENT, FALSE);

	return STATUS_SUCCESS;
}

VOID
SCTPReceiveThread(IN PVOID _ctx)
{
	struct RcvContext *ctx = _ctx;
	struct mpkt *pkt = NULL;
	struct ip *iph;

	DbgPrint("SCTPReceiveThread: start\n");
	while (ctx->bActive == TRUE) {
		DbgPrint("SCTPReceiveThread: before sleep\n");
		KeWaitForSingleObject(&ctx->event,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		DbgPrint("SCTPReceiveThread: after sleep\n");
		for (;;) {
			KeWaitForMutexObject(&inq->mtx,
			    Executive,
			    KernelMode,
			    FALSE,
			    NULL);
			pkt = inq->head;
			if (pkt != NULL) {
				inq->head = pkt->pkt_next;
				if (inq->head == NULL) {
					inq->tail = NULL;
				}
				pkt->pkt_next = NULL;
			}
			KeReleaseMutex(&inq->mtx, 0);

			if (pkt == NULL) {
				break;
			}
			iph = mtod(SCTP_HEADER_TO_CHAIN(pkt), struct ip *);
			if (iph->ip_v == IPVERSION) {
				DbgPrint("before sctp_input\n");
#if 1
				sctp_input(pkt, 20);
#endif
				DbgPrint("after sctp_input\n");
			} else if (iph->ip_v == (IPV6_VERSION >> 4)) {
				DbgPrint("before sctp6_input\n");
				DbgPrint("after sctp6_input\n");
			}
		}
	}
	DbgPrint("SCTPReceiveThread: end\n");
}

/*
 * Copied from $FreeBSD: src/sys/netinet6/in6.c,v 1.51.2.10
 * Convert IP6 address to printable (loggable) representation.
 */
static char digits[] = "0123456789abcdef";
static int ip6round = 0;
char *
ip6_sprintf(addr)
	const struct in6_addr *addr;
{
	static char ip6buf[8][48];
	int i;
	char *cp;
	const u_int16_t *a = (const u_int16_t *)addr;
	const u_int8_t *d;
	int dcolon = 0;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (const u_char *)a;
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d++ & 0xf];
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = 0;
	return (ip6buf[ip6round]);
}

/* XXX Need to change following routines. */
unsigned int RandomValue = 0;

unsigned int // Returns: A random value between 1 and 2^32.
Random(void)
{
    //
    // The algorithm is R = (aR + c) mod m, where R is the random number,
    // a is a magic multiplier, c is a constant, and the modulus m is the
    // maximum number of elements in the period.  We chose our m to be 2^32
    // in order to get the mod operation for free.
    // BUGBUG: What about concurrent calls?
    //
    RandomValue = (1664525 * RandomValue) + 1013904223;

    return RandomValue;
}

void
SeedRandom(uint Seed)
{
    int i;

    //
    // Incorporate the seed into our random value.
    //
    RandomValue ^= Seed;

    //
    // Stir the bits.
    //
    for (i = 0; i < 100; i++)
        (void) Random();
}

void
read_random(uint8_t *buf, unsigned int len)
{
	uint8_t *ptr;

	for (ptr = buf; ptr < buf + len; ptr += sizeof(unsigned int)) {
		*((unsigned int *)ptr) = Random();
	}
}
