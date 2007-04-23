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
 * $Id: ntinit.c,v 1.7 2007/04/23 15:49:41 kozuka Exp $
 */
#pragma data_seg("NONPAGE")

#include "globals.h"

#include <netinet/sctp_os_windows.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_addr.h>
#include <netinet/sctp_output.h>

#include <net/radix.h>

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
NTSTATUS _SCTPReceiveDatagram(IN PVOID, IN LONG, IN PVOID, IN LONG,
    IN PVOID, IN ULONG, IN ULONG, IN ULONG, OUT ULONG *, IN PVOID, OUT PIRP *);
NTSTATUS _SCTPReceiveDatagram6(IN PVOID, IN LONG, IN PVOID, IN LONG,
    IN PVOID, IN ULONG, IN ULONG, IN ULONG, OUT ULONG *, IN PVOID, OUT PIRP *);
NTSTATUS _SCTPSendDatagram(IN struct mpkt *, IN struct in_addr *);
NTSTATUS _SendDatagram6(IN UCHAR *, IN struct in6_addr *, IN ULONG);
VOID SCTPReceiveThread(IN PVOID);
VOID SCTPIrpThread(IN PVOID);
VOID SCTPIrpThread2(IN PVOID);
VOID ClientPnPAddNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);
VOID ClientPnPDelNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);

NTSTATUS SCTPCreate(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPCleanup(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPClose(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatchDeviceControl(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatchInternalDeviceControl(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatch(IN PDEVICE_OBJECT, IN PIRP);

struct RcvContext {
	BOOLEAN		bActive;
	KEVENT		event;
} *RcvContext, *Rcv6Context, *IrpContext, *IrpContext2;

struct ifqueue {
	struct mbuf	*head;
	struct mbuf	*tail;
	KMUTEX		mtx;
} *inq, *in6q;

struct irpqueue {
	TAILQ_ENTRY(irpqueue) entry;
	PIRP irp;
	KEVENT event;
	IO_STATUS_BLOCK statusBlock;
};
TAILQ_HEAD(irpqueuehead, irpqueue);

struct irpqueueinfo {
	struct irpqueuehead head;
	KSPIN_LOCK lock;
} *irpinfo, *irpinfo2;

PDEVICE_OBJECT SctpTcpDeviceObject = NULL, SctpUdpDeviceObject = NULL;
PFILE_OBJECT TpObject, Tp6Object, RcvObject, IrpObject, IrpObject2;
HANDLE TpHandle, Tp6Handle, RcvHandle, IrpHandle, IrpHandle2, BindingHandle;

NPAGED_LOOKASIDE_LIST ExtBufLookaside;
NDIS_HANDLE SctpBufferPool;
NDIS_HANDLE SctpPacketPool;

LARGE_INTEGER zero_timeout;

struct socket *so = NULL;

void mbuf_init(void);
void mbuf_destroy(void);

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
	mbuf_init();
#if 0
	SCTP_HEADER_INIT();
#endif

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

#if 0
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
		    THREAD_ALL_ACCESS,
		    NULL,
		    KernelMode,
		    (PVOID *)&RcvObject,
		    NULL);
		ZwClose(RcvHandle);
	}
#endif

	irpinfo = ExAllocatePool(NonPagedPool, sizeof(*irpinfo));
	RtlZeroMemory(irpinfo, sizeof(*irpinfo));
	TAILQ_INIT(&irpinfo->head);
	KeInitializeSpinLock(&irpinfo->lock);

	IrpContext = ExAllocatePool(NonPagedPool, sizeof(*IrpContext));
	RtlZeroMemory(IrpContext, sizeof(*IrpContext));
	KeInitializeEvent(&IrpContext->event, SynchronizationEvent, FALSE);
	IrpContext->bActive = TRUE;

	InitializeObjectAttributes(&ObjectAttributes,
	    NULL,
	    OBJ_KERNEL_HANDLE,
	    NULL,
	    NULL);
	status = PsCreateSystemThread(&IrpHandle,
	    0,
	    &ObjectAttributes,
	    NULL,
	    NULL,
	    SCTPIrpThread,
	    IrpContext);
	if (status == STATUS_SUCCESS) {
		ObReferenceObjectByHandle(IrpHandle,
		    THREAD_ALL_ACCESS,
		    NULL,
		    KernelMode,
		    (PVOID *)&IrpObject,
		    NULL);
		ZwClose(IrpHandle);
	}

	IrpContext2 = ExAllocatePool(NonPagedPool, sizeof(*IrpContext2));
	RtlZeroMemory(IrpContext2, sizeof(*IrpContext2));
	KeInitializeEvent(&IrpContext2->event, SynchronizationEvent, FALSE);
	IrpContext2->bActive = TRUE;

	irpinfo2 = ExAllocatePool(NonPagedPool, sizeof(*irpinfo2));
	RtlZeroMemory(irpinfo2, sizeof(*irpinfo2));
	TAILQ_INIT(&irpinfo2->head);
	KeInitializeSpinLock(&irpinfo2->lock);

	InitializeObjectAttributes(&ObjectAttributes,
	    NULL,
	    OBJ_KERNEL_HANDLE,
	    NULL,
	    NULL);
	status = PsCreateSystemThread(&IrpHandle2,
	    0,
	    &ObjectAttributes,
	    NULL,
	    NULL,
	    SCTPIrpThread2,
	    IrpContext2);
	if (status == STATUS_SUCCESS) {
		ObReferenceObjectByHandle(IrpHandle2,
		    THREAD_ALL_ACCESS,
		    NULL,
		    KernelMode,
		    (PVOID *)&IrpObject2,
		    NULL);
		ZwClose(IrpHandle2);
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
	DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = SCTPDispatchInternalDeviceControl;
	DriverObject->DriverUnload = Unload;

	/* XXX */
	if (oldIrql > KeGetCurrentIrql()) {
		KeLowerIrql(oldIrql);
	}

	if (0) {
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

	route_init();
#if 0
	if (1) {
		struct route ro;
		RtlZeroMemory(&ro, sizeof(ro));

		ro.ro_dst.sin6.sin6_family = AF_INET6;
		ro.ro_dst.sin6.sin6_len = sizeof(struct sockaddr_in6);
		ro.ro_dst.sin6.sin6_addr.s6_addr[0] = 0xfe;
		ro.ro_dst.sin6.sin6_addr.s6_addr[1] = 0x80;
		ro.ro_dst.sin6.sin6_addr.s6_addr[8] = 0x02;
		ro.ro_dst.sin6.sin6_addr.s6_addr[9] = 0x0c;
		ro.ro_dst.sin6.sin6_addr.s6_addr[10] = 0x29;
		ro.ro_dst.sin6.sin6_addr.s6_addr[11] = 0xff;
		ro.ro_dst.sin6.sin6_addr.s6_addr[12] = 0xfe;
		ro.ro_dst.sin6.sin6_addr.s6_addr[13] = 0x4e;
		ro.ro_dst.sin6.sin6_addr.s6_addr[14] = 0x66;
		ro.ro_dst.sin6.sin6_addr.s6_addr[15] = 0x06;
		ro.ro_dst.sin6.sin6_scope_id = 4;
		rtalloc(&ro);
		if (ro.ro_rt != NULL) {
			DbgPrint("hoge\n");
			DbgPrint("GW: %s/%d\n", ip6_sprintf(&ro.ro_rt->rt_gateway.sin6.sin6_addr), ro.ro_rt->rt_gateway.sin6.sin6_scope_id);
			if (ro.ro_rt->rt_ifp != NULL) {
				DbgPrint("IF_XNAME: %s\n", ro.ro_rt->rt_ifp->if_xname);
			}
			RTFREE(ro.ro_rt);
		}
	}
#endif
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
	struct sctp_inpcb *inp;

	DbgPrint("Enter into Unload\n");

	LIST_FOREACH(inp, &sctppcbinfo.listhead, sctp_list) {
		sctp_inpcb_free(inp, 0, 0);
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
#if 0
	if (RcvContext != NULL) {
		RcvContext->bActive = FALSE;
		DbgPrint("before KeSetEvent\n");
		KeSetEvent(&RcvContext->event, IO_NO_INCREMENT, FALSE);
		DbgPrint("after KeSetEvent\n");
		status = KeWaitForSingleObject(RcvObject,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		DbgPrint("before ObDereferenceObject\n");
		ObDereferenceObject(RcvObject);
		DbgPrint("after ObDereferenceObject\n");
		ExFreePool(RcvContext);
	}
#endif
	if (IrpContext != NULL) {
		IrpContext->bActive = FALSE;
		DbgPrint("before KeSetEvent\n");
		KeSetEvent(&IrpContext->event, IO_NO_INCREMENT, FALSE);
		DbgPrint("after KeSetEvent\n");
		status = KeWaitForSingleObject(IrpObject,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		DbgPrint("before ObDereferenceObject\n");
		ObDereferenceObject(IrpObject);
		DbgPrint("after ObDereferenceObject\n");
		ExFreePool(IrpContext);
	}
	if (IrpContext2 != NULL) {
		IrpContext2->bActive = FALSE;
		DbgPrint("before KeSetEvent\n");
		KeSetEvent(&IrpContext2->event, IO_NO_INCREMENT, FALSE);
		DbgPrint("after KeSetEvent\n");
		status = KeWaitForSingleObject(IrpObject2,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		DbgPrint("before ObDereferenceObject\n");
		ObDereferenceObject(IrpObject2);
		DbgPrint("after ObDereferenceObject\n");
		ExFreePool(IrpContext2);
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

#if 0
	SCTP_HEADER_DESTROY();
#endif
	SCTP_BUF_DESTROY();
	mbuf_destroy();

	DbgPrint("Left from Unload\n");
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
		    _SCTPReceiveDatagram,
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
		    _SCTPReceiveDatagram6,
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
_SCTPSendDatagramComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID context)
{
	PIO_STACK_LOCATION irpSp;
	struct mbuf *o_pak = context;
	PMDL mdl = NULL, nextMdl = NULL;
	PTDI_CONNECTION_INFORMATION connectInfo;

	irpSp = IoGetCurrentIrpStackLocation(irp);

	connectInfo = ((PTDI_REQUEST_KERNEL_SENDDG)&irpSp->Parameters)->SendDatagramInformation;

	DbgPrint("connectInfo=%p, o_pak=%p,irp->MdlAddress=%p,irp=>%p\n",
	    connectInfo, o_pak, irp->MdlAddress, irp);
	if (connectInfo != NULL) {
		DbgPrint("hoge#1\n");
		ExFreePool(connectInfo);
		DbgPrint("hoge#1\n");
	}
	if (o_pak != NULL) {
		DbgPrint("hoge#2\n");
		SCTP_BUF_FREE_ALL(o_pak);
		DbgPrint("hoge#2\n");
	}

	if (irp->MdlAddress != NULL) {
		DbgPrint("hoge3\n");
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			NdisFreeBuffer((PNDIS_BUFFER)mdl);
		}

		irp->MdlAddress = NULL;
		DbgPrint("hoge#3\n");
	}
	DbgPrint("hoge#4\n");
	IoFreeIrp(irp);
	DbgPrint("hoge#4\n");

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
_SCTPSendDatagram(
    IN struct mbuf *o_pak,
    IN struct in_addr *dest)
{
	struct mbuf *m;
	PTDI_CONNECTION_INFORMATION connectInfo;
	PTA_IP_ADDRESS taAddress;
	PDEVICE_OBJECT deviceObject;
	struct irpqueue *irpqueue;
	PIRP irp;
	KIRQL oldIrql;
	KEVENT event;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS status;
	PNDIS_BUFFER buffer = NULL, firstBuffer = NULL, prevBuffer = NULL, failedBuffer = NULL, nextBuffer;
	ULONG packetLength = 0, length = 0;

	DbgPrint("Enter into SCTPSendDatagram\n");

	//NdisQueryPacket(o_pak->m_pkt.ndis_packet, NULL, NULL, &firstBuffer, &packetLength);
	packetLength = SCTP_HEADER_LEN(o_pak);

	DbgPrint("packetLength => %d\n",
	    packetLength);
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

#if 1
	irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
#else
	KeSetEvent(&IrpContext2->event, IO_NO_INCREMENT, FALSE);
	KeAcquireSpinLock(&irpinfo2->lock, &oldIrql);
	irpqueue = TAILQ_FIRST(&irpinfo2->head);
	if (irpqueue == NULL) {
		DbgPrint("irpqueue=NULL\n");
		goto error;
	}
	TAILQ_REMOVE(&irpinfo2->head, irpqueue, entry);
	KeReleaseSpinLock(&irpinfo2->lock, oldIrql);
	irp = irpqueue->irp;
	ExFreePool(irpqueue);
#endif
	if (irp == NULL) {
		DbgPrint("TdiBuildInternalDeviceControlIrp failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	for (m = o_pak; m != NULL; m = SCTP_BUF_GET_NEXT(m)) {
		NdisAllocateBuffer(&status, &buffer, SctpBufferPool, m->m_data, SCTP_BUF_GET_LEN(m));
		if (status != NDIS_STATUS_SUCCESS) {
			goto error;
		}
		if (firstBuffer == NULL) {
			firstBuffer = buffer;
		}
		if (prevBuffer != NULL) {
			NDIS_BUFFER_LINKAGE(prevBuffer) = buffer;
		}

		try {
			MmProbeAndLockPages((PMDL)buffer, KernelMode, IoModifyAccess);
		} except ( EXCEPTION_EXECUTE_HANDLER ) {
			goto error;
		}
		prevBuffer = buffer;
	}

	TdiBuildSendDatagram(irp,
	    deviceObject,
	    TpObject,
	    _SCTPSendDatagramComp,
	    o_pak,
	    (PMDL)firstBuffer,
	    packetLength,
	    connectInfo);

	status = IoCallDriver(deviceObject, irp);
	if (status != STATUS_PENDING) {
		_SCTPSendDatagramComp(deviceObject, irp, o_pak);
	}
	return status;
#if 0
	if (status == STATUS_PENDING) {
		DbgPrint("hoge\n");
		KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
		status = irpqueue->statusBlock.Status;
	}
	if (status != STATUS_SUCCESS) {
		DbgPrint("IoCallDriver failed, code=%X\n", status);
	}

	SCTP_BUF_FREE_ALL(o_pak);
	//NdisFreePacket(o_pak->m_pkt.ndis_packet);
	//ExFreePool(o_pak);
	ExFreePool(connectInfo);
	DbgPrint("Leave from SCTPSendDatagram\n");
	return status;
#endif
error:
	if (buffer != NULL) {
		failedBuffer = buffer;
		for (buffer = firstBuffer; buffer != NULL && buffer != failedBuffer; buffer = nextBuffer) {
			NdisGetNextBuffer(buffer, &nextBuffer);
			MmUnlockPages((PMDL)buffer);
			NdisFreeBuffer(buffer);
		}
	}
	SCTP_HEADER_FREE(o_pak);

	ExFreePool(connectInfo);
	DbgPrint("Leave from SCTPSendDatagram#2\n");
	return status;
}


NTSTATUS
_SCTPSendDatagram6(
    IN struct mbuf *o_pak,
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
	return STATUS_SUCCESS;
}

NTSTATUS
_SCTPReceiveDatagramComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID context)
{
	PMDL mdl = NULL, nextMdl = NULL;
	struct mbuf *i_pak = context;

	DbgPrint("_SCTPReceiveDatagramComp\n");

	DbgPrint("before sctp_input\n");
	sctp_input(i_pak, 20);
	DbgPrint("after sctp_input\n");

	if (irp->MdlAddress != NULL) {
		DbgPrint("hoge3\n");
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		irp->MdlAddress = NULL;
		DbgPrint("hoge#3\n");
	}
	DbgPrint("hoge#4\n");
	IoFreeIrp(irp);
	DbgPrint("hoge#4\n");
	return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS
_SCTPReceiveDatagram(
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
	struct mbuf *i_pak, *m;
	PDEVICE_OBJECT deviceObject;
	struct irpqueue *irpqueue = NULL;
	KIRQL oldIrql;
	PIRP irp;
	PMDL mdl;

	DbgPrint("_SCTPReceiveDatagram( BytesAvailable => %d ):\n", BytesAvailable);
	DbgPrint("_SCTPReceiveDatagram( OptionsLength => %d ):\n", OptionsLength);
	
#if 0
	for (i = 0; i < BytesAvailable; i++) {
		DbgPrint("%0.2X", ((UCHAR *)Tsdu)[i]);
		if (i % 2 != 0)
			DbgPrint(" ");
		if (i % 8 == 7)
			DbgPrint("\n");
	}
	DbgPrint("\n");
#endif

	i_pak = SCTP_GET_HEADER_FOR_OUTPUT(BytesAvailable);
	if (i_pak == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	m = SCTP_HEADER_TO_CHAIN(i_pak);
	SCTP_BUF_SET_LEN(m, BytesAvailable);
	i_pak->m_pkthdr.len = SCTP_BUF_GET_LEN(m);
	deviceObject = IoGetRelatedDeviceObject(TpObject);
#if 1
	irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
#else

	KeSetEvent(&IrpContext->event, IO_NO_INCREMENT, FALSE);
	KeAcquireSpinLock(&irpinfo->lock, &oldIrql);
	irpqueue = TAILQ_FIRST(&irpinfo->head);
	if (irpqueue == NULL) {
		DbgPrint("irpqueue=NULL\n");
		SCTP_HEADER_FREE(i_pak);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	TAILQ_REMOVE(&irpinfo->head, irpqueue, entry);
	KeReleaseSpinLock(&irpinfo->lock, oldIrql);
	irp = irpqueue->irp;
	ExFreePool(irpqueue);
#endif

	mdl = IoAllocateMdl(SCTP_BUF_AT(m, 0), BytesAvailable, FALSE, FALSE, NULL);
	if (!mdl) {
		IoFreeIrp(irp);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(mdl);
		IoFreeIrp(irp);
		return STATUS_UNSUCCESSFUL;
	}

	TdiBuildReceiveDatagram(irp,
	    deviceObject,
	    TpObject,
	    _SCTPReceiveDatagramComp,
	    i_pak,
	    (PMDL)mdl,
	    BytesAvailable,
	    0,
	    NULL,
	    TDI_RECEIVE_NORMAL);
	IoSetNextIrpStackLocation(irp);
	*BytesTaken = 0;
	*IoRequestPacket = irp;

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
_SCTPReceiveDatagram6(
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
	struct mbuf *i_pak, *m;
	unsigned int i;
	struct ip6_hdr *ip6h;

	PTA_IP6_ADDRESS taAddr;
	struct in6_pktinfo_option *pkt6info;

	DbgPrint("_SCTPReceiveDatagram6( BytesAvailable => %d ):\n", BytesAvailable);
	DbgPrint("_SCTPReceiveDatagram6( OptionsLength => %d ):\n", OptionsLength);
	
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

	i_pak = SCTP_GET_HEADER_FOR_OUTPUT(BytesAvailable + sizeof(*ip6h));
	if (i_pak == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	m = SCTP_HEADER_TO_CHAIN(i_pak);

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
	i_pak->m_pkthdr.len = SCTP_BUF_GET_LEN(m);

	KeWaitForMutexObject(&inq->mtx, Executive, KernelMode, FALSE, NULL);
	if (inq->tail == NULL) {
		inq->head = i_pak;
	} else {
		inq->tail->m_nextpkt = i_pak;
	}
	inq->tail = i_pak;
	KeReleaseMutex(&inq->mtx, 0);
	KeSetEvent(&RcvContext->event, IO_NO_INCREMENT, FALSE);

	return STATUS_SUCCESS;
}

VOID
SCTPReceiveThread(IN PVOID _ctx)
{
	struct RcvContext *ctx = _ctx;
	struct mpkt *i_pak = NULL;
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
			i_pak = inq->head;
			if (i_pak != NULL) {
				inq->head = i_pak->m_nextpkt;
				if (inq->head == NULL) {
					inq->tail = NULL;
				}
				i_pak->m_nextpkt = NULL;
			}
			KeReleaseMutex(&inq->mtx, 0);

			if (i_pak == NULL) {
				break;
			}
			iph = mtod(SCTP_HEADER_TO_CHAIN(i_pak), struct ip *);
			if (iph->ip_v == IPVERSION) {
				DbgPrint("before sctp_input\n");
				sctp_input(i_pak, 20);
				DbgPrint("after sctp_input\n");
			} else if (iph->ip_v == (IPV6_VERSION >> 4)) {
				DbgPrint("before sctp6_input\n");
				DbgPrint("after sctp6_input\n");
			}
		}
	}
	DbgPrint("SCTPReceiveThread: end\n");
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID
SCTPIrpThread(IN PVOID _ctx)
{
	struct RcvContext *ctx = _ctx;
	struct irpqueue *irpqueue;
	PIRP irp;
	PDEVICE_OBJECT deviceObject;
	KIRQL oldIrql;
	int i;

	DbgPrint("SCTPIrpThread: start\n");
	deviceObject = IoGetRelatedDeviceObject(TpObject);
	for (i = 0; i < 10; i++) {
#if 0
		irp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE_DATAGRAM,
		    deviceObject,
		    TpObject,
		    NULL,
		    NULL);
#else
		irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
#endif
		irpqueue = ExAllocatePool(NonPagedPool, sizeof(*irpqueue));
		irpqueue->irp = irp;
		KeAcquireSpinLock(&irpinfo->lock, &oldIrql);
		TAILQ_INSERT_HEAD(&irpinfo->head, irpqueue, entry);
		KeReleaseSpinLock(&irpinfo->lock, oldIrql);
	}
	while (ctx->bActive == TRUE) {
		KeWaitForSingleObject(&ctx->event,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		if (ctx->bActive == FALSE) {
			DbgPrint("SCTPIrpThread: false\n");
			break;
		}
#if 0
		irp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE_DATAGRAM,
		    deviceObject,
		    TpObject,
		    NULL,
		    NULL);
#else
		irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
#endif
		irpqueue = ExAllocatePool(NonPagedPool, sizeof(*irpqueue));
		irpqueue->irp = irp;
		KeAcquireSpinLock(&irpinfo->lock, &oldIrql);
		TAILQ_INSERT_HEAD(&irpinfo->head, irpqueue, entry);
		KeReleaseSpinLock(&irpinfo->lock, oldIrql);
		DbgPrint("SCTPIrpThread: before sleep\n");
	}
	DbgPrint("SCTPIrpThread: end\n");
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID
SCTPIrpThread2(IN PVOID _ctx)
{
	struct RcvContext *ctx = _ctx;
	struct irpqueue *irpqueue;
	PIRP irp;
	PDEVICE_OBJECT deviceObject;
	KIRQL oldIrql;
	int i;

	DbgPrint("SCTPIrpThread2: start\n");
	deviceObject = IoGetRelatedDeviceObject(TpObject);
	for (i = 0; i < 10; i++) {
		irpqueue = ExAllocatePool(NonPagedPool, sizeof(*irpqueue));
		KeInitializeEvent(&irpqueue->event, NotificationEvent, FALSE);
#if 0
		irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM,
		    deviceObject,
		    TpObject,
		    &irpqueue->event,
		    &irpqueue->statusBlock);
#else
		irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
#endif
		irpqueue->irp = irp;
		KeAcquireSpinLock(&irpinfo2->lock, &oldIrql);
		TAILQ_INSERT_HEAD(&irpinfo2->head, irpqueue, entry);
		KeReleaseSpinLock(&irpinfo2->lock, oldIrql);
	}
	while (ctx->bActive == TRUE) {
		KeWaitForSingleObject(&ctx->event,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		if (ctx->bActive == FALSE) {
			break;
		}
		irpqueue = ExAllocatePool(NonPagedPool, sizeof(*irpqueue));
#if 0
		KeInitializeEvent(&irpqueue->event, NotificationEvent, FALSE);
		irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM,
		    deviceObject,
		    TpObject,
		    &irpqueue->event,
		    &irpqueue->statusBlock);
#else
		irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
#endif
		irpqueue->irp = irp;
		KeAcquireSpinLock(&irpinfo2->lock, &oldIrql);
		TAILQ_INSERT_HEAD(&irpinfo2->head, irpqueue, entry);
		KeReleaseSpinLock(&irpinfo2->lock, oldIrql);
		DbgPrint("SCTPIrpThread2: before sleep\n");
	}
	DbgPrint("SCTPIrpThread2: end\n");
	PsTerminateSystemThread(STATUS_SUCCESS);
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
