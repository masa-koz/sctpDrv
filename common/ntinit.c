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
 * $Id: ntinit.c,v 1.10 2007/05/15 03:37:26 kozuka Exp $
 */

#include <netinet/sctp_os_windows.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_addr.h>
#include <netinet/sctp_output.h>

#include <net/radix.h>

#define RawIPDeviceWithSCTP L"\\Device\\RawIP\\132"
#define RawIP6DeviceWithSCTP L"\\Device\\RawIp6\\132"

#define DD_SCTP_ONE_TO_ONE_DEVICE_NAME L"\\Device\\SctpTcp"
#define DD_SCTP_ONE_TO_MANY_DEVICE_NAME L"\\Device\\SctpUdp"


typedef struct _IPOutputCtx {
	struct mbuf *o_pak;
	TDI_CONNECTION_INFORMATION sendDatagramInfo;
	TA_IP_ADDRESS address;
} IPOutputCtx;

typedef struct _IP6OutputCtx {
	struct mbuf *o_pak;
	TDI_CONNECTION_INFORMATION sendDatagramInfo;
	TA_IP6_ADDRESS address;
} IP6OutputCtx;

typedef struct _IPInputCtx {
	struct mbuf *i_pak;
	TDI_CONNECTION_INFORMATION returnInfo;
	TA_IP_ADDRESS address;
} IPInputCtx;

typedef struct _IP6InputCtx {
	struct mbuf *i_pak;
	TDI_CONNECTION_INFORMATION returnInfo;
	TA_IP6_ADDRESS address;
	UCHAR options[TDI_CMSG_SPACE(sizeof(struct in6_pktinfo))];
} IP6InputCtx;


NTSTATUS DriverEntry(IN PDRIVER_OBJECT, IN PUNICODE_STRING);
VOID Unload(IN PDRIVER_OBJECT);

NTSTATUS OpenRawSctp(IN UCHAR, OUT HANDLE *, OUT PFILE_OBJECT *);
VOID ClientPnPAddNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);
VOID ClientPnPDelNetAddress(IN PTA_ADDRESS, IN PUNICODE_STRING, IN PTDI_PNP_CONTEXT);
NTSTATUS IPInput(IN PVOID, IN LONG, IN PVOID, IN LONG, IN PVOID, IN ULONG, IN ULONG, IN ULONG, OUT ULONG *, IN PVOID, OUT PIRP *);
NTSTATUS IP6Input(IN PVOID, IN LONG, IN PVOID, IN LONG, IN PVOID, IN ULONG, IN ULONG, IN ULONG, OUT ULONG *, IN PVOID, OUT PIRP *);

NTSTATUS SCTPCreate(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPCleanup(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPClose(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatchDeviceControl(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatchInternalDeviceControl(IN PDEVICE_OBJECT, IN PIRP);
NTSTATUS SCTPDispatch(IN PDEVICE_OBJECT, IN PIRP);

PDEVICE_OBJECT SctpTcpDeviceObject = NULL, SctpUdpDeviceObject = NULL;
PFILE_OBJECT TpObject, Tp6Object;
HANDLE TpHandle, Tp6Handle, BindingHandle;

NPAGED_LOOKASIDE_LIST ExtBufLookaside;
NDIS_HANDLE SctpBufferPool;
NDIS_HANDLE SctpPacketPool;

LARGE_INTEGER zero_timeout;
LARGE_INTEGER StartTime;

uint16_t ip_id = 0;

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
	PDEVICE_OBJECT deviceObject;
	int i;

	DbgPrint("DriverEntry: enter\n");

	oldIrql = KeGetCurrentIrql();

	KeQuerySystemTime(&StartTime);

	mbuf_init();
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

	status = OpenRawSctp(AF_INET, &TpHandle, &TpObject);
	if (status != STATUS_SUCCESS) {
		DbgPrint("DriverEntry: OpenRawSCTP(AF_INET)=%X\n", status);
	}

	status = OpenRawSctp(AF_INET6, &Tp6Handle, &Tp6Object);
	if (status != STATUS_SUCCESS) {
		DbgPrint("DriverEntry: OpenRawSCTP(AF_INET6)=%X\n", status);
	}

	if (TpObject == NULL && Tp6Object == NULL) {
		DbgPrint("DriverEntry: leave #1\n");
		goto error;
	}

	route_init();
	sctp_init();

	if (TpObject != NULL) {
		deviceObject = IoGetRelatedDeviceObject(TpObject);
		irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER,
		    deviceObject,
		    TpObject,
		    NULL,
		    NULL);
		TdiBuildSetEventHandler(irp,
		    deviceObject,
		    TpObject,
		    NULL,
		    NULL,
		    TDI_EVENT_RECEIVE_DATAGRAM,
		    IPInput,
		    NULL);

		status = IoCallDriver(deviceObject, irp);
		if (status != STATUS_SUCCESS) {
			DbgPrint("DriverEntry: IoCallDriver=%X\n", status);
			ObDereferenceObject(TpObject);
			ZwClose(TpHandle);
			TpObject = NULL;
		}
	}

	if (Tp6Object != NULL) {
		deviceObject = IoGetRelatedDeviceObject(Tp6Object);
		irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER,
		    deviceObject,
		    Tp6Object,
		    NULL,
		    NULL);
		TdiBuildSetEventHandler(irp,
		    deviceObject,
		    Tp6Object,
		    NULL,
		    NULL,
		    TDI_EVENT_RECEIVE_DATAGRAM,
		    IPInput,
		    NULL);

		status = IoCallDriver(deviceObject, irp);
		if (status != STATUS_SUCCESS) {
			DbgPrint("DriverEntry: IoCallDriver=%X\n", status);
			ObDereferenceObject(Tp6Object);
			ZwClose(Tp6Handle);
			Tp6Object = NULL;
		}
	}

	if (TpObject == NULL && Tp6Object == NULL) {
		DbgPrint("DriverEntry: leave #2\n");
		goto error;
	}

	RtlInitUnicodeString(&devname, DD_SCTP_ONE_TO_ONE_DEVICE_NAME);
	status = IoCreateDevice(DriverObject, 0, &devname, FILE_DEVICE_NETWORK, 0, FALSE, &SctpTcpDeviceObject);
	if (status != STATUS_SUCCESS) {
		DbgPrint("DriverEntry: leave #3\n");
		goto error;
	}

	RtlInitUnicodeString(&devname, DD_SCTP_ONE_TO_MANY_DEVICE_NAME);
	status = IoCreateDevice(DriverObject, 0, &devname, FILE_DEVICE_NETWORK, 0, FALSE, &SctpUdpDeviceObject);
	if (status != STATUS_SUCCESS) {
		DbgPrint("DriverEntry: leave #4\n");
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

	DbgPrint("DriverEntry: leave\n");
	return STATUS_SUCCESS;
error:
	Unload(DriverObject);
	return status;
}

VOID
Unload(
    IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	int error = 0;
	struct sctp_inpcb *inp;

	DbgPrint("Unload: enter\n");

	LIST_FOREACH(inp, &sctppcbinfo.listhead, sctp_list) {
		DbgPrint("Unload: inp=%p\n", inp);
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

	if (TpObject != NULL) {
		ObDereferenceObject(TpObject);
	}
	if (TpHandle != NULL) {
		status = ZwClose(TpHandle);
	}

	if (Tp6Object != NULL) {
		ObDereferenceObject(Tp6Object);
	}
	if (Tp6Handle != NULL) {
		ZwClose(Tp6Handle);
	}

	IFNET_LOCK_DESTROY();

	mbuf_destroy();

	DbgPrint("Unload: leave\n");
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
IPOutputComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID context)
{
	IPOutputCtx *ctx = context;
	PMDL mdl = NULL, nextMdl = NULL;

	DbgPrint("IPOutputComp: enter\n");

	DbgPrint("IPOutputComp: status=%X,length=%d\n", irp->IoStatus.Status, irp->IoStatus.Information);

	if (ctx != NULL) {
		ExFreePool(ctx);
	}

	if (irp->MdlAddress != NULL) {
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		irp->MdlAddress = NULL;
	}

	IoFreeIrp(irp);

	DbgPrint("IPOutputComp: leave\n");
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
IPOutput(
    IN struct mbuf *o_pak,
    IN struct route *ro)
{
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject;
	PIRP irp;
	struct mbuf *m;
	ULONG totalLength = 0;
	PMDL top = NULL, prevMdl = NULL, nextMdl = NULL, mdl;
	IPOutputCtx *ctx;

	DbgPrint("IPOutput: enter,o_pak=%p\n", o_pak);

	totalLength = SCTP_HEADER_LEN(o_pak);

	if (o_pak == NULL || SCTP_HEADER_TO_CHAIN(o_pak) == NULL || ro == NULL || ro->ro_rt == NULL) {
		DbgPrint("IPOutput: leave #1\n");
		status = STATUS_INVALID_PARAMETER;
		goto error;
	}

	ctx = (IPOutputCtx *)ExAllocatePool(NonPagedPool, sizeof(IPOutputCtx));
	if (ctx == NULL) {
		DbgPrint("IPOutput: leave #2\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	RtlZeroMemory(ctx, sizeof(IPOutputCtx));
	ctx->sendDatagramInfo.RemoteAddressLength = sizeof(TA_IP_ADDRESS);
	ctx->sendDatagramInfo.RemoteAddress = &ctx->address;
	ctx->address.TAAddressCount = 1;
	ctx->address.Address[0].AddressLength = sizeof(TDI_ADDRESS_IP);
	ctx->address.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	if (ro->ro_rt->rt_flags & RT_FLAG_GATEWAY) {
		PUCHAR p;
		RtlCopyMemory(&ctx->address.Address[0].Address[0].in_addr,
		    &ro->ro_rt->rt_gateway.sin.sin_addr, sizeof(struct in_addr));
		p = (PUCHAR)&ro->ro_rt->rt_gateway.sin.sin_addr;
		printf("IPv4 address: %u.%u.%u.%u\n",
		    p[0], p[1], p[2], p[3]);
	} else {
		PUCHAR p;
		RtlCopyMemory(&ctx->address.Address[0].Address[0].in_addr,
		    &ro->ro_dst.sin.sin_addr, sizeof(struct in_addr));
		p = (PUCHAR)&ro->ro_dst.sin.sin_addr;
		printf("IPv4 address: %u.%u.%u.%u\n",
		    p[0], p[1], p[2], p[3]);
	}


	deviceObject = IoGetRelatedDeviceObject(TpObject);
	irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
	if (irp == NULL) {
		DbgPrint("IPOutput: leave #3\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	for (m = SCTP_HEADER_TO_CHAIN(o_pak); m != NULL; m = SCTP_BUF_NEXT(m)) {
		mdl = IoAllocateMdl(SCTP_BUF_AT(m, 0), SCTP_BUF_LEN(m), FALSE, FALSE, NULL);
		if (mdl == NULL) {
			DbgPrint("IPOutput: leave #4\n");
			goto error;
		}
		__try {
			MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			IoFreeMdl(mdl);
			DbgPrint("IPOutput: leave #5\n");
			goto error;
		}
		if (top == NULL) {
			top = mdl;
		}
		if (prevMdl != NULL) {
			NDIS_BUFFER_LINKAGE((PNDIS_BUFFER)prevMdl) = mdl;
		}
		prevMdl = mdl;
	}

	TdiBuildSendDatagram(irp,
	    deviceObject,
	    TpObject,
	    IPOutputComp,
	    ctx,
	    top,
	    totalLength,
	    &ctx->sendDatagramInfo);

	status = IoCallDriver(deviceObject, irp);
	if (status != STATUS_PENDING) {
		IPOutputComp(deviceObject, irp, ctx);
	}
	DbgPrint("IPOutput: leave,o_pak=%p\n", o_pak);
	return status;

error:
	if (top != NULL) {
		for (mdl = top; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}
		top = NULL;
	}
	if (ctx != NULL) {
		ExFreePool(ctx);
	}
	if (o_pak != NULL) {
		m_freem(o_pak);
	}
	DbgPrint("IPOutput: o_pak=%p\n", o_pak);

	return status;
}


NTSTATUS
IP6OutputComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID context)
{
	IP6OutputCtx *ctx = context;
	PMDL mdl = NULL, nextMdl = NULL;

	DbgPrint("IP6OutputComp: enter\n");

	DbgPrint("IP6OutputComp: status=%X,length=%d\n", irp->IoStatus.Status, irp->IoStatus.Information);

	if (ctx != NULL) {
		ExFreePool(ctx);
	}

	if (irp->MdlAddress != NULL) {
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		irp->MdlAddress = NULL;
	}

	IoFreeIrp(irp);

	DbgPrint("IP6OutputComp: leave\n");
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
IP6Output(
    IN struct mbuf *o_pak,
    IN struct route *ro)
{
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject;
	PIRP irp;
	struct mbuf *m;
	ULONG totalLength = 0;
	PMDL top = NULL, prevMdl = NULL, nextMdl = NULL, mdl;
	IP6OutputCtx *ctx;

	DbgPrint("IP6Output: enter\n");

	totalLength = SCTP_HEADER_LEN(o_pak);

	if (o_pak == NULL || SCTP_HEADER_TO_CHAIN(o_pak) == NULL || ro == NULL || ro->ro_rt == NULL) {
		DbgPrint("IP6Output: leave #1\n");
		status = STATUS_INVALID_PARAMETER;
		goto error;
	}

	ctx = (IP6OutputCtx *)ExAllocatePool(NonPagedPool, sizeof(IP6OutputCtx));
	if (ctx == NULL) {
		DbgPrint("IP6Output: leave #2\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	RtlZeroMemory(ctx, sizeof(IP6OutputCtx));
	ctx->sendDatagramInfo.RemoteAddressLength = sizeof(TA_IP6_ADDRESS);
	ctx->sendDatagramInfo.RemoteAddress = &ctx->address;
	ctx->address.TAAddressCount = 1;
	ctx->address.Address[0].AddressLength = sizeof(TDI_ADDRESS_IP6);
	ctx->address.Address[0].AddressType = TDI_ADDRESS_TYPE_IP6;
	RtlCopyMemory(&ctx->address.Address[0].Address[0].sin6_addr,
	    &ro->ro_rt->rt_gateway.sin6.sin6_addr, sizeof(struct in6_addr));
	ctx->address.Address[0].Address[0].sin6_scope_id =
	    ro->ro_rt->rt_gateway.sin6.sin6_scope_id;

	deviceObject = IoGetRelatedDeviceObject(TpObject);
	irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
	if (irp == NULL) {
		DbgPrint("IP6Output: leave #3\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	for (m = SCTP_HEADER_TO_CHAIN(o_pak); m != NULL; m = SCTP_BUF_NEXT(m)) {
		mdl = IoAllocateMdl(SCTP_BUF_AT(m, 0), SCTP_BUF_LEN(m), FALSE, FALSE, NULL);
		if (mdl == NULL) {
			DbgPrint("IP6Output: leave #4\n");
			goto error;
		}
		__try {
			MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			IoFreeMdl(mdl);
			DbgPrint("IP6Output: leave #5\n");
			goto error;
		}
		if (top == NULL) {
			top = mdl;
		}
		if (prevMdl != NULL) {
			NDIS_BUFFER_LINKAGE((PNDIS_BUFFER)prevMdl) = mdl;
		}
		prevMdl = mdl;
	}

	TdiBuildSendDatagram(irp,
	    deviceObject,
	    Tp6Object,
	    IP6OutputComp,
	    ctx,
	    top,
	    totalLength,
	    &ctx->sendDatagramInfo);

	status = IoCallDriver(deviceObject, irp);
	if (status != STATUS_PENDING) {
		IP6OutputComp(deviceObject, irp, ctx);
	}
	DbgPrint("IP6Output: leave\n");
	return status;

error:
	if (top != NULL) {
		for (mdl = top; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}
		top = NULL;
	}
	if (ctx != NULL) {
		ExFreePool(ctx);
	}
	if (o_pak != NULL) {
		m_freem(o_pak);
	}

	return status;
}

NTSTATUS
IPInputComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID context)
{
	KIRQL oldIrql;
	IPInputCtx *ctx = context;
	struct mbuf *m;
	PMDL mdl = NULL, nextMdl = NULL;

	DbgPrint("IPInputComp: enter\n");

	DbgPrint("IPInputComp: status=%X,length=%d\n", irp->IoStatus.Status, irp->IoStatus.Information);
	if (ctx != NULL && ctx->i_pak != NULL) {
		m = SCTP_HEADER_TO_CHAIN(ctx->i_pak);
		SCTP_BUF_LEN(m) = irp->IoStatus.Information;
		ctx->i_pak->m_pkthdr.len = irp->IoStatus.Information;
		if (irp->IoStatus.Information > 20) {
			KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
			sctp_input(ctx->i_pak, 20);
			KeLowerIrql(oldIrql);
		}
	}

	if (irp->MdlAddress != NULL) {
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		irp->MdlAddress = NULL;
	}

	if (ctx != NULL) {
		ExFreePool(ctx);
	}

	IoFreeIrp(irp);

	DbgPrint("IPInputComp: leave\n");
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
IPInput(
    IN PVOID tdiEventContext,
    IN LONG sourceAddressLength,
    IN PVOID sourceAddress,
    IN LONG optionsLength,
    IN PVOID options,
    IN ULONG receiveDatagramFlags,
    IN ULONG bytesIndicated,
    IN ULONG bytesAvailable,
    OUT ULONG *bytesTaken,
    IN PVOID tsdu,
    OUT PIRP *ioRequestPacket)
{
	PDEVICE_OBJECT deviceObject;
	unsigned int i;
	struct mbuf *i_pak, *m;
	IPInputCtx *ctx = NULL;
	PIRP irp = NULL;
	PMDL mdl = NULL;
	KIRQL oldIrql;

	DbgPrint("IPInput: enter\n");
	DbgPrint("IPInput: bytesAvailable=%d,optionsLength=%d\n", bytesAvailable, optionsLength);
	
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

	if (bytesAvailable == bytesIndicated) {
		i_pak = SCTP_GET_HEADER_FOR_OUTPUT(bytesAvailable);
		if (i_pak == NULL) {
			DbgPrint("IPInput: leave #1\n");
			return STATUS_DATA_NOT_ACCEPTED;
		}
		m = SCTP_HEADER_TO_CHAIN(i_pak);
		RtlCopyMemory(SCTP_BUF_AT(m, 0), tsdu, bytesAvailable);
		SCTP_BUF_LEN(m) = bytesAvailable;

		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		sctp_input(i_pak, 20);
		KeLowerIrql(oldIrql);

		*bytesTaken = bytesAvailable;

		DbgPrint("IPInput: leave #2\n");
		return STATUS_SUCCESS;
	}

	ctx = (IPInputCtx *)ExAllocatePool(NonPagedPool, sizeof(IPInputCtx));
	if (ctx == NULL) {
		DbgPrint("IPInput: leave #3\n");
		goto error;
	}

	i_pak = SCTP_GET_HEADER_FOR_OUTPUT(bytesIndicated);
	if (i_pak == NULL) {
		DbgPrint("IPInput: leave #4\n");
		goto error;
	}
	ctx->i_pak = i_pak;
	m = SCTP_HEADER_TO_CHAIN(i_pak);

	deviceObject = IoGetRelatedDeviceObject(TpObject);

	irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
	if (irp == NULL) {
		DbgPrint("IPInput: leave #5\n");
		goto error;
	}

	mdl = IoAllocateMdl(SCTP_BUF_AT(m, 0), bytesIndicated, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		DbgPrint("IPInput: leave #6\n");
		goto error;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("IPInput: leave #7\n");
		IoFreeMdl(mdl);
		mdl = NULL;
		goto error;
	}

	TdiBuildReceiveDatagram(irp,
	    deviceObject,
	    TpObject,
	    IPInputComp,
	    ctx,
	    mdl,
	    bytesIndicated,
	    0,
	    NULL,
	    TDI_RECEIVE_NORMAL);

	IoSetNextIrpStackLocation(irp);

	*bytesTaken = 0;
	*ioRequestPacket = irp;

	DbgPrint("IPInput: leave\n");
	return STATUS_MORE_PROCESSING_REQUIRED;

error:
	if (mdl != NULL) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		mdl = NULL;
	}
		
	if (irp != NULL) {
		IoFreeIrp(irp);
		irp = NULL;
	}

	if (ctx != NULL) {
		ExFreePool(ctx);
		ctx = NULL;
	}
	return STATUS_DATA_NOT_ACCEPTED;
}

NTSTATUS
IP6InputComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID context)
{
	IP6InputCtx *ctx = context;
	struct mbuf *m;
	struct ip6_hdr *ip6h;
	PMDL mdl = NULL, nextMdl = NULL;

	DbgPrint("IP6InputComp: enter\n");

	DbgPrint("IP6InputComp: status=%X,length=%d\n", irp->IoStatus.Status, irp->IoStatus.Information);
	if (ctx != NULL && ctx->i_pak != NULL) {
		m = SCTP_HEADER_TO_CHAIN(ctx->i_pak);

		ip6h = (struct ip6_hdr *)SCTP_BUF_AT(m, 0);
		RtlZeroMemory(ip6h, sizeof(struct ip6_hdr));
		ip6h->ip6_vfc = (IPV6_VERSION & IPV6_VERSION_MASK);
		ip6h->ip6_hlim = 255;
		ip6h->ip6_plen = htons((USHORT)irp->IoStatus.Information);
		ip6h->ip6_nxt = IPPROTO_SCTP;
		RtlCopyMemory(&ip6h->ip6_src, &ctx->address.Address[0].Address[0].sin6_addr,
		    sizeof(struct in6_addr));
		RtlCopyMemory(&ip6h->ip6_dst, &((struct in6_pktinfo *)&ctx->options)->ipi6_addr,
		    sizeof(struct in6_addr));

		SCTP_BUF_LEN(m) = sizeof(struct ip6_hdr) + irp->IoStatus.Information;
		ctx->i_pak->m_pkthdr.len = sizeof(struct ip6_hdr) + irp->IoStatus.Information;
		sctp_input(ctx->i_pak, sizeof(struct ip6_hdr));
	}

	if (irp->MdlAddress != NULL) {
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		irp->MdlAddress = NULL;
	}

	if (ctx != NULL) {
		ExFreePool(ctx);
	}

	IoFreeIrp(irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
IP6Input(
    IN PVOID tdiEventContext,
    IN LONG sourceAddressLength,
    IN PVOID sourceAddress,
    IN LONG optionsLength,
    IN PVOID options,
    IN ULONG receiveDatagramFlags,
    IN ULONG bytesIndicated,
    IN ULONG bytesAvailable,
    OUT ULONG *bytesTaken,
    IN PVOID tsdu,
    OUT PIRP *ioRequestPacket)
{
	PDEVICE_OBJECT deviceObject;
	unsigned int i;
	struct ip6_hdr *ip6h;
	struct mbuf *i_pak, *m;
	IP6InputCtx *ctx = NULL;
	PIRP irp = NULL;
	PMDL mdl = NULL;

	DbgPrint("IP6Input: enter\n");
	DbgPrint("IP6Input: bytesAvailable=%d,optionsLength=%d\n", bytesAvailable, optionsLength);
	
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

	if (sourceAddressLength < sizeof(TA_IP6_ADDRESS) && optionsLength == sizeof(struct in6_pktinfo)) {
		DbgPrint("IP6Input: leave#1\n");
		return STATUS_DATA_NOT_ACCEPTED;
	}

	if (receiveDatagramFlags & TDI_RECEIVE_ENTIRE_MESSAGE) {
		i_pak = SCTP_GET_HEADER_FOR_OUTPUT(sizeof(struct ip6_hdr) + bytesAvailable);
		if (i_pak == NULL) {
			DbgPrint("IPInput: leave #2\n");
			return STATUS_DATA_NOT_ACCEPTED;
		}
		m = SCTP_HEADER_TO_CHAIN(i_pak);

		ip6h = (struct ip6_hdr *)SCTP_BUF_AT(m, 0);
		RtlZeroMemory(ip6h, sizeof(struct ip6_hdr));
		ip6h->ip6_vfc = (IPV6_VERSION & IPV6_VERSION_MASK);
		ip6h->ip6_hlim = 255;
		ip6h->ip6_plen = htons((USHORT)bytesAvailable);
		ip6h->ip6_nxt = IPPROTO_SCTP;
		RtlCopyMemory(&ip6h->ip6_src, &((PTA_IP6_ADDRESS)sourceAddress)->Address[0].Address[0].sin6_addr,
		    sizeof(struct in6_addr));
		RtlCopyMemory(&ip6h->ip6_dst, &((struct in6_pktinfo *)options)->ipi6_addr,
		    sizeof(struct in6_addr));

		RtlCopyMemory(SCTP_BUF_AT(m, sizeof(struct ip6_hdr)), tsdu, bytesAvailable);
		SCTP_BUF_LEN(m) = sizeof(struct ip6_hdr) + bytesAvailable;
		i_pak->m_pkthdr.len = sizeof(struct ip6_hdr) + bytesAvailable;

		sctp_input(i_pak, sizeof(struct ip6_hdr));

		*bytesTaken = bytesAvailable;

		DbgPrint("IPInput: leave #3\n");
		return STATUS_SUCCESS;
	}

	ctx = (IP6InputCtx *)ExAllocatePool(NonPagedPool, sizeof(IP6InputCtx));
	if (ctx == NULL) {
		DbgPrint("IPInput: leave #3\n");
		goto error;
	}
	RtlZeroMemory(ctx, sizeof(IP6InputCtx));

	i_pak = SCTP_GET_HEADER_FOR_OUTPUT(MJUM16BYTES);
	if (i_pak == NULL) {
		DbgPrint("IPInput: leave #4\n");
		goto error;
	}
	ctx->i_pak = i_pak;
	ctx->returnInfo.RemoteAddressLength = sizeof(TA_IP6_ADDRESS);
	ctx->returnInfo.RemoteAddress = &ctx->address;
	ctx->returnInfo.OptionsLength = sizeof(ctx->options);
	ctx->returnInfo.Options = &ctx->options;

	m = SCTP_HEADER_TO_CHAIN(i_pak);

	deviceObject = IoGetRelatedDeviceObject(TpObject);

	irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
	if (irp == NULL) {
		DbgPrint("IPInput: leave #5\n");
		goto error;
	}

	mdl = IoAllocateMdl(SCTP_BUF_AT(m, sizeof(struct ip6_hdr)), MJUM16BYTES - sizeof(struct ip6_hdr), FALSE, FALSE, NULL);
	if (mdl == NULL) {
		DbgPrint("IPInput: leave #6\n");
		goto error;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("IPInput: leave #7\n");
		IoFreeMdl(mdl);
		mdl = NULL;
		goto error;
	}

	TdiBuildReceiveDatagram(irp,
	    deviceObject,
	    TpObject,
	    IPInputComp,
	    ctx,
	    mdl,
	    MJUM16BYTES - sizeof(struct ip6_hdr),
	    0,
	    NULL,
	    TDI_RECEIVE_NORMAL);

	IoSetNextIrpStackLocation(irp);

	*bytesTaken = 0;
	*ioRequestPacket = irp;

	DbgPrint("IP6Input: leave\n");
	return STATUS_MORE_PROCESSING_REQUIRED;

error:
	if (mdl != NULL) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		mdl = NULL;
	}
		
	if (irp != NULL) {
		IoFreeIrp(irp);
		irp = NULL;
	}

	if (ctx != NULL) {
		ExFreePool(ctx);
		ctx = NULL;
	}
	return STATUS_DATA_NOT_ACCEPTED;
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
