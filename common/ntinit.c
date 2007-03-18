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
 * $Id: ntinit.c,v 1.5 2007/03/18 19:25:04 kozuka Exp $
 */
#include "globals.h"

#include <netinet/sctp_os_windows.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_addr.h>

#define RawIPDeviceWithSCTP L"\\Device\\RawIP\\132"
#define RawIP6DeviceWithSCTP L"\\Device\\RawIp6\\132"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT, IN PUNICODE_STRING);
VOID Unload(IN PDRIVER_OBJECT);

NTSTATUS SCTPDispatch(IN PDEVICE_OBJECT, IN PIRP);

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

NTSTATUS SCTPCreate(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPCleanup(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPClose(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDispatchInternalDeviceControl(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDispatchDeviceControl(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);

struct RcvContext {
	BOOLEAN		bActive;
	KEVENT		event;
} *RcvContext, *Rcv6Context;

struct ifqueue {
	struct mpkt	*head;
	struct mpkt	*tail;
	KMUTEX		mtx;
} *inq, *in6q;

PFILE_OBJECT TpObject, Tp6Object, RcvObject;
HANDLE TpHandle, Tp6Handle, RcvHandle, BindingHandle;
struct ifnethead ifnet;
KMUTEX *ifnet_mtx;

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
	
	int i;

	DbgPrint("Enter into DriverEntry\n");

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
#if 0
	sctp_init();
#endif

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = SCTPDispatch;
	}
	DriverObject->DriverUnload = Unload;

#if 0
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

	DbgPrint("Enter into Unload\n");

	if (BindingHandle != NULL) {
		TdiDeregisterPnPHandlers(BindingHandle);
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
		ZwClose(TpHandle);
	}

	if (Tp6Object != NULL) {
		ObDereferenceObject(Tp6Object);
	}
	if (Tp6Handle != NULL) {
		ZwClose(Tp6Handle);
	}
	DbgPrint("Left from Unload\n");
}


VOID
ClientPnPAddNetAddress(
    IN PTA_ADDRESS Address,
    IN PUNICODE_STRING DeviceName,
    IN PTDI_PNP_CONTEXT Context)
{
	unsigned char *p;
	struct ifnet *ifp;
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
			return;
		}
		RtlZeroMemory(ifp, sizeof(*ifp));
		RtlInitUnicodeString(&ifp->if_xname, DeviceName->Buffer);
		TAILQ_INIT(&ifp->if_addrhead);
		IF_LOCK_INIT(ifp);
		ifp->refcount = 1;

		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFNET_WUNLOCK();
	IF_LOCK(ifp);

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ifa->ifa_addr.ss_family == AF_INET &&
		    ((PTDI_ADDRESS_IP)Address->Address)->in_addr == ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr) ||
		    (Address->AddressType == TDI_ADDRESS_TYPE_IP6 &&
		    ifa->ifa_addr.ss_family == AF_INET6 &&
		    RtlCompareMemory(&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
			&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)))) {
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
		IF_LOCK(ifp);
	}
	IFNET_RUNLOCK();
	if (ifp == NULL) {
		DbgPrint("No such device....\n");
		return;
	}

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ifa->ifa_addr.ss_family == AF_INET &&
		    ((PTDI_ADDRESS_IP)Address->Address)->in_addr == ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr) ||
		    (Address->AddressType == TDI_ADDRESS_TYPE_IP6 &&
		    ifa->ifa_addr.ss_family == AF_INET6 &&
		    RtlCompareMemory(&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
			&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)))) {
			break;
		}
	}
	if (ifa == NULL) {
		IF_UNLOCK(ifp);
		DbgPrint("No such address....\n");
		return;
	} else {
		TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);
		IFAFREE(ifa);
		IF_UNLOCK(ifp);
	}

#if 0
	if (TAILQ_EMPTY(&ifp->if_addrhead)) {
		TAILQ_REMOVE(&ifnet, ifp, if_link);
	}
#endif
}


NTSTATUS
SCTPDispatch(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	PIO_STACK_LOCATION irpSp;
	NTSTATUS status;

	DbgPrint("Enter into SCTPDispatch\n");

	irpSp = IoGetCurrentIrpStackLocation(irp);

	switch (irpSp->MajorFunction) {
	case IRP_MJ_CREATE:
		status = SCTPCreate(deviceObject, irp, irpSp);
		break;

	case IRP_MJ_CLEANUP:
		status = SCTPCleanup(deviceObject, irp, irpSp);
		break;

	case IRP_MJ_CLOSE:
		status = SCTPClose(deviceObject, irp, irpSp);
		break;

	case IRP_MJ_DEVICE_CONTROL:
		status = TdiMapUserRequest(deviceObject, irp, irpSp);

		if (status == STATUS_SUCCESS) {
			status = SCTPDispatchInternalDeviceControl(deviceObject, irp, irpSp);
			break;
		}

		status = SCTPDispatchDeviceControl(deviceObject, irp, irpSp);
		break;

	case IRP_MJ_QUERY_SECURITY:
	case IRP_MJ_WRITE:
	case IRP_MJ_READ:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

	DbgPrint("Leave from SCTPDispatch\n");
	return status;
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
		    NULL);
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
		    NULL);
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
		    NULL);
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
		    NULL);
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
				sctp_input(pkt, 20);
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
