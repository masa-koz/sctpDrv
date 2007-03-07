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
 * $Id: ntinit.c,v 1.1 2007/03/07 15:05:05 kozuka Exp $
 */
#include "sctp_common.h"

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

NTSTATUS SCTPCreate(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPCleanup(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPClose(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDispatchInternalDeviceControl(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDispatchDeviceControl(IN PDEVICE_OBJECT, IN PIRP, IN PIO_STACK_LOCATION);

#if 0
NTSTATUS SendDatagram(IN struct SctpAddress *, IN struct SctpAddress *);
#endif


PFILE_OBJECT TpObject, Tp6Object;
HANDLE TpHandle, Tp6Handle;


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
	int i;

	DbgPrint("Enter into DriverEntry\n");
	for ( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++ ) {
		DriverObject->MajorFunction[i] = SCTPDispatch;
	}
	DriverObject->DriverUnload = Unload;

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
	DbgPrint("Enter into Unload\n");
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
		eaInfo->EaValueLength = sizeof (TA_IP_ADDRESS);

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

#if 0
NTSTATUS
SendDatagram(
    IN struct SctpAddress *LocalAddr,
    IN struct SctpAddress *RemoteAddr)
{
	PFILE_OBJECT transport;
	PTDI_CONNECTION_INFORMATION connectInfo;
	PIRP irp;
	KEVENT event;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS status;
	PMDL mdl = NULL;
        UCHAR *pkt;
#ifndef DO_IPV6
	UCHAR Tsdu[] = {
	    0x45,0x00,0x00,0x50,0x00,0xbb,0x00,0x00,0x80,0x84,0x93,0x0b,
	    0xc0,0xa8,0x92,0x81,0xc0,0xa8,0x92,0x01,
	    0x00,0x50,0x00,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	    0x01,0x00,0x00,0x1c,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
	    0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x08,
	    0xc0,0xa8,0x01,0xfb
	};
#else
	UCHAR Tsdu[] = {
	    0x60,0x00,0x00,0x00,0x00,0x28,0x84,0x80,0xfe,0x80,0x00,0x00,
	    0x00,0x00,0x00,0x00,0x02,0x0c,0x29,0xff,0xfe,0x4e,0x66,0x06,
	    0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x50,0x56,0xff,
	    0xfe,0xc0,0x00,0x08,
	    0x00,0x50,0x00,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	    0x01,0x00,0x00,0x1c,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
	    0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x08,
	    0xc0,0xa8,0x01,0xfb
	};
#endif

	DbgPrint("SendDatagram\n");

	pkt = ExAllocatePool(NonPagedPool, sizeof(Tsdu));
	RtlCopyMemory(pkt, Tsdu, sizeof(Tsdu));

	if (RemoteAddr->family != LocalAddr->family) {
		return STATUS_INVALID_PARAMETER;
	}

	if (RemoteAddr->family == AF_INET) {
		PTA_IP_ADDRESS address;

		DbgPrint("RemoteAddr->family == AF_INET\n");
		connectInfo = (PTDI_CONNECTION_INFORMATION)ExAllocatePool(NonPagedPool,
		    sizeof(TDI_CONNECTION_INFORMATION) +
		    sizeof(TA_IP_ADDRESS));
		if (connectInfo == NULL) {
			DbgPrint("ERROR: No memory for PTDI_CONNECTION_INFORMATION\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(connectInfo,
		    sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));
		DbgPrint("after -- RtlZeroMemory\n");
		connectInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
		connectInfo->RemoteAddress = (PUCHAR)connectInfo +
		    sizeof(TDI_CONNECTION_INFORMATION);
		address = (PTA_IP_ADDRESS)connectInfo->RemoteAddress;
		address->TAAddressCount = 1;
		address->Address[0].AddressLength = sizeof(TDI_ADDRESS_IP);
		address->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
		RtlCopyMemory(&((PTDI_ADDRESS_IP)address->Address[0].Address)->in_addr,
		    &RemoteAddr->addr.in_addr, sizeof(struct in_addr));

		transport = Transport;
	} else if (RemoteAddr->family == AF_INET6) {
		PTA_IP6_ADDRESS address;

		DbgPrint("RemoteAddr->family == AF_INET6\n");
		connectInfo = (PTDI_CONNECTION_INFORMATION)ExAllocatePool(NonPagedPool,
		    sizeof(TDI_CONNECTION_INFORMATION) +
		    sizeof(TA_IP6_ADDRESS));
		if (connectInfo == NULL) {
			DbgPrint("ERROR: No memory for PTDI_CONNECTION_INFORMATION\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(connectInfo,
		    sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP6_ADDRESS));
		connectInfo->RemoteAddressLength = sizeof(TA_IP6_ADDRESS);
		connectInfo->RemoteAddress = (PUCHAR)connectInfo +
		    sizeof(TDI_CONNECTION_INFORMATION);
		address = (PTA_IP6_ADDRESS)connectInfo->RemoteAddress;
		address->TAAddressCount = 1;
		address->Address[0].AddressLength = sizeof(TDI_ADDRESS_IP6);
		address->Address[0].AddressType = TDI_ADDRESS_TYPE_IP6;
		RtlCopyMemory(&((PTDI_ADDRESS_IP6)address->Address[0].Address)->sin6_addr,
		    &RemoteAddr->addr.in6.addr, sizeof(struct in6_addr));
	    
		((PTDI_ADDRESS_IP6)address->Address[0].Address)->sin6_scope_id =
		    RemoteAddr->addr.in6.scope_id;
		transport = Transport;
	} else {
		DbgPrint("Unknown Address Family!\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (transport == NULL) {
		DbgPrint("No Transport, family=%d\n", RemoteAddr->family);
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrint("hoge#1\n");
	irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM,
	    RawIPObject,
	    transport,
	    NULL,
	    NULL);
	DbgPrint("hoge#2\n");
	if (irp == NULL) {
		DbgPrint("TdiBuildInternalDeviceControlIrp == NULL\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	DbgPrint("hoge#3\n");

	mdl = IoAllocateMdl(pkt, sizeof(Tsdu), FALSE, FALSE, NULL);
	if (mdl == NULL) {
		DbgPrint( "IoAllocateMdl == NULL\n" );
		goto done;
	}
	DbgPrint("hoge#4\n");
	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(mdl);
		mdl = NULL;
	}
	DbgPrint("hoge#5\n");
	if (mdl == NULL) {
		DbgPrint( "IoAllocateMdl == NULL\n" );
		goto done;
	}

	TdiBuildSendDatagram(irp,
	    RawIPObject,
	    transport,
	    NULL,
	    NULL,
	    mdl,
	    sizeof(Tsdu),
	    connectInfo);
	DbgPrint("hoge#6\n");
#if 0
	TAILQ_FOREACH(buffer, BufferChain, next) {
		if (buffer == BufferChain->tqh_first)
			continue;
		buffer->mdl = IoAllocateMdl(buffer->p,
		    buffer->length,
		    TRUE,
		    FALSE,
		    irp);
		if (buffer->mdl == NULL) {
			goto done;
		}
	}
	TAILQ_FOREACH(buffer, BufferChain, next) {
		try {
			MmProbeAndLockPages(buffer->mdl, KernelMode, IoModifyAccess);
		} except ( EXCEPTION_EXECUTE_HANDLER ) {
			goto error_mdl;
		}
	}
#endif
	DbgPrint("hoge#7\n");
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	irp->UserEvent = &event;
	irp->UserIosb = &statusBlock;
	status = IoCallDriver(RawIPObject, irp);
	DbgPrint("hoge#8\n");
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
	}
	DbgPrint("hoge#9\n");
	status = statusBlock.Status;
	if (status == STATUS_SUCCESS) {
		DbgPrint( "status == STATUS_SUCCESS\n" );
	}

done:
	ExFreePool(connectInfo);
	ExFreePool(pkt);
	return status;

error_mdl:
	DbgPrint("error_mdl\n");
	if (mdl != NULL) {
		IoFreeMdl(mdl);
	}
	ExFreePool(connectInfo);
	return STATUS_INSUFFICIENT_RESOURCES;
}
#endif


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
	int i;

	DbgPrint("ReceiveDatagram( BytesAvailable => %d ):\n", BytesAvailable);
	DbgPrint("ReceiveDatagram( OptionsLength => %d ):\n", OptionsLength);
	
	for (i = 0; i < BytesAvailable; i++) {
		DbgPrint("%0.2X", ((UCHAR *)Tsdu)[i]);
		if (i % 2 != 0)
			DbgPrint(" ");
		if (i % 8 == 7)
			DbgPrint("\n");
	}
	DbgPrint("\n");

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
	int i;
	PTA_IP6_ADDRESS taAddr;
	struct in6_pktinfo_option *pkt6info;

	DbgPrint("ReceiveDatagram( BytesAvailable => %d ):\n", BytesAvailable);
	DbgPrint("ReceiveDatagram( OptionsLength => %d ):\n", OptionsLength);
	
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
	return STATUS_SUCCESS;
}
