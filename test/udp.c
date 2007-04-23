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
 * $Id: udp.c,v 1.1 2007/04/23 15:48:26 kozuka Exp $
 */
#include <ntddk.h>
#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>

#undef TYPE_ALIGNMENT
#define TYPE_ALIGNMENT( t ) __alignof(t)

__inline USHORT
ntohs(USHORT x)
{
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}

__inline ULONG
ntohl(ULONG x)
{
    return (((x & 0xffL) << 24) | ((x & 0xff00L) << 8) |
        ((x & 0xff0000L) >> 8) | ((x &0xff000000L) >> 24));
}

#ifdef SCTP
#define UdpDevice L"\\Device\\SctpUdp"
#else
#define UdpDevice L"\\Device\\Udp"
#endif


PFILE_OBJECT UdpObject;
HANDLE UdpHandle;

struct ThreadCtx {
	BOOLEAN bActive;
	KEVENT event;
} *ThrCtx;

#ifdef SCTP
struct sctp_sndrcvinfo {
        USHORT sinfo_stream;
        USHORT sinfo_ssn;
        USHORT sinfo_flags;
        ULONG sinfo_ppid;
        ULONG sinfo_context;
        ULONG sinfo_timetolive;
        ULONG sinfo_tsn;
        ULONG sinfo_cumtsn;
        ULONG sinfo_assoc_id;
        UCHAR __reserve_pad[96];
};
#endif

struct RcvDgCtx {
	KEVENT event;
	NTSTATUS status;
	ULONG length;
	TDI_CONNECTION_INFORMATION returnInfo;
	TA_IP_ADDRESS address;
#ifdef SCTP
	UCHAR option[TDI_CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
#endif
};

struct SndDgCtx {
	KEVENT event;
	NTSTATUS status;
	ULONG length;
	TDI_CONNECTION_INFORMATION sendDatagramInfo;
	TA_IP_ADDRESS address;
#ifdef SCTP
	UCHAR option[TDI_CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
#endif
};

PFILE_OBJECT ThrObject;


NTSTATUS DriverEntry(IN PDRIVER_OBJECT, IN PUNICODE_STRING);
VOID Unload(IN PDRIVER_OBJECT);
VOID ReceiveDatagramThread(IN PVOID);
NTSTATUS ReceiveDatagramComp(IN PDEVICE_OBJECT, IN PIRP, IN PVOID);
NTSTATUS SendDatagram(IN PUCHAR, IN ULONG, IN PIRP, IN struct SndDgCtx *, IN KEVENT);
NTSTATUS SendDatagramComp(IN PDEVICE_OBJECT, IN PIRP, IN PVOID);
NTSTATUS Dispatch(IN PDEVICE_OBJECT, IN PIRP);


NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT driverObject,
    IN PUNICODE_STRING registryPath)
{
	int i;
	NTSTATUS status;
	UNICODE_STRING devname;
	PFILE_FULL_EA_INFORMATION eaInfo;
	ULONG eaLength;
	OBJECT_ATTRIBUTES attr;
	PTA_IP_ADDRESS ipAddress;
	IO_STATUS_BLOCK statusBlock;

	HANDLE thrHandle;

	DbgPrint("DriverEntry: start\n");

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		driverObject->MajorFunction[i] = Dispatch;
	}
	driverObject->DriverUnload = Unload;

	// Open Address Object, similar to socket() + bind(0.0.0.0)
	eaLength = sizeof(FILE_FULL_EA_INFORMATION) + sizeof(TdiTransportAddress) + sizeof(TA_IP_ADDRESS);
	eaInfo = ExAllocatePool(NonPagedPool, eaLength);
	if (eaInfo == NULL) {
		DbgPrint("DriverEntry: ExAllocatePool failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	RtlZeroMemory(eaInfo, eaLength);
	eaInfo->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
	RtlCopyMemory(eaInfo->EaName, TdiTransportAddress, sizeof(TdiTransportAddress));
	eaInfo->EaValueLength = sizeof (TA_IP_ADDRESS);

	ipAddress = (PTA_IP_ADDRESS)(eaInfo->EaName + sizeof(TdiTransportAddress));
	ipAddress->TAAddressCount = 1;
	ipAddress->Address[0].AddressLength = sizeof(TDI_ADDRESS_IP);
	ipAddress->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	ipAddress->Address[0].Address[0].sin_port = ntohs(80);

	RtlInitUnicodeString(&devname, UdpDevice);
	InitializeObjectAttributes(&attr, &devname, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&UdpHandle,
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
		DbgPrint("DriverEntry: ZwCreateFile failed. status=%X\n", status);
		goto done;
	}
	DbgPrint("statusBlock.Information=>%d\n", statusBlock.Information);

	status = ObReferenceObjectByHandle(UdpHandle,
	    GENERIC_READ | GENERIC_WRITE,
	    NULL,
	    KernelMode,
	    &UdpObject,
	    NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint("DriverEntry: ObReferenceObjectByHandle failed. status=%X\n", status);
		ZwClose(UdpHandle);
		UdpHandle = NULL;
		goto done;
	}

	ThrCtx = ExAllocatePool(NonPagedPool, sizeof(*ThrCtx));
	KeInitializeEvent(&ThrCtx->event, SynchronizationEvent, FALSE);
	ThrCtx->bActive = TRUE;

	InitializeObjectAttributes(&attr,
	    NULL,
	    OBJ_KERNEL_HANDLE,
	    NULL,
	    NULL);

	status = PsCreateSystemThread(&thrHandle,
	    0L,
	    &attr,
	    NULL,
	    NULL,
	    ReceiveDatagramThread,
	    ThrCtx);
	if (status == STATUS_SUCCESS) {
		ObReferenceObjectByHandle(thrHandle,
		    THREAD_ALL_ACCESS,
		    NULL,
		    KernelMode,
		    (PVOID *)&ThrObject,
		    NULL);
		ZwClose(thrHandle);
	} else {
		DbgPrint("DriverEntry: PsCreateSystemThread failed. status=%X\n", status);
		ZwClose(thrHandle);
		ThrObject = NULL;
		ExFreePool(ThrCtx);
		Unload(driverObject);
	}
done:
	ExFreePool(eaInfo);
	DbgPrint("DriverEntry: end\n");
	return status;
}


VOID
Unload(
    IN PDRIVER_OBJECT driverObject)
{
	NTSTATUS status;

	DbgPrint("Unload: start\n");
	if (ThrObject != NULL) {
		ThrCtx->bActive = FALSE;
		KeSetEvent(&ThrCtx->event, IO_NO_INCREMENT, FALSE);
		status = KeWaitForSingleObject(ThrObject,
		    Executive,
		    KernelMode,
		    FALSE,
		    NULL);
		ObDereferenceObject(ThrObject);
		ExFreePool(ThrCtx);
	}
	if (UdpObject != NULL) {
		ObDereferenceObject(UdpObject);
	}

	if (UdpHandle != NULL) {
		ZwClose(UdpHandle);
	}
	DbgPrint("Unload: end\n");
}


VOID
ReceiveDatagramThread(
    IN PVOID ctx)
{
	struct ThreadCtx *thrCtx = ctx;
	struct RcvDgCtx *rcvDgCtx = NULL;
	struct SndDgCtx *sndDgCtx = NULL;
	PDEVICE_OBJECT deviceObject;
	PIRP irp = NULL;
	PMDL mdl = NULL;
	PVOID events[2];
	UCHAR *data;
	ULONG maxLength = 1500;
	NTSTATUS status = STATUS_SUCCESS, waitStatus = STATUS_SUCCESS;
	size_t i;
	PUCHAR addr;
#ifdef SCTP
	PTDI_CMSGHDR scmsgp, scmsgp2;
	struct sctp_sndrcvinfo *srcv, *srcv2;
#endif

	DbgPrint("ReceiveDatagramThread: start\n");

	deviceObject = IoGetRelatedDeviceObject(UdpObject);

	irp = IoAllocateIrp(deviceObject->StackSize + 1, FALSE);
	if (irp == NULL) {
		DbgPrint("ReceiveDatagramThread: IoAllocateIrp failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	data = ExAllocatePool(PagedPool, maxLength);
	if (data == NULL) {
		DbgPrint("ReceiveDatagramThread: ExAllocatePool(PagedPool) failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	rcvDgCtx = ExAllocatePool(NonPagedPool, sizeof(*rcvDgCtx));
	if (rcvDgCtx == NULL) {
		DbgPrint("ReceiveDatagramThread: ExAllocatePool failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	RtlZeroMemory(rcvDgCtx, sizeof(*rcvDgCtx));
	KeInitializeEvent(&rcvDgCtx->event, SynchronizationEvent, FALSE);
	
	rcvDgCtx->returnInfo.RemoteAddressLength = sizeof(TA_IP_ADDRESS);
	rcvDgCtx->returnInfo.RemoteAddress = &rcvDgCtx->address;

#ifdef SCTP
	rcvDgCtx->returnInfo.OptionsLength = sizeof(rcvDgCtx->option);
	rcvDgCtx->returnInfo.Options = &rcvDgCtx->option;
	scmsgp = (PTDI_CMSGHDR)&rcvDgCtx->option;
	scmsgp->cmsg_len = TDI_CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	scmsgp->cmsg_level = 132; /* IPPROTO_SCTP */
	scmsgp->cmsg_type = 0x0002; /* SCTP_SNDRCV */
	srcv = (struct sctp_sndrcvinfo *)(TDI_CMSG_DATA(scmsgp));
#endif

	sndDgCtx = ExAllocatePool(NonPagedPool, sizeof(*sndDgCtx));
	if (sndDgCtx == NULL) {
		DbgPrint("ReceiveDatagramThread: ExAllocatePool#2 failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	RtlZeroMemory(sndDgCtx, sizeof(*sndDgCtx));
	KeInitializeEvent(&sndDgCtx->event, SynchronizationEvent, FALSE);

	sndDgCtx->sendDatagramInfo.RemoteAddressLength = sizeof(TA_IP_ADDRESS);
	sndDgCtx->sendDatagramInfo.RemoteAddress = &sndDgCtx->address;

#ifdef SCTP
	sndDgCtx->sendDatagramInfo.OptionsLength = sizeof(sndDgCtx->option);
	sndDgCtx->sendDatagramInfo.Options = &sndDgCtx->option;
	scmsgp2 = (PTDI_CMSGHDR)&sndDgCtx->option;
	scmsgp2->cmsg_len = TDI_CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	scmsgp2->cmsg_level = 132; /* IPPROTO_SCTP */
	scmsgp2->cmsg_type = 0x0002; /* SCTP_SNDRCV */
	srcv2 = (struct sctp_sndrcvinfo *)(TDI_CMSG_DATA(scmsgp2));
#endif

	events[0] = &rcvDgCtx->event;
	events[1] = &thrCtx->event;

	while (thrCtx->bActive == TRUE) {
		mdl = IoAllocateMdl(data, maxLength, FALSE, FALSE, NULL);
		if (mdl == NULL) {
			DbgPrint("ReceiveDatagramThread: IoAllocateMdl failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}

		__try {
			MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("ReceiveDatagramThread: MmProbeAndLockPages failed\n");
			IoFreeMdl(mdl);
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		if (status == STATUS_INSUFFICIENT_RESOURCES) {
			goto done;
		}

		TdiBuildReceiveDatagram(irp,
		    deviceObject,
		    UdpObject,
		    ReceiveDatagramComp,
		    rcvDgCtx,
		    mdl,
		    maxLength,
		    NULL,
		    &rcvDgCtx->returnInfo,
		    TDI_RECEIVE_NORMAL);

		status = IoCallDriver(deviceObject, irp);
		DbgPrint("ReceiveDatagramThread: IoCallDriver status=%X\n", status);
		if (status != STATUS_PENDING) {
			ReceiveDatagramComp(deviceObject, irp, rcvDgCtx);
		}

		waitStatus = KeWaitForMultipleObjects(2, events, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
		switch (waitStatus) {
		case STATUS_WAIT_0:
			addr = (UCHAR *)&((PTDI_ADDRESS_IP)rcvDgCtx->address.Address[0].Address)->in_addr;
			DbgPrint("status=%X,length=%d,from=%ld.%ld.%ld.%ld\n", rcvDgCtx->status, rcvDgCtx->length,
			    addr[0], addr[1], addr[2], addr[3]);
			DbgPrint("data=\"");
			for (i = 0; i < rcvDgCtx->length; i++) {
				DbgPrint("%c", data[i]);
			}
			DbgPrint("\"\n");
#ifdef SCTP
			if (rcvDgCtx->returnInfo.OptionsLength == TDI_CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))) {
				DbgPrint("sinfo_stream=%d,sinfo_ssn=%d,sinfo_flags=%d,sinfo_ppid=%d,sinfo_context=%d,sinfo_timetolive=%d,sinfo_tsn=%d,sinfo_cumtsn=%d,sinfo_assoc_id=%d\n",
				    srcv->sinfo_stream,
				    srcv->sinfo_ssn,
				    srcv->sinfo_flags,
				    srcv->sinfo_ppid,
				    srcv->sinfo_context,
				    srcv->sinfo_timetolive,
				    srcv->sinfo_tsn,
				    srcv->sinfo_cumtsn,
				    srcv->sinfo_assoc_id);
			}
			srcv2->sinfo_assoc_id = srcv->sinfo_assoc_id;
#endif
			RtlCopyMemory(sndDgCtx->sendDatagramInfo.RemoteAddress, rcvDgCtx->returnInfo.RemoteAddress,
			    rcvDgCtx->returnInfo.RemoteAddressLength);
			sndDgCtx->sendDatagramInfo.RemoteAddressLength = rcvDgCtx->returnInfo.RemoteAddressLength;
			SendDatagram(data, rcvDgCtx->length, irp, sndDgCtx, thrCtx->event);
			break;
		case STATUS_WAIT_1:
			DbgPrint("ReceiveDatagramThread: try to cancel irp=%p\n", irp);
			IoCancelIrp(irp);
			DbgPrint("ReceiveDatagramThread: wait for completion\n");
			waitStatus = KeWaitForSingleObject(&rcvDgCtx->event, Executive, KernelMode, FALSE, NULL);
			break;
		default:
			break;
		}

		if (thrCtx->bActive == FALSE) {
			break;
		}
	}
done:
	if (irp != NULL) {
		IoFreeIrp(irp);
	}
	if (data != NULL) {
		ExFreePool(data);
	}
	if (rcvDgCtx != NULL) {
		ExFreePool(rcvDgCtx);
	}
#if 0
	if (events != NULL) {
		ExFreePool(events);
	}
#endif
	DbgPrint("ReceiveDatagramThread: end\n");
	PsTerminateSystemThread(status);
}


NTSTATUS
ReceiveDatagramComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID ctx)
{
	PIO_STACK_LOCATION irpSp;
	PMDL mdl = NULL, nextMdl = NULL;
	struct RcvDgCtx *rcvDgCtx = ctx;
	PTDI_CONNECTION_INFORMATION returnInformation;

	DbgPrint("ReceiveDatagramComp: start\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);

	//returnInformation = ((PTDI_REQUEST_KERNEL_RECEIVEDG)&irpSp->Parameters)->ReturnInformation;

	rcvDgCtx->status = irp->IoStatus.Status;
	rcvDgCtx->length = irp->IoStatus.Information;

	if (irp->MdlAddress != NULL) {
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		irp->MdlAddress = NULL;
	}
	KeSetEvent(&rcvDgCtx->event, IO_NO_INCREMENT, FALSE);
	DbgPrint("ReceiveDatagramComp: end\n");

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
SendDatagram(
    IN PUCHAR data,
    IN ULONG length,
    IN PIRP irp,
    IN struct SndDgCtx *sndDgCtx,
    IN KEVENT event)
{
	NTSTATUS status, waitStatus;
	PDEVICE_OBJECT deviceObject;
	PMDL mdl = NULL;
	PVOID events[2];
	LARGE_INTEGER timeout;

	DbgPrint("SendDatagram: start\n");

	deviceObject = IoGetRelatedDeviceObject(UdpObject);

	mdl = IoAllocateMdl(data, length, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		DbgPrint("SendDatagram: IoAllocateMdl failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("ReceiveDatagramThread: MmProbeAndLockPages failed\n");
		IoFreeMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	TdiBuildSendDatagram(irp,
	    deviceObject,
	    UdpObject,
	    SendDatagramComp,
	    sndDgCtx,
	    mdl,
	    length,
	    &sndDgCtx->sendDatagramInfo);

	events[0] = &sndDgCtx->event;
	events[1] = &event;

	status = IoCallDriver(deviceObject, irp);
	DbgPrint("SendDatagram: IoCallDriver status=%X\n", status);
	if (status != STATUS_PENDING) {
		SendDatagramComp(deviceObject, irp, sndDgCtx);
	}
	waitStatus = KeWaitForMultipleObjects(2, events, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
	switch (waitStatus) {
	case STATUS_WAIT_0:
		DbgPrint("SendDatagram: status=%X,length=%d\n", sndDgCtx->status, sndDgCtx->length);
		return sndDgCtx->status;
	case STATUS_WAIT_1:
		DbgPrint("SendDatagram: timeout\n");
		IoCancelIrp(irp);
		KeWaitForSingleObject(&sndDgCtx->event, Executive, KernelMode, FALSE, NULL);
		return sndDgCtx->status;
	default:
		break;
	}

	return waitStatus;
}


NTSTATUS
SendDatagramComp(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp,
    IN PVOID ctx)
{
	PIO_STACK_LOCATION irpSp;
	PMDL mdl = NULL, nextMdl = NULL;
	struct SndDgCtx *sndDgCtx = ctx;

	DbgPrint("SendDatagramComp: start\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);

	sndDgCtx->status = irp->IoStatus.Status;
	sndDgCtx->length = irp->IoStatus.Information;

	if (irp->MdlAddress != NULL) {
		for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
			nextMdl = mdl->Next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		irp->MdlAddress = NULL;
	}
	KeSetEvent(&sndDgCtx->event, IO_NO_INCREMENT, FALSE);
	DbgPrint("SendDatagramComp: end\n");

	return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS
Dispatch(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	return STATUS_NOT_SUPPORTED;
}
