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
 * $Id: ntdisp.c,v 1.4 2007/04/23 15:49:41 kozuka Exp $
 */
#include "globals.h"

typedef struct sctp_context {
	union {
		HANDLE			AddressHandle;
		CONNECTION_CONTEXT	ConnectionContext;
		HANDLE			ControlChannel;
	} Handle;
	int refcount;
	BOOLEAN cancelIrps;
	KEVENT cleanupEvent;
} SCTP_CONTEXT, *PSCTP_CONTEXT;

#include <netinet/sctp_os_windows.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_addr.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_output.h>

int sctp_attach(struct socket *);
int sctp_bind(struct socket *, struct sockaddr *);
int sctp_detach(struct socket *);
int sctp_disconnect(struct socket *);
#if 0
int sctp_soreceive(struct socket *, struct sockaddr **, struct uio *, struct mbuf **, struct mbuf **, int *);
#endif

NTSTATUS SCTPPrepareIrpForCancel(IN PSCTP_CONTEXT, IN PIRP, PDRIVER_CANCEL);
VOID SCTPCancelRequest(IN PDEVICE_OBJECT, IN PIRP);
VOID SCTPCancelComplete(IN VOID *, IN ULONG , IN ULONG);
VOID SCTPRequestComplete(IN VOID *, IN ULONG , IN ULONG);

NTSTATUS SCTPAssociateAddress(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDisassociateAddress(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPListen(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPAccept(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPConnect(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPReceiveDatagram(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPSendDatagram(IN PIRP, IN PIO_STACK_LOCATION);
VOID SCTPCleanupComplete(PVOID, NTSTATUS, unsigned int);

void SCTPAbortAndIndicateDisconnect(IN CONNECTION_CONTEXT);

NTSTATUS TdiOpenAddress(PTDI_REQUEST, TRANSPORT_ADDRESS UNALIGNED *, USHORT, BOOLEAN);
NTSTATUS TdiOpenConnection(PTDI_REQUEST);
NTSTATUS TdiCloseAddress(PTID_REQUEST);
NTSTATUS TdiCloseConnection(PTID_REQUEST);
NTSTATUS TdiAssociateAddress(IN PTDI_REQUEST, IN HANDLE);
NTSTATUS TdiDisassociateAddress(IN PTDI_REQUEST);
NTSTATUS TdiListen(IN PTDI_REQUEST, IN USHORT, IN PTDI_CONNECTION_INFORMATION, IN PTDI_CONNECTION_INFORMATION);
NTSTATUS TdiAccept(IN PTDI_REQUEST, IN PTDI_CONNECTION_INFORMATION, IN PTDI_CONNECTION_INFORMATION);
NTSTATUS TdiDisconnect(IN PTDI_REQUEST, IN void *, IN USHORT, IN PTDI_CONNECTION_INFORMATION, IN PTDI_CONNECTION_INFORMATION);
NTSTATUS TdiReceiveDatagram(IN PTDI_REQUEST, IN PTDI_CONNECTION_INFORMATION, IN PTDI_CONNECTION_INFORMATION, IN ULONG, OUT ULONG*, IN PNDIS_BUFFER);
NTSTATUS TdiReceiveDatagramCommon(IN struct socket *, IN PSCTP_DGRCV_REQUEST, OUT ULONG *);
void TdiCancelReceiveDatagram(IN HANDLE, IN PVOID);
NTSTATUS TdiSendDatagram(IN PTDI_REQUEST, IN PTDI_CONNECTION_INFORMATION, IN ULONG, OUT ULONG *, IN PNDIS_BUFFER);
void TdiCancelSendDatagram(IN HANDLE, IN PVOID);

extern PDEVICE_OBJECT SctpTcpDeviceObject;
extern PDEVICE_OBJECT SctpUdpDeviceObject;

static FILE_FULL_EA_INFORMATION UNALIGNED *FindEAInfo(PFILE_FULL_EA_INFORMATION, CHAR *, USHORT);

NTSTATUS
SCTPPrepareIrpForCancel(
    IN PSCTP_CONTEXT sctpContext,
    IN PIRP irp,
    PDRIVER_CANCEL cancelRoutine)
{
	KIRQL oldIrql;

	DbgPrint("SCTPPrepareIrpForCancel: enter\n");
	IoAcquireCancelSpinLock(&oldIrql);

	if (!irp->Cancel) {
		IoMarkIrpPending(irp);
		IoSetCancelRoutine(irp, cancelRoutine);
		sctpContext->refcount++;

		IoReleaseCancelSpinLock(oldIrql);
		DbgPrint("SCTPPrepareIrpForCancel: leave #2\n");
		return STATUS_SUCCESS;
	}

	IoReleaseCancelSpinLock(oldIrql);
	irp->IoStatus.Status = STATUS_CANCELLED;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

	DbgPrint("SCTPPrepareIrpForCancel: leave\n");
	return STATUS_CANCELLED;
}

VOID
SCTPCancelRequest(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp;
	PFILE_OBJECT fileObject;
	PSCTP_CONTEXT sctpContext;
	TDI_REQUEST request;

	DbgPrint("SCTPCancelRequest: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);
	fileObject = irpSp->FileObject;
	sctpContext = (PSCTP_CONTEXT)fileObject->FsContext;

	IoSetCancelRoutine(irp, NULL);

	sctpContext->refcount++;

	IoReleaseCancelSpinLock(irp->CancelIrql);

	DbgPrint("SCTPCancelRequest: MinorFunction=%d\n", irpSp->MinorFunction);

	switch (irpSp->MinorFunction) {
	case TDI_SEND:
	case TDI_RECEIVE:
		SCTPAbortAndIndicateDisconnect(sctpContext->Handle.ConnectionContext);
		break;

	case TDI_SEND_DATAGRAM:
		TdiCancelSendDatagram(sctpContext->Handle.AddressHandle, irp);
		break;
	case TDI_RECEIVE_DATAGRAM:
		TdiCancelReceiveDatagram(sctpContext->Handle.AddressHandle, irp);
		break;

	case TDI_DISASSOCIATE_ADDRESS:
		break;

	default:
		request.Handle.ConnectionContext = sctpContext->Handle.ConnectionContext;
		request.RequestNotifyObject = SCTPCancelComplete;
		request.RequestContext = fileObject;

		status = TdiDisconnect(&request, NULL, TDI_DISCONNECT_ABORT, NULL, NULL);
		break;
	}

	if (status != STATUS_PENDING) {
		SCTPCancelComplete(fileObject, 0, 0);
	}
	DbgPrint("SCTPCancelRequest: leave\n");
}

VOID
SCTPCancelComplete(
    IN VOID *context,
    IN ULONG unused1,
    IN ULONG unused2)
{
	KIRQL oldIrql;
	PFILE_OBJECT fileObject;
	PSCTP_CONTEXT sctpContext;

	DbgPrint("SCTPCancelComplete: enter\n");

	fileObject = (PFILE_OBJECT)context;
	sctpContext = (PSCTP_CONTEXT)fileObject->FsContext;

	IoAcquireCancelSpinLock(&oldIrql);

	if (--(sctpContext->refcount) == 0) {
		KeSetEvent(&sctpContext->cleanupEvent, 0, FALSE);
	}

	IoReleaseCancelSpinLock(oldIrql);

	DbgPrint("SCTPCancelComplete: leave\n");
	return;
}

void
SCTPRequestComplete(
    IN VOID *context,
    IN ULONG status,
    IN ULONG length)
{
	PIRP irp;
	PIO_STACK_LOCATION irpSp;
	KIRQL oldIrql;
	PSCTP_CONTEXT sctpContext;

	DbgPrint("SCTPRequestComplete: enter\n");
	irp = (PIRP)context;
	irpSp = IoGetCurrentIrpStackLocation(irp);
	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;

	IoAcquireCancelSpinLock(&oldIrql);

	IoSetCancelRoutine(irp, NULL);

	if (--(sctpContext->refcount) == 0) {
		KeSetEvent(&sctpContext->cleanupEvent, 0, FALSE);
	}

	if (irp->Cancel || sctpContext->cancelIrps) {
		status = (ULONG)STATUS_CANCELLED;
		length = 0;
	}

	IoReleaseCancelSpinLock(oldIrql);

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = length;

	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
	DbgPrint("SCTPRequestComplete: leave\n");
}


NTSTATUS
SCTPCreate(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;
	struct sctp_context *sctpContext;
	FILE_FULL_EA_INFORMATION *ea0, *ea;
	TDI_REQUEST request;

	DbgPrint("SCTPCreate: enter\n");

	irpSp = IoGetCurrentIrpStackLocation(irp);

	RtlZeroMemory(&request, sizeof(request));

	sctpContext = ExAllocatePool(NonPagedPool, sizeof(struct sctp_context));
	if (sctpContext == NULL) {
		DbgPrint("SCTPCreate: leave #1\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	DbgPrint("sctpContext=%p, sizeof(SCTP_CONTEXT)=%d\n", sctpContext, sizeof(struct sctp_context));
	RtlZeroMemory(sctpContext, sizeof(SCTP_CONTEXT));

	sctpContext->refcount = 1;
	sctpContext->cancelIrps = FALSE;

	ea0 = (PFILE_FULL_EA_INFORMATION)irp->AssociatedIrp.SystemBuffer;
	if (ea0 == NULL) {
		/* TDI_CONTROL_CHANNEL_FILE */
		DbgPrint("SCTPCreate: try to get TDI_CONTROL_CHANNEL_FILE\n");
		sctpContext->Handle.ControlChannel = NULL;
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONTROL_CHANNEL_FILE;
		return STATUS_SUCCESS;
	}

	ea = FindEAInfo(ea0, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH);
	if (ea != NULL) {
		/* TDI_TRANSPORT_ADDRESS_FILE */
		DbgPrint("SCTPCreate: try to get TDI_TRANSPORT_ADDRESS_FILE\n");

		if (deviceObject == SctpTcpDeviceObject) {
			status = TdiOpenAddress(
			    &request,
			    (TRANSPORT_ADDRESS *)&ea->EaName[ea->EaNameLength + 1],
			    SOCK_STREAM, 
			    ((irpSp->Parameters.Create.ShareAccess & FILE_SHARE_READ) ||
			     (irpSp->Parameters.Create.ShareAccess & FILE_SHARE_WRITE)));
		} else {
			status = TdiOpenAddress(
			    &request,
			    (TRANSPORT_ADDRESS *)&ea->EaName[ea->EaNameLength + 1],
			    SOCK_SEQPACKET, 
			    ((irpSp->Parameters.Create.ShareAccess & FILE_SHARE_READ) ||
			     (irpSp->Parameters.Create.ShareAccess & FILE_SHARE_WRITE)));
		}

		if (status != STATUS_SUCCESS) {
			DbgPrint("TdiOpenAddress failed, code=%d\n", status);
			ExFreePool(sctpContext);
			DbgPrint("SCTPCreate: leave #2\n");
			return status;
		}

		sctpContext->Handle.AddressHandle = request.Handle.AddressHandle;
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_TRANSPORT_ADDRESS_FILE;
		DbgPrint("SCTPCreate: leave #3\n");
		return STATUS_SUCCESS;
	}

	ea = FindEAInfo(ea0, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH);
	if (ea != NULL) {
		/* TDI_CONNECTION_FILE */

		DbgPrint("SCTPCreate: try to get TDI_CONNECTION_FILE\n");
		status = TdiOpenConnection(&request);
		if (status != STATUS_SUCCESS) {
			ExFreePool(sctpContext);
			DbgPrint("TdiOpenConnection failed, code=%d\n", status);
			DbgPrint("SCTPCreate: leave #4\n");
			return status;
		}

		sctpContext->Handle.ConnectionContext = request.Handle.ConnectionContext;
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONNECTION_FILE;
		DbgPrint("SCTPCreate: leave #5\n");
		return STATUS_SUCCESS;
	}

	DbgPrint("SCTPCreate: leave\n");
	return STATUS_INVALID_EA_NAME;
}

NTSTATUS
SCTPCleanup(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;
	KIRQL oldIrql;
	PSCTP_CONTEXT sctpContext;
	TDI_REQUEST request;

	DbgPrint("SCTPCleanup: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);

	RtlZeroMemory(&request, sizeof(request));

	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;

	IoAcquireCancelSpinLock(&oldIrql);

	sctpContext->cancelIrps = TRUE;
	KeResetEvent(&sctpContext->cleanupEvent);

	IoReleaseCancelSpinLock(oldIrql);

	request.RequestNotifyObject = SCTPCleanupComplete;
	request.RequestContext = irp;

	if ((int)irpSp->FileObject->FsContext2 == TDI_TRANSPORT_ADDRESS_FILE) {
		request.Handle.AddressHandle = sctpContext->Handle.AddressHandle;
		status = TdiCloseAddress(&request);
	} else if ((int)irpSp->FileObject->FsContext2 == TDI_CONNECTION_FILE) {
		request.Handle.ConnectionContext = sctpContext->Handle.ConnectionContext;
		status = TdiCloseConnection(&request);
	} else if ((int)irpSp->FileObject->FsContext2 == TDI_CONTROL_CHANNEL_FILE) {
		status = STATUS_SUCCESS;
	} else {
		IoAcquireCancelSpinLock(&oldIrql);
		sctpContext->cancelIrps = FALSE;
		IoReleaseCancelSpinLock(oldIrql);

		DbgPrint("SCTPCleanup: leave #1\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (status != STATUS_PENDING) {
		SCTPCleanupComplete(irp, status, 0);
	} else {
		status = KeWaitForSingleObject(&sctpContext->cleanupEvent, UserRequest, KernelMode, FALSE, NULL);
	}

	DbgPrint("SCTPCleanup: leave\n");
	return irp->IoStatus.Status;
}

void
SCTPCleanupComplete(
    PVOID context,
    NTSTATUS status,
    unsigned int unused)
{
	KIRQL oldIrql;
	PIRP irp;
	PIO_STACK_LOCATION irpSp;
	PSCTP_CONTEXT sctpContext = context;

	IoAcquireCancelSpinLock(&oldIrql);

	sctpContext->refcount--;
	if (sctpContext->refcount == 0) {
		KeSetEvent(&sctpContext->cleanupEvent, 0, FALSE);
	}

	IoReleaseCancelSpinLock(oldIrql);
}

NTSTATUS
SCTPClose(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	PIO_STACK_LOCATION irpSp;
	PSCTP_CONTEXT sctpContext;

	irpSp = IoGetCurrentIrpStackLocation(irp);

	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;
	ExFreePool(sctpContext);

	return STATUS_SUCCESS;
}

NTSTATUS
SCTPDispatchInternalDeviceControl(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;

	DbgPrint("SCTPDispatchInternalDeviceControl: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);
	DbgPrint("SCTPDispatchInternalDeviceControl: irp=%p,irpSp=%p\n", irp, irpSp);
	if (((int)irpSp->FileObject->FsContext2) == TDI_CONNECTION_FILE) {
		switch (irpSp->MinorFunction) {
		case TDI_ASSOCIATE_ADDRESS:
			status = SCTPAssociateAddress(irp, irpSp);
			irp->IoStatus.Status = status;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #1\n");
			return status;
		case TDI_DISASSOCIATE_ADDRESS:
			status = SCTPDisassociateAddress(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #2\n");
			return status;
		case TDI_LISTEN:
			status = SCTPListen(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #3\n");
			return status;
		case TDI_ACCEPT:
			status = SCTPAccept(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #4\n");
			return status;
		default:
			break;
		}
	} else if (
	    ((int)irpSp->FileObject->FsContext2) == TDI_TRANSPORT_ADDRESS_FILE) {
		switch (irpSp->MinorFunction) {
		case TDI_RECEIVE_DATAGRAM:
			status = SCTPReceiveDatagram(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #5\n");
			return status;
		case TDI_SEND_DATAGRAM:
			status = SCTPSendDatagram(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #6\n");
			return status;
		default:
			break;
		}
	}
	DbgPrint("SCTPDispatchInternalDeviceControl: leave\n");
	return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
SCTPDispatchDeviceControl(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;

	DbgPrint("SCTPDispatchInternalDeviceControl: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);

	status = TdiMapUserRequest(deviceObject, irp, irpSp);
	if (status == STATUS_SUCCESS) {
		status = SCTPDispatchInternalDeviceControl(deviceObject, irp);
		DbgPrint("SCTPDispatchInternalDeviceControl: leave #1\n");
	}

	DbgPrint("SCTPDispatchInternalDeviceControl: leave\n");
	return STATUS_SUCCESS;
}

NTSTATUS
SCTPDispatch(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;

	irpSp = IoGetCurrentIrpStackLocation(irp);
	DbgPrint("SCTPDispatch: irp=%p,irpSp=%p\n", irp, irpSp);
	return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
SCTPAssociateAddress(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	TDI_REQUEST request;
	PSCTP_CONTEXT sctpContext, sctpContext2;
	PTDI_REQUEST_KERNEL_ASSOCIATE associateInformation;
	PFILE_OBJECT fileObject;

	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;
	request.Handle.ConnectionContext = sctpContext->Handle.ConnectionContext;
	associateInformation =
	    (PTDI_REQUEST_KERNEL_ASSOCIATE)&irpSp->Parameters;

	status = ObReferenceObjectByHandle(associateInformation->AddressHandle,
	    0, NULL, KernelMode, &fileObject, NULL);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	if ((fileObject->DeviceObject == SctpTcpDeviceObject) &&
	    (((int)fileObject->FsContext2) == TDI_TRANSPORT_ADDRESS_FILE)) {
		sctpContext2 = (PSCTP_CONTEXT)fileObject->FsContext;
		status = TdiAssociateAddress(&request, sctpContext2->Handle.AddressHandle);
		sctpContext2->Handle.ConnectionContext = request.Handle.ConnectionContext;

		ObDereferenceObject(fileObject);
	} else {
		status = STATUS_INVALID_HANDLE;
		ObDereferenceObject(fileObject);
	}

	return status;
}

NTSTATUS
SCTPDisassociateAddress(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	TDI_REQUEST request;
	PSCTP_CONTEXT sctpContext;

	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;
	request.Handle.ConnectionContext = sctpContext->Handle.ConnectionContext;
	request.RequestNotifyObject = SCTPRequestComplete;
	request.RequestContext = irp;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = TdiDisassociateAddress(&request);
	if (status != STATUS_PENDING) {
		SCTPRequestComplete(irp, status, 0);
	}
	return STATUS_PENDING;
}


NTSTATUS
SCTPListen(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	TDI_REQUEST request;
	PTDI_REQUEST_KERNEL_LISTEN listenRequest;
	PTDI_CONNECTION_INFORMATION requestInformation, returnInformation;
	PSCTP_CONTEXT sctpContext;

	listenRequest = (PTDI_REQUEST_KERNEL_LISTEN)&(irpSp->Parameters);
	requestInformation = listenRequest->RequestConnectionInformation;
	returnInformation = listenRequest->ReturnConnectionInformation;

	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;
	request.Handle.ConnectionContext = sctpContext->Handle.ConnectionContext;
	request.RequestNotifyObject = SCTPRequestComplete;
	request.RequestContext = irp;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = TdiListen(&request, (ushort)listenRequest->RequestFlags,
	    requestInformation, returnInformation);
	if (status != STATUS_PENDING) {
		SCTPRequestComplete(irp, status, 0);
	}
	return STATUS_PENDING;
}

NTSTATUS
SCTPAccept(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	TDI_REQUEST request;
	PTDI_REQUEST_KERNEL_ACCEPT acceptRequest;
	PTDI_CONNECTION_INFORMATION requestInformation, returnInformation;
	PSCTP_CONTEXT sctpContext;

	acceptRequest = (PTDI_REQUEST_KERNEL_ACCEPT)&(irpSp->Parameters);
	requestInformation = acceptRequest->RequestConnectionInformation;
	returnInformation = acceptRequest->ReturnConnectionInformation;

	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;
	request.Handle.ConnectionContext = sctpContext->Handle.ConnectionContext;
	request.RequestNotifyObject = SCTPRequestComplete;
	request.RequestContext = irp;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = TdiAccept(&request, requestInformation, returnInformation);
	    
	if (status != STATUS_PENDING) {
		SCTPRequestComplete(irp, status, 0);
	}
	return STATUS_PENDING;
}

NTSTATUS
SCTPReceiveDatagram(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	TDI_REQUEST request;
	PSCTP_CONTEXT sctpContext;
	PTDI_REQUEST_KERNEL_RECEIVEDG datagramInformation;
	ULONG receivedLength = 0;

	DbgPrint("SCTPReceiveDatagram: enter\n");
	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;
	datagramInformation = (PTDI_REQUEST_KERNEL_RECEIVEDG)&irpSp->Parameters;

	request.Handle.AddressHandle = sctpContext->Handle.AddressHandle;
	request.RequestNotifyObject = SCTPRequestComplete;
	request.RequestContext = irp;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		DbgPrint("SCTPReceiveDatagram: leave #1\n");
		return status;
	}

	status = TdiReceiveDatagram(&request,
	    datagramInformation->ReceiveDatagramInformation,
	    datagramInformation->ReturnDatagramInformation,
	    datagramInformation->ReceiveLength,
	    &receivedLength,
	    irp->MdlAddress);
	if (status == STATUS_PENDING) {
		DbgPrint("SCTPReceiveDatagram: leave #2\n");
		return status;
	}

	SCTPRequestComplete(irp, status, receivedLength);

	DbgPrint("SCTPReceiveDatagram: leave\n");
	return STATUS_PENDING;
}

NTSTATUS
SCTPSendDatagram(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	TDI_REQUEST request;
	PSCTP_CONTEXT sctpContext;
	PTDI_REQUEST_KERNEL_SENDDG datagramInformation;
	ULONG sentLength = 0;

	DbgPrint("SCTPSendDatagram: enter\n");
	sctpContext = (PSCTP_CONTEXT)irpSp->FileObject->FsContext;
	datagramInformation = (PTDI_REQUEST_KERNEL_SENDDG)&irpSp->Parameters;

	request.Handle.AddressHandle = sctpContext->Handle.AddressHandle;
	request.RequestNotifyObject = SCTPRequestComplete;
	request.RequestContext = irp;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		DbgPrint("SCTPSendDatagram: leave #1\n");
		return status;
	}

	status = TdiSendDatagram(&request,
	    datagramInformation->SendDatagramInformation,
	    datagramInformation->SendLength,
	    &sentLength,
	    irp->MdlAddress);
	if (status == STATUS_PENDING) {
		DbgPrint("SCTPSendDatagram: leave #2\n");
		return status;
	}

	SCTPRequestComplete(irp, status, sentLength);

	DbgPrint("SCTPSendDatagram: leave\n");
	return STATUS_PENDING;
}

void
SCTPAbortAndIndicateDisconnect(
    IN CONNECTION_CONTEXT connectionContext)
{
}


NTSTATUS
TdiOpenAddress(
    PTDI_REQUEST request,
    TRANSPORT_ADDRESS *addr0,
    USHORT type,
    BOOLEAN reuse)
{
	NTSTATUS status;
	struct sockaddr *addr;
	struct socket *so = NULL;
	int error = 0;

	switch (addr0->Address[0].AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		if (addr0->Address[0].AddressLength == sizeof(TDI_ADDRESS_IP)) {
			addr = (struct sockaddr *)&addr0->Address;
			addr->sa_len = sizeof(struct sockaddr_in);
		}
		break;
	case TDI_ADDRESS_TYPE_IP6:
		if (addr0->Address[0].AddressLength == sizeof(TDI_ADDRESS_IP6)) {
			addr = (struct sockaddr *)&addr0->Address;
			addr->sa_len = sizeof(struct sockaddr_in6);
		}
		break;
	default:
		return TDI_BAD_ADDR;
	}

	so = ExAllocatePool(NonPagedPool, sizeof(*so)); /* XXX */
	RtlZeroMemory(so, sizeof(*so));
	STAILQ_INIT(&so->so_dgrcv_reqs);
	STAILQ_INIT(&so->so_dgsnd_reqs);
	SOCKBUF_LOCK_INIT(&so->so_rcv);
	SOCKBUF_LOCK_INIT(&so->so_snd);
	so->so_type = type;

	error = sctp_attach(so);
	if (error != 0) {
		DbgPrint("sctp_attach failed, error=%d\n", error);
		ExFreePool(so);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	error = sctp_bind(so, addr);
	if (error != 0) {
		DbgPrint("sctp_bind failed, error=%d\n", error);
		sctp_detach(so);
		SOCKBUF_LOCK_DESTROY(&so->so_rcv);
		SOCKBUF_LOCK_DESTROY(&so->so_snd);
		ExFreePool(so);
		return STATUS_SHARING_VIOLATION;
	}

	if (so->so_type == SOCK_SEQPACKET) {
		so->so_qlimit = 1; /* XXX */
	}
	request->Handle.AddressHandle = so;
	return STATUS_SUCCESS;
}

NTSTATUS
TdiOpenConnection(
    PTDI_REQUEST request)
{
	NTSTATUS status;

	request->Handle.ConnectionContext = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS
TdiCloseAddress(
    PTDI_REQUEST request)
{
	struct socket *so;
	int error = 0;
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("TdiCloseAddress: enter\n");
	so = (struct socket *)request->Handle.AddressHandle;

	error = sctp_detach(so);
	if (error != 0) {
		status = STATUS_INVALID_PARAMETER;
	}
	SOCKBUF_LOCK_DESTROY(&so->so_rcv);
	SOCKBUF_LOCK_DESTROY(&so->so_snd);
	DbgPrint("TdiCloseAddress: leave\n");
	return status;
}

NTSTATUS
TdiCloseConnection(
    PTDI_REQUEST request)
{
	return STATUS_SUCCESS;
}

NTSTATUS
TdiAssociateAddress(
    IN PTDI_REQUEST request,
    IN HANDLE handle)
{
	struct socket *so;

	so = (struct socket *)handle;
	so->so_qlen++;
	request->Handle.ConnectionContext = so;

	return STATUS_SUCCESS;
}

NTSTATUS
TdiDisassociateAddress(
    IN PTDI_REQUEST request)
{
	return STATUS_SUCCESS;
}

NTSTATUS
TdiListen(
    IN PTDI_REQUEST request,
    IN USHORT flags,
    IN PTDI_CONNECTION_INFORMATION requestConnectionInformation,
    IN PTDI_CONNECTION_INFORMATION returnConnectionInformation)
{
	return STATUS_SUCCESS;
}

NTSTATUS
TdiAccept(
    IN PTDI_REQUEST request,
    IN PTDI_CONNECTION_INFORMATION requestConnectionInformation,
    IN PTDI_CONNECTION_INFORMATION returnConnectionInformation)
{
	return STATUS_SUCCESS;
}

NTSTATUS
TdiDisconnect(
    IN PTDI_REQUEST request,
    IN void *timeOut,
    IN USHORT flags,
    IN PTDI_CONNECTION_INFORMATION requestConnectionInformation,
    IN PTDI_CONNECTION_INFORMATION returnConnectionInformation)
{
	struct socket *so;
	int error = 0;

	so = (struct socket *)request->Handle.ConnectionContext;
	if (so == NULL) {
		return STATUS_INVALID_PARAMETER;
	}
	error = sctp_disconnect(so);

	switch (error) {
	case 0:
		return STATUS_SUCCESS;
	default:
		return STATUS_INVALID_PARAMETER;
	}
}

NTSTATUS
TdiReceiveDatagram(
    IN PTDI_REQUEST request,
    IN PTDI_CONNECTION_INFORMATION receiveDatagramInformation,
    IN PTDI_CONNECTION_INFORMATION returnDatagramInformation,
    IN ULONG receiveLength,
    OUT ULONG *receivedLength,
    IN PNDIS_BUFFER buffer)
{
	NTSTATUS status;
	struct socket *so;
	PSCTP_DGRCV_REQUEST drr;

	DbgPrint("TdiReceiveDatagram: enter\n");
	so = (struct socket *)request->Handle.AddressHandle;

	drr = ExAllocatePool(NonPagedPool, sizeof(*drr));
	RtlZeroMemory(drr, sizeof(*drr));

	drr->drr_conninfo = returnDatagramInformation;
	drr->drr_complete = request->RequestNotifyObject;
	drr->drr_context = request->RequestContext;
	drr->drr_buffer = buffer;
	drr->drr_size = receiveLength;
	status = TdiReceiveDatagramCommon(so, drr, receivedLength);

	if (status == STATUS_PENDING) {
		SOCK_LOCK(so);
		STAILQ_INSERT_TAIL(&so->so_dgrcv_reqs, drr, drr_entry);
		SOCK_UNLOCK(so);
	} else {
		ExFreePool(drr);
	}

	DbgPrint("TdiReceiveDatagram: leave\n");
	return status;
}

NTSTATUS
TdiReceiveDatagramCommon(
    IN struct socket *so,
    IN PSCTP_DGRCV_REQUEST drr,
    OUT ULONG *receivedLength)
{
	NTSTATUS status;
	struct uio uio;
	struct mbuf *control = NULL;
	struct sockaddr *from = NULL;
	int flags;
	PTA_IP_ADDRESS taAddr;
	int error = 0;

	DbgPrint("TdiReceiveDatagramCommon: leave\n");

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = drr->drr_buffer;
	uio.uio_resid = drr->drr_size;
	uio.uio_rw = UIO_READ;

	flags = MSG_DONTWAIT;
	error = sctp_soreceive(so, &from, &uio, NULL, &control, &flags);
	if (error == EWOULDBLOCK) {
		DbgPrint("TdiReceiveDatagramCommon: leave #1\n");
		return STATUS_PENDING;
	}

	if (error == 0) {
		if (from != NULL) {
			if (from->sa_family == AF_INET &&
			    drr->drr_conninfo != NULL &&
			    drr->drr_conninfo->RemoteAddressLength >= sizeof(TA_IP_ADDRESS)) {
				taAddr = (PTA_IP_ADDRESS)drr->drr_conninfo->RemoteAddress;
				taAddr->TAAddressCount = 1;
				drr->drr_conninfo->RemoteAddressLength = taAddr->Address[0].AddressLength =
				    sizeof(TA_IP_ADDRESS);
				taAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
				taAddr->Address[0].Address[0].sin_port = ((struct sockaddr_in *)from)->sin_port;
				taAddr->Address[0].Address[0].in_addr = ((struct sockaddr_in *)from)->sin_addr.s_addr;
			}
			ExFreePool(from);
		}
		if (control != NULL) {
			if (drr->drr_conninfo != NULL &&
			    drr->drr_conninfo->OptionsLength >= SCTP_BUF_LEN(control)) {
				RtlCopyMemory(drr->drr_conninfo->Options, SCTP_BUF_AT(control, 0),
				    SCTP_BUF_LEN(control));
				drr->drr_conninfo->OptionsLength = SCTP_BUF_LEN(control);
			}
			SCTP_BUF_FREE_ALL(control);
		}
		if (receivedLength != NULL) {
			*receivedLength = (ULONG)uio.uio_offset;
		} else {
			(*(drr->drr_complete))(drr->drr_context, STATUS_SUCCESS, (ULONG)uio.uio_offset);
		}
		DbgPrint("TdiReceiveDatagramCommon: leave #2\n");
		return STATUS_SUCCESS;
	} else {
		if (receivedLength != NULL) {
			*receivedLength = 0;
		} else {
			(*(drr->drr_complete))(drr->drr_context, STATUS_INVALID_PARAMETER, 0);
		}
		if (from != NULL) {
			ExFreePool(from);
		}
		if (control != NULL) {
			SCTP_BUF_FREE_ALL(control);
		}
		DbgPrint("TdiReceiveDatagramCommon: leave #3\n");
		return STATUS_INVALID_PARAMETER;
	}
}


void
TdiCancelReceiveDatagram(
    IN HANDLE addressHandle,
    IN PVOID context)
{
	struct socket *so = addressHandle;
	PSCTP_DGRCV_REQUEST drr, drr_tmp;

	DbgPrint("TdiCancelReceiveDatagram: enter\n");
	SOCK_LOCK(so);
	STAILQ_FOREACH_SAFE(drr, &so->so_dgrcv_reqs, drr_entry, drr_tmp) {
		if (drr->drr_context != context) {
			continue;
		}
		STAILQ_REMOVE(&so->so_dgrcv_reqs, drr, sctp_dgrcv_request, drr_entry);
		break;
	}
	SOCK_UNLOCK(so);

	DbgPrint("TdiCancelReceiveDatagram: drr=%p\n", drr);
	if (drr != NULL) {
		(*(drr->drr_complete))(drr->drr_context, STATUS_CANCELLED, 0);
		ExFreePool(drr);
	}
	DbgPrint("TdiCancelReceiveDatagram: leave\n");
}

NTSTATUS
TdiSendDatagram(
    IN PTDI_REQUEST request,
    IN PTDI_CONNECTION_INFORMATION sendDatagramInformation,
    IN ULONG sendLength,
    OUT ULONG *sentLength,
    IN PNDIS_BUFFER buffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	struct socket *so;
	int error = 0;
	struct sockaddr *addr = NULL;
	struct mbuf *control = NULL;
	struct uio uio;
	PSCTP_DGSND_REQUEST dsr;

	DbgPrint("TdiSendDatagram: enter\n");
	so = (struct socket *)request->Handle.AddressHandle;

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = buffer;
	uio.uio_resid = sendLength;
	uio.uio_rw = UIO_WRITE;

	if (sendDatagramInformation->RemoteAddressLength > sizeof(TA_ADDRESS)) {
		if (((PTA_ADDRESS)sendDatagramInformation->RemoteAddress)->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ((PTA_ADDRESS)sendDatagramInformation->RemoteAddress)->AddressLength == sizeof(TA_IP_ADDRESS)) {
			error = getsockaddr(&addr, sendDatagramInformation->RemoteAddress, sizeof(struct sockaddr_in));
			if (error < 0) {
				addr = NULL;
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto done;
			}
		}
	}

	if (sendDatagramInformation != NULL && sendDatagramInformation->OptionsLength > sizeof(TDI_CMSGHDR)) {
		 control = sctp_get_mbuf_for_msg(sendDatagramInformation->OptionsLength,
		    0,
		    M_DONTWAIT,
		    1,
		    MT_SONAME);
		if (control != NULL) {
			RtlCopyMemory(SCTP_BUF_AT(control, 0), sendDatagramInformation->Options,
			    sendDatagramInformation->OptionsLength);
			SCTP_BUF_LEN(control) = sendDatagramInformation->OptionsLength;
		}
	}

	error = sctp_sosend(so, addr, &uio, NULL, control, MSG_NBIO);
	DbgPrint("TdiSendDatagram: sctp_sosend=%d\n", error);
	if (error != EWOULDBLOCK) {
		if (error == 0) {
			status = STATUS_SUCCESS;
		} else {
			status = STATUS_INVALID_PARAMETER; /* XXX */
		}
		DbgPrint("TdiSendDatagram: leave #1\n");
		goto done;
	}

	dsr = ExAllocatePool(NonPagedPool, sizeof(*dsr));
	if (dsr == NULL) {
		DbgPrint("TdiSendDatagram: leave #2\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	RtlZeroMemory(dsr, sizeof(*dsr));

	dsr->dsr_conninfo = sendDatagramInformation;
	dsr->dsr_complete = request->RequestNotifyObject;
	dsr->dsr_context = request->RequestContext;
	dsr->dsr_buffer = buffer;
	dsr->dsr_size = sendLength;
	dsr->dsr_addr = addr;

	SOCKBUF_LOCK(&so->so_snd);
	STAILQ_INSERT_TAIL(&so->so_dgsnd_reqs, dsr, dsr_entry);
	SOCKBUF_UNLOCK(&so->so_snd);

	DbgPrint("TdiSendDatagram: leave\n");
	return STATUS_PENDING;

done:
	if (addr != NULL) {
		ExFreePool(addr);
	}
	DbgPrint("TdiSendDatagram: leave #0\n");
	return status;
}

void
TdiCancelSendDatagram(
    IN HANDLE addressHandle,
    IN PVOID context)
{
	struct socket *so = addressHandle;
	PSCTP_DGSND_REQUEST dsr, dsr_tmp;

	DbgPrint("TdiCancelSendDatagram: enter\n");
	SOCKBUF_LOCK(&so->so_snd);
	STAILQ_FOREACH_SAFE(dsr, &so->so_dgsnd_reqs, dsr_entry, dsr_tmp) {
		if (dsr->dsr_context != context) {
			continue;
		}
		STAILQ_REMOVE(&so->so_dgsnd_reqs, dsr, sctp_dgsnd_request, dsr_entry);
		break;
	}
	SOCKBUF_UNLOCK(&so->so_snd);

	DbgPrint("TdiCancelSendDatagram: dsr=%p\n", dsr);
	if (dsr != NULL) {
		(*(dsr->dsr_complete))(dsr->dsr_context, STATUS_CANCELLED, 0);
		ExFreePool(dsr);
	}
	DbgPrint("TdiCancelReceiveDatagram: leave\n");
}

void
sorwakeup_locked(
    struct socket *so)
{
	NTSTATUS status;
	int error = 0;
	int flags;
	struct uio uio;
	struct sockaddr *from = NULL;
	struct mbuf *control = NULL;

	PSCTP_DGRCV_REQUEST drr;

	struct mbuf *m = NULL, *n;
	TDI_STATUS rcvdgStatus;
	unsigned int length, bytesTaken;

	PTA_IP_ADDRESS taAddr;
	PTA_IP6_ADDRESS ta6Addr;

	PIRP irp;
	PIO_STACK_LOCATION irpSp;
	PTDI_REQUEST_KERNEL_RECEIVEDG datagramInformation;

	DbgPrint("sorwakeup: enter\n");
	while (
	    (!STAILQ_EMPTY(&so->so_dgrcv_reqs)) &&
	    so->so_rcv.sb_cc > 0
	    ) {
		drr = STAILQ_FIRST(&so->so_dgrcv_reqs);
		DbgPrint("sorwakeup: drr=%p\n", drr);
		status = TdiReceiveDatagramCommon(so, drr, NULL);

		if (status == STATUS_PENDING) {
			break;
		}
		STAILQ_REMOVE_HEAD(&so->so_dgrcv_reqs, drr_entry);
		ExFreePool(drr);
	}

	if (so->so_rcv.sb_cc > 0 && so->so_rcvdg != NULL) {
		while (so->so_rcv.sb_cc > 0) {
			flags = MSG_DONTWAIT;
			error = sctp_soreceive(so, &from, NULL, &m, NULL, &flags);
			if (error != 0) {
				break;
			}
			length = 0;
			if (m != NULL) {
				n = m;
				while (n != NULL) {
					length += SCTP_BUF_GET_LEN(n);
					n = SCTP_BUF_GET_NEXT(n);
				}
			}
			rcvdgStatus = (*(so->so_rcvdg))(so->so_rcvdgarg,
			    from->sa_len,
			    from,
			    0,
			    NULL,
			    TDI_RECEIVE_COPY_LOOKAHEAD,
			    SCTP_BUF_GET_LEN(m),
			    length,
			    &bytesTaken,
			    SCTP_BUF_AT(m, 0),
			    &irp);

			if (rcvdgStatus == TDI_MORE_PROCESSING) {
				irpSp = IoGetCurrentIrpStackLocation(irp);
				datagramInformation =
				    (PTDI_REQUEST_KERNEL_RECEIVEDG)&irpSp->Parameters;

				RtlZeroMemory(&uio, sizeof(uio));
				uio.uio_buffer = irp->MdlAddress;
				uio.uio_resid = datagramInformation->ReceiveLength;
				uio.uio_rw = UIO_READ;
				uiomove(SCTP_BUF_AT(m, bytesTaken), SCTP_BUF_GET_LEN(m) - bytesTaken, &uio);
				n = SCTP_BUF_GET_NEXT(m);
				while (n != NULL) {
					uiomove(SCTP_BUF_AT(n, 0), SCTP_BUF_GET_LEN(n), &uio);
					n = SCTP_BUF_GET_NEXT(n);
				}
				irp->IoStatus.Information = length - bytesTaken;
				irp->IoStatus.Status = STATUS_SUCCESS;
			}
		}
	}
	SOCKBUF_UNLOCK(&so->so_rcv);
	DbgPrint("sorwakeup: leave\n");
}

void
sowwakeup_locked(
    struct socket *so)
{
	int error = 0;
	NTSTATUS status = STATUS_SUCCESS;
	struct uio uio;
	PSCTP_DGSND_REQUEST dsr;
	struct mbuf *control = NULL;

	DbgPrint("sowwakeup: enter\n");
	while ((!STAILQ_EMPTY(&so->so_dgsnd_reqs))) {
		dsr = STAILQ_FIRST(&so->so_dgsnd_reqs);
		if (dsr == NULL) {
			break;
		}
		DbgPrint("sowwakeup: dsr=%p\n", dsr);

		RtlZeroMemory(&uio, sizeof(uio));
		uio.uio_buffer = dsr->dsr_buffer;
		uio.uio_resid = dsr->dsr_size;
		uio.uio_rw = UIO_WRITE;

		if (dsr->dsr_conninfo != NULL && dsr->dsr_conninfo->OptionsLength > sizeof(TDI_CMSGHDR)) {
			 control = sctp_get_mbuf_for_msg(dsr->dsr_conninfo->OptionsLength,
			    0,
			    M_DONTWAIT,
			    1,
			    MT_SONAME);
			if (control != NULL) {
				RtlCopyMemory(SCTP_BUF_AT(control, 0), dsr->dsr_conninfo->Options,
				    dsr->dsr_conninfo->OptionsLength);
				SCTP_BUF_LEN(control) = dsr->dsr_conninfo->OptionsLength;
			}
		}

		error = sctp_sosend(so, dsr->dsr_addr, &uio, NULL, control, MSG_NBIO);
		DbgPrint("sorwakeup: sctp_sosend=%d\n", error);
		if (error == EWOULDBLOCK) {
			break;
		}
		
		STAILQ_REMOVE_HEAD(&so->so_dgsnd_reqs, dsr_entry);
		if (error == 0) {
			(*(dsr->dsr_complete))(dsr->dsr_context, STATUS_SUCCESS, (ULONG)uio.uio_offset);
		} else {
			(*(dsr->dsr_complete))(dsr->dsr_context, STATUS_INVALID_PARAMETER, (ULONG)uio.uio_offset); /* XXX */
		}
		if (dsr->dsr_addr != NULL) {
			ExFreePool(dsr->dsr_addr);
		}
		ExFreePool(dsr);
	}
	SOCKBUF_UNLOCK(&so->so_snd);
	DbgPrint("sowwakeup: leave\n");
}

int
uiomove(
    void *data,
    unsigned int length,
    struct uio *uio)
{
	void *cp = NULL, *ptr = NULL;
	unsigned int iov_len = 0, n;
	struct iovec *iov;
	PNDIS_BUFFER buffer, next_buffer;

	DbgPrint("uiomove: enter\n");
	cp = data;
	n = length;
	if (uio->uio_iov != NULL) {
		DbgPrint("uiomove: #1\n");
		while (n > 0 && uio->uio_resid) {
			iov = uio->uio_iov;
			iov_len = iov->iov_len;
			if (iov_len == 0) {
				uio->uio_iov++;
				uio->uio_iovcnt--;
				continue;
			}
			if (iov_len > n) {
				iov_len = n;
			}

			if (uio->uio_rw == UIO_READ) {
				RtlCopyMemory(iov->iov_base, cp, iov_len);
			} else {
				RtlCopyMemory(cp, iov->iov_base, iov_len);
			}

			iov->iov_base = (char *)iov->iov_base + iov_len;
			iov->iov_len -= iov_len;
			uio->uio_resid -= iov_len;
			uio->uio_offset += iov_len;
			cp = (char *)cp + iov_len;
			n -= iov_len;
		}
	} else if (
	    uio->uio_buffer != NULL
	    ) {
		DbgPrint("uiomove: #2\n");
		while (n > 0 && uio->uio_buffer != NULL && uio->uio_resid) {
			DbgPrint("n=%d,uio_buffer=%p,uio_offset=%d,uio_resid=%d\n",
			    n, uio->uio_buffer, uio->uio_offset, uio->uio_resid);
			NdisQueryBuffer(uio->uio_buffer, &ptr, &iov_len);

			if (ptr == NULL || iov_len - uio->uio_buffer_offset <= 0) {
				NdisGetNextBuffer(uio->uio_buffer, &next_buffer);
				uio->uio_buffer = next_buffer;
				uio->uio_buffer_offset = 0;
				continue;
			}

			ptr = (char *)ptr + uio->uio_buffer_offset;
			iov_len -= uio->uio_buffer_offset;

			if (iov_len > n) {
				iov_len = n;
			}

			if (uio->uio_rw == UIO_READ) {
				RtlCopyMemory(ptr, cp, iov_len);
			} else {
				RtlCopyMemory(cp, ptr, iov_len);
			}

			uio->uio_buffer_offset += iov_len;
			uio->uio_resid -= iov_len;
			uio->uio_offset += iov_len;
			cp = (char *)cp + iov_len;
			n -= iov_len;
		}
	} else {
		DbgPrint("uiomove: leave #1\n");
		return -1;
	}

	DbgPrint("uiomove: leave\n");
	return 0;
}

int
sbreserve(
    struct sockbuf *sb,
    u_long cc,
    struct socket *so)
{
	sb->sb_mbmax = cc;
	sb->sb_hiwat = cc;
	if ((u_int)sb->sb_lowat > sb->sb_hiwat) {
		sb->sb_lowat = sb->sb_hiwat;
	}
	return 1;
}

int
soreserve(
    struct socket *so,
    u_long sndcc,
    u_long rcvcc)
{
	sbreserve(&so->so_snd, sndcc, so);
	sbreserve(&so->so_rcv, rcvcc, so);

	if (so->so_rcv.sb_lowat == 0) {
		so->so_rcv.sb_lowat = 1;
	}
	if (so->so_snd.sb_lowat == 0) {
		so->so_snd.sb_lowat = MCLBYTES;
	}
	if ((u_int)so->so_snd.sb_lowat > so->so_snd.sb_hiwat) {
		so->so_snd.sb_lowat = so->so_snd.sb_hiwat;
	}
	return 0;
}

int
getsockaddr(
    struct sockaddr **namp,
    caddr_t uaddr,
    size_t len)
{
	struct sockaddr *sa;

	if (len < (size_t)FIELD_OFFSET(struct sockaddr, sa_data[0])) {
		return EINVAL;
	}

	sa = ExAllocatePool(NonPagedPool, len);
	if (sa == NULL) {
		return ENOMEM;
	}
	RtlCopyMemory(sa, uaddr, len);
	sa->sa_len = (u_short)len;
	*namp = sa;
	
	return 0;

}

struct sockaddr *
sodupsockaddr(
    struct sockaddr *sa,
    int mflags)
{
	struct sockaddr *sa2;

	sa2 = ExAllocatePool(NonPagedPool, sa->sa_len);
	if (sa2 == NULL) {
		return NULL;
	}
	RtlCopyMemory(sa2, sa, sa->sa_len);
	return sa2;
}

static FILE_FULL_EA_INFORMATION UNALIGNED *
FindEAInfo(
    PFILE_FULL_EA_INFORMATION start,
    CHAR *target,
    USHORT length)
{
	int i, ii;
	FILE_FULL_EA_INFORMATION UNALIGNED *ptr;

	do {
		ptr = start;
		start += ptr->NextEntryOffset;

		DbgPrint("EaNameLength=%d,length=%d\n", ptr->EaNameLength, length);
        	if (ptr->EaNameLength != length) {
			continue;
		}

		for (i = 0; i < ptr->EaNameLength; i++) {
			DbgPrint("%c", ptr->EaName[i]);
		}
		DbgPrint("\n");
		for (i = 0; i < length; i++) {
			DbgPrint("%c", target[i]);
		}
		DbgPrint("\n");
		if (RtlCompareMemory(ptr->EaName, target, length) == length) {
			return ptr;
		}
		DbgPrint("NextEntryOffset=%d\n", ptr->NextEntryOffset);
        } while (ptr->NextEntryOffset != 0);

	return NULL;
}


VOID
CustomTimerDpc(
    IN struct _KDPC *dpc,
    IN PVOID  deferredContext,
    IN PVOID  systemArgument1,
    IN PVOID  systemArgument2)
{
	sctp_os_timer_t *tmr = deferredContext;
	LARGE_INTEGER expireTime;

	DbgPrint("CustomTimerDpc: enter\n");

	DbgPrint("CustomTimerDpc: tmr=%p\n", tmr);

	tmr->active = TRUE;
	(*(tmr->func))(tmr->arg);
	tmr->active = FALSE;

	if (tmr->pending == TRUE) {
		KeQuerySystemTime(&expireTime);
		expireTime.QuadPart += (LONGLONG)(100 * 10000)*(tmr->ticks);
		KeSetTimer(&tmr->tmr, expireTime, &tmr->dpc);
	}

	DbgPrint("CustomTimerDpc: leave\n");
}
