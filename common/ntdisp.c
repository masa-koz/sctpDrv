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
 * $Id: ntdisp.c,v 1.12 2007/05/26 19:06:14 kozuka Exp $
 */
#include "globals.h"

#include <netinet/sctp_os_windows.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_addr.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_output.h>

typedef struct socket SCTP_SOCKET, *PSCTP_SOCKET;

typedef struct sctp_context {
	PSCTP_SOCKET socket;
	BOOLEAN dupSocket;
	CONNECTION_CONTEXT connCtx;
	int refcount;
	BOOLEAN cancelIrps;
	KEVENT cleanupEvent;
} SCTP_DRIVER_CONTEXT, *PSCTP_DRIVER_CONTEXT;

int sctp_attach(struct socket *, int proto, struct proc *);
int sctp_bind(struct socket *, struct sockaddr *, struct proc *);
int sctp_detach(struct socket *);
int sctp_connect(struct socket *, struct sockaddr *);
int sctp_disconnect(struct socket *);
int sctp_abort(struct socket *);
#if 0
int sctp_soreceive(struct socket *, struct sockaddr **, struct uio *, struct mbuf **, struct mbuf **, int *);
#endif

NTSTATUS SCTPPrepareIrpForCancel(IN PSCTP_DRIVER_CONTEXT, IN PIRP, PDRIVER_CANCEL);
VOID SCTPCancelRequest(IN PDEVICE_OBJECT, IN PIRP);
VOID SCTPCancelComplete(IN VOID *, IN ULONG , IN ULONG);
VOID SCTPRequestComplete(IN VOID *, IN ULONG , IN ULONG);

NTSTATUS SCTPAssociateAddress(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDisassociateAddress(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPListen(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPAccept(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPConnect(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDisconnect(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDispatchSend(IN PIRP, IN PIO_STACK_LOCATION);

NTSTATUS SCTPDispatchReceiveDatagram(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPReceiveDatagram(IN PSCTP_SOCKET, IN PSCTP_DGRCV_REQUEST);
void SCTPCancelReceiveDatagram(IN PSCTP_SOCKET, IN PVOID);
void SCTPDeliverData(struct socket *);
void SCTPDeliverDataEvent(struct socket *);
void SCTPDeliverDatagram(struct socket *);
void SCTPDeliverDatagramEvent(struct socket *);
void SCTPNotifyDisconnect(struct socket *);

NTSTATUS SCTPDispatchSend(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPDispatchSendDatagram(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPSendDatagram(IN PSCTP_SOCKET, IN PSCTP_DGSND_REQUEST);
void SCTPCancelSendDatagram(IN PSCTP_SOCKET, IN PVOID);
void SCTPNotifySend(struct socket *);
void SCTPNotifySendDatagram(struct socket *);

NTSTATUS SCTPSetEventHandler(IN PIRP, IN PIO_STACK_LOCATION);
NTSTATUS SCTPQueryInformation(IN PIRP, IN PIO_STACK_LOCATION);

int convertsockaddr(PTRANSPORT_ADDRESS, ULONG *, struct sockaddr *);

static FILE_FULL_EA_INFORMATION UNALIGNED *FindEAInfo(PFILE_FULL_EA_INFORMATION, CHAR *, USHORT);

KSPIN_LOCK accept_lock;

extern PDEVICE_OBJECT SctpTcpDeviceObject;
extern PDEVICE_OBJECT SctpUdpDeviceObject;
extern LARGE_INTEGER StartTime;


NTSTATUS
SCTPPrepareIrpForCancel(
    IN PSCTP_DRIVER_CONTEXT sctpContext,
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
		DbgPrint("SCTPPrepareIrpForCancel: refcount=%d\n", sctpContext->refcount);

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
	KIRQL oldIrql;
	PIO_STACK_LOCATION irpSp;
	PFILE_OBJECT fileObject;
	PSCTP_DRIVER_CONTEXT sctpContext;

	DbgPrint("SCTPCancelRequest: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);
	fileObject = irpSp->FileObject;
	sctpContext = (PSCTP_DRIVER_CONTEXT)fileObject->FsContext;

	IoSetCancelRoutine(irp, NULL);

	sctpContext->refcount++;
	DbgPrint("SCTPCancelRequest: refcount=%d\n", sctpContext->refcount);

	IoReleaseCancelSpinLock(irp->CancelIrql);

	DbgPrint("SCTPCancelRequest: MinorFunction=%d\n", irpSp->MinorFunction);

	switch (irpSp->MinorFunction) {
	case TDI_SEND_DATAGRAM:
		SCTPCancelSendDatagram(sctpContext->socket, irp);
		break;
	case TDI_RECEIVE_DATAGRAM:
		SCTPCancelReceiveDatagram(sctpContext->socket, irp);
		break;
	default:
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		soabort(sctpContext->socket);
		KeLowerIrql(oldIrql);
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
	PSCTP_DRIVER_CONTEXT sctpContext;

	DbgPrint("SCTPCancelComplete: enter\n");

	fileObject = (PFILE_OBJECT)context;
	sctpContext = (PSCTP_DRIVER_CONTEXT)fileObject->FsContext;

	IoAcquireCancelSpinLock(&oldIrql);

	if (--(sctpContext->refcount) == 0) {
		KeSetEvent(&sctpContext->cleanupEvent, 0, FALSE);
	}
	DbgPrint("SCTPCancelComplete: refcount=%d\n", sctpContext->refcount);

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
	PSCTP_DRIVER_CONTEXT sctpContext;

	DbgPrint("SCTPRequestComplete: enter\n");

	DbgPrint("SCTPRequestComplete: status=%X,length=%d\n", status, length);

	irp = (PIRP)context;
	irpSp = IoGetCurrentIrpStackLocation(irp);
	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;

	IoAcquireCancelSpinLock(&oldIrql);

	IoSetCancelRoutine(irp, NULL);

	if (--(sctpContext->refcount) == 0) {
		KeSetEvent(&sctpContext->cleanupEvent, 0, FALSE);
	}
	DbgPrint("SCTPRequestComplete: refcount=%d\n", sctpContext->refcount);

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
	NTSTATUS status = STATUS_INVALID_EA_NAME;
	KIRQL oldIrql;
	PIO_STACK_LOCATION irpSp;
	struct sctp_context *sctpContext;
	FILE_FULL_EA_INFORMATION *ea0, *ea;
	PTRANSPORT_ADDRESS taAddr = NULL;
	struct sockaddr *addr = NULL;
	struct socket *so = NULL;
	int error = 0;

	DbgPrint("SCTPCreate: enter\n");

	irpSp = IoGetCurrentIrpStackLocation(irp);

	sctpContext = ExAllocatePool(NonPagedPool, sizeof(struct sctp_context));
	if (sctpContext == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrint("SCTPCreate: leave #0-1\n");
		goto done;
	}
	RtlZeroMemory(sctpContext, sizeof(SCTP_DRIVER_CONTEXT));

	KeInitializeEvent(&sctpContext->cleanupEvent, SynchronizationEvent, FALSE);
	sctpContext->refcount = 1;
	DbgPrint("SCTPCreate: refcount=%d\n", sctpContext->refcount);
	sctpContext->cancelIrps = FALSE;

	ea0 = (PFILE_FULL_EA_INFORMATION)irp->AssociatedIrp.SystemBuffer;
	if (ea0 == NULL) {
		/* TDI_CONTROL_CHANNEL_FILE */
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONTROL_CHANNEL_FILE;
		status = STATUS_SUCCESS;
		DbgPrint("SCTPCreate: leave #1-1\n");
		goto done;
	}

	ea = FindEAInfo(ea0, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH);
	if (ea != NULL) {
		/* TDI_TRANSPORT_ADDRESS_FILE */

		taAddr = (TRANSPORT_ADDRESS *)&ea->EaName[ea->EaNameLength + 1];
		switch (taAddr->Address[0].AddressType) {
		case TDI_ADDRESS_TYPE_IP:
			if (taAddr->Address[0].AddressLength == sizeof(TDI_ADDRESS_IP)) {
				addr = (struct sockaddr *)&taAddr->Address;
				addr->sa_len = sizeof(struct sockaddr_in);
			}
			break;
		case TDI_ADDRESS_TYPE_IP6:
			if (taAddr->Address[0].AddressLength == sizeof(TDI_ADDRESS_IP6)) {
				addr = (struct sockaddr *)&taAddr->Address;
				addr->sa_len = sizeof(struct sockaddr_in6);
			}
			break;
		default:
			status = TDI_BAD_ADDR;
			ExFreePool(sctpContext);
			DbgPrint("SCTPCreate: leave #2-1\n");
			goto done;
		}

		so = soalloc();
		if (so == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DbgPrint("SCTPCreate: leave #2-2\n");
			goto done;
		}

		if (((irpSp->Parameters.Create.ShareAccess & FILE_SHARE_READ) ||
		     (irpSp->Parameters.Create.ShareAccess & FILE_SHARE_WRITE))) {
		}
		if (deviceObject == SctpTcpDeviceObject) {
			so->so_type = SOCK_STREAM;
		} else {
			so->so_type = SOCK_SEQPACKET;
		}

		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		error = sctp_attach(so, IPPROTO_SCTP, NULL);
		if (error != 0) {
			KeLowerIrql(oldIrql);
			status = STATUS_INSUFFICIENT_RESOURCES;
			ExFreePool(so);
			ExFreePool(sctpContext);
			DbgPrint("SCTPCreate: leave #2-3\n");
			goto done;
		}

		error = sctp_bind(so, addr, NULL);
		if (error != 0) {
			DbgPrint("sctp_bind failed, error=%d\n", error);
			status = STATUS_SHARING_VIOLATION;
			sctp_detach(so);
			KeLowerIrql(oldIrql);
			SOCKBUF_LOCK_DESTROY(&so->so_rcv);
			SOCKBUF_LOCK_DESTROY(&so->so_snd);
			ExFreePool(so);
			ExFreePool(sctpContext);
			DbgPrint("SCTPCreate: leave #2-4\n");
			goto done;
		}

		if (so->so_type == SOCK_STREAM) {
			TAILQ_INIT(&so->so_incomp);
			TAILQ_INIT(&so->so_comp);
		} else {
			so->so_qlimit = 1;
		}
		so->so_options |= SO_USECONTROL; /* XXX */
		KeLowerIrql(oldIrql);

		sctpContext->socket = so;
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_TRANSPORT_ADDRESS_FILE;
		DbgPrint("SCTPCreate: leave #2-5\n");
		status = STATUS_SUCCESS;
		goto done;
	}

	ea = FindEAInfo(ea0, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH);
	if (ea != NULL) {
		/* TDI_CONNECTION_FILE */

		DbgPrint("ea->EaValueLength=%d\n", ea->EaValueLength);
		DbgPrint("&ea->EaName[ea->EaNameLength + 1]=%p\n", &ea->EaName[ea->EaNameLength + 1]);
		sctpContext->connCtx = *(CONNECTION_CONTEXT UNALIGNED *)&ea->EaName[ea->EaNameLength + 1];
		sctpContext->dupSocket = FALSE;
		DbgPrint("sctpContext->connCtx=%p\n", sctpContext->connCtx);
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONNECTION_FILE;
		DbgPrint("SCTPCreate: leave #3-1\n");
		status = STATUS_SUCCESS;
		goto done;
	}

	DbgPrint("SCTPCreate: leave\n");
done:
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

	return status;
}

VOID SCTPCleanupComplete(PVOID, NTSTATUS, unsigned int);

NTSTATUS
SCTPCleanup(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp;
	KIRQL oldIrql;
	PSCTP_DRIVER_CONTEXT sctpContext;
	struct socket *so = NULL;
	int error = 0;

	DbgPrint("SCTPCleanup: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;

	IoAcquireCancelSpinLock(&oldIrql);

	sctpContext->cancelIrps = TRUE;
	KeResetEvent(&sctpContext->cleanupEvent);

	IoReleaseCancelSpinLock(oldIrql);

	if ((int)irpSp->FileObject->FsContext2 == TDI_TRANSPORT_ADDRESS_FILE) {
		DbgPrint("SCTPCleanup: #1.1\n");
		so = sctpContext->socket;
		if (so != NULL) {
			KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
			error = sctp_detach(so);
			SOCK_LOCK(so);
			sofree(so);
			KeLowerIrql(oldIrql);
		}

		status = STATUS_SUCCESS;
	} else if (
	    (int)irpSp->FileObject->FsContext2 == TDI_CONNECTION_FILE) {
		DbgPrint("SCTPCleanup: #1.2\n");
		if (sctpContext->dupSocket == TRUE && sctpContext->socket != NULL) {
			so = sctpContext->socket;
			KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
			if (so->so_pcb != NULL) {
				error = sctp_detach(so);
			}
			SOCK_LOCK(so);
			sofree(so);
			KeLowerIrql(oldIrql);
		}

		status = STATUS_SUCCESS;
	} else if ((int)irpSp->FileObject->FsContext2 == TDI_CONTROL_CHANNEL_FILE) {
		DbgPrint("SCTPCleanup: #1.3\n");
		status = STATUS_SUCCESS;
	} else {
		DbgPrint("SCTPCleanup: #1.4\n");
		IoAcquireCancelSpinLock(&oldIrql);
		sctpContext->cancelIrps = FALSE;
		IoReleaseCancelSpinLock(oldIrql);

		status = irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

		DbgPrint("SCTPCleanup: leave #1\n");
		return status;
	}

	SCTPCleanupComplete(irp, status, 0);

	status = KeWaitForSingleObject(&sctpContext->cleanupEvent, UserRequest, KernelMode, FALSE, NULL);

	if (so != NULL) {
		SOCKBUF_LOCK_DESTROY(&so->so_rcv);
		SOCKBUF_LOCK_DESTROY(&so->so_snd);
	}

	status = irp->IoStatus.Status;
	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

	DbgPrint("SCTPCleanup: leave=%X\n", status);
	return status;
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
	PSCTP_DRIVER_CONTEXT sctpContext;

	irp = (PIRP)context;
	irpSp = IoGetCurrentIrpStackLocation(irp);
	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;

	IoAcquireCancelSpinLock(&oldIrql);

	sctpContext->refcount--;
	DbgPrint("SCTPCleanupComplete: refcount=%d\n", sctpContext->refcount);
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
	PSCTP_DRIVER_CONTEXT sctpContext;

	DbgPrint("SCTPClose: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	ExFreePool(sctpContext);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

	DbgPrint("SCTPClose: leave\n");
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
	if (((int)irpSp->FileObject->FsContext2) == TDI_CONNECTION_FILE) {
		DbgPrint("SCTPDispatchInternalDeviceControl: TDI_CONNECTION_FILE,MinorFunction=%X\n", irpSp->MinorFunction);
		switch (irpSp->MinorFunction) {
		case TDI_ASSOCIATE_ADDRESS:
			status = SCTPAssociateAddress(irp, irpSp);
			break;
		case TDI_DISASSOCIATE_ADDRESS:
			status = SCTPDisassociateAddress(irp, irpSp);
			break;
		case TDI_LISTEN:
			status = SCTPListen(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #1.3\n");
			return status;
		case TDI_ACCEPT:
			status = SCTPAccept(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #1.4\n");
			return status;
		case TDI_CONNECT:
			status = SCTPConnect(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #1.5\n");
			return status;
		case TDI_DISCONNECT:
			status = SCTPDisconnect(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #1.6\n");
			return status;
		case TDI_SEND:
			status = SCTPDispatchSend(irp, irpSp);

			DbgPrint("SCTPDispatchInternalDeviceControl: leave #1.7\n");
			return status;
		case TDI_QUERY_INFORMATION:
			status = SCTPQueryInformation(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #1.8\n");
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	} else if (
	    ((int)irpSp->FileObject->FsContext2) == TDI_TRANSPORT_ADDRESS_FILE) {
		DbgPrint("SCTPDispatchInternalDeviceControl: TDI_TRANSPORT_ADDRESS_FILE,MinorFunction=%X\n", irpSp->MinorFunction);
		switch (irpSp->MinorFunction) {
		case TDI_RECEIVE_DATAGRAM:
			status = SCTPDispatchReceiveDatagram(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #2.1\n");
			return status;
		case TDI_SEND_DATAGRAM:
			status = SCTPDispatchSendDatagram(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #2.2\n");
			return status;
		case TDI_SET_EVENT_HANDLER:
			status = SCTPSetEventHandler(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #2.3\n");
			return status;
		case TDI_QUERY_INFORMATION:
			status = SCTPQueryInformation(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #2.4\n");
			return status;
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	} else {
		DbgPrint("SCTPDispatchInternalDeviceControl: TDI_CONTROL_CHANNEL_FILE,MinorFunction=%X\n");
		switch (irpSp->MinorFunction) {
		case TDI_QUERY_INFORMATION:
			status = SCTPQueryInformation(irp, irpSp);
			DbgPrint("SCTPDispatchInternalDeviceControl: leave #3\n");
			return status;
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

	DbgPrint("SCTPDispatchInternalDeviceControl: leave,status=%X\n", status);
	return status;
}

NTSTATUS
SCTPDispatchDeviceControl(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;

	DbgPrint("SCTPDispatchDeviceControl: enter\n");
	irpSp = IoGetCurrentIrpStackLocation(irp);

	status = TdiMapUserRequest(deviceObject, irp, irpSp);
	if (status == STATUS_SUCCESS) {
		status = SCTPDispatchInternalDeviceControl(deviceObject, irp);
		DbgPrint("SCTPDispatchDeviceControl: leave #1\n");
	}

	DbgPrint("SCTPDispatchDeviceControl: leave\n");
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
	KIRQL oldIrql;
	PSCTP_DRIVER_CONTEXT sctpContext, sctpContext2;
	PTDI_REQUEST_KERNEL_ASSOCIATE associateInformation;
	PFILE_OBJECT fileObject;
	struct socket *so = NULL;
	struct sctp_inpcb *inp = NULL;
#if 0
	PSCTP_ASSOC_CONN asc = NULL;
#endif

	DbgPrint("SCTPAssociateAddress: enter\n");

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	    (PTDI_REQUEST_KERNEL_ASSOCIATE)&irpSp->Parameters;
	associateInformation = (PTDI_REQUEST_KERNEL_ASSOCIATE)&irpSp->Parameters;

	status = ObReferenceObjectByHandle(associateInformation->AddressHandle,
	    0, NULL, KernelMode, &fileObject, NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint("SCTPAssociateAddress: leave #1\n");
		return status;
	}

	if (fileObject->DeviceObject != SctpTcpDeviceObject) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}

	if (sctpContext->socket != NULL) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}

	if (((int)fileObject->FsContext2) != TDI_TRANSPORT_ADDRESS_FILE) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}

	sctpContext2 = (PSCTP_DRIVER_CONTEXT)fileObject->FsContext;

	so = sctpContext2->socket;
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp != NULL && (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0) {
		sctpContext->socket = so;
		status = STATUS_SUCCESS;
	} else {
		status = STATUS_INVALID_HANDLE;
	}

done:
	ObDereferenceObject(fileObject);

	DbgPrint("SCTPAssociateAddress: leave #3\n");
	return status;
}

NTSTATUS
SCTPDisassociateAddress(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	TDI_REQUEST request;
	PSCTP_DRIVER_CONTEXT sctpContext;

	DbgPrint("SCTPDisassociateAddress: enter\n");
	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;

	sctpContext->socket = NULL;

	return STATUS_SUCCESS;
}


NTSTATUS
SCTPListen(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
#if 0
	NTSTATUS status;
	KIRQL oldIrql;
	PTDI_REQUEST_KERNEL_LISTEN listenRequest;
	PTDI_CONNECTION_INFORMATION requestInformation, returnInformation;
	PSCTP_DRIVER_CONTEXT sctpContext;
	PSCTP_CONN_REQUEST cnr = NULL;
	struct socket *head = NULL, *so = NULL;

	DbgPrint("SCTPListen: enter\n");
	listenRequest = (PTDI_REQUEST_KERNEL_LISTEN)&(irpSp->Parameters);
	requestInformation = listenRequest->RequestConnectionInformation;
	returnInformation = listenRequest->ReturnConnectionInformation;

	if ((listenRequest->RequestFlags & TDI_QUERY_ACCEPT) != 0) {
		DbgPrint("SCTPListen: leave #1\n");
		return STATUS_INVALID_PARAMETER;
	}
	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;

	if (sctpContext->socket == NULL || sctpContext->socket->so_head != NULL) {
		DbgPrint("SCTPListen: leave #2\n");
		return STATUS_INVALID_CONNECTION;
	}
	head = sctpContext->socket;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		DbgPrint("SCTPListen: leave #3\n");
		return status;
	}

	cnr = ExAllocatePool(NonPagedPool, sizeof(*cnr));
	if (cnr == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrint("SCTPListen: leave #4\n");
		goto done;
	}
	RtlZeroMemory(cnr, sizeof(*cnr));

	cnr->cnr_conninfo = returnInformation;
	cnr->cnr_complete = SCTPRequestComplete;
	cnr->cnr_context = irp;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	SOCK_LOCK(head);
	head->so_qlimit++;
	STAILQ_INSERT_TAIL(&head->so_conn_reqs, cnr, cnr_entry);
	SOCK_UNLOCK(head);
	KeLowerIrql(oldIrql);

	status = STATUS_SUCCESS;
	DbgPrint("SCTPListen: leave #5\n");
done:
	if (status != STATUS_PENDING) {
		SCTPRequestComplete(irp, status, 0);
	}
	return STATUS_PENDING;
#else
	return STATUS_INVALID_DEVICE_REQUEST;
#endif
}

NTSTATUS
SCTPAccept(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
#if 0
	NTSTATUS status;
	PTDI_REQUEST_KERNEL_ACCEPT acceptRequest;
	PTDI_CONNECTION_INFORMATION requestInformation, returnInformation;
	PSCTP_DRIVER_CONTEXT sctpContext;

	acceptRequest = (PTDI_REQUEST_KERNEL_ACCEPT)&(irpSp->Parameters);
	requestInformation = acceptRequest->RequestConnectionInformation;
	returnInformation = acceptRequest->ReturnConnectionInformation;

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	request.Handle.connectionContext = sctpContext->handle.connectionContext;
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
#else
	return STATUS_INVALID_DEVICE_REQUEST;
#endif
}

NTSTATUS
SCTPConnect(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_REQUEST_KERNEL_CONNECT connectRequest;
	PTDI_CONNECTION_INFORMATION requestInformation, returnInformation;
	PSCTP_DRIVER_CONTEXT sctpContext;
	struct socket *so = NULL;
	PTRANSPORT_ADDRESS tAddr = NULL;
	struct sockaddr *addr = NULL;
	PSCTP_CONN_REQUEST connr = NULL;
	PLARGE_INTEGER timeout = NULL;

	DbgPrint("SCTPConnect: enter\n");

	connectRequest = (PTDI_REQUEST_KERNEL_CONNECT)&irpSp->Parameters;
	requestInformation = connectRequest->RequestConnectionInformation;
	returnInformation = connectRequest->ReturnConnectionInformation;

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	if (sctpContext->socket == NULL) {
		DbgPrint("SCTPConnect: leave #1\n");
		status = STATUS_INVALID_CONNECTION;
		goto done1;
	}
	so = sctpContext->socket;

	if (requestInformation != NULL && requestInformation->RemoteAddressLength >= sizeof(TRANSPORT_ADDRESS)) {
		tAddr = (TRANSPORT_ADDRESS *)requestInformation->RemoteAddress;
		switch (tAddr->Address[0].AddressType) {
		case TDI_ADDRESS_TYPE_IP:
			DbgPrint("sizeof(TDI_ADDRESS_IP)=%d,sizeof(struct sockaddr_in)=%d\n", sizeof(TDI_ADDRESS_IP), sizeof(struct sockaddr_in));
			if (tAddr->Address[0].AddressLength == sizeof(TDI_ADDRESS_IP)) {
				addr = (struct sockaddr *)&tAddr->Address;
				addr->sa_len = sizeof(struct sockaddr_in);
			} else {
				status = TDI_BAD_ADDR;
			}
			break;
		case TDI_ADDRESS_TYPE_IP6:
			if (tAddr->Address[0].AddressLength == sizeof(TDI_ADDRESS_IP6)) {
				addr = (struct sockaddr *)&tAddr->Address;
				addr->sa_len = sizeof(struct sockaddr_in6);
			}
			break;
		default:
			status = TDI_BAD_ADDR;
			break;
                }
	} else {
		status = TDI_BAD_ADDR;
	}

	if (status != STATUS_SUCCESS) {
		DbgPrint("SCTPConnect: leave #2\n");
		goto done1;
	}
	DbgPrint("SCTPConnect: dest=");
	sctp_print_address(addr);

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		/* This IRP canceled. */
		DbgPrint("SCTPConnect: leave #3\n");
		return status;
	}

	connr = ExAllocatePool(NonPagedPool, sizeof(*connr));
	if (connr == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrint("SCTPConnect: leave #4\n");
		goto done;
	}
	RtlZeroMemory(connr, sizeof(*connr));

	connr->conn_complete = SCTPRequestComplete;
	connr->conn_context = irp;
	connr->conn_conninfo = returnInformation;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	SOCK_LOCK(so);
	so->so_conn_req = connr;
	so->so_conn_ctx = sctpContext->connCtx;
	SOCK_UNLOCK(so);

	error = sctp_connect(so, addr);
	KeLowerIrql(oldIrql);
	status = STATUS_PENDING;

done:
	if (status != STATUS_PENDING) {
		SCTPRequestComplete(irp, status, 0);
	}
	DbgPrint("SCTPConnect: leave\n");
	return STATUS_PENDING;

done1:
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
	DbgPrint("SCTPConnect: leave #1\n");
	return status;
}

NTSTATUS
SCTPDisconnect(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;
	int error = 0;
	PTDI_REQUEST_KERNEL_DISCONNECT disconnectRequest;
	PSCTP_DRIVER_CONTEXT sctpContext;
	struct socket *so = NULL;
	struct sctp_inpcb *inp = NULL;
	PSCTP_CONN_REQUEST connr = NULL;
	PLARGE_INTEGER timeout = NULL;

	DbgPrint("SCTPDisconnect: enter\n");
	disconnectRequest = (PTDI_REQUEST_KERNEL_DISCONNECT)&(irpSp->Parameters);

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	if (sctpContext->socket == NULL) {
		DbgPrint("SCTPDisconnect: leave #1\n");
		status = STATUS_INVALID_CONNECTION;
		goto done1;
	}

	so = sctpContext->socket;
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL || (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0) {
		DbgPrint("SCTPDisconnect: leave #2\n");
		status = STATUS_INVALID_CONNECTION;
		goto done1;
	}

	if (so->so_disconn_req != NULL) {
		DbgPrint("SCTPDisconnect: leave #3\n");
		status = STATUS_INVALID_CONNECTION;
		goto done1;
	}

	if ((disconnectRequest->RequestFlags & TDI_DISCONNECT_ABORT) != 0) {
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		error = sctp_abort(so);
		KeLowerIrql(oldIrql);
		DbgPrint("SCTPDisconnect: leave #4\n");
		status = STATUS_SUCCESS;
		goto done1;
	}

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		/* This IRP canceled. */
		DbgPrint("SCTPDisconnect: leave #5\n");
		return status;
	}

	connr = ExAllocatePool(NonPagedPool, sizeof(*connr));
	if (connr == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrint("SCTPDisconnect: leave #6\n");
		goto done;
	}
	RtlZeroMemory(connr, sizeof(*connr));

	connr->conn_complete = SCTPRequestComplete;
	connr->conn_context = irp;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	SOCK_LOCK(so);
	so->so_disconn_req = connr;
	SOCK_UNLOCK(so);

	error = sctp_disconnect(so);
	status = STATUS_PENDING;
done:
	if (status != STATUS_PENDING) {
		SCTPRequestComplete(irp, status, 0);
	}
	KeLowerIrql(oldIrql);
	DbgPrint("SCTPDisconnect: leave\n");
	return STATUS_PENDING;

done1:
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
	DbgPrint("SCTPDisconnect: leave #1\n");
	return status;
}


NTSTATUS
SCTPDispatchSend(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;
	int error = 0;
	PTDI_REQUEST_KERNEL_SEND sendRequest;
	PSCTP_DRIVER_CONTEXT sctpContext;
	struct socket *so = NULL;
	struct uio uio;
	ULONG sendLength = 0, sentLength = 0;
	PSCTP_SND_REQUEST sndr = NULL;

	DbgPrint("SCTPDispatchSend: enter\n");
	sendRequest = (PTDI_REQUEST_KERNEL_SEND)&(irpSp->Parameters);

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	if (sctpContext->socket == NULL) {
		DbgPrint("SCTPDispatchSend: leave #1\n");
		status = STATUS_INVALID_CONNECTION;
		goto done1;
	}
	so = sctpContext->socket;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		/* This IRP canceled. */
		DbgPrint("SCTPDispatchSend: leave #2\n");
		return status;
	}

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_resid = sendRequest->SendLength;
	uio.uio_rw = UIO_WRITE;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = sctp_sosend(so, NULL, &uio, NULL, NULL, MSG_NBIO, NULL);
	DbgPrint("SCTPDispatchSend: sctp_sosend=%d\n", error);

	if (error == 0) {
		sentLength = sendRequest->SendLength;;
		status = STATUS_SUCCESS;
	} else if (error == EWOULDBLOCK && (sendRequest->SendFlags & TDI_SEND_NON_BLOCKING) != 0) {
		status = STATUS_DEVICE_NOT_READY;
	} else if (error == EWOULDBLOCK) {
		sndr = ExAllocatePool(NonPagedPool, sizeof(*sndr));
		RtlZeroMemory(sndr, sizeof(*sndr));

		sndr->snd_complete = SCTPRequestComplete;
		sndr->snd_context = irp;
		sndr->snd_buffer = irp->MdlAddress;
		sndr->snd_size = sendRequest->SendLength;

		SOCK_LOCK(so);
		STAILQ_INSERT_TAIL(&so->so_snd_reqs, sndr, snd_entry);
		SOCK_UNLOCK(so);

		status = STATUS_PENDING;
	} else {
		status = STATUS_INVALID_CONNECTION;
	}

	if (status != STATUS_PENDING) {
		SCTPRequestComplete(irp, status, sentLength);
	}

	KeLowerIrql(oldIrql);

	DbgPrint("SCTPDispatchSend: leave\n");
	return STATUS_PENDING;

done1:
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
	DbgPrint("SCTPDispatchSend: leave #1\n");
	return status;
}


NTSTATUS
SCTPDispatchReceiveDatagram(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	KIRQL oldIrql;
	PSCTP_DRIVER_CONTEXT sctpContext;
	PTDI_REQUEST_KERNEL_RECEIVEDG datagramInformation;
	struct socket *so = NULL;
	PSCTP_DGRCV_REQUEST dgrcvr = NULL;
	ULONG receivedLength = 0;

	DbgPrint("SCTPDispatchReceiveDatagram: enter\n");
	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	datagramInformation = (PTDI_REQUEST_KERNEL_RECEIVEDG)&irpSp->Parameters;

	so = sctpContext->socket;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		/* This IRP canceled. */
		DbgPrint("SCTPDispatchReceiveDatagram: leave #1\n");
		return status;
	}

	dgrcvr = ExAllocatePool(NonPagedPool, sizeof(*dgrcvr));
	RtlZeroMemory(dgrcvr, sizeof(*dgrcvr));

	dgrcvr->dgrcv_conninfo = datagramInformation->ReturnDatagramInformation;
	dgrcvr->dgrcv_complete = SCTPRequestComplete;
	dgrcvr->dgrcv_context = irp;
	dgrcvr->dgrcv_buffer = irp->MdlAddress;
	dgrcvr->dgrcv_size = datagramInformation->ReceiveLength;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	status = SCTPReceiveDatagram(sctpContext->socket, dgrcvr);
	if (status != STATUS_PENDING) {
		ExFreePool(dgrcvr);
	} else {
		SOCK_LOCK(so);
		STAILQ_INSERT_TAIL(&so->so_dgrcv_reqs, dgrcvr, dgrcv_entry);
		SOCK_UNLOCK(so);
	}

	KeLowerIrql(oldIrql);

	DbgPrint("SCTPDispatchReceiveDatagram: leave\n");
	return STATUS_PENDING;
}

NTSTATUS
SCTPReceiveDatagram(
    IN PSCTP_SOCKET socket,
    IN PSCTP_DGRCV_REQUEST dgrcvr)
{
	NTSTATUS status = STATUS_SUCCESS;
	struct socket *so = socket;
	struct uio uio;
	struct mbuf *control = NULL;
	struct sockaddr *from = NULL;
	int flags;
	int error = 0;

	DbgPrint("SCTPReceiveDatagram: leave\n");

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = dgrcvr->dgrcv_buffer;
	uio.uio_resid = dgrcvr->dgrcv_size;
	uio.uio_rw = UIO_READ;

	flags = MSG_DONTWAIT;
	error = sctp_soreceive(so, &from, &uio, NULL, &control, &flags);

	if (error == EWOULDBLOCK) {
		DbgPrint("SCTPReceiveDatagram: leave #1\n");
	}

	if (error == 0) {
		if (from != NULL && dgrcvr->dgrcv_conninfo != NULL) {
			if (convertsockaddr(dgrcvr->dgrcv_conninfo->RemoteAddress,
				&dgrcvr->dgrcv_conninfo->RemoteAddressLength, from) < 0) {
				dgrcvr->dgrcv_conninfo->RemoteAddress = NULL;
				dgrcvr->dgrcv_conninfo->RemoteAddressLength = 0;
			}
		}

		if (control != NULL && dgrcvr->dgrcv_conninfo != NULL) {
			if (dgrcvr->dgrcv_conninfo->OptionsLength >= SCTP_BUF_LEN(control)) {
				RtlCopyMemory(dgrcvr->dgrcv_conninfo->Options, SCTP_BUF_AT(control, 0),
				    SCTP_BUF_LEN(control));
				dgrcvr->dgrcv_conninfo->OptionsLength = SCTP_BUF_LEN(control);
			} else {
				dgrcvr->dgrcv_conninfo->Options = NULL;
				dgrcvr->dgrcv_conninfo->OptionsLength = 0;
			}
		}

		(*(dgrcvr->dgrcv_complete))(dgrcvr->dgrcv_context, STATUS_SUCCESS, (ULONG)uio.uio_offset);
		status = STATUS_SUCCESS;
	} else if (error == EWOULDBLOCK) {
		status = STATUS_PENDING;
	} else {
		(*(dgrcvr->dgrcv_complete))(dgrcvr->dgrcv_context, STATUS_INVALID_PARAMETER, 0);
		status = STATUS_INVALID_PARAMETER;
	}

	if (from != NULL) {
		ExFreePool(from);
	}
	if (control != NULL) {
		m_freem(control);
	}

	return status;
}

void
SCTPCancelReceiveDatagram(
    IN PSCTP_SOCKET socket,
    IN PVOID context)
{
	struct socket *so = socket;
	PSCTP_DGRCV_REQUEST dgrcvr, dgrcvr_tmp;

	DbgPrint("SCTPCancelReceiveDatagram: enter\n");

	SOCK_LOCK(so);
	/* Find out requests for a canceling IRP. */
	STAILQ_FOREACH_SAFE(dgrcvr, &so->so_dgrcv_reqs, dgrcv_entry, dgrcvr_tmp) {
		if (dgrcvr->dgrcv_context != context) {
			continue;
		}
		STAILQ_REMOVE(&so->so_dgrcv_reqs, dgrcvr, sctp_dgrcv_request, dgrcv_entry);
		break;
	}
	SOCK_UNLOCK(so);

	DbgPrint("SCTPCancelReceiveDatagram: dgrcvr=%p\n", dgrcvr);
	if (dgrcvr != NULL) {
		(*(dgrcvr->dgrcv_complete))(dgrcvr->dgrcv_context, STATUS_CANCELLED, 0);
		ExFreePool(dgrcvr);
	}
	DbgPrint("SCTPCancelReceiveDatagram: leave\n");
}


NTSTATUS
SCTPDispatchSendDatagram(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	KIRQL oldIrql;
	PSCTP_DRIVER_CONTEXT sctpContext;
	PTDI_REQUEST_KERNEL_SENDDG datagramInformation;
	PTDI_CONNECTION_INFORMATION sendDatagramInformation;

	int error = 0;
	struct socket *so = NULL;
	struct sockaddr *addr = NULL;
	struct mbuf *control = NULL;
	struct uio uio;
	PSCTP_DGSND_REQUEST dgsndr = NULL;

	DbgPrint("SCTPDispatchSendDatagram: enter\n");
	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	datagramInformation = (PTDI_REQUEST_KERNEL_SENDDG)&irpSp->Parameters;

	status = SCTPPrepareIrpForCancel(sctpContext, irp, SCTPCancelRequest);
	if (status != STATUS_SUCCESS) {
		/* This IRP canceled. */
		DbgPrint("SCTPDispatchSendDatagram: leave #1\n");
		return status;
	}

	sendDatagramInformation = datagramInformation->SendDatagramInformation;
	if (sendDatagramInformation->RemoteAddressLength > sizeof(TA_ADDRESS)) {
		if (((PTA_ADDRESS)sendDatagramInformation->RemoteAddress)->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ((PTA_ADDRESS)sendDatagramInformation->RemoteAddress)->AddressLength == sizeof(TA_IP_ADDRESS)) {
			error = getsockaddr(&addr, sendDatagramInformation->RemoteAddress, sizeof(struct sockaddr_in));
			if (error < 0) {
				addr = NULL;
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto error;
			}
		}
	}

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_resid = datagramInformation->SendLength;
	uio.uio_rw = UIO_WRITE;

	if (sctpContext->socket->so_options & SO_USECONTROL) {
		control = sctp_get_mbuf_for_msg(CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)),
		    0,
		    M_DONTWAIT,
		    1,
		    MT_SONAME);
		if (control != NULL) {

			uiomove(SCTP_BUF_AT(control, 0), CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)), &uio);
			SCTP_BUF_LEN(control) = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
		}
	}

	dgsndr = ExAllocatePool(NonPagedPool, sizeof(*dgsndr));
	if (dgsndr == NULL) {
		DbgPrint("SCTPDispatchSendDatagram: leave #2\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}
	RtlZeroMemory(dgsndr, sizeof(*dgsndr));

	dgsndr->dgsnd_conninfo = sendDatagramInformation;
	dgsndr->dgsnd_complete = SCTPRequestComplete;
	dgsndr->dgsnd_context = irp;
	dgsndr->dgsnd_buffer = uio.uio_buffer;
	dgsndr->dgsnd_size = uio.uio_resid;
	dgsndr->dgsnd_offset = uio.uio_offset;
	dgsndr->dgsnd_addr = addr;
	dgsndr->dgsnd_control = control;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	status = SCTPSendDatagram(sctpContext->socket, dgsndr);
	if (status != STATUS_PENDING) {
		if (dgsndr->dgsnd_addr != NULL) {
			ExFreePool(dgsndr->dgsnd_addr);
		}
		if (dgsndr->dgsnd_control != NULL) {
			sctp_m_freem(dgsndr->dgsnd_control);
		}
		ExFreePool(dgsndr);
	} else {
		SOCK_LOCK(so);
		STAILQ_INSERT_TAIL(&so->so_dgsnd_reqs, dgsndr, dgsnd_entry);
		SOCK_UNLOCK(so);
	}

	KeLowerIrql(oldIrql);

	return STATUS_PENDING;
error:
	SCTPRequestComplete(irp, status, 0);

	if (addr != NULL) {
		ExFreePool(addr);
	}
	if (control != NULL) {
		sctp_m_freem(control);
	}

	DbgPrint("SCTPDispatchSendDatagram: leave #0\n");
	return STATUS_PENDING;
}

NTSTATUS
SCTPSendDatagram(
    IN PSCTP_SOCKET socket,
    IN PSCTP_DGSND_REQUEST dgsndr)
{
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	struct socket *so = socket;
	struct uio uio;

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = dgsndr->dgsnd_buffer;
	uio.uio_resid = dgsndr->dgsnd_size;
	uio.uio_offset = dgsndr->dgsnd_offset;
	uio.uio_rw = UIO_WRITE;

	error = sctp_sosend(so, dgsndr->dgsnd_addr, &uio, NULL, dgsndr->dgsnd_control, MSG_NBIO, NULL);
	DbgPrint("SCTPDispatchSendDatagram: sctp_sosend=%d\n", error);

	if (error == 0) {
		(*(dgsndr->dgsnd_complete))(dgsndr->dgsnd_context, STATUS_SUCCESS, dgsndr->dgsnd_size);
		status = STATUS_SUCCESS;
	} else if (error == EWOULDBLOCK) {
		status = STATUS_PENDING;
	} else {
		(*(dgsndr->dgsnd_complete))(dgsndr->dgsnd_context, STATUS_INVALID_PARAMETER, 0);
		status = STATUS_INVALID_PARAMETER;
	}

	return status;
}


void
SCTPCancelSendDatagram(
    IN PSCTP_SOCKET socket,
    IN PVOID context)
{
	struct socket *so = socket;
	PSCTP_DGSND_REQUEST dgsndr, dgsndr_tmp;

	DbgPrint("SCTPCancelSendDatagram: enter\n");
	SOCK_LOCK(so);
	STAILQ_FOREACH_SAFE(dgsndr, &so->so_dgsnd_reqs, dgsnd_entry, dgsndr_tmp) {
		if (dgsndr->dgsnd_context != context) {
			continue;
		}
		STAILQ_REMOVE(&so->so_dgsnd_reqs, dgsndr, sctp_dgsnd_request, dgsnd_entry);
		break;
	}
	SOCKBUF_UNLOCK(&so->so_snd);

	DbgPrint("SCTPCancelSendDatagram: dgsndr=%p\n", dgsndr);
	if (dgsndr != NULL) {
		(*(dgsndr->dgsnd_complete))(dgsndr->dgsnd_context, STATUS_CANCELLED, 0);
		ExFreePool(dgsndr);
	}
	DbgPrint("SCTPCancelReceiveDatagram: leave\n");
}


NTSTATUS
SCTPSetEventHandler(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;
	PSCTP_DRIVER_CONTEXT sctpContext;
	PTDI_REQUEST_KERNEL_SET_EVENT event;
	struct socket *so = NULL;

	DbgPrint("SCTPSetEventHandler: enter\n");
	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	event = (PTDI_REQUEST_KERNEL_SET_EVENT)&(irpSp->Parameters);

	so = sctpContext->socket;
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	SOCK_LOCK(so);

	DbgPrint("SCTPSetEventHandler: EventType=%X\n", event->EventType);
	switch (event->EventType) {
	case TDI_EVENT_CONNECT:
		so->so_qlimit = 1;
		so->so_conn = event->EventHandler;
		so->so_connarg = event->EventContext;
		break;
	case TDI_EVENT_DISCONNECT:
		so->so_disconn_event = event->EventHandler;
		so->so_disconn_arg = event->EventContext;
		break;
	case TDI_EVENT_ERROR:
		so->so_error_event = event->EventHandler;
		so->so_error_arg = event->EventContext;
		break;
	case TDI_EVENT_RECEIVE:
		so->so_rcv_event = event->EventHandler;
		so->so_rcv_arg = event->EventContext;
		break;
	case TDI_EVENT_RECEIVE_DATAGRAM:
		so->so_rcvdg = event->EventHandler;
		so->so_rcvdgarg = event->EventContext;
		status = STATUS_SUCCESS;
		break;
	case TDI_EVENT_SEND_POSSIBLE:
		so->so_sndnotify_event = event->EventHandler;
		so->so_sndnotify_arg = event->EventContext;
		break;
	case TDI_EVENT_CHAINED_RECEIVE:
	default:
		status = TDI_BAD_EVENT_TYPE;
		break;
	}

	SOCK_UNLOCK(so);
	KeLowerIrql(oldIrql);

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

	DbgPrint("SCTPSetEventHandler: leave\n");
	return status;
}

NTSTATUS
SCTPQueryInformation(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	TDI_REQUEST request;
	PSCTP_DRIVER_CONTEXT sctpContext;
	PTDI_REQUEST_KERNEL_QUERY_INFORMATION queryInformation;
	PMDL mdl;
	ULONG receiveLength = 0;
	ULONG receivedLength = 0;

	struct socket *so = NULL;
	union {
		TDI_CONNECTION_INFO connInfo;
		TDI_ADDRESS_INFO addrInfo;
		TDI_PROVIDER_INFO providerInfo;
		TDI_PROVIDER_STATISTICS providerStats;
		TDI_DATAGRAM_INFO dgInfo;
		TDI_MAX_DATAGRAM_INFO dgMaxInfo;
		UCHAR raw[sizeof(TDI_ADDRESS_INFO)- sizeof(TRANSPORT_ADDRESS) + sizeof(TA_IP6_ADDRESS)];
	} info;
	ULONG infoLength = 0;
	ULONG tAddrLength = 0;
	struct uio uio;

	DbgPrint("SCTPQueryInformation: enter\n");

	sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
	queryInformation = (PTDI_REQUEST_KERNEL_QUERY_INFORMATION)&(irpSp->Parameters);

	DbgPrint("SCTPQueryInformation: QueryType=%X\n", queryInformation->QueryType);

	switch (queryInformation->QueryType) {
	case TDI_QUERY_BROADCAST_ADDRESS:
	case TDI_QUERY_PROVIDER_INFO:
	case TDI_QUERY_PROVIDER_STATISTICS:
		if (((int)irpSp->FileObject->FsContext2) != TDI_CONTROL_CHANNEL_FILE) {
			status = STATUS_INVALID_PARAMETER;
		}
		break;
	case TDI_QUERY_ADDRESS_INFO:
		if (((int)irpSp->FileObject->FsContext2) == TDI_CONNECTION_FILE) {
			so = sctpContext->socket;
		} else if (((int)irpSp->FileObject->FsContext2) == TDI_TRANSPORT_ADDRESS_FILE) {
			so = sctpContext->socket;
		} else {
			status = STATUS_INVALID_PARAMETER;
		}
		break;
	case TDI_QUERY_CONNECTION_INFO:
		if (((int)irpSp->FileObject->FsContext2) == TDI_CONNECTION_FILE) {
			so = sctpContext->socket;
		} else {
			status = STATUS_INVALID_PARAMETER;
		}
		break;
	default:
		status = STATUS_NOT_IMPLEMENTED;
	}

	if (status != STATUS_SUCCESS) {
		irp->IoStatus.Status = status;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
		DbgPrint("SCTPQueryInformation: leave #1\n");
		return status;
	}

	mdl = irp->MdlAddress;
	while (mdl != NULL) {
		receiveLength += MmGetMdlByteCount(mdl);
		mdl = mdl->Next;
	}

	status = SCTPPrepareIrpForCancel(sctpContext, irp, NULL);
	if (status != STATUS_SUCCESS) {
		/* This IRP canceled. */
		DbgPrint("SCTPQueryInformation: leave #2\n");
		return status;
	}

	DbgPrint("TdiQueryInformation: QueryType=%X,receiveLength=%d\n", queryInformation->QueryType, receiveLength);

	RtlZeroMemory(&info, sizeof(info));

	switch (queryInformation->QueryType) {
	case TDI_QUERY_BROADCAST_ADDRESS:
		status = TDI_INVALID_QUERY;
		break;
	case TDI_QUERY_PROVIDER_INFO:
		info.providerInfo.Version = 0x0200;
		info.providerInfo.MaxSendSize = 0;
		info.providerInfo.MaxConnectionUserData = 0;
		info.providerInfo.MaxDatagramSize = 0;
		info.providerInfo.ServiceFlags =
		    TDI_SERVICE_CONNECTION_MODE |
		    TDI_SERVICE_ORDERLY_RELEASE |
		    TDI_SERVICE_ERROR_FREE_DELIVERY |
		    TDI_SERVICE_CONNECTIONLESS_MODE |
		    TDI_SERVICE_INTERNAL_BUFFERING |
#if 0
		    TDI_SERVICE_DELAYED_ACCEPTANCE |
#endif
		    TDI_SERVICE_NO_ZERO_LENGTH;
		info.providerInfo.MinimumLookaheadData = 1;
		info.providerInfo.MaximumLookaheadData = 0xffff;
		info.providerInfo.NumberOfResources = 0;
		info.providerInfo.StartTime = StartTime;
		infoLength = sizeof(TDI_PROVIDER_INFO);
		break;
	case TDI_QUERY_ADDRESS_INFO:
		info.addrInfo.ActivityCount = 1;
		{
			struct sockaddr_in sin;

			RtlZeroMemory(&sin, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_len = sizeof(sin);

			tAddrLength = sizeof(TA_IP6_ADDRESS);
			convertsockaddr(&info.addrInfo.Address, &tAddrLength, (struct sockaddr *)&sin);
		}
		infoLength = sizeof(TDI_ADDRESS_INFO)- sizeof(TRANSPORT_ADDRESS) + tAddrLength;
		break;
	default:
		status = TDI_INVALID_QUERY;
		break;
	}

	if (status != STATUS_SUCCESS) {
		DbgPrint("TdiQueryInformation: leave #1\n");
		goto done;
	}

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_resid = receiveLength;
	uio.uio_rw = UIO_WRITE;

	uiomove(&info, infoLength, &uio);
	if ((ULONG)uio.uio_offset < infoLength) {
		status = TDI_BUFFER_OVERFLOW;
		DbgPrint("TdiQueryInformation: leave #2\n");
		goto done;
	} else {
		status = STATUS_SUCCESS;
		receivedLength = (ULONG)uio.uio_offset;
		DbgPrint("TdiQueryInformation: leave #3\n");
		goto done;
	}
done:
	SCTPRequestComplete(irp, status, receivedLength);

	DbgPrint("SCTPQueryInformation: leave\n");
	return STATUS_PENDING;
}


struct socket *
soalloc(void)
{
	struct socket *so = NULL;
	
	so = ExAllocatePool(NonPagedPool, sizeof(*so)); /* XXX */
	if (so == NULL) {
		return NULL;
	}

	RtlZeroMemory(so, sizeof(*so));
#if 0
	STAILQ_INIT(&so->so_assoc_conns);
	STAILQ_INIT(&so->so_conn_reqs);
#endif
	STAILQ_INIT(&so->so_dgrcv_reqs);
	STAILQ_INIT(&so->so_dgsnd_reqs);
	TAILQ_INIT(&so->so_incomp);
	TAILQ_INIT(&so->so_comp);
	TAILQ_INIT(&so->so_decomp);
	SOCKBUF_LOCK_INIT(&so->so_rcv);
	SOCKBUF_LOCK_INIT(&so->so_snd);

	return so;
}

void
sofree(
    struct socket *so)
{
	int error = 0;
	struct sctp_snd_request *sndr = NULL;
	struct socket *head, *so1;

	DbgPrint("sofree: enter\n");

	head = so->so_head;
	if (head != NULL) {
		DbgPrint("sofree: #1\n");
		SOCK_LOCK(head);
		if (so->so_qstate & SQ_INCOMP) {
			DbgPrint("sofree: #1.1\n");
			TAILQ_REMOVE(&head->so_incomp, so, so_list);
			head->so_incqlen--;
			so->so_qstate &= ~SQ_INCOMP;
		}

		if (so->so_qstate & SQ_DECOMP) {
			DbgPrint("sofree: #1.2\n");
			TAILQ_REMOVE(&head->so_decomp, so, so_list);
			head->so_deqlen--;
			so->so_qstate &= ~SQ_DECOMP;
		}
		SOCK_UNLOCK(head);
	}

	while (!TAILQ_EMPTY(&so->so_incomp)) {
		DbgPrint("sofree: #2\n");
		so1 = TAILQ_FIRST(&so->so_incomp);
		TAILQ_REMOVE(&so->so_incomp, so1, so_list);
		error = soabort(so1);
		sofree(so1);
	}

	while (!TAILQ_EMPTY(&so->so_decomp)) {
		DbgPrint("sofree: #3\n");
		so1 = TAILQ_FIRST(&so->so_decomp);
		TAILQ_REMOVE(&so->so_decomp, so1, so_list);
		error = soabort(so1);
		sofree(so1);
	}

	SOCKBUF_LOCK(&so->so_snd);

	SOCKBUF_LOCK_DESTROY(&so->so_rcv);
	SOCKBUF_LOCK_DESTROY(&so->so_snd);

	ExFreePool(so);
}

struct socket *
sonewconn(
    struct socket *head,
    int connstatus)
{
	struct socket *so = NULL;
	int error = 0;

	DbgPrint("sonewconn: enter\n");
	so = soalloc();
	if (so == NULL) {
		DbgPrint("sonewconn: leave #1\n");
		return NULL;
	}
	so->so_head = head;
	so->so_type = head->so_type;

	so->so_rcv.sb_lowat = head->so_rcv.sb_lowat;
	so->so_snd.sb_lowat = head->so_snd.sb_lowat;
	so->so_rcv.sb_timeo = head->so_rcv.sb_timeo;
	so->so_snd.sb_timeo = head->so_snd.sb_timeo;

	error = sctp_attach(so, IPPROTO_SCTP, NULL);

	so->so_qstate |= SQ_INCOMP;

	SOCK_LOCK(head);
	TAILQ_INSERT_TAIL(&head->so_incomp, so, so_list);
	head->so_incqlen++;
	SOCK_UNLOCK(head);

	DbgPrint("sonewconn: leave #2\n");
	return so;
}

void
soisconnected(
    struct socket *so)
{
	NTSTATUS status;
	int error = 0;
	struct socket *head = NULL;
	struct sctp_conn_request *connr = NULL;
	PIRP irp = NULL;
	PIO_STACK_LOCATION irpSp = NULL;
	PSCTP_DRIVER_CONTEXT sctpContext = NULL;

	struct sctp_inpcb *inp = NULL;
	struct sctp_tcb *stcb = NULL;
	struct sockaddr *addr = NULL;
        PTRANSPORT_ADDRESS tAddr = NULL;
        ULONG tAddrLength = 0;
        union {
                TA_IP_ADDRESS ip;
                TA_IP6_ADDRESS ip6;
        } taAddr;
	CONNECTION_CONTEXT connContext = NULL;
	PTDI_REQUEST_KERNEL_ACCEPT acceptRequest;
	PTDI_REQUEST_KERNEL_CONNECT connectRequest;
	PTDI_CONNECTION_INFORMATION requestInformation, returnInformation;

	DbgPrint("soisconnected: enter\n");
	SOCK_LOCK(so);
	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING|SS_ISCONFIRMING);
	so->so_state |= SS_ISCONNECTED;
	head = so->so_head;

	if (head != NULL && (so->so_qstate & SQ_INCOMP) != 0) {
		DbgPrint("soisconnected: #2\n");
		SOCK_LOCK(head);
		TAILQ_REMOVE(&head->so_incomp, so, so_list);
		head->so_incqlen--;
		so->so_qstate &= ~SQ_INCOMP;

		if (head->so_conn != NULL) {
			DbgPrint("soisconnected: #2.1\n");

			error = sctp_accept(so, &addr);
			if (error != 0 || addr == NULL) {
				DbgPrint("soisconnected: sctp_accept=%d\n", error);
				TAILQ_INSERT_TAIL(&head->so_decomp, so, so_list);
				head->so_deqlen++;
				so->so_qstate |= SQ_DECOMP;
				SOCK_UNLOCK(head);
				SOCK_UNLOCK(so);
				return;
			}

			tAddr = (PTRANSPORT_ADDRESS)&taAddr;
			tAddrLength = sizeof(taAddr);
			if (convertsockaddr(tAddr, &tAddrLength, addr) < 0) {
				tAddr = NULL;
				tAddrLength = 0;
			}

			status = (*(head->so_conn))(head->so_connarg,
			    tAddrLength,
			    tAddr,
			    0,
			    NULL,
			    0,
			    NULL,
			    &connContext,
			    &irp
			    );

			DbgPrint("soisconnected: status=%X\n", status);
			if (status == STATUS_MORE_PROCESSING_REQUIRED) {
				DbgPrint("soisconnected: #2.1.2.1\n");

				irpSp = IoGetCurrentIrpStackLocation(irp);
				acceptRequest = (PTDI_REQUEST_KERNEL_ACCEPT)&(irpSp->Parameters);
				requestInformation = acceptRequest->RequestConnectionInformation;
				returnInformation = acceptRequest->ReturnConnectionInformation;
				sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
				so->so_head = NULL;

				so->so_rcv_event = head->so_rcv_event;
				so->so_rcv_arg = head->so_rcv_arg;
				so->so_disconn_event = head->so_disconn_event;
				so->so_disconn_arg = head->so_disconn_arg;

				so->so_conn_ctx = sctpContext->connCtx;

				sctpContext->socket = so;
				sctpContext->dupSocket = TRUE;

				if (returnInformation != NULL &&
				    (ULONG)returnInformation->RemoteAddressLength >= tAddrLength) {
					RtlCopyMemory(returnInformation->RemoteAddress, tAddr, tAddrLength);
					returnInformation->RemoteAddressLength = tAddrLength;
				}

				irp->IoStatus.Information = 0;
				irp->IoStatus.Status = STATUS_SUCCESS;
				IoCompleteRequest(irp, 2);
			} else {
				DbgPrint("soisconnected: #2.1.2.2\n");
				TAILQ_INSERT_TAIL(&head->so_decomp, so, so_list);
				head->so_deqlen++;
				so->so_qstate |= SQ_DECOMP;
			}
			if (addr != NULL) {
				ExFreePool(addr);
			}
			SOCK_UNLOCK(head);
		} else {
#if 0
			cnr = STAILQ_FIRST(&head->so_conn_reqs);
			if (cnr != NULL) {
				DbgPrint("soisconnected: #2.2.1\n");
				SOCK_UNLOCK(head);
				STAILQ_REMOVE_HEAD(&head->so_conn_reqs, cnr_entry);
				irp = (PIRP)cnr->cnr_context;
				irpSp = IoGetCurrentIrpStackLocation(irp);
				sctpContext = (PSCTP_DRIVER_CONTEXT)irpSp->FileObject->FsContext;
				sctpContext->socket = so;
				(*(cnr->cnr_complete))(irp, STATUS_SUCCESS, 0);
			} else {
				DbgPrint("soisconnected: #2.2.2\n");
				SOCK_UNLOCK(head);
				TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
				head->so_qlen++;
				so->so_qstate |= SQ_COMP;
			}
#endif
		}
	} else if (so->so_conn_req != NULL) {
		connr = so->so_conn_req;
		returnInformation = connr->conn_conninfo;

		if (returnInformation != NULL && returnInformation->RemoteAddressLength > sizeof(TRANSPORT_ADDRESS)) {
			inp = (struct sctp_inpcb *)so->so_pcb;
			if (inp != NULL) {
				SCTP_INP_RLOCK(inp);
				stcb = LIST_FIRST(&inp->sctp_asoc_list);
				if (stcb != NULL) {
					SCTP_TCB_LOCK(stcb);
					tAddr = (PTRANSPORT_ADDRESS)returnInformation->RemoteAddress;
					tAddrLength = returnInformation->RemoteAddressLength;
					if (convertsockaddr(tAddr, &tAddrLength,
						(struct sockaddr *)&stcb->asoc.primary_destination->ro._l_addr) < 0) {
						tAddr = NULL;
						tAddrLength = 0;
					}
					SCTP_TCB_UNLOCK(stcb);
				}
				SCTP_INP_RUNLOCK(inp);
			}
		}

		if (returnInformation != NULL && tAddr != NULL) {
			returnInformation->RemoteAddressLength = tAddrLength;
		} else if (returnInformation != NULL) {
			returnInformation->RemoteAddress = NULL;
			returnInformation->RemoteAddressLength = 0;
		}

		(*(connr->conn_complete))(connr->conn_context, STATUS_SUCCESS, 0);
		ExFreePool(connr);
		so->so_conn_req = NULL;
	}
	SOCK_UNLOCK(so);
	DbgPrint("soisconnected: leave\n");
}

void
sorwakeup_locked(
    struct socket *so)
{
	struct sctp_inpcb *inp = NULL;

	DbgPrint("sorwakeup_locked: enter\n");
	switch (so->so_type) {
	case SOCK_STREAM:
		inp = (struct sctp_inpcb *)so->so_pcb;
		if (inp != NULL &&
		    ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) != 0 ||
		     (inp->sctp_flags & SCTP_PCB_FLAGS_WAS_CONNECTED) != 0
		    )){
			SCTPDeliverData(so);
		} else {
		}
		break;
	case SOCK_DGRAM:
	case SOCK_SEQPACKET:
		SCTPDeliverDatagram(so);
		break;
	}
	SOCKBUF_UNLOCK(&so->so_rcv);
}

void
SCTPDeliverData(
    struct socket *so)
{
#if 0
	NTSTATUS status = STATUS_SUCCESS;
	PSCTP_DGRCV_REQUEST dgrcvr = NULL, dgrcvr_temp = NULL;

	STAILQ_FOREACH_SAFE(dgrcvr, &so->so_dgrcv_reqs, dgrcv_entry, dgrcv_temp) {
		status = SCTPReceiveData(so, dgrcvr);
		if (status != STATUS_PENDING) {
			STAILQ_REMOVE(&so->so_dgrcv_reqs, dgrcvr, sctp_dgrcv_request, dgrcv_entry);
			ExFreePool(dgrcvr);
		}
		if (status != STATUS_SUCCESS) {
			break;
		}
	}
#endif
	while (so->so_rcv.sb_cc > 0 && so->so_rcv_event != NULL) {
		DbgPrint("SCTPDeliverData: #1\n");
		SCTPDeliverDataEvent(so);
	}

	DbgPrint("SCTPDeliverData: so_error=%d,so_rcv.sb_cc=%d\n", so->so_error, so->so_rcv.sb_cc);
	if (so->so_error == ECONNREFUSED || so->so_error == ECONNRESET) {
		SCTPNotifyDisconnect(so);
	}
}

void
SCTPDeliverDataEvent(
    struct socket *so)
{
	NTSTATUS status;
	NTSTATUS rcvStatus;
	int error = 0;
	int flags;
	struct uio uio;
	struct mbuf *control = NULL;

	struct mbuf *m = NULL, *n = NULL;
	unsigned int bytesTaken, offset;
	int length;

	PIRP irp;
	PIO_STACK_LOCATION irpSp;
	PTDI_REQUEST_KERNEL_RECEIVE information;

	DbgPrint("SCTPDeliverDataEvent: enter\n");

	flags = MSG_DONTWAIT;
	error = sctp_soreceive(so, NULL, NULL, &m, &control, &flags);

	if (error != 0 || m == NULL) {
		DbgPrint("SCTPDeliverDataEvent: leave #1\n");
		goto done;
	}

	length = 0;
	n = m;
	while (n != NULL) {
		length += SCTP_BUF_LEN(n);
		n = SCTP_BUF_NEXT(n);
	}
	DbgPrint("SCTPProcessReceiveEvent: length=%d, LEN=%d\n", length, SCTP_BUF_LEN(m));

	DbgPrint("so->so_conn_ctx=%p\n", so->so_conn_ctx);
	if (so->so_options & SO_USECONTROL) {
		rcvStatus = (*(so->so_rcv_event))(
		    so->so_rcv_arg,
		    so->so_conn_ctx,
		    TDI_RECEIVE_NORMAL | TDI_RECEIVE_COPY_LOOKAHEAD,
		    SCTP_BUF_LEN(control),
		    SCTP_BUF_LEN(control) + length,
		    &bytesTaken,
		    SCTP_BUF_AT(control, 0),
		    &irp);
	} else {
		rcvStatus = (*(so->so_rcv_event))(
		    so->so_rcv_arg,
		    so->so_conn_ctx,
		    TDI_RECEIVE_NORMAL |
		    ((SCTP_BUF_LEN(m) == length) ? TDI_RECEIVE_ENTIRE_MESSAGE : TDI_RECEIVE_COPY_LOOKAHEAD),
		    SCTP_BUF_LEN(m),
		    length,
		    &bytesTaken,
		    SCTP_BUF_AT(m, 0),
		    &irp);
	}

	DbgPrint("SCTPProcessReceiveEvent: rcvStatus=%X,bytesTaken=%d\n", rcvStatus, bytesTaken);
	if (rcvStatus == STATUS_MORE_PROCESSING_REQUIRED) {
		irpSp = IoGetCurrentIrpStackLocation(irp);
		information = (PTDI_REQUEST_KERNEL_RECEIVE)&irpSp->Parameters;

		RtlZeroMemory(&uio, sizeof(uio));
		uio.uio_buffer = irp->MdlAddress;
		uio.uio_resid = information->ReceiveLength;
		uio.uio_rw = UIO_READ;
		offset = bytesTaken;

		if (so->so_options & SO_USECONTROL) {
			if (offset < (ULONG)SCTP_BUF_LEN(control)) {
				uiomove(SCTP_BUF_AT(control, offset), SCTP_BUF_LEN(control) - offset, &uio);
			}
			offset = 0;
		}

		n = m;
		do {
			uiomove(SCTP_BUF_AT(n, offset), SCTP_BUF_LEN(n) - offset, &uio);
			offset = 0;
			n = SCTP_BUF_NEXT(n);
		} while (n != NULL);

		irp->IoStatus.Information = length - bytesTaken;
		if (so->so_options & SO_USECONTROL) {
			irp->IoStatus.Information += SCTP_BUF_LEN(control);
		}
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, 2);
	}
done:
	if (m != NULL) {
		sctp_m_freem(m);
	}
	if (control != NULL) {
		sctp_m_freem(control);
	}
}

void
SCTPNotifyDisconnect(
    struct socket *so)
{
	PSCTP_CONN_REQUEST connr = NULL;
	PSCTP_SND_REQUEST sndr = NULL;
	NTSTATUS disconnStatus;

	DbgPrint("SCTPNotifyDisconnect: enter\n");

	if (so->so_conn_req != NULL) {
		DbgPrint("SCTPNotifyDisconnect: #1\n");
		connr = so->so_conn_req;
		(*(connr->conn_complete))(connr->conn_context, TDI_CONN_REFUSED, 0);
		ExFreePool(connr);
		so->so_conn_req = NULL;
	}

	if (so->so_disconn_req != NULL) {
		DbgPrint("SCTPNotifyDisconnect: #2.1\n");
		connr = so->so_disconn_req;
		(*(connr->conn_complete))(connr->conn_context, STATUS_SUCCESS, 0);
		ExFreePool(connr);
		so->so_disconn_req = NULL;
	} else if (so->so_disconn_event != NULL) {
		DbgPrint("SCTPNotifyDisconnect: #2.2\n");
		disconnStatus = (*(so->so_disconn_event))(
		    so->so_disconn_arg,
		    so->so_conn_ctx,
		    0,
		    NULL,
		    0,
		    NULL,
		    so->so_error == ECONNREFUSED ? TDI_DISCONNECT_RELEASE : TDI_DISCONNECT_ABORT);
		DbgPrint("SCTPNotifyDisconnect: disconnStatus=%X\n", disconnStatus);
	}

}

void
SCTPDeliverDatagram(
    struct socket *so)
{
	NTSTATUS status = STATUS_SUCCESS;
	PSCTP_DGRCV_REQUEST dgrcvr = NULL;
	DbgPrint("SCTPDeliverDatagram: enter\n");

	while ((!STAILQ_EMPTY(&so->so_dgrcv_reqs)) && so->so_rcv.sb_cc > 0) {
		DbgPrint("SCTPDeliverDatagram: #1\n");
		dgrcvr = STAILQ_FIRST(&so->so_dgrcv_reqs);

		status = SCTPReceiveDatagram(so, dgrcvr);
		if (status != STATUS_PENDING) {
			STAILQ_REMOVE_HEAD(&so->so_dgrcv_reqs, dgrcv_entry);
			ExFreePool(dgrcvr);
		}
		if (status != STATUS_SUCCESS) {
			break;
		}
	}

	while (so->so_rcv.sb_cc > 0 && so->so_rcvdg != NULL) {
		DbgPrint("SCTPDeliverDatagram: #2-1\n");
		SCTPDeliverDatagramEvent(so);
	}
	DbgPrint("SCTPDeliverDatagram: leave\n");
}

void
SCTPDeliverDatagramEvent(
    struct socket *so)
{
	NTSTATUS status;
	int error = 0;
	int flags;
	struct uio uio;
	struct sockaddr *from = NULL;
	struct mbuf *control = NULL;
	struct wsacmsghdr *msghdr = NULL;

	struct mbuf *m = NULL, *n = NULL;
	TDI_STATUS rcvdgStatus;
	unsigned int bytesTaken, offset;
	int length;

	PTRANSPORT_ADDRESS tAddr = NULL;
	ULONG tAddrLength = 0;
	union {
		TA_IP_ADDRESS ip;
		TA_IP6_ADDRESS ip6;
	} taAddr;

	PIRP irp;
	PIO_STACK_LOCATION irpSp;
	PTDI_REQUEST_KERNEL_RECEIVEDG datagramInformation;
	PTDI_CONNECTION_INFORMATION returnDatagramInformation;

	flags = MSG_DONTWAIT;
	error = sctp_soreceive(so, &from, NULL, &m, &control, &flags);

	if (error != 0 || m == NULL) {
		DbgPrint("SCTPDeliverDatagram: leave #2-1-1\n");
		goto done;
	}

	length = 0;
	n = m;
	while (n != NULL) {
		length += SCTP_BUF_LEN(n);
		n = SCTP_BUF_NEXT(n);
	}
	DbgPrint("SCTPDeliverDatagram: length=%d, LEN=%d\n", length, SCTP_BUF_LEN(m));

	if (from != NULL) {
		tAddr = (PTRANSPORT_ADDRESS)&taAddr;
		tAddrLength = sizeof(taAddr);
		if (convertsockaddr(tAddr, &tAddrLength, from) < 0) {
			tAddr = NULL;
			tAddrLength = 0;
		}
	}

	if (so->so_options & SO_USECONTROL) {
		rcvdgStatus = (*(so->so_rcvdg))(
		    so->so_rcvdgarg,
		    tAddrLength,
		    tAddr,
		    0,
		    NULL,
		    TDI_RECEIVE_COPY_LOOKAHEAD,
		    SCTP_BUF_LEN(control),
		    SCTP_BUF_LEN(control) + length,
		    &bytesTaken,
		    SCTP_BUF_AT(control, 0),
		    &irp);
	} else {
		rcvdgStatus = (*(so->so_rcvdg))(
		    so->so_rcvdgarg,
		    tAddrLength,
		    tAddr,
		    0,
		    NULL,
		    ((length > SCTP_BUF_LEN(m)) ? TDI_RECEIVE_COPY_LOOKAHEAD : TDI_RECEIVE_ENTIRE_MESSAGE),
		    SCTP_BUF_LEN(m),
		    length,
		    &bytesTaken,
		    SCTP_BUF_AT(m, 0),
		    &irp);
	}

	DbgPrint("SCTPDeliverDatagram: rcvdgStatus=%X,bytesTaken=%d\n", rcvdgStatus, bytesTaken);
	if (rcvdgStatus == STATUS_MORE_PROCESSING_REQUIRED) {
		DbgPrint("SCTPDeliverDatagram: #2-1-1-1\n");

		irpSp = IoGetCurrentIrpStackLocation(irp);
		datagramInformation = (PTDI_REQUEST_KERNEL_RECEIVEDG)&irpSp->Parameters;
		returnDatagramInformation = datagramInformation->ReturnDatagramInformation;

		if (returnDatagramInformation != NULL) {
			if (tAddr != NULL &&
			    (ULONG)returnDatagramInformation->RemoteAddressLength >= tAddrLength) {
				RtlCopyMemory(returnDatagramInformation->RemoteAddress,
				    tAddr, tAddrLength);
				returnDatagramInformation->RemoteAddressLength =
				    ((PTA_ADDRESS)&tAddr->Address[0])->AddressLength;
			} else {
				returnDatagramInformation->RemoteAddress = NULL;
				returnDatagramInformation->RemoteAddressLength = 0;
			}

#if 0
			if (control != NULL &&
			    returnDatagramInformation->OptionsLength >= SCTP_BUF_LEN(control)) {
				RtlCopyMemory(returnDatagramInformation->Options,
				    SCTP_BUF_AT(control, 0), SCTP_BUF_LEN(control));
			} else {
				returnDatagramInformation->Options = NULL;
				returnDatagramInformation->OptionsLength = 0;
			}
#endif
		}

		RtlZeroMemory(&uio, sizeof(uio));
		uio.uio_buffer = irp->MdlAddress;
		uio.uio_resid = datagramInformation->ReceiveLength;
		uio.uio_rw = UIO_READ;
		offset = bytesTaken;

		if (so->so_options & SO_USECONTROL) {
			if (offset < (ULONG)SCTP_BUF_LEN(control)) {
				uiomove(SCTP_BUF_AT(control, offset), SCTP_BUF_LEN(control) - offset, &uio);
			}
			offset = 0;
		}

		n = m;
		do {
			uiomove(SCTP_BUF_AT(n, offset), SCTP_BUF_LEN(n) - offset, &uio);
			offset = 0;
			n = SCTP_BUF_NEXT(n);
		} while (n != NULL);

		irp->IoStatus.Information = length - bytesTaken;
		if (so->so_options & SO_USECONTROL) {
			irp->IoStatus.Information += SCTP_BUF_LEN(control);
		}
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, 2);
	}

done:
	if (from != NULL) {
		ExFreePool(from);
	}
	if (control != NULL) {
		sctp_m_freem(control);
	}
}

int
soabort(
    struct socket *so)
{
	int error = 0;
	DbgPrint("soabort: enter\n");

	error = sctp_abort(so);

	SOCK_LOCK(so);
	so->so_error= ECONNRESET;
	SCTPNotifyDisconnect(so);
	SOCK_UNLOCK(so);
	return 0;
}


void
sowwakeup_locked(
    struct socket *so)
{
	struct sctp_inpcb *inp = NULL;

	DbgPrint("sowwakeup_locked: enter\n");
	switch (so->so_type) {
	case SOCK_STREAM:
		inp = (struct sctp_inpcb *)so->so_pcb;
		if (inp != NULL &&
		    ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) != 0)) {
			SCTPNotifySend(so);
		}
		break;
	case SOCK_DGRAM:
		SCTPNotifySendDatagram(so);
		break;
	}

	SOCKBUF_UNLOCK(&so->so_snd);
	DbgPrint("sowwakeup_locked: leave\n");
}

void
SCTPNotifySend(
    struct socket *so)
{
	NTSTATUS status = STATUS_SUCCESS;
	PSCTP_SND_REQUEST sndr = NULL;
	struct uio uio;
	int error = 0;

	DbgPrint("SCTPNotifySend: enter\n");

	while ((!STAILQ_EMPTY(&so->so_snd_reqs)) && so->so_snd.sb_mbmax - so->so_snd.sb_cc > 0) {
		sndr = STAILQ_FIRST(&so->so_snd_reqs);

		RtlZeroMemory(&uio, sizeof(uio));
		uio.uio_buffer = sndr->snd_buffer;
		uio.uio_resid = sndr->snd_size;
		uio.uio_rw = UIO_WRITE;

		error = sctp_sosend(so, NULL, &uio, NULL, NULL, MSG_NBIO, NULL);
		if (error != EWOULDBLOCK) {
			if (error == 0) {
				(*(sndr->snd_complete))(sndr->snd_context, STATUS_SUCCESS, sndr->snd_size);
			} else {
				(*(sndr->snd_complete))(sndr->snd_context, STATUS_INVALID_PARAMETER, 0);
			}
			STAILQ_REMOVE(&so->so_snd_reqs, sndr, sctp_snd_request, snd_entry);
			ExFreePool(sndr);
		} else {
			break;
		}
	}

	SOCK_LOCK(so);
	if (so->so_sndnotify_event != NULL && so->so_conn_ctx != NULL) {
		DbgPrint("SCTPNotifySend: #1\n");

		status = (*(so->so_sndnotify_event))(so->so_sndnotify_arg,
		    so->so_conn_ctx,
		    so->so_snd.sb_mbmax - so->so_snd.sb_cc);

		DbgPrint("SCTPNotifySend: status=%X\n", status);
	}
	SOCK_UNLOCK(so);

	DbgPrint("SCTPNotifySend: leave\n");
}

void
SCTPNotifySendDatagram(
    struct socket *so)
{
	NTSTATUS status = STATUS_SUCCESS;
	PSCTP_DGSND_REQUEST dgsndr = NULL;

	DbgPrint("SCTPNotifySendDatagram: enter\n");

	while ((!STAILQ_EMPTY(&so->so_dgsnd_reqs)) && so->so_snd.sb_mbmax - so->so_snd.sb_cc > 0) {
		dgsndr = STAILQ_FIRST(&so->so_dgsnd_reqs);

		status = SCTPSendDatagram(so, dgsndr);
		if (status != STATUS_PENDING) {
			STAILQ_REMOVE(&so->so_dgsnd_reqs, dgsndr, sctp_dgsnd_request, dgsnd_entry);
			ExFreePool(dgsndr);
		} else {
			break;
		}
	}

	DbgPrint("SCTPNotifySendDatagram: leave\n");
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

int
convertsockaddr(
    PTRANSPORT_ADDRESS tAddr,
    ULONG *len0,
    struct sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	PTA_ADDRESS taAddr;
	PTA_IP_ADDRESS taIpAddr;
	PTA_IP6_ADDRESS taIp6Addr;
	ULONG len;

	DbgPrint("convertsockaddr: enter\n");
	if (sa == NULL || tAddr == NULL || len0 == NULL) {
		DbgPrint("convertsockaddr: leave #1\n");
		return -1;
	}
	len = *len0;

	if (sa->sa_family == AF_INET &&
	    len >= sizeof(TA_IP_ADDRESS)) {
		DbgPrint("convertsockaddr: #1\n");
		sin = (struct sockaddr_in *)sa;
		taIpAddr = (PTA_IP_ADDRESS)tAddr;
		RtlZeroMemory(taIpAddr, sizeof(TA_IP_ADDRESS));
		taIpAddr->TAAddressCount = 1;
		taIpAddr->Address[0].AddressLength = 14;
		DbgPrint("TDI_ADDRESS_LENGTH_IP=%d\n", TDI_ADDRESS_LENGTH_IP);
		taIpAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
		taIpAddr->Address[0].Address[0].sin_port = sin->sin_port;
		taIpAddr->Address[0].Address[0].in_addr = sin->sin_addr.s_addr;
		*len0 = sizeof(TA_IP_ADDRESS);
	} else if (
	    sa->sa_family == AF_INET6 &&
	    len >= sizeof(TA_IP6_ADDRESS)) {
		DbgPrint("convertsockaddr: #2\n");
		sin6 = (struct sockaddr_in6 *)sa;
		taIp6Addr = (PTA_IP6_ADDRESS)tAddr;
		RtlZeroMemory(taIp6Addr, sizeof(TA_IP6_ADDRESS));
		taIp6Addr->TAAddressCount = 1;
		taIp6Addr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP6;
		taIp6Addr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP6;
		taIp6Addr->Address[0].Address[0].sin6_port = sin6->sin6_port;
		RtlCopyMemory(&taIp6Addr->Address[0].Address[0].sin6_addr,
		    &sin6->sin6_addr, sizeof(struct in6_addr));
		taIp6Addr->Address[0].Address[0].sin6_scope_id = sin6->sin6_scope_id;
		*len0 = sizeof(TA_IP6_ADDRESS);
	} else {
		DbgPrint("convertsockaddr: #3\n");
		DbgPrint("convertsockaddr: leave #3\n");
		return -1;
	}
	DbgPrint("convertsockaddr: *len0=%d\n", *len0);
	DbgPrint("convertsockaddr: leave\n");
	return *len0;
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
