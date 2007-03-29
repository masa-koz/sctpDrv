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
 * $Id: ntdisp.c,v 1.3 2007/03/29 07:40:23 kozuka Exp $
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

int sctp_attach(struct socket *);
int sctp_bind(struct socket *, struct sockaddr *);
int sctp_detach(struct socket *);

NTSTATUS SCTPOpenAddress(PTDI_REQUEST, TRANSPORT_ADDRESS UNALIGNED *, USHORT, BOOLEAN);
NTSTATUS SCTPOpenConnection(PTDI_REQUEST);
NTSTATUS SCTPCleanupAddress(PTID_REQUEST);
NTSTATUS SCTPCleanupConnection(PTID_REQUEST);
void SCTPCleanupComplete(PVOID, NTSTATUS, unsigned int);

extern PDEVICE_OBJECT SctpTcpDeviceObject;
extern PDEVICE_OBJECT SctpUdpDeviceObject;

static FILE_FULL_EA_INFORMATION UNALIGNED *FindEAInfo(PFILE_FULL_EA_INFORMATION, CHAR *, USHORT);

NTSTATUS
SCTPCreate(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;
	PSCTP_CONTEXT sctpContext;
	FILE_FULL_EA_INFORMATION *ea0, *ea;
	TDI_REQUEST request;

	DbgPrint("SCTPCreate:\n");

	irpSp = IoGetCurrentIrpStackLocation(irp);

	RtlZeroMemory(&request, sizeof(request));

	sctpContext = ExAllocatePool(NonPagedPool, sizeof(SCTP_CONTEXT));
	if (sctpContext == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(sctpContext, sizeof(*sctpContext));

	sctpContext->refcount = 1;

	ea0 = (PFILE_FULL_EA_INFORMATION)irp->AssociatedIrp.SystemBuffer;
	if (ea0 == NULL) {
		/* TDI_CONTROL_CHANNEL_FILE */
		sctpContext->Handle.ControlChannel = NULL;
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONTROL_CHANNEL_FILE;
		return STATUS_SUCCESS;
	}

	ea = FindEAInfo(ea0, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH);
	if (ea != NULL) {
		/* TDI_TRANSPORT_ADDRESS_FILE */

		if (deviceObject == SctpTcpDeviceObject) {
			status = SCTPOpenAddress(
			    &request,
			    (TRANSPORT_ADDRESS *)&ea->EaName[ea->EaNameLength + 1],
			    SOCK_STREAM, 
			    ((irpSp->Parameters.Create.ShareAccess & FILE_SHARE_READ) ||
			     (irpSp->Parameters.Create.ShareAccess & FILE_SHARE_WRITE)));
		} else {
			status = SCTPOpenAddress(
			    &request,
			    (TRANSPORT_ADDRESS *)&ea->EaName[ea->EaNameLength + 1],
			    SOCK_SEQPACKET, 
			    ((irpSp->Parameters.Create.ShareAccess & FILE_SHARE_READ) ||
			     (irpSp->Parameters.Create.ShareAccess & FILE_SHARE_WRITE)));
		}

		if (status != STATUS_SUCCESS) {
			ExFreePool(sctpContext);
			DbgPrint("SCTPOpenAddress failed, code=%d\n", status);
			return status;
		}

		sctpContext->Handle.AddressHandle = request.Handle.AddressHandle;
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_TRANSPORT_ADDRESS_FILE;
		return STATUS_SUCCESS;
	}

	ea = FindEAInfo(ea0, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH);
	if (ea != NULL) {
		/* TDI_CONNECTION_FILE */

		status = SCTPOpenConnection(&request);
		if (status != STATUS_SUCCESS) {
			ExFreePool(sctpContext);
			DbgPrint("SCTPOpenConnection failed, code=%d\n", status);
			return status;
		}

		sctpContext->Handle.ConnectionContext = request.Handle.ConnectionContext;
		irpSp->FileObject->FsContext = sctpContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONNECTION_FILE;
		return STATUS_SUCCESS;
	}

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
		status = SCTPCleanupAddress(&request);
	} else if ((int)irpSp->FileObject->FsContext2 == TDI_CONNECTION_FILE) {
		request.Handle.ConnectionContext = sctpContext->Handle.ConnectionContext;
		status = SCTPCleanupConnection(&request);
	} else if ((int)irpSp->FileObject->FsContext2 == TDI_CONTROL_CHANNEL_FILE) {
		status = STATUS_SUCCESS;
	} else {
		IoAcquireCancelSpinLock(&oldIrql);
		sctpContext->cancelIrps = FALSE;
		IoReleaseCancelSpinLock(oldIrql);

		return STATUS_INVALID_PARAMETER;
	}

	if (status != STATUS_PENDING) {
		SCTPCleanupComplete(irp, status, 0);
	} else {
		status = KeWaitForSingleObject(&sctpContext->cleanupEvent, UserRequest, KernelMode, FALSE, NULL);
	}

	return irp->IoStatus.Status;
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
	PIO_STACK_LOCATION irpSp;

	irpSp = IoGetCurrentIrpStackLocation(irp);
	return STATUS_SUCCESS;
}

NTSTATUS
SCTPDispatchDeviceControl(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;

	irpSp = IoGetCurrentIrpStackLocation(irp);

	status = TdiMapUserRequest(deviceObject, irp, irpSp);
	if (status == STATUS_SUCCESS) {
		return SCTPDispatchInternalDeviceControl(deviceObject, irp);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
SCTPDispatch(
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
{
	NTSTATUS status;

	return STATUS_INVALID_DEVICE_REQUEST;
}


NTSTATUS
SCTPOpenAddress(
    PTDI_REQUEST request,
    TRANSPORT_ADDRESS *addr0,
    USHORT type,
    BOOLEAN reuse)
{
	NTSTATUS status;
	struct sockaddr *addr;
	struct socket *so = NULL;
	int error = 0;

	addr = (struct sockaddr *)&addr0->Address;
	so = ExAllocatePool(NonPagedPool, sizeof(*so)); /* XXX */
	RtlZeroMemory(so, sizeof(*so));
	so->so_type = type;

	error = sctp_attach(so);
	if (error != 0) {
		DbgPrint("sctp_attach failed, error=%d\n", error);
		ExFreePool(so);
		return STATUS_INVALID_PARAMETER;
	}

	error = sctp_bind(so, addr);
	if (error != 0) {
		DbgPrint("sctp_bind failed, error=%d\n", error);
		sctp_detach(so);
		ExFreePool(so);
		return STATUS_INVALID_PARAMETER;
	}

	request->Handle.AddressHandle = so;
	return STATUS_SUCCESS;
}

NTSTATUS
SCTPOpenConnection(
    PTDI_REQUEST request)
{
	NTSTATUS status;

	request->Handle.ConnectionContext = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS
SCTPCleanupAddress(
    PTDI_REQUEST request)
{
	return STATUS_SUCCESS;
}

NTSTATUS
SCTPCleanupConnection(
    PTDI_REQUEST request)
{
	return STATUS_SUCCESS;
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

static FILE_FULL_EA_INFORMATION UNALIGNED *
FindEAInfo(
    PFILE_FULL_EA_INFORMATION start,
    CHAR *target,
    USHORT length)
{
	int i;
	FILE_FULL_EA_INFORMATION UNALIGNED *ptr;

	for (ptr = start; ptr->NextEntryOffset != 0; ptr += ptr->NextEntryOffset) {
        	if (ptr->EaNameLength != length) {
			continue;
		}

		if (RtlCompareMemory(ptr->EaName, target, length) == length) {
			return ptr;
		}
        }

	return NULL;
}
