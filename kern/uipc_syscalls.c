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

#include <ndis.h>

#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/poll.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#ifdef SCTP
#include <netinet/sctp.h>
#include <netinet/sctp_peeloff.h>
#endif /* SCTP */

typedef struct socket_context {
	struct socket *socket;
	PVOID protocolInfo;
	ULONG protocolInfoLength;
} SOCKET_CONTEXT, *PSOCKET_CONTEXT;


extern LARGE_INTEGER StartTime;
extern PDEVICE_OBJECT SctpSocketDeviceObject;
#ifdef SCTP
extern PDEVICE_OBJECT SctpTdiTcpDeviceObject, SctpTdiUdpDeviceObject;
#endif

MALLOC_DEFINE(M_IOV, 'km04', "iov", "large iov's");
MALLOC_DEFINE(M_SYSCALL, 'km05', "syscall", "syscall");
MALLOC_DEFINE(M_SOCKET, 'km06', "socket", "socket");
MALLOC_DEFINE(M_TDI, 'km07', "tdi", "tdi");

static
NTSTATUS
LockWsabuf(
    IN OUT PSOCKET_WSABUF lpBuffers,
    IN DWORD dwBufferCount,
    IN LOCK_OPERATION operation,
    OUT struct iovec ** iov0)
{
	NTSTATUS status = STATUS_SUCCESS;
	struct iovec *iov = NULL;
	size_t iovlen = 0;
	PMDL *mdls = NULL;
	int i;

	DebugPrint(DEBUG_KERN_VERBOSE, "LockWsabuf - enter\n");

	if (lpBuffers == NULL || iov0 == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "LockWsabuf - leave#1\n");
		goto error;
	}

	iovlen = (sizeof(struct iovec) + sizeof(PMDL)) * dwBufferCount;
	*iov0 = iov = malloc(iovlen, M_IOV, M_ZERO);
	if (iov == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "LockWsabuf - leave#2\n");
		goto error;
	}

	mdls = (PMDL *)&iov[dwBufferCount];

	for (i = 0; i < dwBufferCount; i++) {
		if (lpBuffers[i].buf != NULL) {
			mdls[i] = IoAllocateMdl(lpBuffers[i].buf, lpBuffers[i].len,
			    FALSE, FALSE, NULL);
			if (mdls[i] != NULL) {
				__try {
					MmProbeAndLockPages(mdls[i], KernelMode, operation);
				} __except (EXCEPTION_EXECUTE_HANDLER) {
					IoFreeMdl(mdls[i]);
					status = GetExceptionCode();
					DebugPrint(DEBUG_KERN_VERBOSE, "LockWsabuf - leave#2\n");
					goto error;
				}
			}
			iov[i].iov_base = MmGetSystemAddressForMdlSafe(mdls[i], NormalPagePriority);
			if (iov[i].iov_base == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				DebugPrint(DEBUG_KERN_VERBOSE, "LockWsabuf - leave#3\n");
				goto error;
			}
			iov[i].iov_len = lpBuffers[i].len;
		} else {
			mdls[i] = NULL;
			iov[i].iov_base = NULL;
			iov[i].iov_len = 0;
			goto error;
		}
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "LockWsabuf - leave\n");
	return status;
error:
	if (mdls != NULL) {
		for (i = 0; i < dwBufferCount; i++) {
			if (mdls[i] != NULL) {
				MmUnlockPages(mdls[i]);
				IoFreeMdl(mdls[i]);
			}
		}
	}
	if (iov != NULL) {
		free(iov, M_IOV);
	}
	if (iov0 != NULL) {
		*iov0 = NULL;
	}
	return status;
}

static
VOID
UnlockWsabuf(
    IN struct iovec *iov,
    IN DWORD dwBufferCount)
{
	PMDL *mdls = NULL;
	int i;

	DebugPrint(DEBUG_KERN_VERBOSE, "UnlockWsabuf - enter\n");

	mdls = (PMDL *)&iov[dwBufferCount];

	for (i = 0; i < dwBufferCount; i++) {
		if (mdls[i] != NULL) {
			MmUnlockPages(mdls[i]);
			IoFreeMdl(mdls[i]);
		}
	}
	free(iov, M_IOV);

	DebugPrint(DEBUG_KERN_VERBOSE, "UnlockWsabuf - leave\n");
}


NTSTATUS
SCTPCreateSocket(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_CONTEXT socketContext = NULL;
	PFILE_FULL_EA_INFORMATION ea0 = NULL, ea = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateSocket - enter\n");

	socketContext = malloc(sizeof(SOCKET_CONTEXT), M_SOCKET, M_ZERO);
	if (socketContext == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateSocket - leave #1\n");
		goto done;
	}

	ea0 = (PFILE_FULL_EA_INFORMATION)irp->AssociatedIrp.SystemBuffer;
	if (ea0 != NULL) {
		ea = FindEAInfo(ea0, ProtocolInfo, sizeof(ProtocolInfo) - 1);
		if (ea == NULL) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateSocket - leave #2\n");
			goto done;
		}
		socketContext->protocolInfo = malloc(ea->EaValueLength, M_SOCKET, M_ZERO);
		if (socketContext->protocolInfo == NULL) {
			free(socketContext, M_SOCKET);
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateSocket - leave #3\n");
			goto done;
		}
		RtlCopyMemory(socketContext->protocolInfo, &ea->EaName[ea->EaNameLength + 1],
		    ea->EaValueLength);
		socketContext->protocolInfoLength = ea->EaValueLength;
	}

	irpSp->FileObject->FsContext = socketContext;
	
	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateSocket - leave\n");
done:
	return status;
}

NTSTATUS
SCTPDispatchOpenRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_OPEN_REQUEST openReq = NULL;
	PSOCKET_CONTEXT socketContext = NULL;
	int error = 0;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchOpenRequest - enter\n");

	openReq = (PSOCKET_OPEN_REQUEST)irp->AssociatedIrp.SystemBuffer;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = socreate(openReq->af, &so, openReq->type, openReq->protocol,
	    NULL, NULL);
	KeLowerIrql(oldIrql);
	if (error == 0) {
		socketContext->socket = so;
	} else {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchOpenRequest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchGetProtocolInfo(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_OPEN_REQUEST openReq = NULL;
	PSOCKET_CONTEXT socketContext = NULL;
	int error = 0;
	PVOID protocolInfo = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetProtocolInfo - enter\n");

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;

	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < socketContext->protocolInfoLength) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetProtocolInfo - leave#1\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (socketContext->protocolInfo != NULL && socketContext->protocolInfoLength > 0) {
		protocolInfo = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		if (protocolInfo == NULL) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetProtocolInfo - leave#2\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlCopyMemory(protocolInfo, socketContext->protocolInfo,
		    socketContext->protocolInfoLength);
	}
	irp->IoStatus.Information = socketContext->protocolInfoLength;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetProtocolInfo - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchBindRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	struct sockaddr *sa;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchBindReqest- enter\n");

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	sa = (struct sockaddr *)irp->AssociatedIrp.SystemBuffer;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = sobind(so, sa, NULL);
	KeLowerIrql(oldIrql);
	if (error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchBindReqest- leave\n");
	return status;
}

NTSTATUS
SCTPDispatchConnectRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	struct sockaddr *sa;
	LARGE_INTEGER timeout;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchConnectReqest- enter\n");

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	sa = (struct sockaddr *)irp->AssociatedIrp.SystemBuffer;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = soconnect(so, sa, NULL);
	SOCK_LOCK(so);
	if ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		if (so->so_timeo > 0) {
			timeout.QuadPart = -10000000 * so->so_timeo;
		}
		SOCK_UNLOCK(so);
		KeLowerIrql(oldIrql);
		status = KeWaitForSingleObject(&so->so_waitEvent, UserRequest,
		    UserMode, FALSE, so->so_timeo > 0 ? &timeout : NULL);
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		SOCK_LOCK(so);
		error = so->so_error;
	}
	SOCK_UNLOCK(so);
	KeLowerIrql(oldIrql);
	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchConnectReqest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchListenRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	int backlog = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchListenReqest- enter\n");

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	backlog = *(int *)irp->AssociatedIrp.SystemBuffer;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = solisten(so, backlog, NULL);
	KeLowerIrql(oldIrql);
	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchListenReqest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchAcceptRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_CONTEXT socketContext = NULL, socketContext1 = NULL;
	PSOCKET_ACCEPT_REQUEST acceptReq = NULL;
	PFILE_OBJECT fileObj = NULL;

	struct socket *head = NULL, *so = NULL;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;
	LARGE_INTEGER timeout;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchAcceptReqest- enter\n");

	acceptReq = (PSOCKET_ACCEPT_REQUEST)irp->AssociatedIrp.SystemBuffer;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	head = socketContext->socket;

	status = ObReferenceObjectByHandle(acceptReq->socket,
	    FILE_ALL_ACCESS,
	    NULL,
	    KernelMode,
	    (PVOID *)&fileObj,
	    NULL);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchAcceptReqest - leave#1\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	ACCEPT_LOCK();

	while (TAILQ_EMPTY(&head->so_comp) && head->so_error == 0) {
		if (head->so_rcv.sb_state & SBS_CANTRCVMORE) {
			head->so_error = ECONNABORTED;
			break;
		}
		ACCEPT_UNLOCK();
		KeLowerIrql(oldIrql);
		status = KeWaitForSingleObject(&head->so_waitEvent, UserRequest,
		    UserMode, FALSE, NULL);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchAcceptReqest - leave#2\n");
			goto done;
		}
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		ACCEPT_LOCK();
	}
	if (head->so_error != 0) {
		error = head->so_error;
		head->so_error = 0;
		ACCEPT_UNLOCK();
		KeLowerIrql(oldIrql);
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchAcceptReqest - leave#3\n");
		goto done;
	}

	so = TAILQ_FIRST(&head->so_comp);
	SOCK_LOCK(so);
	soref(so);

	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	so->so_state |= (head->so_state & SS_NBIO);
	so->so_qstate &= ~SQ_COMP;
	so->so_head = NULL;

	SOCK_UNLOCK(so);
	ACCEPT_UNLOCK();

	error = soaccept(so, &sa);

	KeLowerIrql(oldIrql);

	if (error == 0) {
		socketContext1 = (PSOCKET_CONTEXT)fileObj->FsContext;
		socketContext1->socket = so;
		if (socketContext->protocolInfoLength > 0) {
			socketContext1->protocolInfo = malloc(socketContext->protocolInfoLength, M_SOCKET, M_ZERO);
			if (socketContext1->protocolInfo == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchAcceptReqest - leave#4\n");
				goto done;
			}
			RtlCopyMemory(socketContext1->protocolInfo, socketContext->protocolInfo,
			    socketContext->protocolInfoLength);
			socketContext1->protocolInfoLength = socketContext->protocolInfoLength;
		}

		if (sa != NULL && acceptReq->addr != NULL) {
			switch (sa->sa_family) {
			case AF_INET:
				salen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				salen = sizeof(struct sockaddr_in6);
				break;
			default:
				salen = 0;
			}
			if (acceptReq->addrlen > salen) {
				acceptReq->addrlen = salen;
			}
			copyout(sa, acceptReq->addr, acceptReq->addrlen);
		}
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchAcceptReqest - leave\n");
done:
	if (fileObj != NULL) {
		ObDereferenceObject(fileObj);
	}
	if (sa != NULL) {
		free(sa, M_SONAME);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	return status;
}

#ifdef SCTP
NTSTATUS
SCTPDispatchPeeloffRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_CONTEXT socketContext = NULL, socketContext1 = NULL;
	PSOCKET_PEELOFF_REQUEST peeloffReq = NULL;
	PFILE_OBJECT fileObj = NULL;

	struct socket *head = NULL, *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchPeeloffRequest - enter\n");

	peeloffReq = (PSOCKET_PEELOFF_REQUEST)irp->AssociatedIrp.SystemBuffer;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	head = socketContext->socket;

	status = ObReferenceObjectByHandle(peeloffReq->socket,
	    FILE_ALL_ACCESS,
	    NULL,
	    KernelMode,
	    (PVOID *)&fileObj,
	    NULL);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchPeeloffRequest - leave#1\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = sctp_can_peel_off(head, (sctp_assoc_t)peeloffReq->assoc_id);
	if (error != 0) {
		KeLowerIrql(oldIrql);
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchPeeloffRequest - leave#2\n");
		goto done;
	}

	so = sonewconn(head, SS_ISCONNECTED);
	if (so == NULL) {
		KeLowerIrql(oldIrql);
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchPeeloffRequest - leave#3\n");
		goto done;
	}

	SOCK_LOCK(so);
	soref(so);
	SOCK_UNLOCK(so);

	ACCEPT_LOCK();

	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	so->so_state |= (head->so_state & SS_NBIO);
	so->so_state &= ~SS_NOFDREF;
	so->so_qstate &= ~SQ_COMP;
	so->so_head = NULL;

	ACCEPT_UNLOCK();

        error = sctp_do_peeloff(head, so, (sctp_assoc_t)peeloffReq->assoc_id);

	KeLowerIrql(oldIrql);

	if (error == 0) {
		socketContext1 = (PSOCKET_CONTEXT)fileObj->FsContext;
		socketContext1->socket = so;
		if (socketContext->protocolInfoLength > 0) {
			socketContext1->protocolInfo = malloc(socketContext->protocolInfoLength, M_SOCKET, M_ZERO);
			if (socketContext1->protocolInfo == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchPeeloffRequest - leave#4\n");
				goto done;
			}
			RtlCopyMemory(socketContext1->protocolInfo, socketContext->protocolInfo,
			    socketContext->protocolInfoLength);
			socketContext1->protocolInfoLength = socketContext->protocolInfoLength;
		}
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchPeeloffRequest - leave\n");
done:
	if (fileObj != NULL) {
		ObDereferenceObject(fileObj);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	return status;
}
#endif

typedef struct _SOCKET_SEND_PARAM {
	struct iovec *iov;
	int iovlen;
	int len;
	struct sockaddr *to;
	struct sockaddr_storage to_ss;
	int flags;
	PSOCKET_OVERLAPPED overlapped;
	PMDL overlappedMdl;
} SOCKET_SEND_PARAM, *PSOCKET_SEND_PARAM;

NTSTATUS
SCTPDispatchSendRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SEND_REQUEST sendReq = NULL;
	PSOCKET_SEND_PARAM sendParam = NULL;
	struct uio uio;
	int i;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_SEND_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#1\n");
		goto done;
	}
	sendReq = (PSOCKET_SEND_REQUEST)irp->AssociatedIrp.SystemBuffer;

	sendParam = malloc(sizeof(SOCKET_SEND_PARAM), M_SYSCALL, M_ZERO);
	if (sendParam == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#2\n");
		goto done;
	}

	status = LockWsabuf(sendReq->lpBuffers, sendReq->dwBufferCount, IoReadAccess, &sendParam->iov);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#3\n");
		goto done;
	}
	sendParam->iovlen = sendReq->dwBufferCount;

	for (i = 0; i < sendParam->iovlen; i++) {
		if ((sendParam->len += sendParam->iov[i].iov_len) < 0) {
			error = EINVAL;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#4\n");
			goto done;
		}
	}

	if (sendReq->lpTo != NULL && sendReq->iTolen > 0) {
		if (sendReq->iTolen > sizeof(struct sockaddr_storage)) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#5\n");
			goto done;
		}
		copyin(sendReq->lpTo, &sendParam->to_ss, sendReq->iTolen);
		sendParam->to = (struct sockaddr *)&sendParam->to_ss;
	}

	if (sendReq->lpOverlapped != NULL) {
		sendParam->overlapped = sendReq->lpOverlapped;
		status = LockBuffer(sendReq->lpOverlapped, sizeof(SOCKET_OVERLAPPED), IoModifyAccess,
		    &sendParam->overlappedMdl);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#6\n");
			goto done;
		}
		sendParam->overlapped = MmGetSystemAddressForMdlSafe(sendParam->overlappedMdl, NormalPagePriority);
		if (sendParam->overlapped == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#7\n");
			goto done;
		}
	}


	uio.uio_iov = sendParam->iov;
	uio.uio_iovcnt = sendParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_offset = 0;
	uio.uio_resid = sendParam->len;

	sendParam->flags = sendReq->dwFlags;
	if (sendReq->lpOverlapped != NULL) {
		sendParam->flags |= MSG_DONTWAIT;
	}

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = sosend(so, sendParam->to, &uio, NULL, NULL, sendParam->flags, NULL);
	if (error == EWOULDBLOCK && sendParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_snd);
		so->so_snd.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_snd.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_snd);

		KeLowerIrql(oldIrql);

		(PSOCKET_SEND_PARAM)irp->Tail.Overlay.DriverContext[0] = sendParam;

		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave#8\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_WRITE) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_snd);
		if (sowriteable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_WRITE;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_snd);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = sendParam->len - uio.uio_resid;
	}

	if (sendParam->overlapped != NULL) {
		sendParam->overlapped->Internal = sendParam->len - uio.uio_resid;
		sendParam->overlapped->InternalHigh = sendParam->flags;
	}
done:
	if (sendParam != NULL && sendParam->iov != NULL) {
		UnlockWsabuf(sendParam->iov, sendParam->iovlen);
	}
	if (sendParam != NULL && sendParam->overlappedMdl != NULL) {
		UnlockBuffer(sendParam->overlappedMdl);
	}
	if (sendParam != NULL) {
		free(sendParam, M_SYSCALL);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchSendRequestDeferred(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SEND_PARAM sendParam = NULL;
	struct uio uio;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequestDeferred - enter\n");

	sendParam = (PSOCKET_SEND_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (sendParam == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequestDeferred - leave#2\n");
		goto done;
	}

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_iov = sendParam->iov;
	uio.uio_iovcnt = sendParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_offset = 0;
	uio.uio_resid = sendParam->len;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = sosend(so, (struct sockaddr *)&sendParam->to, &uio, NULL, NULL, sendParam->flags, NULL);
	if (error == EWOULDBLOCK && sendParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_snd);
		so->so_snd.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_snd.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_snd);

		KeLowerIrql(oldIrql);

		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequestDeferred - leave#3\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_WRITE) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_snd);
		if (sowriteable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_WRITE;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_snd);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = sendParam->len - uio.uio_resid;
	}

	if (sendParam->overlapped != NULL) {
		sendParam->overlapped->Internal = sendParam->len - uio.uio_resid;
		sendParam->overlapped->InternalHigh = sendParam->flags;
	}
done:
	irp->Tail.Overlay.DriverContext[0] = NULL;
	if (sendParam != NULL && sendParam->iov != NULL) {
		UnlockWsabuf(sendParam->iov, sendParam->iovlen);
	}
	if (sendParam != NULL && sendParam->overlappedMdl != NULL) {
		UnlockBuffer(sendParam->overlappedMdl);
	}
	if (sendParam != NULL) {
		free(sendParam, M_SYSCALL);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequestDeferred - leave\n");
	return status;
}

void
SCTPDispatchSendRequestCanceled(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	PSOCKET_SEND_PARAM sendParam = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequestCanceled - enter\n");

	sendParam = (PSOCKET_SEND_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (sendParam == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequestCanceled - leave#1\n");
		return;
	}

	if (sendParam->iov != NULL) {
		UnlockWsabuf(sendParam->iov, sendParam->iovlen);
	}
	if (sendParam->overlappedMdl != NULL) {
		UnlockBuffer(sendParam->overlappedMdl);
	}
	free(sendParam, M_SYSCALL);

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendRequestCanceled- leave\n");
	return;
}

typedef struct _SOCKET_SENDMSG_PARAM {
	PSOCKET_WSAMSG msg;
	PMDL msgMdl;
	struct iovec *iov;
	int iovlen;
	int len;
	struct sockaddr *name;
	struct sockaddr_storage name_ss;
	struct mbuf *control;
	int flags;
	PSOCKET_OVERLAPPED overlapped;
	PMDL overlappedMdl;
} SOCKET_SENDMSG_PARAM, *PSOCKET_SENDMSG_PARAM;

NTSTATUS
SCTPDispatchSendMsgRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SENDMSG_REQUEST sendMsgReq = NULL;
	PSOCKET_SENDMSG_PARAM sendMsgParam = NULL;
	struct uio uio;
	struct mbuf *control = NULL;
	int i;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_SENDMSG_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#1\n");
		goto done;
	}
	sendMsgReq = (PSOCKET_SENDMSG_REQUEST)irp->AssociatedIrp.SystemBuffer;

	if (sendMsgReq->lpMsg == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#2\n");
		goto done;
	}

	sendMsgParam = malloc(sizeof(SOCKET_SENDMSG_PARAM), M_SYSCALL, M_ZERO);
	if (sendMsgParam == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#3\n");
		goto done;
	}

	status = LockBuffer(sendMsgReq->lpMsg, sizeof(SOCKET_WSAMSG), IoReadAccess, &sendMsgParam->msgMdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#4\n");
		goto done;
	}
	sendMsgParam->msg = MmGetSystemAddressForMdlSafe(sendMsgParam->msgMdl, NormalPagePriority);
	if (sendMsgParam->msg == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#5\n");
		goto done;
	}

	status = LockWsabuf(sendMsgParam->msg->lpBuffers, sendMsgParam->msg->dwBufferCount, IoReadAccess,
	    &sendMsgParam->iov);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#6\n");
		goto done;
	}
	sendMsgParam->iovlen = sendMsgParam->msg->dwBufferCount;
	for (i = 0; i < sendMsgParam->iovlen; i++) {
		if ((sendMsgParam->len += sendMsgParam->iov[i].iov_len) < 0) {
			error = EINVAL;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#7\n");
			goto done;
		}
	}

	if (sendMsgParam->msg->name != NULL && sendMsgParam->msg->namelen > 0) {
		if (sendMsgParam->msg->namelen > sizeof(struct sockaddr_storage)) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#8\n");
			goto done;
		}
		copyin(sendMsgParam->msg->name, &sendMsgParam->name_ss, sendMsgParam->msg->namelen);
		sendMsgParam->name = (struct sockaddr *)&sendMsgParam->name_ss;
	}

	if (sendMsgParam->msg->Control.buf != NULL && sendMsgParam->msg->Control.len > 0) {
		control = m_getm2(NULL, sendMsgParam->msg->Control.len, M_DONTWAIT, MT_SONAME, M_EOR);
		    
		if (control == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#9\n");
			goto done;
		}
		if ((control->m_flags & M_EOR) == 0) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#10\n");
			goto done;
		}
		copyin(sendMsgParam->msg->Control.buf,  mtod(control, caddr_t), sendMsgParam->msg->Control.len);
		control->m_len = sendMsgParam->msg->Control.len;
	}

	sendMsgParam->flags = sendMsgReq->dwFlags;

	if (sendMsgReq->lpOverlapped != NULL) {
		sendMsgParam->flags |= MSG_DONTWAIT;
		 status = LockBuffer(sendMsgReq->lpOverlapped, sizeof(SOCKET_OVERLAPPED), IoModifyAccess,
		    &sendMsgParam->overlappedMdl);
		if (status != STATUS_SUCCESS) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#11\n");
			goto done;
		}
		sendMsgParam->overlapped = MmGetSystemAddressForMdlSafe(sendMsgParam->overlappedMdl, NormalPagePriority);
		if (sendMsgParam->overlapped == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#12\n");
			goto done;
		}
	}

	uio.uio_iov = sendMsgParam->iov;
	uio.uio_iovcnt = sendMsgParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_offset = 0;
	uio.uio_resid = sendMsgParam->len;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	if (sendMsgParam->control != NULL) {
		control = m_copym(sendMsgParam->control, 0, M_COPYALL, M_DONTWAIT);
	}
	error = sosend(so, sendMsgParam->name, &uio, NULL, control, sendMsgParam->flags, NULL);
	if (error == EWOULDBLOCK && sendMsgParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_snd);
		so->so_snd.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_snd.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_snd);

		KeLowerIrql(oldIrql);

		(PSOCKET_SENDMSG_PARAM)irp->Tail.Overlay.DriverContext[0] = sendMsgParam;

		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#13\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_WRITE) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_snd);
		if (sowriteable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_WRITE;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_snd);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = sendMsgParam->len - uio.uio_resid;
	}

	if (sendMsgParam->overlapped != NULL) {
		sendMsgParam->overlapped->Internal = sendMsgParam->len - uio.uio_resid;
		sendMsgParam->overlapped->InternalHigh = sendMsgParam->flags;
	}
done:
	if (sendMsgParam != NULL && sendMsgParam->msgMdl != NULL) {
		UnlockBuffer(sendMsgParam->msgMdl);
	}
	if (sendMsgParam != NULL && sendMsgParam->iov != NULL) {
		UnlockWsabuf(sendMsgParam->iov, sendMsgParam->iovlen);
	}
	if (sendMsgParam != NULL && sendMsgParam->control != NULL) {
		m_freem(sendMsgParam->control);
	}
	if (sendMsgParam != NULL && sendMsgParam->overlappedMdl != NULL) {
		UnlockBuffer(sendMsgParam->overlappedMdl);
	}
	if (sendMsgParam != NULL) {
		free(sendMsgParam, M_SYSCALL);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchSendMsgRequestDeferred(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SENDMSG_PARAM sendMsgParam = NULL;
	struct uio uio;
	struct mbuf *control = NULL;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequestDeferred - enter\n");

	sendMsgParam = (PSOCKET_SENDMSG_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (sendMsgParam == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequestDeferred - leave#1\n");
		goto done;
	}

	uio.uio_iov = sendMsgParam->iov;
	uio.uio_iovcnt = sendMsgParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_offset = 0;
	uio.uio_resid = sendMsgParam->len;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	if (sendMsgParam->control != NULL) {
		control = m_copym(sendMsgParam->control, 0, M_COPYALL, M_DONTWAIT);
	}
	error = sosend(so, sendMsgParam->name, &uio, NULL, control, sendMsgParam->flags, NULL);
	if (error == EWOULDBLOCK && sendMsgParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_snd);
		so->so_snd.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_snd.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_snd);

		KeLowerIrql(oldIrql);

		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequestDeferred - leave#2\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_WRITE) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_snd);
		if (sowriteable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_WRITE;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_snd);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = sendMsgParam->len - uio.uio_resid;
	}

	if (sendMsgParam->overlapped != NULL) {
		sendMsgParam->overlapped->Internal = sendMsgParam->len - uio.uio_resid;
		sendMsgParam->overlapped->InternalHigh = sendMsgParam->flags;
	}
done:
	if (sendMsgParam != NULL && sendMsgParam->msgMdl != NULL) {
		UnlockBuffer(sendMsgParam->msgMdl);
	}
	if (sendMsgParam != NULL && sendMsgParam->iov != NULL) {
		UnlockWsabuf(sendMsgParam->iov, sendMsgParam->iovlen);
	}
	if (sendMsgParam != NULL && sendMsgParam->control != NULL) {
		m_freem(sendMsgParam->control);
	}
	if (sendMsgParam != NULL && sendMsgParam->overlappedMdl != NULL) {
		UnlockBuffer(sendMsgParam->overlappedMdl);
	}
	if (sendMsgParam != NULL) {
		free(sendMsgParam, M_SYSCALL);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequestDeferred - leave\n");
	return status;
}

void
SCTPDispatchSendMsgRequestCanceled(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	PSOCKET_SENDMSG_PARAM sendMsgParam = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequestCanceled - enter\n");

	sendMsgParam = (PSOCKET_SENDMSG_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (sendMsgParam == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequestCanceled - leave#1\n");
		return;
	}

	if (sendMsgParam->msgMdl != NULL) {
		UnlockBuffer(sendMsgParam->msgMdl);
	}
	if (sendMsgParam->iov != NULL) {
		UnlockWsabuf(sendMsgParam->iov, sendMsgParam->iovlen);
	}
	if (sendMsgParam->control != NULL) {
		m_freem(sendMsgParam->control);
	}
	if (sendMsgParam->overlappedMdl != NULL) {
		UnlockBuffer(sendMsgParam->overlappedMdl);
	}
	free(sendMsgParam, M_SYSCALL);
}

#ifdef SCTP
NTSTATUS
SCTPDispatchSctpSendRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SCTPSEND_REQUEST sctpSendReq = NULL;
	struct uio uio;
	struct iovec iov[1];
	PMDL mdl = NULL;
	struct sctp_sndrcvinfo sinfo, *u_sinfo = NULL;
	struct sockaddr *to = NULL;
	struct sockaddr_storage to_ss;
	int flags = 0;
	SOCKET_OVERLAPPED overlapped;
	PKEVENT event = NULL;
	int i;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	DWORD len = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpSendRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_SCTPSEND_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpSendRequest - leave#1\n");
		goto done;
	}
	sctpSendReq = (PSOCKET_SCTPSEND_REQUEST)irp->AssociatedIrp.SystemBuffer;

	if (sctpSendReq->sinfo != NULL) {
		copyin(sctpSendReq->sinfo, &sinfo, sizeof(sinfo));
		u_sinfo = &sinfo;
	}

	if (sctpSendReq->to != NULL && sctpSendReq->tolen > 0) {
		if (sctpSendReq->tolen > sizeof(to_ss)) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpSendRequest - leave#2\n");
			goto done;
		}
		copyin(sctpSendReq->to, &to_ss, sctpSendReq->tolen);
		to = (struct sockaddr *)&to_ss;
		if ((to->sa_family == AF_INET && sctpSendReq->tolen != sizeof(struct sockaddr_in)) ||
		    (to->sa_family == AF_INET6 && sctpSendReq->tolen != sizeof(struct sockaddr_in6))) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpSendRequest - leave#3\n");
			goto done;
		}
	}

	status = LockBuffer(sctpSendReq->data, sctpSendReq->len, IoReadAccess, &mdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpSendRequest - leave#4\n");
		goto done;
	}
	iov[0].iov_base = sctpSendReq->data;
	iov[0].iov_len = sctpSendReq->len;

	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_offset = 0;
	uio.uio_resid = sctpSendReq->len;

	flags = sctpSendReq->flags;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;
	len = uio.uio_resid;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = sctp_lower_sosend(so, to, &uio, NULL, NULL, flags, 1, u_sinfo, NULL);
	KeLowerIrql(oldIrql);

	UnlockBuffer(mdl);
	if (error == 0) {
		irp->IoStatus.Information = len - uio.uio_resid;
	}

done:
	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpSendRequest - leave\n");
	return status;
}
#endif

typedef struct _SOCKET_RECV_PARAM {
	struct iovec *iov;
	int iovlen;
	int len;
	struct sockaddr *from;
	PMDL fromMdl;
	socklen_t *fromlen;
	PMDL fromlenMdl;
	int *flags;
	PMDL flagsMdl;
	PSOCKET_OVERLAPPED overlapped;
	PMDL overlappedMdl;
} SOCKET_RECV_PARAM, *PSOCKET_RECV_PARAM;

NTSTATUS
SCTPDispatchRecvRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_RECV_REQUEST recvReq = NULL;
	PSOCKET_RECV_PARAM recvParam = NULL;
	struct uio uio;
	struct sockaddr *fromsa = NULL;
	socklen_t fromsalen;
	int flags = 0;
	int i;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_RECV_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#1\n");
		goto done;
	}
	recvReq = (PSOCKET_RECV_REQUEST)irp->AssociatedIrp.SystemBuffer;

	if (recvReq->lpBuffers == NULL || recvReq->lpFlags == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#2\n");
		goto done;
	}

	recvParam = malloc(sizeof(SOCKET_RECV_PARAM), M_SYSCALL, M_ZERO);
	if (recvParam == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#3\n");
		goto done;
	}

	recvParam->iovlen = recvReq->dwBufferCount;
	status = LockWsabuf(recvReq->lpBuffers, recvParam->iovlen, IoWriteAccess, &recvParam->iov);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#4\n");
		goto done;
	}

	for (i = 0; i < recvParam->iovlen; i++) {
		if ((recvParam->len += recvParam->iov[i].iov_len) < 0) {
			error = EINVAL;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#5\n");
			goto done;
		}
	}

	if (recvReq->lpFrom != NULL && recvReq->lpFromlen != NULL) {
		status = LockBuffer(recvReq->lpFromlen, sizeof(int), IoModifyAccess, &recvParam->fromlenMdl);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#6\n");
			goto done;
		}
		recvParam->fromlen = MmGetSystemAddressForMdlSafe(recvParam->fromlenMdl, NormalPagePriority);
		if (recvParam->fromlen == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#7\n");
			goto done;
		}

		status = LockBuffer(recvReq->lpFrom, *(recvParam->fromlen), IoModifyAccess, &recvParam->fromMdl);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#8\n");
			goto done;
		}
		recvParam->from = MmGetSystemAddressForMdlSafe(recvParam->fromMdl, NormalPagePriority);
		if (recvParam->from == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#9\n");
			goto done;
		}
	}

	status = LockBuffer(recvReq->lpFlags, sizeof(DWORD), IoModifyAccess, &recvParam->flagsMdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#10\n");
		goto done;
	}
	recvParam->flags = MmGetSystemAddressForMdlSafe(recvParam->flagsMdl, NormalPagePriority);
	if (recvParam->flags == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#11\n");
		goto done;
	}

	if (recvReq->lpOverlapped != NULL) {
		*(recvParam->flags) |= MSG_DONTWAIT;

		status = LockBuffer(recvReq->lpOverlapped, sizeof(SOCKET_OVERLAPPED), IoModifyAccess,
		    &recvParam->overlappedMdl);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#10\n");
			goto done;
		}
		recvParam->overlapped = MmGetSystemAddressForMdlSafe(recvParam->overlappedMdl, NormalPagePriority);
		if (recvParam->overlapped == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#11\n");
			goto done;
		}
	}

	uio.uio_iov = recvParam->iov;
	uio.uio_iovcnt = recvParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_offset = 0;
	uio.uio_resid = recvParam->len;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	flags = *(recvParam->flags);

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = soreceive(so, &fromsa, &uio, NULL, NULL, &flags);
	if (error == EWOULDBLOCK && recvParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_rcv);
		so->so_rcv.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_rcv.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_rcv);

		KeLowerIrql(oldIrql);

		(PSOCKET_RECV_PARAM)irp->Tail.Overlay.DriverContext[0] = recvParam;

		if (fromsa != NULL) {
			ExFreePool(fromsa);
		}
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave#12\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_READ) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_rcv);
		if (soreadable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_READ;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		if (recvParam->from != NULL && recvParam->fromlen != NULL && fromsa != NULL) {
			switch (fromsa->sa_family) {
			case AF_INET:
				fromsalen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				fromsalen = sizeof(struct sockaddr_in6);
				break;
			default:
				fromsalen = 0;
			}
			if (*(recvParam->fromlen) > fromsalen) {
				*(recvParam->fromlen) = fromsalen;
			}
			RtlCopyMemory(recvParam->from, fromsa, *(recvParam->fromlen));
		}
		*(recvParam->flags) = flags & ~MSG_DONTWAIT;
		irp->IoStatus.Information = recvParam->len - uio.uio_resid;
	}
	    
	if (recvParam->overlapped != NULL) {
		recvParam->overlapped->Internal = recvParam->len - uio.uio_resid;
		recvParam->overlapped->InternalHigh = flags;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequest - leave\n");
done:
	if (recvParam != NULL && recvParam->iov != NULL) {
		UnlockWsabuf(recvParam->iov, recvParam->iovlen);
	}
	if (recvParam != NULL && recvParam->fromMdl != NULL) {
		UnlockBuffer(recvParam->fromMdl);
	}
	if (recvParam != NULL && recvParam->fromlenMdl != NULL) {
		UnlockBuffer(recvParam->fromlenMdl);
	}
	if (recvParam != NULL && recvParam->flagsMdl != NULL) {
		UnlockBuffer(recvParam->flagsMdl);
	}
	if (recvParam != NULL && recvParam->overlappedMdl != NULL) {
		UnlockBuffer(recvParam->overlappedMdl);
	}
	if (recvParam != NULL) {
		free(recvParam, M_SYSCALL);
	}

	if (fromsa != NULL) {
		ExFreePool(fromsa);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

NTSTATUS
SCTPDispatchRecvRequestDeferred(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_RECV_PARAM recvParam = NULL;
	struct uio uio;
	struct sockaddr *fromsa = NULL;
	socklen_t fromsalen;
	int flags = 0;
	int i;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequestDeferred - enter\n");

	recvParam = (PSOCKET_RECV_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (recvParam == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequestDeferred - leave#1\n");
		goto done;
	}

	uio.uio_iov = recvParam->iov;
	uio.uio_iovcnt = recvParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_offset = 0;
	uio.uio_resid = recvParam->len;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	flags = *(recvParam->flags);

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = soreceive(so, &fromsa, &uio, NULL, NULL, &flags);
	if (error == EWOULDBLOCK && recvParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_rcv);
		so->so_rcv.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_rcv.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_rcv);

		KeLowerIrql(oldIrql);

		if (fromsa != NULL) {
			ExFreePool(fromsa);
		}
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequestDeferred - leave#2\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_READ) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_rcv);
		if (soreadable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_READ;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
		SOCKEVENT_UNLOCK(&so->so_event);
	}
	KeLowerIrql(oldIrql);

	if (error == 0) {
		if (recvParam->from != NULL && recvParam->fromlen != NULL && fromsa != NULL) {
			switch (fromsa->sa_family) {
			case AF_INET:
				fromsalen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				fromsalen = sizeof(struct sockaddr_in6);
				break;
			default:
				fromsalen = 0;
			}
			if (*(recvParam->fromlen) > fromsalen) {
				*(recvParam->fromlen) = fromsalen;
			}
			RtlCopyMemory(recvParam->from, fromsa, *(recvParam->fromlen));
		}
		*(recvParam->flags) = flags & ~MSG_DONTWAIT;
		irp->IoStatus.Information = recvParam->len - uio.uio_resid;
	}
	    
	if (recvParam->overlapped != NULL) {
		recvParam->overlapped->Internal = recvParam->len - uio.uio_resid;
		recvParam->overlapped->InternalHigh = flags;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequestDeferred - leave\n");
done:
	if (recvParam != NULL && recvParam->iov != NULL) {
		UnlockWsabuf(recvParam->iov, recvParam->iovlen);
	}
	if (recvParam != NULL && recvParam->fromMdl != NULL) {
		UnlockBuffer(recvParam->fromMdl);
	}
	if (recvParam != NULL && recvParam->fromlenMdl != NULL) {
		UnlockBuffer(recvParam->fromlenMdl);
	}
	if (recvParam != NULL && recvParam->overlappedMdl != NULL) {
		UnlockBuffer(recvParam->overlappedMdl);
	}
	if (recvParam != NULL) {
		free(recvParam, M_SYSCALL);
	}

	if (fromsa != NULL) {
		ExFreePool(fromsa);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

void
SCTPDispatchRecvRequestCanceled(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	PSOCKET_RECV_PARAM recvParam = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequestCanceled - enter\n");

	recvParam = (PSOCKET_RECV_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (recvParam == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequestCanceled - leave#1\n");
		return;
	}

	if (recvParam->iov != NULL) {
		UnlockWsabuf(recvParam->iov, recvParam->iovlen);
	}
	if (recvParam->fromMdl != NULL) {
		UnlockBuffer(recvParam->fromMdl);
	}
	if (recvParam->fromlenMdl != NULL) {
		UnlockBuffer(recvParam->fromlenMdl);
	}
	if (recvParam->overlappedMdl != NULL) {
		UnlockBuffer(recvParam->overlappedMdl);
	}
	free(recvParam, M_SYSCALL);

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvRequestCanceled - leave\n");
	return;
}

typedef struct _SOCKET_RECVMSG_PARAM {
	PSOCKET_WSAMSG msg;
	PMDL msgMdl;
	struct iovec *iov;
	int iovlen;
	int len;
	struct sockaddr *name;
	PMDL nameMdl;
	PCHAR control;
	PMDL controlMdl;
	PSOCKET_OVERLAPPED overlapped;
	PMDL overlappedMdl;
} SOCKET_RECVMSG_PARAM, *PSOCKET_RECVMSG_PARAM;

NTSTATUS
SCTPDispatchRecvMsgRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_RECVMSG_REQUEST recvMsgReq = NULL;
	PSOCKET_RECVMSG_PARAM recvMsgParam = NULL;
	struct uio uio;
	struct sockaddr *namesa = NULL;
	socklen_t namesalen = 0;
	struct mbuf *control = NULL, *m = NULL;
	int flags = 0;
	PCHAR control_buf = NULL;
	int control_len = 0, copylen = 0;
	int i;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_RECVMSG_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#1\n");
		goto done;
	}
	recvMsgReq = (PSOCKET_RECVMSG_REQUEST)irp->AssociatedIrp.SystemBuffer;

	if (recvMsgReq->lpMsg == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#2\n");
		goto done;
	}

	recvMsgParam = malloc(sizeof(SOCKET_RECVMSG_PARAM), M_SYSCALL, M_ZERO);
	if (recvMsgParam == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#3\n");
		goto done;
	}

	status = LockBuffer(recvMsgReq->lpMsg, sizeof(SOCKET_WSAMSG), IoModifyAccess, &recvMsgParam->msgMdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#4\n");
		goto done;
	}

	recvMsgParam->msg = MmGetSystemAddressForMdlSafe(recvMsgParam->msgMdl, NormalPagePriority);
	if (recvMsgParam->msg == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#5\n");
		goto done;
	}

	if (recvMsgParam->msg->lpBuffers == NULL || recvMsgParam->msg->name == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#6\n");
		goto done;
	}

        status = LockWsabuf(recvMsgParam->msg->lpBuffers, recvMsgParam->msg->dwBufferCount, IoWriteAccess,
	    &recvMsgParam->iov);
        if (status != STATUS_SUCCESS) {
                DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest - leave#7\n");
                goto done;
        }
        recvMsgParam->iovlen = recvMsgParam->msg->dwBufferCount;
        for (i = 0; i < recvMsgParam->iovlen; i++) {
                if ((recvMsgParam->len += recvMsgParam->iov[i].iov_len) < 0) {
                        error = EINVAL;
                        DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest -leave#8\n");
                        goto done;
                }
        }

	status = LockBuffer(recvMsgParam->msg->name, recvMsgParam->msg->namelen, IoWriteAccess, &recvMsgParam->nameMdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#9\n");
		goto done;
	}

	recvMsgParam->name = MmGetSystemAddressForMdlSafe(recvMsgParam->nameMdl, NormalPagePriority);
	if (recvMsgParam->name == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#10\n");
		goto done;
	}

	if (recvMsgParam->msg->Control.buf != NULL && recvMsgParam->msg->Control.len > 0) {
		 status = LockBuffer(recvMsgParam->msg->Control.buf, recvMsgParam->msg->Control.len, IoWriteAccess,
		    &recvMsgParam->controlMdl);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#11\n");
			goto done;
		}

		recvMsgParam->control = MmGetSystemAddressForMdlSafe(recvMsgParam->controlMdl, NormalPagePriority);
		if (recvMsgParam->control == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#12\n");
			goto done;
		}
	}

	if (recvMsgReq->lpOverlapped != NULL) {
		recvMsgParam->msg->dwFlags |= MSG_DONTWAIT;
		status = LockBuffer(recvMsgReq->lpOverlapped, sizeof(SOCKET_OVERLAPPED), IoWriteAccess,
		    &recvMsgParam->overlappedMdl);
		if (status != STATUS_SUCCESS) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSendMsgRequest -leave#13\n");
                        goto done;
		}
		recvMsgParam->overlapped = MmGetSystemAddressForMdlSafe(recvMsgParam->overlappedMdl, NormalPagePriority);
		if (recvMsgParam->overlapped == NULL) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#14\n");
			goto done;
		}
        }

	uio.uio_iov = recvMsgParam->iov;
	uio.uio_iovcnt = recvMsgParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_offset = 0;
	uio.uio_resid = recvMsgParam->len;


	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	flags = recvMsgParam->msg->dwFlags;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = soreceive(so, &namesa, &uio, NULL, &control, &flags);
	if (error == EWOULDBLOCK && recvMsgParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_rcv);
		so->so_rcv.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_rcv.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_rcv);

		KeLowerIrql(oldIrql);

		(PSOCKET_RECVMSG_PARAM)irp->Tail.Overlay.DriverContext[0] = recvMsgParam;
		if (namesa != NULL) {
			ExFreePool(namesa);
		}
		if (control != NULL) {
			m_freem(control);
		}
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave#15\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_READ) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_rcv);
		if (soreadable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_READ;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		if (namesa != NULL) {
			switch (namesa->sa_family) {
			case AF_INET:
				namesalen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				namesalen = sizeof(struct sockaddr_in6);
				break;
			default:
				namesalen = 0;
			}
			if (recvMsgParam->msg->namelen > namesalen) {
				recvMsgParam->msg->namelen = namesalen;
			}
			RtlCopyMemory(recvMsgParam->name, namesa, recvMsgParam->msg->namelen);
		}

		if (control != NULL) {
			control_len = recvMsgParam->msg->Control.len;
			control_buf = recvMsgParam->control;
			recvMsgParam->msg->Control.len = 0;

			for (m = control; m != NULL && control_len > 0; m = m->m_next) {
				if (control_len > m->m_len) {
					copylen = m->m_len;
				} else {
					recvMsgParam->msg->dwFlags |= MSG_CTRUNC;
					copylen = control_len;
				}
				RtlCopyMemory(control_buf, mtod(m, caddr_t), copylen);
				control_buf += copylen;
				control_len -= copylen;
			}
			recvMsgParam->msg->Control.len = control_buf - recvMsgParam->control;
		}

		irp->IoStatus.Information = recvMsgParam->len - uio.uio_resid;
	}
	    
	if (recvMsgParam->overlapped != NULL) {
		recvMsgParam->overlapped->Internal = recvMsgParam->len - uio.uio_resid;
		recvMsgParam->overlapped->InternalHigh = flags;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequest - leave\n");
done:
	if (recvMsgParam != NULL && recvMsgParam->msgMdl != NULL) {
		UnlockBuffer(recvMsgParam->msgMdl);
	}
	if (recvMsgParam != NULL && recvMsgParam->iov != NULL) {
		UnlockWsabuf(recvMsgParam->iov, recvMsgParam->iovlen);
	}
	if (recvMsgParam != NULL && recvMsgParam->nameMdl != NULL) {
		UnlockBuffer(recvMsgParam->nameMdl);
	}
	if (recvMsgParam != NULL && recvMsgParam->controlMdl != NULL) {
		UnlockBuffer(recvMsgParam->controlMdl);
	}
	if (recvMsgParam != NULL && recvMsgParam->overlappedMdl != NULL) {
		UnlockBuffer(recvMsgParam->overlappedMdl);
	}
	if (recvMsgParam != NULL) {
		free(recvMsgParam, M_SYSCALL);
	}

	if (namesa != NULL) {
		ExFreePool(namesa);
	}
	if (control != NULL) {
		m_freem(control);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

NTSTATUS
SCTPDispatchRecvMsgRequestDeferred(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_RECVMSG_PARAM recvMsgParam = NULL;
	struct uio uio;
	struct sockaddr *namesa = NULL;
	socklen_t namesalen = 0;
	struct mbuf *control = NULL, *m = NULL;
	int flags = 0;
	PCHAR control_buf = NULL;
	int control_len = 0, copylen = 0;
	int i;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequestDeferred - enter\n");

	recvMsgParam = (PSOCKET_RECVMSG_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (recvMsgParam == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequestDeferred - leave#1\n");
		goto done;
	}

	uio.uio_iov = recvMsgParam->iov;
	uio.uio_iovcnt = recvMsgParam->iovlen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_offset = 0;
	uio.uio_resid = recvMsgParam->len;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	flags = recvMsgParam->msg->dwFlags;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = soreceive(so, &namesa, &uio, NULL, &control, &flags);
	if (error == EWOULDBLOCK && recvMsgParam->overlapped != NULL) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_rcv);
		so->so_rcv.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_rcv.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_rcv);

		KeLowerIrql(oldIrql);

		(PSOCKET_RECVMSG_PARAM)irp->Tail.Overlay.DriverContext[0] = recvMsgParam;
		if (namesa != NULL) {
			ExFreePool(namesa);
		}
		if (control != NULL) {
			m_freem(control);
		}
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequestDeferred - leave#2\n");
		return status;
	}

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_READ) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_rcv);
		if (soreadable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_READ;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		if (namesa != NULL) {
			switch (namesa->sa_family) {
			case AF_INET:
				namesalen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				namesalen = sizeof(struct sockaddr_in6);
				break;
			default:
				namesalen = 0;
			}
			if (recvMsgParam->msg->namelen > namesalen) {
				recvMsgParam->msg->namelen = namesalen;
			}
			RtlCopyMemory(recvMsgParam->name, namesa, recvMsgParam->msg->namelen);
		}

		if (control != NULL) {
			control_len = recvMsgParam->msg->Control.len;
			control_buf = recvMsgParam->control;
			recvMsgParam->msg->Control.len = 0;

			for (m = control; m != NULL && control_len > 0; m = m->m_next) {
				if (control_len > m->m_len) {
					copylen = m->m_len;
				} else {
					recvMsgParam->msg->dwFlags |= MSG_CTRUNC;
					copylen = control_len;
				}
				RtlCopyMemory(control_buf, mtod(m, caddr_t), copylen);
				control_buf += copylen;
				control_len -= copylen;
			}
			recvMsgParam->msg->Control.len = control_buf - recvMsgParam->control;
		}

		irp->IoStatus.Information = recvMsgParam->len - uio.uio_resid;
	}
	    
	if (recvMsgParam->overlapped != NULL) {
		recvMsgParam->overlapped->Internal = recvMsgParam->len - uio.uio_resid;
		recvMsgParam->overlapped->InternalHigh = flags;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequestDeferred - leave\n");
done:
	irp->Tail.Overlay.DriverContext[0] = NULL;

	if (recvMsgParam != NULL && recvMsgParam->msgMdl != NULL) {
		UnlockBuffer(recvMsgParam->msgMdl);
	}
	if (recvMsgParam != NULL && recvMsgParam->iov != NULL) {
		UnlockWsabuf(recvMsgParam->iov, recvMsgParam->iovlen);
	}
	if (recvMsgParam != NULL && recvMsgParam->nameMdl != NULL) {
		UnlockBuffer(recvMsgParam->nameMdl);
	}
	if (recvMsgParam != NULL && recvMsgParam->controlMdl != NULL) {
		UnlockBuffer(recvMsgParam->controlMdl);
	}
	if (recvMsgParam != NULL && recvMsgParam->overlappedMdl != NULL) {
		UnlockBuffer(recvMsgParam->overlappedMdl);
	}
	if (recvMsgParam != NULL) {
		ExFreePool(recvMsgParam);
	}

	if (namesa != NULL) {
		ExFreePool(namesa);
	}
	if (control != NULL) {
		m_freem(control);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

void
SCTPDispatchRecvMsgRequestCanceled(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	PSOCKET_RECVMSG_PARAM recvMsgParam = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequestCanceled - enter\n");

	recvMsgParam = (PSOCKET_RECVMSG_PARAM)irp->Tail.Overlay.DriverContext[0];
	if (recvMsgParam == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequestCanceled - leave#1\n");
		return;
	}

	if (recvMsgParam->msgMdl != NULL) {
		UnlockBuffer(recvMsgParam->msgMdl);
	}
	if (recvMsgParam->iov != NULL) {
		UnlockWsabuf(recvMsgParam->iov, recvMsgParam->iovlen);
	}
	if (recvMsgParam->nameMdl != NULL) {
		UnlockBuffer(recvMsgParam->nameMdl);
	}
	if (recvMsgParam->controlMdl != NULL) {
		UnlockBuffer(recvMsgParam->controlMdl);
	}
	if (recvMsgParam->overlappedMdl != NULL) {
		UnlockBuffer(recvMsgParam->overlappedMdl);
	}
	ExFreePool(recvMsgParam);

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchRecvMsgRequestCanceled - leave\n");
}

#ifdef SCTP
NTSTATUS
SCTPDispatchSctpRecvRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SCTPRECV_REQUEST sctpRecvReq = NULL;
	struct uio uio;
	struct iovec iov[1];
	PMDL mdl = NULL;
	int fromlen = 0;
	struct sockaddr_storage from_ss;
	struct sctp_sndrcvinfo sinfo;
	int msg_flags = 0;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	DWORD len = 0;
	int salen = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpRecvRequest - enter\n");

	irp->IoStatus.Information = 0;

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_SCTPRECV_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpRecvRequest - leave#1\n");
		goto done;
	}
	sctpRecvReq = (PSOCKET_SCTPRECV_REQUEST)irp->AssociatedIrp.SystemBuffer;

	if (sctpRecvReq->fromlen != NULL) {
		copyin(sctpRecvReq->fromlen, &fromlen, sizeof(fromlen));
	}

	status = LockBuffer(sctpRecvReq->data, sctpRecvReq->len, IoWriteAccess, &mdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpRecvRequest - leave#2\n");
		goto done;
	}
	iov[0].iov_base = sctpRecvReq->data;
	iov[0].iov_len = sctpRecvReq->len;

	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_offset = 0;
	uio.uio_resid = sctpRecvReq->len;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;
	len = uio.uio_resid;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = sctp_sorecvmsg(so, &uio, NULL, (struct sockaddr *)&from_ss, fromlen, &msg_flags, &sinfo, 1);

	if (so->so_event.se_Event != NULL && (so->so_event.se_Events & FD_READ) != 0) {
		SOCKEVENT_LOCK(&so->so_event);
		SOCKBUF_LOCK(&so->so_rcv);
		if (soreadable(so)) {
			so->so_event.se_EventsRet.lNetworkEvents |= FD_READ;
			KeSetEvent(so->so_event.se_Event, 0, FALSE);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
		SOCKEVENT_UNLOCK(&so->so_event);
	}

	KeLowerIrql(oldIrql);

	UnlockBuffer(mdl);

	if (error) {
		if (uio.uio_resid != len && error == EWOULDBLOCK) {
			error = 0;
		}
	}
	if (error) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpRecvRequest - leave#2\n");
		goto done;
	}

	if (sctpRecvReq->sinfo != NULL) {
		copyout(&sinfo, sctpRecvReq->sinfo, sizeof(sinfo));
	}

	if (sctpRecvReq->msg_flags != NULL) {
		copyout(&msg_flags, sctpRecvReq->msg_flags, sizeof(msg_flags));
	}

	if (fromlen > 0 && sctpRecvReq->from != NULL) {
		switch (from_ss.ss_family) {
		case AF_INET:
			salen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			salen = sizeof(struct sockaddr_in6);
			break;
		default:
			salen = 0;
		}
		if (fromlen > salen) {
			copyout(&salen, sctpRecvReq->fromlen, sizeof(salen));
			copyout(&from_ss, sctpRecvReq->from, salen);
		}
	}
	    
	irp->IoStatus.Information = len - uio.uio_resid;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSctpRecvRequest - leave\n");
done:
	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	return status;
}
#endif

NTSTATUS
SCTPDispatchSelectRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	NTSTATUS waitStatus = STATUS_SUCCESS;
	int error = 0;
	int fd_setsize = 0;
	PSOCKET_SELECT_REQUEST selectReq = NULL;
	int fd_count = 0;
	PSOCKET_FD_SET readfds = NULL;
	PSOCKET_FD_SET writefds = NULL;
	PSOCKET_FD_SET exceptfds = NULL;
	int ofd_count = 0;
	PSOCKET_FD_SET oreadfds = NULL;
	PSOCKET_FD_SET owritefds = NULL;
	PSOCKET_FD_SET oexceptfds = NULL;
	int i;

	int readIdx = 0, writeIdx = 0, exceptIdx = 0;
	PFILE_OBJECT *fileObjs = NULL;
	PKEVENT *kEvents = NULL;
	PFILE_OBJECT fileObj = NULL;
	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;

	struct timeval timeoutTv;
	LARGE_INTEGER timeout;
	BOOLEAN infinite = FALSE;
	PKWAIT_BLOCK waitBlockArray = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_SELECT_REQUEST) ||
	    irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SOCKET_SELECT_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#1\n");
		goto done;
	}
	selectReq = (PSOCKET_SELECT_REQUEST)irp->AssociatedIrp.SystemBuffer;

	fd_setsize = sizeof(SOCKET_FD_SET) + sizeof(HANDLE) * selectReq->fd_setsize;
#define getfds(uaddr, kaddr, len) do { \
	if (uaddr != NULL) { \
		kaddr = ExAllocatePoolWithTag(PagedPool, len, 'km51'); \
		if (kaddr == NULL) { \
			status = STATUS_INSUFFICIENT_RESOURCES; \
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#2\n"); \
			goto done; \
		} \
		error = copyin(uaddr, kaddr, len); \
		if (error != 0) { \
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#3\n"); \
			goto done; \
		} \
	} \
} while (0)
	getfds(selectReq->readfds, readfds, fd_setsize);
	getfds(selectReq->writefds, writefds, fd_setsize);
	getfds(selectReq->exceptfds, exceptfds, fd_setsize);
#undef getfds

	fd_count = 0;
	fd_count += readfds != NULL ? readfds->fd_count : 0;
	fd_count += writefds != NULL ? writefds->fd_count : 0;
	fd_count += exceptfds != NULL ? exceptfds->fd_count : 0;
	if (fd_count > 64) {
		status = STATUS_INSUFFICIENT_RESOURCES; \
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#4\n"); \
		goto done; \
	}

	readIdx = 0;
	writeIdx = readfds != NULL ? readfds->fd_count : 0;
	exceptIdx = writeIdx + (writefds != NULL ? writefds->fd_count : 0);

#define allocfds(ofds, num) do { \
	if ((num) > 0) { \
		(ofds) = ExAllocatePoolWithTag(PagedPool, sizeof(SOCKET_FD_SET) + sizeof(HANDLE) * (num), 'km51'); \
		if ((ofds) == NULL) { \
			status = STATUS_INSUFFICIENT_RESOURCES; \
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#5\n"); \
			goto done; \
		} \
		RtlZeroMemory((ofds), sizeof(SOCKET_FD_SET) + sizeof(HANDLE) * (num)); \
	} \
} while (0)
	if (readfds != NULL) {
		allocfds(oreadfds, readfds->fd_count);
	}
	if (writefds!= NULL) {
		allocfds(owritefds, writefds->fd_count);
	}
	if (exceptfds != NULL) {
		allocfds(oexceptfds, exceptfds->fd_count);
	}
#undef allocfds

	if (fd_count > 0) {
		fileObjs = ExAllocatePoolWithTag(PagedPool, sizeof(PFILE_OBJECT) * fd_count, 'km51');
		if (fileObjs == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#6\n");
			goto done;
		}
		RtlZeroMemory(fileObjs, sizeof(PFILE_OBJECT) * fd_count);

		kEvents = ExAllocatePoolWithTag(PagedPool, sizeof(PKEVENT) * fd_count, 'km51');
		if (kEvents == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#7\n");
			goto done;
		}
		RtlZeroMemory(kEvents, sizeof(PKEVENT) * fd_count);
	}

#define getobjs(fds, objs) do { \
	for (i = 0; i < fds->fd_count; i++) { \
		status = ObReferenceObjectByHandle(fds->fd_array[i], \
		    FILE_ALL_ACCESS, \
		    NULL, \
		    KernelMode, \
		    (PVOID *)&(objs)[i], \
		    NULL); \
		if (status != STATUS_SUCCESS) { \
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#8\n"); \
			goto done; \
		} \
	} \
} while (0)
	if (readfds != NULL) {
		getobjs(readfds, &fileObjs[readIdx]);
	}
	if (writefds != NULL) {
		getobjs(writefds, &fileObjs[writeIdx]);
	}
	if (exceptfds != NULL) {
		getobjs(exceptfds, &fileObjs[exceptIdx]);
	}
#undef getobjs

#define getevents(fds, objs, events, name) do { \
	for (i = 0; i < (fds)->fd_count; i++) { \
		fileObj = (objs)[i]; \
		socketContext = (PSOCKET_CONTEXT)fileObj->FsContext; \
		so = socketContext->socket; \
		if (so == NULL) { \
			status = STATUS_INVALID_PARAMETER; \
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#9\n"); \
			goto done; \
		} \
		(events)[i] = &so->name##.sb_selEvent; \
	} \
} while (0)
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	if (readfds != NULL) {
		getevents(readfds, &fileObjs[readIdx], &kEvents[readIdx], so_rcv);
	}
	if (writefds != NULL) {
		getevents(writefds, &fileObjs[writeIdx], &kEvents[writeIdx], so_snd);
	}
	if (exceptfds != NULL) {
		getevents(exceptfds, &fileObjs[exceptIdx], &kEvents[exceptIdx], so_snd);
	}
	KeLowerIrql(oldIrql);
#undef getevents

	if (fd_count > THREAD_WAIT_OBJECTS) {
		waitBlockArray = ExAllocatePoolWithTag(PagedPool, sizeof(KWAIT_BLOCK) * fd_count, 'km51');
		if (waitBlockArray == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#12\n");
			goto done;
		}
	}

	if (!selectReq->infinite) {
		if (selectReq->timeout.tv_sec || selectReq->timeout.tv_usec) {
			microtime(&timeoutTv);
			timevaladd(&timeoutTv, (struct timeval *)&selectReq->timeout);
			timeout.QuadPart = 10000000 * timeoutTv.tv_sec + 10 * timeoutTv.tv_usec;
		} else {
			timeout.QuadPart = 0;
		}
	} else {
		infinite = TRUE;
	}

	for (;;) {
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#define checkevents(fds, objs, ofds, flag) do { \
	for (i = 0; i < (fds)->fd_count; i++) { \
		fileObj = (objs)[i]; \
		socketContext = (PSOCKET_CONTEXT)fileObj->FsContext; \
		so = socketContext->socket; \
		if (sopoll(so, flag, NULL, NULL)) { \
			(ofds)->fd_array[(ofds)->fd_count] = (fds)->fd_array[i]; \
			(ofds)->fd_count++; \
		} \
	} \
} while (0)
		if (readfds != NULL && oreadfds != NULL) {
			checkevents(readfds, &fileObjs[readIdx], oreadfds, POLLRDNORM);
			ofd_count += oreadfds->fd_count;
		}
		if (writefds != NULL && owritefds != NULL) {
			checkevents(writefds, &fileObjs[writeIdx], owritefds, POLLWRNORM);
			ofd_count += owritefds->fd_count;
		}
		if (exceptfds != NULL && oexceptfds != NULL) {
			checkevents(exceptfds, &fileObjs[exceptIdx], oexceptfds, POLLRDBAND);
			ofd_count += oexceptfds->fd_count;
		}
#undef checkevents

		KeLowerIrql(oldIrql);

		if (ofd_count > 0) {
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave#11\n"); \
			goto done;
		}

		waitStatus = KeWaitForMultipleObjects(fd_count,
		    kEvents,
		    WaitAny,
		    UserRequest,
		    UserMode,
		    FALSE,
		    !infinite ? &timeout : NULL,
		    waitBlockArray);

		if (waitStatus >= STATUS_WAIT_0 && waitStatus <= STATUS_WAIT_63) {
			continue;
		} else {
			break;
		}
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSelectRequest - leave\n");
done:

#define putfds(uaddr, kaddr, len) do { \
	error = copyout(kaddr, uaddr, len); \
	if (error != 0) { \
		goto done2; \
	} \
} while (0)
	if (status == STATUS_SUCCESS) {
		if (readfds != NULL && oreadfds != NULL) {
			putfds(selectReq->readfds, oreadfds, fd_setsize);
		}
		if (writefds != NULL && owritefds != NULL) {
			putfds(selectReq->writefds, owritefds, fd_setsize);
		}
		if (exceptfds != NULL && oexceptfds != NULL) {
			putfds(selectReq->exceptfds, oexceptfds, fd_setsize);
		}

		selectReq->nfds = ofd_count;
		irp->IoStatus.Information = sizeof(SOCKET_SELECT_REQUEST);
	}
#undef putfds
done2:

	if (fileObjs != NULL) {
		for (i = 0; i < fd_count; i++) {
			if (fileObjs[i] == NULL) {
				continue;
			}
			ObDereferenceObject(fileObjs[i]);
		}
		ExFreePool(fileObjs);
	}
	
	if (kEvents != NULL) {
		ExFreePool(kEvents);
	}

	if (waitBlockArray != NULL) {
		ExFreePool(waitBlockArray);
	}

	if (readfds != NULL) {
		ExFreePool(readfds);
	}
	if (writefds != NULL) {
		ExFreePool(writefds);
	}
	if (exceptfds != NULL) {
		ExFreePool(exceptfds);
	}

	if (oreadfds != NULL) {
		ExFreePool(oreadfds);
	}
	if (owritefds != NULL) {
		ExFreePool(owritefds);
	}
	if (oexceptfds != NULL) {
		ExFreePool(oexceptfds);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

NTSTATUS
SCTPDispatchEventSelectRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_EVENTSELECT_REQUEST selEventReq = NULL;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	PKEVENT selEvent = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEventSelectRequest - enter\n");

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;
	if (so == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEventSelectRequest - leave#1\n");
		goto done;
	}

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_EVENTSELECT_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEventSelectRequest - leave#2\n");
		goto done;
	}
	selEventReq = (PSOCKET_EVENTSELECT_REQUEST)irp->AssociatedIrp.SystemBuffer;

	if (selEventReq->hEventObject == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEventSelectRequest - leave#3\n");
		goto done;
	}
	status = ObReferenceObjectByHandle(selEventReq->hEventObject,
	    FILE_ALL_ACCESS,
	    NULL,
	    KernelMode,
	    (PVOID *)&selEvent,
	    NULL);
	if (status != STATUS_SUCCESS) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEventSelectRequest - leave#4\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	SOCKEVENT_LOCK(&so->so_event);
	if (so->so_event.se_Event != selEvent) {
		if (so->so_event.se_Event != NULL) {
			ObDereferenceObject(so->so_event.se_Event);
			so->so_event.se_Event = NULL;
		}
		so->so_event.se_Event = selEvent;
		ObReferenceObject(so->so_event.se_Event);
	}

	if (selEventReq->lNetworkEvents != 0) {
		so->so_event.se_Events = selEventReq->lNetworkEvents;
		RtlZeroMemory(&so->so_event.se_EventsRet, sizeof(so->so_event.se_EventsRet));
	} else {
		ObDereferenceObject(so->so_event.se_Event);
		so->so_event.se_Event = NULL;
		RtlZeroMemory(&so->so_event.se_Events, sizeof(so->so_event.se_Events));
		RtlZeroMemory(&so->so_event.se_EventsRet, sizeof(so->so_event.se_EventsRet));
	}

	SOCKEVENT_UNLOCK(&so->so_event);
	KeLowerIrql(oldIrql);

done:
	if (selEvent != NULL) {
		ObDereferenceObject(selEvent);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEventSelectRequest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchEnumNetworkEventsRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_ENUMNETWORKEVENTS_REQUEST enumEventsReq = NULL;

	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	PKEVENT selEvent = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEnumNetworkEventsRequest - enter\n");

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;
	if (so == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEnumNetworkEventsRequest - leave#1\n");
		goto done;
	}

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_ENUMNETWORKEVENTS_REQUEST) ||
	    irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SOCKET_ENUMNETWORKEVENTS_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEnumEventRequest - leave#2\n");
		goto done;
	}
	enumEventsReq = (PSOCKET_ENUMNETWORKEVENTS_REQUEST)irp->AssociatedIrp.SystemBuffer;

	if (enumEventsReq->hEventObject == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEnumNetworkEventsRequest - leave#3\n");
		goto done;
	}
	status = ObReferenceObjectByHandle(enumEventsReq->hEventObject,
	    FILE_ALL_ACCESS,
	    NULL,
	    KernelMode,
	    (PVOID *)&selEvent,
	    NULL);
	if (status != STATUS_SUCCESS) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEnumNetworkEventsRequest - leave#4\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	SOCKEVENT_LOCK(&so->so_event);
	if (so->so_event.se_Event != selEvent) {
		SOCKEVENT_UNLOCK(&so->so_event);
		KeLowerIrql(oldIrql);
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEnumNetworkEventsRequest- leave#5\n");
		goto done;
	}

	RtlCopyMemory(&enumEventsReq->networkEvents, &so->so_event.se_EventsRet, sizeof(so->so_event.se_EventsRet));
	RtlZeroMemory(&so->so_event.se_EventsRet, sizeof(so->so_event.se_EventsRet));
	SOCKEVENT_UNLOCK(&so->so_event);
	KeLowerIrql(oldIrql);

	irp->IoStatus.Information = sizeof(SOCKET_ENUMNETWORKEVENTS_REQUEST);
done:
	if (selEvent != NULL) {
		ObDereferenceObject(selEvent);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchEnumNetworkEventsRequest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchSetOptionRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SOCKOPT_REQUEST optReq = NULL;

	PSOCKET_CONTEXT socketContext = NULL;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	struct sockopt sopt;
	PMDL mdl = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSetOptionRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_SOCKOPT_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSetOptionRequest - leave#1\n");
		goto done;
	}
	optReq = (PSOCKET_SOCKOPT_REQUEST)irp->AssociatedIrp.SystemBuffer;

	RtlZeroMemory(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = optReq->level;
	sopt.sopt_name = optReq->optname;

	status = LockBuffer(optReq->optval, optReq->optlen, IoReadAccess, &mdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSetOptionRequest - leave#2\n");
		goto done;
	}
	sopt.sopt_val = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
	if (sopt.sopt_val == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;		
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSetOptionRequest - leave#3\n");
		goto done;
	}
	sopt.sopt_valsize = optReq->optlen;

	if (irpSp->DeviceObject == SctpSocketDeviceObject) {
		socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
		so = socketContext->socket;
	} else {
		tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
		so = tdiContext->socket;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = sosetopt(so, &sopt);
	KeLowerIrql(oldIrql);

done:
	if (mdl != NULL) {
		UnlockBuffer(mdl);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchSetOptionRequest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchGetOptionRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PSOCKET_SOCKOPT_REQUEST optReq = NULL;

	PSOCKET_CONTEXT socketContext = NULL;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	struct sockopt sopt;
	PMDL mdl = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetOptionRequest - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SOCKET_SOCKOPT_REQUEST)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetOptionRequest - leave#1\n");
		goto done;
	}
	optReq = (PSOCKET_SOCKOPT_REQUEST)irp->AssociatedIrp.SystemBuffer;

	RtlZeroMemory(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = optReq->level;
	sopt.sopt_name = optReq->optname;

	status = LockBuffer(optReq->optval, optReq->optlen, IoWriteAccess, &mdl);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetOptionRequest - leave#2\n");
		goto done;
	}
	sopt.sopt_val = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
	if (sopt.sopt_val == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetOptionRequest - leave#3\n");
		goto done;
	}
	sopt.sopt_valsize = optReq->optlen;

	if (irpSp->DeviceObject == SctpSocketDeviceObject) {
		socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
		so = socketContext->socket;
	} else {
		tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
		so = tdiContext->socket;
	}
	
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = sogetopt(so, &sopt);
	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = sopt.sopt_valsize;
	}
done:
	if (mdl != NULL) {
		UnlockBuffer(mdl);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetOptionRequest - leave\n");
	return status;
}

NTSTATUS
SCTPDispatchGetSockName(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_CONTEXT socketContext = NULL;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	int error = 0;
	struct sockaddr *sa = NULL, *asa = NULL;
	socklen_t salen = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetSockName - enter\n");

	if (irpSp->DeviceObject == SctpSocketDeviceObject) {
		socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
		so = socketContext->socket;
	} else {
		tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
		so = tdiContext->socket;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &sa);
	KeLowerIrql(oldIrql);

	if (error != 0 || sa == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetSockName - leave#1\n");
		goto done;
	}

	switch (sa->sa_family) {
	case AF_INET:
		salen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		salen = sizeof(struct sockaddr_in6);
		break;
	default:
		error = EINVAL;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetSockName - leave#2\n");
		goto done;
	}

	asa = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
	if (asa == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetSockName - leave#3\n");
		goto done;
	}

	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < salen) {
		salen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	}
	RtlCopyMemory(asa, sa, salen);
	irp->IoStatus.Information = salen;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetSockName - leave\n");
done:
	if (sa != NULL) {
		ExFreePool(sa);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

NTSTATUS
SCTPDispatchGetPeerName(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_CONTEXT socketContext = NULL;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	int error = 0;
	struct sockaddr *sa = NULL, *asa = NULL;
	socklen_t salen = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetPeerName - enter\n");

	if (irpSp->DeviceObject == SctpSocketDeviceObject) {
		socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
		so = socketContext->socket;
	} else {
		tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
		so = tdiContext->socket;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, &sa);
	KeLowerIrql(oldIrql);

	if (error != 0 || sa == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetPeerName - leave#1\n");
		goto done;
	}

	switch (sa->sa_family) {
	case AF_INET:
		salen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		salen = sizeof(struct sockaddr_in6);
		break;
	default:
		error = EINVAL;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetPeerName - leave#2\n");
		goto done;
	}

	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < salen) {
		status = STATUS_ACCESS_VIOLATION;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetPeerName - leave#3\n");
		goto done;
	}

	asa = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
	if (asa == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetPeerName - leave#4\n");
		goto done;
	}

	RtlCopyMemory(asa, sa, salen);
	irp->IoStatus.Information = salen;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchGetPeerName - leave\n");
done:
	if (sa != NULL) {
		ExFreePool(sa);
	}

	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

NTSTATUS
SCTPDispatchShutdown(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_CONTEXT socketContext = NULL;
	struct socket *so = NULL;
	int error = 0;
	int how = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchShutdown - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(int)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchShutdown - leave#1\n");
		goto done;
	}
	how = *(int *)irp->AssociatedIrp.SystemBuffer;

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;
	so = socketContext->socket;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = soshutdown(so, how);
	KeLowerIrql(oldIrql);

	irp->IoStatus.Information = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchShutdown - leave\n");
done:
	if (status == STATUS_SUCCESS && error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}
	return status;
}

NTSTATUS
SCTPCloseSocket(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_CONTEXT socketContext = NULL;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	int error = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCloseSocket - enter\n");

	socketContext = (PSOCKET_CONTEXT)irpSp->FileObject->FsContext;

	if (socketContext == NULL || socketContext->socket == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCloseSocket - leave#1\n");
		goto done;
	}
	so = socketContext->socket;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = soclose(so);
	KeLowerIrql(oldIrql);

	ExFreePool(socketContext);
	if (error != 0) {
		status = (NTSTATUS)(0xC0FF0000 | error);
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCloseSocket - leave\n");
done:
	return status;
}


#ifdef SCTP
NTSTATUS
SCTPCreateTdi(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp,
    IN int type,
    IN int proto)
{
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	KIRQL oldIrql;
	PTDI_CONTEXT tdiContext = NULL;
	PFILE_FULL_EA_INFORMATION ea0 = NULL, ea = NULL;
	int dom;
	PTRANSPORT_ADDRESS tAddr = NULL;
	struct sockaddr_storage addr;
	struct sockaddr *sa = NULL;
	int salen = 0;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - enter\n");

	tdiContext = malloc(sizeof(TDI_CONTEXT), M_TDI, M_ZERO);
	if (tdiContext == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #1\n");
		goto done;
	}

	KeInitializeEvent(&tdiContext->cleanupEvent, SynchronizationEvent, FALSE);
	tdiContext->cleaning = FALSE;

	ea0 = (PFILE_FULL_EA_INFORMATION)irp->AssociatedIrp.SystemBuffer;
	if (ea0 == NULL) {
		/* TDI_CONTROL_CHANNEL_FILE */
		irpSp->FileObject->FsContext = tdiContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONTROL_CHANNEL_FILE;
		status = STATUS_SUCCESS;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #2\n");
		goto done;
	}

	ea = FindEAInfo(ea0, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH);
	if (ea != NULL) {
		/* TDI_TRANSPORT_ADDRESS_FILE */
		tAddr = (TRANSPORT_ADDRESS *)&ea->EaName[ea->EaNameLength + 1];
		RtlZeroMemory(&addr, sizeof(addr));
		sa = (struct sockaddr *)&addr;
		salen = sizeof(addr);

		if (ta2sa(tAddr, sa, &salen) < 0) {
			status = TDI_BAD_ADDR;
			ExFreePool(tdiContext);
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #3\n");
			goto done;
		}
		if (tAddr->Address[0].AddressType == TDI_ADDRESS_TYPE_IP) {
			dom = AF_INET;
		} else if (
		    tAddr->Address[0].AddressType == TDI_ADDRESS_TYPE_IP6) {
			dom = AF_INET6;
		}

		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

		error = socreate(dom, &so, type, proto, NULL, NULL);
		if (error != 0) {
			KeLowerIrql(oldIrql);
			ExFreePool(tdiContext);

			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #4\n");
			goto done;
		}

		error = sobind(so, (struct sockaddr *)&addr, NULL);
		if (error != 0) {
			error = soclose(so);
			KeLowerIrql(oldIrql);
			ExFreePool(tdiContext);

			status = STATUS_SHARING_VIOLATION;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #5\n");
			goto done;
		}

		if (type == SOCK_SEQPACKET) {
			/* XXX TDI architecture dos not allow listen() for SOCK_SEQPACK.
			 * So, try to enable accepting INIT at this time. */
			error = solisten(so, 1, NULL);
			if (error != 0) {
				error = soclose(so);
				KeLowerIrql(oldIrql);
				ExFreePool(tdiContext);

				status = STATUS_SHARING_VIOLATION;
				DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #6\n");
				goto done;
			}
		}

		KeLowerIrql(oldIrql);

		tdiContext->socket = so;
		irpSp->FileObject->FsContext = tdiContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_TRANSPORT_ADDRESS_FILE;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #7\n");
		status = STATUS_SUCCESS;
		goto done;
	}

	ea = FindEAInfo(ea0, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH);
	if (ea != NULL) {
		tdiContext->connCtx = *(CONNECTION_CONTEXT UNALIGNED *)&ea->EaName[ea->EaNameLength + 1];
		irpSp->FileObject->FsContext = tdiContext;
		irpSp->FileObject->FsContext2 = (PVOID)TDI_CONNECTION_FILE;
		status = STATUS_SUCCESS;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave #8\n");
		goto done;
	}

	status = STATUS_INVALID_EA_NAME;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCreateTdi - leave\n");
done:
	return status;
}

NTSTATUS
SCTPDispatchTdiAssociateAddress(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PTDI_CONTEXT tdiContext = NULL, tdiContext2 = NULL;
	PTDI_REQUEST_KERNEL_ASSOCIATE associateInformation = NULL;
	PFILE_OBJECT fileObject = NULL;
	struct socket *so = NULL;
	int error = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket != NULL) {
		status = STATUS_INVALID_HANDLE;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress - leave#1\n");
		goto done;
	}
	associateInformation = (PTDI_REQUEST_KERNEL_ASSOCIATE)&irpSp->Parameters;
	if (associateInformation == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress - leave#2\n");
		goto done;
	}

	status = ObReferenceObjectByHandle(associateInformation->AddressHandle,
	    0, NULL, KernelMode, &fileObject, NULL);
	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress - leave#3\n");
		return status;
	}

	if (fileObject->DeviceObject != SctpTdiTcpDeviceObject ||
	    PtrToLong(fileObject->FsContext2) != TDI_TRANSPORT_ADDRESS_FILE) {
		ObDereferenceObject(fileObject);
		status = STATUS_INVALID_HANDLE;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress - leave#4\n");
		goto done;
	}

	tdiContext2 = (PTDI_CONTEXT)fileObject->FsContext;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	so = tdiContext2->socket;
	atomic_add_int(&tdiContext2->backlog, 1);
	
	error = solisten(so, tdiContext2->backlog, NULL);
	if (error != 0) {
		KeLowerIrql(oldIrql);
		ObDereferenceObject(fileObject);
		status = STATUS_INVALID_HANDLE;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress : solisten=%d\n", error);
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress - leave#5\n");
		goto done;
	}

	tdiContext->fileObject = fileObject;

	KeLowerIrql(oldIrql);
	status = STATUS_SUCCESS;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiAssociateAddress - leave\n");
done:
	return status;
}


NTSTATUS
SCTPDispatchTdiDisassociateAddress(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PTDI_CONTEXT tdiContext = NULL;
	PTDI_CONTEXT tdiContext2 = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiDisassociateAddress - enter\n");
	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL) {
		status = STATUS_INVALID_HANDLE;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiDisassociateAddress - leave#1\n");
		goto done;
	}

	if (tdiContext->fileObject != NULL) {
		tdiContext2 = (PTDI_CONTEXT)tdiContext->fileObject->FsContext;
		atomic_add_int(&tdiContext2->backlog, 1);
		ObDereferenceObject(tdiContext->fileObject);
		tdiContext->fileObject = NULL;
	}
	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiDisassociateAddress - leave\n");
done:
	return STATUS_SUCCESS;
}

NTSTATUS
SCTPDispatchTdiConnect(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	PTDI_REQUEST_KERNEL_CONNECT connectRequest = NULL;
	PTDI_CONNECTION_INFORMATION requestInformation = NULL;
	PTRANSPORT_ADDRESS tAddr = NULL;
	struct sockaddr_storage addr;
	struct sockaddr *sa = NULL;
	int salen = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnect - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		status = STATUS_INVALID_CONNECTION;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnect - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;
	
	connectRequest = (PTDI_REQUEST_KERNEL_CONNECT)&irpSp->Parameters;
	requestInformation = connectRequest->RequestConnectionInformation;

	if (requestInformation != NULL && requestInformation->RemoteAddressLength >= sizeof(TRANSPORT_ADDRESS)) {
		tAddr = (TRANSPORT_ADDRESS *)requestInformation->RemoteAddress;
		RtlZeroMemory(&addr, sizeof(addr));
		sa = (struct sockaddr *)&addr;
		salen = sizeof(addr);

		if (ta2sa(tAddr, sa, &salen) < 0) {
			status = TDI_BAD_ADDR;
		}
	}

	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnect - leave#2\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	error = soconnect(so, sa, NULL);
	if (error == 0) {
		status = STATUS_PENDING;
		SOCK_LOCK(so);
		so->so_rcv.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_rcv.sb_csq, irp, NULL);
		SOCK_UNLOCK(so);
	}
	KeLowerIrql(oldIrql);

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnect - leave\n");
done:
	return status;
}

NTSTATUS
SCTPDispatchTdiConnectComplete(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	PTDI_REQUEST_KERNEL_CONNECT connectRequest = NULL;
	PTDI_CONNECTION_INFORMATION returnInformation = NULL;
	struct sockaddr *sa = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnectComplete - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		status = STATUS_INVALID_CONNECTION;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnectComplete - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;
	
	connectRequest = (PTDI_REQUEST_KERNEL_CONNECT)&irpSp->Parameters;
	returnInformation = connectRequest->ReturnConnectionInformation;

	if (so->so_error != 0) {
		status = TDI_NOT_ASSOCIATED;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnectComplete - leave#2\n");
		goto done;
	}

	if (returnInformation != NULL &&
	    returnInformation->RemoteAddress != NULL &&
	    returnInformation->RemoteAddressLength > sizeof(TRANSPORT_ADDRESS)
	    ) {
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, &sa);
		KeLowerIrql(oldIrql);
		if (error == 0 && sa != NULL) {
			if (sa2ta(sa, returnInformation->RemoteAddress, &returnInformation->RemoteAddressLength) < 0) {
				returnInformation->RemoteAddress = NULL;
				returnInformation->RemoteAddressLength = 0;
			}
		}
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiConnectComplete - leave\n");
done:
	if (sa != NULL) {
		ExFreePool(sa);
	}
	return status;
}

NTSTATUS
SCTPDispatchTdiDisconnect(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_REQUEST_KERNEL_DISCONNECT disconnectRequest;
	PTDI_CONTEXT tdiContext;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiDisconnect - enter\n");
	disconnectRequest = (PTDI_REQUEST_KERNEL_DISCONNECT)&(irpSp->Parameters);

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		status = STATUS_INVALID_CONNECTION;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiDisconnect - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;
	
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	if ((disconnectRequest->RequestFlags & TDI_DISCONNECT_ABORT) == 0) {
		error = sodisconnect(so);
	} else {
		soabort(so);
	}
	KeLowerIrql(oldIrql);

	if (error != 0) {
		status = STATUS_INVALID_PARAMETER;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiDisconnect - leave\n");
done:
	return status;
}


NTSTATUS
SCTPDispatchTdiSend(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_REQUEST_KERNEL_SEND sendRequest;
	PTDI_CONTEXT tdiContext;
	struct socket *so = NULL;
	struct uio uio;
	int flags = 0;
	int len = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSend - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		status = STATUS_INVALID_CONNECTION;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSend - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;

	sendRequest = (PTDI_REQUEST_KERNEL_SEND)&irpSp->Parameters;

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_buffer_offset = 0;
	uio.uio_resid = sendRequest->SendLength;
	uio.uio_rw = UIO_WRITE;

	flags = MSG_DONTWAIT;
	len = uio.uio_resid;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = sosend(so, NULL, &uio, NULL, NULL, flags, NULL);
	if (error == EWOULDBLOCK) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_snd);
		so->so_snd.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_snd.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_snd);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = len - uio.uio_resid;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSend - leave\n");
done:
	if (status == STATUS_SUCCESS && error != 0) {
	}
	return status;
}

NTSTATUS
SCTPDispatchTdiReceive(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_CONTEXT tdiContext;
	struct socket *so = NULL;
	PTDI_REQUEST_KERNEL_RECEIVE information = NULL;
	struct uio uio;
	int flags = 0;
	int len = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiReceive - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiReceive - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;

	information = (PTDI_REQUEST_KERNEL_RECEIVE)(&irpSp->Parameters);

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_buffer_offset = 0;
	uio.uio_rw = UIO_READ;
	uio.uio_offset = 0;
	uio.uio_resid = information->ReceiveLength;

	flags = MSG_DONTWAIT;
	len = uio.uio_resid;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = soreceive(so, NULL, &uio, NULL, NULL, &flags);
	if (error == EWOULDBLOCK) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_rcv);
		so->so_rcv.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_rcv.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_rcv);
	}
	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = len - uio.uio_resid;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiReceive - leave\n");
done:
	if (status == STATUS_SUCCESS && error != 0) {
	}
	return status;
}

NTSTATUS
SCTPDispatchTdiReceiveDatagram(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_CONTEXT tdiContext;
	struct socket *so = NULL;
	PTDI_REQUEST_KERNEL_RECEIVEDG datagramInformation = NULL;
	PTDI_CONNECTION_INFORMATION receiveDatagramInformation = NULL;
	PTDI_CONNECTION_INFORMATION returnDatagramInformation = NULL;
	struct uio uio;
	struct sockaddr *sa = NULL;
	struct mbuf *control = NULL, *m = NULL;
	int flags = 0;
	int len = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiReceiveDatagram - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReceiveDatagram - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;

	datagramInformation = (PTDI_REQUEST_KERNEL_RECEIVEDG)(&irpSp->Parameters);
	receiveDatagramInformation = datagramInformation->ReceiveDatagramInformation;
	returnDatagramInformation = datagramInformation->ReturnDatagramInformation;

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_buffer_offset = 0;
	uio.uio_rw = UIO_READ;
	uio.uio_offset = 0;
	uio.uio_resid = datagramInformation->ReceiveLength;

	flags = MSG_DONTWAIT;
	len = uio.uio_resid;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = soreceive(so, &sa, &uio, NULL, &control, &flags);
	if (error == EWOULDBLOCK) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_rcv);
		so->so_rcv.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_rcv.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_rcv);
	}

	KeLowerIrql(oldIrql);

	if (error == 0) {
		irp->IoStatus.Information = len - uio.uio_resid;
		if (returnDatagramInformation != NULL) {
			if (sa != NULL && returnDatagramInformation->RemoteAddress != NULL) {
				if (sa2ta(sa, returnDatagramInformation->RemoteAddress,
					&returnDatagramInformation->RemoteAddressLength)
				    ) {
					returnDatagramInformation->RemoteAddress = NULL;
					returnDatagramInformation->RemoteAddressLength = 0;
				}
			}
			if (control != NULL && returnDatagramInformation->Options != NULL) {
				if (returnDatagramInformation->OptionsLength >= control->m_len) {
					RtlCopyMemory(returnDatagramInformation->Options,
					    mtod(control, caddr_t), control->m_len);
					returnDatagramInformation->OptionsLength = control->m_len;
				} else {
					returnDatagramInformation->Options = NULL;
					returnDatagramInformation->OptionsLength = 0;
				}
			}
		}

		irp->IoStatus.Information = len - uio.uio_resid;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiReceiveDatagram - leave\n");
done:
	if (sa != NULL) {
		ExFreePool(sa);
	}
	if (control != NULL) {
		m_freem(control);
	}
	if (status == STATUS_SUCCESS && error != 0) {
	}
	return status;
}

NTSTATUS
SCTPDispatchTdiSendDatagram(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	PTDI_REQUEST_KERNEL_SENDDG datagramInformation;
	PTDI_CONNECTION_INFORMATION sendDatagramInformation;
	PTRANSPORT_ADDRESS tAddr = NULL;
	struct sockaddr_storage dst;
	struct sockaddr *sa = NULL;
	struct uio uio;
	int salen = 0;
	struct mbuf *control = NULL;
	int flags = 0;
	int len = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSendDatagram - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSendDatagram - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;
	datagramInformation = (PTDI_REQUEST_KERNEL_SENDDG)&irpSp->Parameters;
	sendDatagramInformation = datagramInformation->SendDatagramInformation;

	if (sendDatagramInformation != NULL &&
	    sendDatagramInformation->RemoteAddress != NULL &&
	    sendDatagramInformation->RemoteAddressLength >= sizeof(TRANSPORT_ADDRESS)
	    ) {
		tAddr = (TRANSPORT_ADDRESS *)sendDatagramInformation->RemoteAddress;
		RtlZeroMemory(&dst, sizeof(dst));
		sa = (struct sockaddr *)&dst;
		salen = sizeof(dst);

		if (ta2sa(tAddr, sa, &salen) < 0) {
			status = TDI_BAD_ADDR;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSendDatagram - leave#2\n");
			goto done;
		}
	}

	if (sendDatagramInformation != NULL &&
	    sendDatagramInformation->Options != NULL &&
	    sendDatagramInformation->OptionsLength > 0
	    ) {
		control = m_getm2(NULL, sendDatagramInformation->OptionsLength, M_DONTWAIT,
		    MT_SONAME, M_EOR);
		if (control == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSendDatagram - leave#3\n");
			goto done;
		}
		if ((control->m_flags & M_EOR) == 0) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSendDatagram - leave#4\n");
			goto done;
		}
		RtlCopyMemory(mtod(control, caddr_t), sendDatagramInformation->Options,
		    sendDatagramInformation->OptionsLength);
		control->m_len = sendDatagramInformation->OptionsLength;
	}

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_buffer_offset = 0;
	uio.uio_rw = UIO_WRITE;
	uio.uio_resid = datagramInformation->SendLength;

	flags = MSG_DONTWAIT;
	len = uio.uio_resid;

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	error = sosend(so, sa, &uio, NULL, control, flags, NULL);
	control = NULL;

	KeLowerIrql(oldIrql);

	if (error == EWOULDBLOCK) {
		status = STATUS_PENDING;

		SOCKBUF_LOCK(&so->so_snd);
		so->so_snd.sb_flags |= SB_AIO;
		IoCsqInsertIrp((PIO_CSQ)&so->so_snd.sb_csq, irp, NULL);
		SOCKBUF_UNLOCK(&so->so_snd);
	}

	if (error == 0) {
		irp->IoStatus.Information = len - uio.uio_resid;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSendDatagram - leave\n");
done:
	if (control != NULL) {
		m_freem(control);
	}
	if (status == STATUS_SUCCESS && error != 0) {
	}
	return status;
}

NTSTATUS
SCTPDispatchTdiSetEventHandler(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;
	PTDI_CONTEXT tdiContext = NULL;
	PTDI_REQUEST_KERNEL_SET_EVENT event = NULL;
	struct socket *so = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSetEventHandler - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;
	if (tdiContext == NULL || tdiContext->socket == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSetEventHandler - leave#1\n");
		goto done;
	}
	so = tdiContext->socket;

	event = (PTDI_REQUEST_KERNEL_SET_EVENT)&(irpSp->Parameters);
	if (event == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSetEventHandler - leave#2\n");
		goto done;
	}

	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	SOCK_LOCK(so);
	switch (event->EventType) {
	case TDI_EVENT_CONNECT:
		so->so_tdi_event.so_tdi_conn = event->EventHandler;
		so->so_tdi_event.so_tdi_conn_arg = event->EventContext;
		break;
	case TDI_EVENT_DISCONNECT:
		so->so_tdi_event.so_tdi_disconn = event->EventHandler;
		so->so_tdi_event.so_tdi_disconn_arg = event->EventContext;
		break;
	case TDI_EVENT_RECEIVE:
	case TDI_EVENT_RECEIVE_EXPEDITED:
		so->so_tdi_event.so_tdi_rcv = event->EventHandler;
		so->so_tdi_event.so_tdi_rcv_arg = event->EventContext;
		break;
	case TDI_EVENT_RECEIVE_DATAGRAM:
		so->so_tdi_event.so_tdi_rcvdg = event->EventHandler;
		so->so_tdi_event.so_tdi_rcvdg_arg = event->EventContext;
		break;
	case TDI_EVENT_SEND_POSSIBLE:
		so->so_tdi_event.so_tdi_snd = event->EventHandler;
		so->so_tdi_event.so_tdi_snd_arg = event->EventContext;
		break;
	case TDI_EVENT_ERROR:
		so->so_tdi_event.so_tdi_err = event->EventHandler;
		so->so_tdi_event.so_tdi_err_arg = event->EventContext;
		break;
	default:
		status = TDI_BAD_EVENT_TYPE;
		break;
	}
	SOCK_UNLOCK(so);

	KeLowerIrql(oldIrql);

	irp->IoStatus.Information = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiSetEventHandler - leave\n");
done:
	return status;
}

NTSTATUS
SCTPDispatchTdiQueryInformation(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTDI_CONTEXT tdiContext = NULL;
	PTDI_REQUEST_KERNEL_QUERY_INFORMATION queryInformation = NULL;
	TDI_REQUEST request;
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

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiQueryInformation - enter\n");

	queryInformation = (PTDI_REQUEST_KERNEL_QUERY_INFORMATION)&(irpSp->Parameters);
	if (queryInformation == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiQueryInformation - leave#1\n");
		goto done;
	}

	switch (queryInformation->QueryType) {
	case TDI_QUERY_BROADCAST_ADDRESS:
	case TDI_QUERY_PROVIDER_INFO:
	case TDI_QUERY_PROVIDER_STATISTICS:
		if (PtrToLong(irpSp->FileObject->FsContext2) != TDI_CONTROL_CHANNEL_FILE) {
			status = STATUS_INVALID_PARAMETER;
		}
		break;
	case TDI_QUERY_ADDRESS_INFO:
		if (PtrToLong(irpSp->FileObject->FsContext2) == TDI_CONNECTION_FILE) {
			so = tdiContext->socket;
		} else if (PtrToLong(irpSp->FileObject->FsContext2) == TDI_TRANSPORT_ADDRESS_FILE) {
			so = tdiContext->socket;
		} else {
			status = STATUS_INVALID_PARAMETER;
		}
		break;
	case TDI_QUERY_CONNECTION_INFO:
		if (PtrToLong(irpSp->FileObject->FsContext2) == TDI_CONNECTION_FILE) {
			so = tdiContext->socket;
		} else {
			status = STATUS_INVALID_PARAMETER;
		}
		break;
	default:
		status = STATUS_NOT_IMPLEMENTED;
	}

	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiQueryInformation - leave#2\n");
		goto done;
	}

	mdl = irp->MdlAddress;
	while (mdl != NULL) {
		receiveLength += MmGetMdlByteCount(mdl);
		mdl = mdl->Next;
	}

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

			tAddrLength = sizeof(TA_IP6_ADDRESS);
			sa2ta((struct sockaddr *)&sin, &info.addrInfo.Address, &tAddrLength);
		}
		infoLength = sizeof(TDI_ADDRESS_INFO)- sizeof(TRANSPORT_ADDRESS) + tAddrLength;
		break;
	default:
		status = TDI_INVALID_QUERY;
		break;
	}

	if (status != STATUS_SUCCESS) {
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiQueryInformation - leave#3\n");
		goto done;
	}

	RtlZeroMemory(&uio, sizeof(uio));
	uio.uio_buffer = irp->MdlAddress;
	uio.uio_resid = receiveLength;
	uio.uio_rw = UIO_WRITE;

	uiomove(&info, infoLength, &uio);
	if ((ULONG)uio.uio_offset < infoLength) {
		status = TDI_BUFFER_OVERFLOW;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiQueryInformation - leave#4\n");
		goto done;
	} else {
		status = STATUS_SUCCESS;
		receivedLength = (ULONG)uio.uio_offset;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchTdiQueryInformation - leave#5\n");
		goto done;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPQueryInformation - leave\n");
done:
	return status;
}

NTSTATUS
SCTPCloseTdi(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	KIRQL oldIrql;
	NTSTATUS status = STATUS_SUCCESS;
	PSOCKET_CONTEXT socketContext = NULL;
	PTDI_CONTEXT tdiContext = NULL;
	struct socket *so = NULL;
	int error = 0;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCloseTdi - enter\n");

	tdiContext = (PTDI_CONTEXT)irpSp->FileObject->FsContext;

	if (tdiContext == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCloseTdi - leave#1\n");
		goto done;
	}
	if (tdiContext->socket != NULL) {
		so = tdiContext->socket;
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		error = soclose(so);
		KeLowerIrql(oldIrql);
		if (error != 0) {
			status = STATUS_INVALID_PARAMETER;
		}
	}
	ExFreePool(tdiContext);

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPCloseTdi - leave\n");
done:
	return status;
}
#endif
