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

#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/systm.h>


int
copyin(
    void *uaddr,
    void *kaddr,
    size_t len)
{
	int error = 0;
	PMDL mdl = NULL;

	mdl = IoAllocateMdl(uaddr, len, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		error = ENOMEM;
		goto error;
	}
	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		error = EFAULT;
		goto error;
	}
	RtlCopyMemory(kaddr, uaddr, len);

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return 0;
error:
	if (mdl != NULL) {
		IoFreeMdl(mdl);
	}
	return (error);
}

int
copyout(
    void *kaddr,
    void *uaddr,
    size_t len)
{
	int error = 0;
	PMDL mdl = NULL;

	mdl = IoAllocateMdl(uaddr, len, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		error = ENOMEM;
		goto error;
	}
	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		error = EFAULT;
		goto error;
	}
	RtlCopyMemory(uaddr, kaddr, len);

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return 0;
error:
	if (mdl != NULL) {
		IoFreeMdl(mdl);
	}
	return (error);
}

int
uiomove(
    void *cp,
    int n,
    struct uio *uio)
{
	void *ptr = NULL;
	int iov_len = 0;
	struct iovec *iov;
	PNDIS_BUFFER buffer, next_buffer;
	PMDL mdl = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "uiomove - enter\n");

	if (uio == NULL || (uio->uio_iov == NULL && uio->uio_buffer == NULL)) {
		DebugPrint(DEBUG_KERN_VERBOSE, "uiomove - leave#1\n");
		return EINVAL;
	}

	if (uio->uio_iov != NULL) {
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
				if (uio->uio_segflg == UIO_USERSPACE) {
					copyout(cp, iov->iov_base, iov_len);
				} else if (
				    uio->uio_segflg == UIO_SYSSPACE) {
					RtlCopyMemory(iov->iov_base, cp, iov_len);
				}
			} else {
				if (uio->uio_segflg == UIO_USERSPACE) {
					copyin(iov->iov_base, cp, iov_len);
				} else if (
				    uio->uio_segflg == UIO_SYSSPACE) {
					RtlCopyMemory(cp, iov->iov_base, iov_len);
				}
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
		while (n > 0 && uio->uio_buffer != NULL && uio->uio_resid) {
			NdisQueryBufferSafe(uio->uio_buffer, &ptr, &iov_len, NormalPagePriority);
			if (ptr == NULL) {
				return ENOMEM;
			}

			if (ptr == NULL || uio->uio_buffer_offset >= iov_len) {
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
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "uiomove - leave\n");
	return 0;
}

PVOID
LockRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	DebugPrint(DEBUG_KERN_VERBOSE, "LockRequest - enter\n");

	irp->MdlAddress = IoAllocateMdl(
	    irpSp->Parameters.DeviceIoControl.Type3InputBuffer,
	    irpSp->Parameters.DeviceIoControl.InputBufferLength,
	    FALSE,
	    FALSE,
	    NULL);
	if (irp->MdlAddress == NULL) {
		DebugPrint(DEBUG_KERN_VERBOSE, "LockRequest - leave#1\n");
		return NULL;
	}

	MmProbeAndLockPages(irp->MdlAddress, KernelMode, IoModifyAccess);
	irpSp->Parameters.DeviceIoControl.Type3InputBuffer = MmMapLockedPagesSpecifyCache(
	    irp->MdlAddress,
	    KernelMode,
	    MmCached,
	    NULL,
	    FALSE,
	    NormalPagePriority);

	DebugPrint(DEBUG_KERN_VERBOSE, "LockRequest - leave\n");
	return irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
}

VOID
UnlockRequest(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	DebugPrint(DEBUG_KERN_VERBOSE, "UnlockRequest - enter\n");
	MmUnmapLockedPages(
	    irpSp->Parameters.DeviceIoControl.Type3InputBuffer,
	    irp->MdlAddress);
	MmUnlockPages(irp->MdlAddress);
	IoFreeMdl(irp->MdlAddress);
	irp->MdlAddress = NULL;
	DebugPrint(DEBUG_KERN_VERBOSE, "UnlockRequest - leave\n");
}

NTSTATUS
LockBuffer(
    IN void *uaddr,
    IN size_t len,
    IN LOCK_OPERATION operation,
    OUT PMDL *mdl0)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMDL mdl = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "LockBuffer - enter\n");
	if (uaddr == NULL || mdl0 == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "LockBuffer - leave#1\n");
		goto error;
	}

	*mdl0 = mdl = IoAllocateMdl(uaddr, len, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DebugPrint(DEBUG_KERN_VERBOSE, "LockBuffer - leave#2\n");
		goto error;
	}
	__try {
		MmProbeAndLockPages(mdl, KernelMode, operation);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		DebugPrint(DEBUG_KERN_VERBOSE, "LockBuffer - leave#3\n");
		goto error;
	}

	DebugPrint(DEBUG_KERN_VERBOSE, "LockBuffer - leave\n");
	return status;
error:
	if (mdl != NULL) {
		IoFreeMdl(mdl);
	}
	if (mdl0 != NULL) {
		*mdl0 = NULL;
	}
	return status;
}

VOID
UnlockBuffer(
    IN PMDL mdl)
{
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
}


PFILE_FULL_EA_INFORMATION
FindEAInfo(
    IN PFILE_FULL_EA_INFORMATION start,
    IN CHAR *target,
    IN USHORT length)
{
	int i, ii;
	PFILE_FULL_EA_INFORMATION ptr;

	DebugPrint(DEBUG_KERN_VERBOSE, "FindEAInfo - enter\n");

	do {
		ptr = start;
		start += ptr->NextEntryOffset;

        	if (ptr->EaNameLength != length) {
			continue;
		}
		if (RtlCompareMemory(ptr->EaName, target, length) == length) {
			DebugPrint(DEBUG_KERN_VERBOSE, "FindEAInfo - leave#1\n");
			return ptr;
		}
        } while (ptr->NextEntryOffset != 0);

	DebugPrint(DEBUG_KERN_VERBOSE, "FindEAInfo - leave\n");
	return NULL;
}
