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

#include <string.h>

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

MALLOC_DEFINE(M_SYSCTL, 'km00', "sysctl", "sysctl");

struct sysctl_oid_list sysctl_oid_top;

void
sysctl_init(void)
{
	SLIST_INIT(&sysctl_oid_top);
#ifdef DBG
	sysctl_add_oid(&sysctl_oid_top, "dbg", CTLTYPE_INT|CTLFLAG_RW,
	    &debug_on, sizeof(debug_on), NULL, "Configure debug output");
#endif
#ifdef SCTP
	sysctl_setup_sctp();
#endif
}


void
sysctl_destroy(void)
{
	struct sysctl_oid *oidp, *oidp2;

	SLIST_FOREACH_SAFE(oidp, &sysctl_oid_top, oid_link, oidp2) {
		if (oidp->oid_name != NULL) {
			FREE(oidp->oid_name, M_SYSCTL);
			oidp->oid_name = NULL;
		}
		if (oidp->oid_desc != NULL) {
			FREE(oidp->oid_desc, M_SYSCTL);
			oidp->oid_desc = NULL;
		}
		SLIST_REMOVE(&sysctl_oid_top, oidp, sysctl_oid, oid_link);
		FREE(oidp, M_SYSCTL);
	}
}

struct sysctl_oid *
sysctl_find_byname(const char *name)
{
	struct sysctl_oid *oid = NULL;

	if (name != NULL) {
		if (*name != '\0') {
			SLIST_FOREACH(oid, &sysctl_oid_top, oid_link) {
				if (strcmp(oid->oid_name, name) == 0) {
					break;
				}
			}
		} else {
			oid = SLIST_FIRST(&sysctl_oid_top);
		}
	}
	return oid;
}

void
sysctl_add_oid(
    struct sysctl_oid_list *head,
    const char *name,
    uint32_t kind,
    void *arg1,
    int arg2,
    int (*handler)(struct sysctl_oid *, void *, int, struct sysctl_req *),
    const char *desc)
{
	struct sysctl_oid *oidp = NULL;
	int len;

	MALLOC(oidp, struct sysctl_oid *, sizeof(struct sysctl_oid), M_SYSCTL, M_ZERO);
	if (oidp == NULL) {
		goto error;
	}

	if (name != NULL) {
		len = strlen(name);
		MALLOC(oidp->oid_name, char *, len + 1, M_SYSCTL, M_ZERO);
		if (oidp->oid_name == NULL) {
			goto error;
		}
		strncpy(oidp->oid_name, name, len);
	}
	if (desc != NULL) {
		len = strlen(desc);
		MALLOC(oidp->oid_desc, char *, len + 1, M_SYSCTL, M_ZERO);
		if (oidp->oid_desc == NULL) {
			goto error;
		}
		strncpy(oidp->oid_desc, desc, len);
	}

	oidp->oid_kind = kind;
	oidp->oid_arg1 = arg1;
	oidp->oid_arg2 = arg2;
	oidp->oid_handler = handler;

	SLIST_INSERT_HEAD(head, oidp, oid_link);
	return;

error:
	if (oidp != NULL && oidp->oid_desc != NULL) {
		FREE(oidp->oid_desc, M_SYSCTL);
	}

	if (oidp != NULL && oidp->oid_name != NULL) {
		FREE(oidp->oid_name, M_SYSCTL);
	}

	if (oidp != NULL) {
		FREE(oidp, M_SYSCTL);
	}
}

int
sysctl_copyout(
    struct sysctl_req *req,
    void *ptr,
    int len)
{
	int error = 0;
	int i = 0;

	if (req->data != NULL) {
		i = len;
		if ((req->datalen - req->dataidx) < len) {
			i = 0;
		}
		if (i > 0) {
			error = copyout(ptr, (char *)req->data + req->dataidx, i);
			if (error != 0) {
				return error;
			}
		}
	}

	req->dataidx += len;
	if (req->data != NULL && i != len) {
		error = ENOMEM;
	}

	return error;
}

int
sysctl_copyin(
    struct sysctl_req *req,
    void *ptr,
    int len)
{
	int error = 0;

	if (req->new_data == NULL) {
		return EINVAL;
	}
	if ((req->new_datalen - req->new_dataidx) < len) {
		return EINVAL;
	}

	error = copyin((char *)req->new_data + req->new_dataidx, ptr, len);
	if (error != 0) {
		return error;
	}

	req->new_dataidx += len;

	return 0;
}

int
sysctl_handle_int(SYSCTL_HANDLER_ARGS)
{
	int tmpout, error = 0;

	if (arg1 != NULL) {
		tmpout = *(int *)arg1;
	} else {
		tmpout = arg2;
	}

	error = SYSCTL_OUT(req, &tmpout, sizeof(int));
	if (error != 0) {
		return error;
	}

	if (req->new_data == NULL) {
		return 0;
	}
	if (arg1 == NULL || (oidp->oid_kind & CTLFLAG_WR) == 0) {
		return EPERM;
	}

	error = SYSCTL_IN(req, arg1, sizeof(int));
	return error;
}

int
sysctl_handle_struct(SYSCTL_HANDLER_ARGS)
{
	int error = 0;

	if (arg1 == NULL) {
		return EPERM;
	}

	error = SYSCTL_OUT(req, arg1, arg2);
	if (error != 0) {
		return error;
	}

	if (req->new_data == NULL) {
		return 0;
	}
	if ((oidp->oid_kind & CTLFLAG_WR) == 0) {
		return EPERM;
	}

	error = SYSCTL_IN(req, arg1, arg2);
	return error;
}


NTSTATUS
SCTPDispatchSysctl(
    IN PIRP irp,
    IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	int error = 0;
	struct sysctl_req *req = NULL;
	struct sysctl_oid *oidp = NULL, *nxt_oidp = NULL;
	char *name = NULL;

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - enter\n");

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct sysctl_req) ||
	    irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(struct sysctl_req)) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#1\n");
		goto done;
	}
	req = (struct sysctl_req *)irp->AssociatedIrp.SystemBuffer;

	if (req->namelen > 0) {
		MALLOC(name, char *, req->namelen, M_SYSCTL, M_ZERO);
		if (name == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#2\n");
			goto done;
		}
		if (copyin(req->name, name, req->namelen) < 0) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#3\n");
			goto done;
		}
		name[req->namelen - 1] = '\0';
		oidp = sysctl_find_byname(name);
	} else {
		oidp = SLIST_FIRST(&sysctl_oid_top);
	}

	if (oidp == NULL || oidp->oid_name == NULL) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#4\n");
		goto done;
	}

	if (oidp->oid_handler != NULL) {
		error = oidp->oid_handler(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	} else {
		switch (oidp->oid_kind & CTLTYPE_MASK) {
		case CTLTYPE_INT:
			error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
			break;
		case CTLTYPE_STRUCT:
			error = sysctl_handle_struct(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
			break;
		default:
			error = EINVAL;
		}
	}
	if (error != 0) {
		status = STATUS_INVALID_PARAMETER;
		DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#5\n");
		goto done;
	}


	if (req->namelen >= strlen(oidp->oid_name) + 1) {
		if (copyout(oidp->oid_name, req->name, strlen(oidp->oid_name) + 1) < 0) {
			status = STATUS_INVALID_PARAMETER;
			DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#6\n");
			goto done;
		}
	}
	req->namelen = strlen(oidp->oid_name) + 1;

	if (oidp->oid_desc != NULL) {
		if (req->desclen >= strlen(oidp->oid_desc) + 1) {
			if (copyout(oidp->oid_desc, req->desc, strlen(oidp->oid_desc) + 1) < 0) {
				status = STATUS_INVALID_PARAMETER;
				DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#7\n");
				goto done;
			}
		}
		req->descidx = strlen(oidp->oid_desc) + 1;
	}

	nxt_oidp = SLIST_NEXT(oidp, oid_link);
	if (nxt_oidp != NULL && nxt_oidp->oid_name != NULL) {
		if (req->nxt_namelen >= strlen(nxt_oidp->oid_name) + 1) {
			if (copyout(nxt_oidp->oid_name, req->nxt_name, strlen(nxt_oidp->oid_name) + 1) < 0) {
				status = STATUS_INVALID_PARAMETER;
				DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave#8\n");
				goto done;
			}
		}
		req->nxt_nameidx = strlen(nxt_oidp->oid_name) + 1;
	}
	req->kind = oidp->oid_kind;

	irp->IoStatus.Information = sizeof(struct sysctl_req);

	DebugPrint(DEBUG_KERN_VERBOSE, "SCTPDispatchReadSysctl - leave\n");
done:
	return status;
}
