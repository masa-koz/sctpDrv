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
#ifndef _SYS_SYSCTL_H_
#define _SYS_SYSCTL_H_

#include <sys/types.h>
#include <sys/queue.h>

#define	CTL_MAXNAME	24

#define CTLTYPE_MASK	0x000f
#define CTLTYPE_INT	0x0001
#define CTLTYPE_STRING	0x0002
#define CTLTYPE_QUAD	0x0003
#define CTLTYPE_STRUCT	0x0004
#define CTLTYPE_UINT	0x0005
#define CTLTYPE_LONG	0x0006
#define CTLTYPE_ULONG	0x0007

#define CTLFLAG_RD	0x00010000
#define CTLFLAG_WR	0x00020000
#define CTLFLAG_RW	(CTLFLAG_RD|CTLFLAG_WR)


MALLOC_DECLARE(M_SYSCTL);

struct sysctl_req {
	char		*name;
	INT		namelen;
	ULONG		kind;
	void		*data;
	INT		datalen;
	INT		dataidx;
	void		*new_data;
	INT		new_datalen;
	INT		new_dataidx;
	char		*desc;
	INT		desclen;
	INT		descidx;
	char		*nxt_name;
	INT		nxt_namelen;
	INT		nxt_nameidx;
};

#if defined(_KERNEL)
struct sysctl_oid {
	SLIST_ENTRY(sysctl_oid)	oid_link;
	uint32_t		oid_kind;
	void			*oid_arg1;
	int			oid_arg2;
	char			*oid_name;
	int			(*oid_handler)(struct sysctl_oid *, void *, int, struct sysctl_req *);
	char			*oid_desc;
};
SLIST_HEAD(sysctl_oid_list, sysctl_oid);

extern struct sysctl_oid_list sysctl_oid_top;

void sysctl_init(void);
void sysctl_destroy(void);
struct sysctl_oid *sysctl_find_byname(const char *);


#define SYSCTL_HANDLER_ARGS struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req
#define SYSCTL_OUT sysctl_copyout
#define SYSCTL_IN sysctl_copyin

int sysctl_copyout(struct sysctl_req *, void *, int);
int sysctl_copyin(struct sysctl_req *, void *, int);
int sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int sysctl_handle_struct(SYSCTL_HANDLER_ARGS);

void sysctl_add_oid(struct sysctl_oid_list *, const char *, uint32_t,
    void *, int, int (*)(struct sysctl_oid *, void *, int, struct sysctl_req *),
    const char *);

NTSTATUS SCTPDispatchSysctl(IN PIRP, IN PIO_STACK_LOCATION);
    
#ifdef SCTP
void sysctl_setup_sctp(void);
#endif
#endif /* KERNEL */

#endif /* _SYS_SYSCTL_H_ */
