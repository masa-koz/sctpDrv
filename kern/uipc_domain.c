/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 *	@(#)uipc_domain.c	8.2 (Berkeley) 10/18/93
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/kern/uipc_domain.c,v 1.52 2008/03/16 10:58:05 rwatson Exp $");

#include <ntifs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <netinet/in.h>
#include <netinet6/in6.h>

extern KSPIN_LOCK so_global_lock;

struct domain *domains;		/* registered protocol domains */

/*
 * Dummy protocol specific user requests function pointer array.
 * All functions return EOPNOTSUPP.
 */
struct pr_usrreqs nousrreqs = {
	NULL,			/* pru_abort */
	pru_accept_notsupp, 	/* pru_accept */
	pru_attach_notsupp,	/* pru_attach */
	pru_bind_notsupp,	/* pru_bind */
	pru_connect_notsupp,	/* pru_connect */
	pru_connect2_notsupp,	/* pru_connect2 */
	pru_control_notsupp,	/* pru_control */
	NULL,			/* pru_detach */
	pru_disconnect_notsupp,	/* pru_disconnect */
	pru_listen_notsupp,	/* pru_listen */
	pru_peeraddr_notsupp,	/* pru_peeraddr */
	pru_rcvd_notsupp,	/* pru_rcvd */
	pru_rcvoob_notsupp,	/* pru_rcvoob */
	pru_send_notsupp,	/* pru_send */
	pru_sense_null,		/* pru_sense */
	pru_shutdown_notsupp,	/* pru_shutdown */
	NULL,			/* pru_flush */
	pru_sockaddr_notsupp,	/* pru_sockaddr */
	pru_sosend_notsupp,	/* pru_sosend */
	pru_soreceive_notsupp,	/* pru_soreceive */
	pru_sopoll_notsupp,	/* pru_sopoll */
	NULL,			/* pru_sosetlabel */
	NULL,			/* pru_close */
};

static void
protosw_init(struct protosw *pr)
{
	struct pr_usrreqs *pu;

	pu = pr->pr_usrreqs;
	KASSERT(pu != NULL, ("protosw_init: %ssw[%d] has no usrreqs!",
	    pr->pr_domain->dom_name,
	    (int)(pr - pr->pr_domain->dom_protosw)));

#define DEFAULT(foo, bar)	if ((foo) == NULL)  (foo) = (bar)
	DEFAULT(pu->pru_accept, pru_accept_notsupp);
	DEFAULT(pu->pru_connect, pru_connect_notsupp);
	DEFAULT(pu->pru_connect2, pru_connect2_notsupp);
	DEFAULT(pu->pru_control, pru_control_notsupp);
	DEFAULT(pu->pru_listen, pru_listen_notsupp);
	DEFAULT(pu->pru_rcvd, pru_rcvd_notsupp);
	DEFAULT(pu->pru_rcvoob, pru_rcvoob_notsupp);
	DEFAULT(pu->pru_sense, pru_sense_null);
	DEFAULT(pu->pru_sosend, pru_sosend_notsupp);
	DEFAULT(pu->pru_soreceive, pru_soreceive_notsupp);
	DEFAULT(pu->pru_sopoll, pru_sopoll_notsupp);
#undef DEFAULT
	if (pr->pr_init)
		(*pr->pr_init)();
}

/* ARGSUSED*/
void
domaininit(void)
{

	KeInitializeSpinLock(&accept_lock);
	KeInitializeSpinLock(&so_global_lock);

	/*
	 * Before we do any setup, make sure to initialize the
	 * zone allocator we get struct sockets from.
	 */
	ExInitializeNPagedLookasideList(&socket_zone, NULL, NULL, 0, sizeof(struct socket), 0x64657246, 0);
	if (max_linkhdr < 16)		/* XXX */
		max_linkhdr = 16;

	inetdomain.dom_next = &inet6domain;
	domains = &inetdomain;
}

void
domaindestroy(void)
{
	ExDeleteNPagedLookasideList(&socket_zone);
}

struct protosw *
pffindtype(int family, int type)
{
	struct domain *dp;
	struct protosw *pr;

	for (dp = domains; dp; dp = dp->dom_next)
		if (dp->dom_family == family)
			goto found;
	return (0);
found:
	for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
		if (pr->pr_type && pr->pr_type == type)
			return (pr);
	return (0);
}

struct protosw *
pffindproto(int family, int protocol, int type)
{
	struct domain *dp;
	struct protosw *pr;
	struct protosw *maybe = 0;

	if (family == 0)
		return (0);
	for (dp = domains; dp; dp = dp->dom_next)
		if (dp->dom_family == family)
			goto found;
	return (0);
found:
	for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++) {
		if ((pr->pr_protocol == protocol) && (pr->pr_type == type))
			return (pr);

		if (type == SOCK_RAW && pr->pr_type == SOCK_RAW &&
		    pr->pr_protocol == 0 && maybe == (struct protosw *)0)
			maybe = pr;
	}
	return (maybe);
}
