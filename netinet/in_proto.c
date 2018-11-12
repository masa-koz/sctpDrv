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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/protosw.h>

#include <netinet/in.h>
#ifdef SCTP
#include <netinet/sctp_var.h>
#endif

extern struct pr_usrreqs nousrreqs;

struct protosw inetsw[] = {
{
	SOCK_RAW,	/* pr_type */
	&inetdomain,	/* pr_domain */
	IPPROTO_ICMP,	/* pr_protocol */
	PR_WANTRCVD,	/* pr_flags */
	NULL,		/* XXX pr_input */
	NULL,		/* XXX pr_output */
	NULL,		/* XXX pr_ctlinput */
	NULL,		/* XXX pr_ctloutput */
	NULL,		/* pr_ousrreq */
	NULL,		/* XXX pr_init */
	NULL,		/* XXX pr_fasttimo */
	NULL,		/* XXX pr_slowtimo */
	NULL,		/* XXX pr_drain */
	&nousrreqs,
},
#ifdef SCTP
{
	SOCK_DGRAM,	/* pr_type */
	&inetdomain,	/* pr_domain */
	IPPROTO_SCTP,	/* pr_protocol */
	PR_WANTRCVD,	/* pr_flags */
	sctp_input,	/* XXX pr_input */
	NULL,		/* XXX pr_output */
	sctp_ctlinput,	/* XXX pr_ctlinput */
	sctp_ctloutput,	/* XXX pr_ctloutput */
	NULL,		/* pr_ousrreq */
	NULL,		/* XXX pr_init */
	NULL,		/* XXX pr_fasttimo */
	NULL,		/* XXX pr_slowtimo */
	NULL,		/* XXX pr_drain */
	&sctp_usrreqs
},
{
	SOCK_SEQPACKET,	/* pr_type */
	&inetdomain,	/* pr_domain */
	IPPROTO_SCTP,	/* pr_protocol */
	PR_WANTRCVD,	/* pr_flags */
	sctp_input,	/* XXX pr_input */
	NULL,		/* XXX pr_output */
	sctp_ctlinput,	/* XXX pr_ctlinput */
	sctp_ctloutput,	/* XXX pr_ctloutput */
	NULL,		/* pr_ousrreq */
	NULL,		/* XXX pr_init */
	NULL,		/* XXX pr_fasttimo */
	NULL,		/* XXX pr_slowtimo */
	NULL,		/* XXX pr_drain */
	&sctp_usrreqs
},
{
	SOCK_STREAM,	/* pr_type */
	&inetdomain,	/* pr_domain */
	IPPROTO_SCTP,	/* pr_protocol */
	PR_WANTRCVD,	/* pr_flags */
	sctp_input,	/* XXX pr_input */
	NULL,		/* XXX pr_output */
	sctp_ctlinput,	/* XXX pr_ctlinput */
	sctp_ctloutput,	/* XXX pr_ctloutput */
	NULL,		/* pr_ousrreq */
	NULL,		/* XXX pr_init */
	NULL,		/* XXX pr_fasttimo */
	NULL,		/* XXX pr_slowtimo */
	NULL,		/* XXX pr_drain */
	&sctp_usrreqs
},
#endif
};

struct domain inetdomain = {
	AF_INET,	/* dom_family */
	"internet",	/* dom_name */
	NULL,		/* dom_init */
	NULL,		/* dom_externalize */
	NULL,		/* dom_dispose */
	inetsw,		/* dom_protosw */
	&inetsw[sizeof(inetsw)/sizeof(inetsw[0])],	/* dom_protoswNPROTOSW */
	NULL,		/* dom_next */
	NULL,		/* XXX dom_rtattach */
	0,		/* XXX dom_rtoffset */
	0,		/* dom_maxrtkey */
	NULL,		/* dom_ifattach */
	NULL,		/* dom_ifdetach */
};


u_char inetctlerrmap[PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		EMSGSIZE,	EHOSTDOWN,	EHOSTUNREACH,
	EHOSTUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		EHOSTUNREACH,	0,
	ENOPROTOOPT,	ECONNREFUSED
};
