/*-
 * Copyright (c) 1982, 1985, 1986, 1988, 1993, 1994
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
 *	@(#)socket.h	8.4 (Berkeley) 2/21/94
 * $FreeBSD: src/sys/sys/socket.h,v 1.102 2008/08/08 22:40:04 delphij Exp $
 */

#ifndef _SYS_SOCKET_H_
#define	_SYS_SOCKET_H_

#include <ntifs.h>

#include <ws2def.h>
#include <ws2ipdef.h>

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/iovec.h>

/*
 * Definitions related to sockets: types, address families, options.
 */

/*
 * Types
 */
#define	SOCK_STREAM	1		/* stream socket */
#define	SOCK_DGRAM	2		/* datagram socket */
#define	SOCK_RAW	3		/* raw-protocol interface */
#if __BSD_VISIBLE
#define	SOCK_RDM	4		/* reliably-delivered message */
#endif
#define	SOCK_SEQPACKET	5		/* sequenced packet stream */

/*
 * Option flags per-socket.
 */
#define	SO_DEBUG	0x0001		/* turn on debugging info recording */
#define	SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */
#define	SO_USELOOPBACK	0x0040		/* bypass hardware when possible */
#define	SO_LINGER	0x0080		/* linger on close if data present */
#define	SO_OOBINLINE	0x0100		/* leave received OOB data in line */
#if __BSD_VISIBLE
#define	SO_REUSEPORT	0x0200		/* allow local address & port reuse */
#define	SO_TIMESTAMP	0x0400		/* timestamp received dgram traffic */
#define	SO_NOSIGPIPE	0x0800		/* no SIGPIPE from EPIPE */
#define	SO_ACCEPTFILTER	0x1000		/* there is an accept filter */
#define	SO_BINTIME	0x2000		/* timestamp received dgram traffic */
#endif
#define	SO_DONTLINGER		(int)(~SO_LINGER)
#define	SO_EXCLUSIVEADDRUSE	((int)(~SO_REUSEADDR))

/*
 * Additional options, not kept in so_options.
 */
#define	SO_SNDBUF	0x1001		/* send buffer size */
#define	SO_RCVBUF	0x1002		/* receive buffer size */
#define	SO_SNDLOWAT	0x1003		/* send low-water mark */
#define	SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define	SO_SNDTIMEO	0x1005		/* send timeout */
#define	SO_RCVTIMEO	0x1006		/* receive timeout */
#define	SO_ERROR	0x1007		/* get error status and clear */
#define	SO_TYPE		0x1008		/* get socket type */
#if __BSD_VISIBLE
#define	SO_LABEL	0x1009		/* socket's MAC label */
#define	SO_PEERLABEL	0x1010		/* socket's peer's MAC label */
#define	SO_LISTENQLIMIT	0x1011		/* socket's backlog limit */
#define	SO_LISTENQLEN	0x1012		/* socket's complete queue length */
#define	SO_LISTENINCQLEN	0x1013	/* socket's incomplete queue length */
#define SO_SETFIB	0x1014		/* use this FIB to route */
#endif

/*
 * Structure used for manipulating linger option.
 */
struct linger {
	int	l_onoff;		/* option on/off */
	int	l_linger;		/* linger time */
};

#if __BSD_VISIBLE
struct accept_filter_arg {
	char	af_name[16];
	char	af_arg[256-16];
};
#endif
#define	SO_NO_OFFLOAD	0x4000		/* socket cannot be offloaded */
#define	SO_NO_DDP	0x8000		/* disable direct data placement */

#define	FD_READ_BIT	 0
#define FD_READ		 (1 << FD_READ_BIT)

#define FD_WRITE_BIT	 1
#define FD_WRITE	 (1 << FD_WRITE_BIT)

#define FD_OOB_BIT	 2
#define FD_OOB		 (1 << FD_OOB_BIT)

#define FD_ACCEPT_BIT	 3
#define FD_ACCEPT	 (1 << FD_ACCEPT_BIT)

#define FD_CONNECT_BIT	 4
#define FD_CONNECT	 (1 << FD_CONNECT_BIT)

#define FD_CLOSE_BIT	 5
#define FD_CLOSE	 (1 << FD_CLOSE_BIT)

#define FD_QOS_BIT	 6
#define FD_QOS		 (1 << FD_QOS_BIT)

#define FD_GROUP_QOS_BIT 7
#define FD_GROUP_QOS	 (1 << FD_GROUP_QOS_BIT)

#define FD_ROUTING_INTERFACE_CHANGE_BIT 8
#define FD_ROUTING_INTERFACE_CHANGE	(1 << FD_ROUTING_INTERFACE_CHANGE_BIT)

#define FD_ADDRESS_LIST_CHANGE_BIT 9
#define FD_ADDRESS_LIST_CHANGE	   (1 << FD_ADDRESS_LIST_CHANGE_BIT)

#define FD_MAX_EVENTS	 10
#define FD_ALL_EVENTS	 ((1 << FD_MAX_EVENTS) - 1)

typedef struct _WSANETWORKEVENTS {
	long lNetworkEvents;
	int iErrorCode[FD_MAX_EVENTS];
} WSANETWORKEVENTS, *LPWSANETWORKEVENTS;


/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	SOL_SOCKET	0xffff		/* options for socket level */

#if __BSD_VISIBLE
/*
 * Protocol families, same as address families for now.
 */
#define	PF_UNSPEC	AF_UNSPEC
#define	PF_LOCAL	AF_LOCAL
#define	PF_UNIX		PF_LOCAL	/* backward compatibility */
#define	PF_INET		AF_INET
#define	PF_IMPLINK	AF_IMPLINK
#define	PF_PUP		AF_PUP
#define	PF_CHAOS	AF_CHAOS
#define	PF_NETBIOS	AF_NETBIOS
#define	PF_ISO		AF_ISO
#define	PF_OSI		AF_ISO
#define	PF_ECMA		AF_ECMA
#define	PF_DATAKIT	AF_DATAKIT
#define	PF_CCITT	AF_CCITT
#define	PF_SNA		AF_SNA
#define PF_DECnet	AF_DECnet
#define PF_DLI		AF_DLI
#define PF_LAT		AF_LAT
#define	PF_HYLINK	AF_HYLINK
#define	PF_APPLETALK	AF_APPLETALK
#define	PF_ROUTE	AF_ROUTE
#define	PF_LINK		AF_LINK
#define	PF_XTP		pseudo_AF_XTP	/* really just proto family, no AF */
#define	PF_COIP		AF_COIP
#define	PF_CNT		AF_CNT
#define	PF_SIP		AF_SIP
#define	PF_IPX		AF_IPX
#define PF_RTIP		pseudo_AF_RTIP	/* same format as AF_INET */
#define PF_PIP		pseudo_AF_PIP
#define	PF_ISDN		AF_ISDN
#define	PF_KEY		pseudo_AF_KEY
#define	PF_INET6	AF_INET6
#define	PF_NATM		AF_NATM
#define	PF_ATM		AF_ATM
#define	PF_NETGRAPH	AF_NETGRAPH
#define	PF_SLOW		AF_SLOW
#define PF_SCLUSTER	AF_SCLUSTER
#define	PF_ARP		AF_ARP
#define	PF_BLUETOOTH	AF_BLUETOOTH

#define	PF_MAX		AF_MAX

/*
 * Definitions for network related sysctl, CTL_NET.
 *
 * Second level is protocol family.
 * Third level is protocol number.
 *
 * Further levels are defined by the individual families below.
 */
#define NET_MAXID	AF_MAX

#define CTL_NET_NAMES { \
	{ 0, 0 }, \
	{ "unix", CTLTYPE_NODE }, \
	{ "inet", CTLTYPE_NODE }, \
	{ "implink", CTLTYPE_NODE }, \
	{ "pup", CTLTYPE_NODE }, \
	{ "chaos", CTLTYPE_NODE }, \
	{ "xerox_ns", CTLTYPE_NODE }, \
	{ "iso", CTLTYPE_NODE }, \
	{ "emca", CTLTYPE_NODE }, \
	{ "datakit", CTLTYPE_NODE }, \
	{ "ccitt", CTLTYPE_NODE }, \
	{ "ibm_sna", CTLTYPE_NODE }, \
	{ "decnet", CTLTYPE_NODE }, \
	{ "dec_dli", CTLTYPE_NODE }, \
	{ "lat", CTLTYPE_NODE }, \
	{ "hylink", CTLTYPE_NODE }, \
	{ "appletalk", CTLTYPE_NODE }, \
	{ "route", CTLTYPE_NODE }, \
	{ "link_layer", CTLTYPE_NODE }, \
	{ "xtp", CTLTYPE_NODE }, \
	{ "coip", CTLTYPE_NODE }, \
	{ "cnt", CTLTYPE_NODE }, \
	{ "rtip", CTLTYPE_NODE }, \
	{ "ipx", CTLTYPE_NODE }, \
	{ "sip", CTLTYPE_NODE }, \
	{ "pip", CTLTYPE_NODE }, \
	{ "isdn", CTLTYPE_NODE }, \
	{ "key", CTLTYPE_NODE }, \
	{ "inet6", CTLTYPE_NODE }, \
	{ "natm", CTLTYPE_NODE }, \
	{ "atm", CTLTYPE_NODE }, \
	{ "hdrcomplete", CTLTYPE_NODE }, \
	{ "netgraph", CTLTYPE_NODE }, \
	{ "snp", CTLTYPE_NODE }, \
	{ "scp", CTLTYPE_NODE }, \
}

/*
 * PF_ROUTE - Routing table
 *
 * Three additional levels are defined:
 *	Fourth: address family, 0 is wildcard
 *	Fifth: type of info, defined below
 *	Sixth: flag(s) to mask with for NET_RT_FLAGS
 */
#define NET_RT_DUMP	1		/* dump; may limit to a.f. */
#define NET_RT_FLAGS	2		/* by flags, e.g. RESOLVING */
#define NET_RT_IFLIST	3		/* survey interface list */
#define	NET_RT_IFMALIST	4		/* return multicast address list */
#define	NET_RT_MAXID	5

#define CTL_NET_RT_NAMES { \
	{ 0, 0 }, \
	{ "dump", CTLTYPE_STRUCT }, \
	{ "flags", CTLTYPE_STRUCT }, \
	{ "iflist", CTLTYPE_STRUCT }, \
	{ "ifmalist", CTLTYPE_STRUCT }, \
}
#endif /* __BSD_VISIBLE */

/*
 * Maximum queue length specifiable by listen.
 */
#define	SOMAXCONN	128

/*
 * Message header for recvmsg and sendmsg calls.
 * Used value-result for recvmsg, value only for sendmsg.
 */
struct msghdr {
	void		*msg_name;		/* optional address */
	socklen_t	 msg_namelen;		/* size of address */
	struct iovec	*msg_iov;		/* scatter/gather array */
	int		 msg_iovlen;		/* # elements in msg_iov */
	void		*msg_control;		/* ancillary data, see below */
	socklen_t	 msg_controllen;	/* ancillary data buffer len */
	int		 msg_flags;		/* flags on received message */
};

#define	MSG_OOB		0x0001		/* process out-of-band data */
#define	MSG_PEEK	0x0002		/* peek at incoming message */
#define	MSG_DONTROUTE	0x0004		/* send without using routing tables */
#define	MSG_WAITALL	0x0008		/* wait for full request or error */
#define MSG_PARTIAL	0x8000		/* partial send or recv for message xport */
#define MSG_NOTIFICATION 0x1000		/* SCTP notification */
#if __BSD_VISIBLE
#define	MSG_DONTWAIT	0x0010		/* this message should be nonblocking */
#define	MSG_EOF		0x0020		/* data completes connection */
#define	MSG_NBIO	0x0040		/* FIONBIO mode, used by fifofs */
#define	MSG_COMPAT      0x0080		/* used in sendit() */
#endif
#define	MSG_EOR		0x0100		/* data completes record */
#ifdef _KERNEL
#define	MSG_SOCALLBCK   0x0200		/* for use by socket callbacks - soreceive (TCP) */
#endif
#if __BSD_VISIBLE
#define	MSG_NOSIGNAL	0x0400		/* do not generate SIGPIPE on EOF */
#endif

#if __BSD_VISIBLE
/*
 * Socket credentials.
 */
#if 0
struct sockcred {
	uid_t	sc_uid;			/* real user id */
	uid_t	sc_euid;		/* effective user id */
	gid_t	sc_gid;			/* real group id */
	gid_t	sc_egid;		/* effective group id */
	int	sc_ngroups;		/* number of supplemental groups */
	gid_t	sc_groups[1];		/* variable length */
};

/*
 * Compute size of a sockcred structure with groups.
 */
#define	SOCKCREDSIZE(ngrps) \
	(sizeof(struct sockcred) + (sizeof(gid_t) * ((ngrps) - 1)))
#endif
#endif /* __BSD_VISIBLE */

#if _WIN32_WINNT < 0x0600
#define cmsghdr		_WSACMSGHDR
#define CMSG_ALIGN	WSA_CMSGHDR_ALIGN
#define CMSGDATA_ALIGN	WSA_CMSGDATA_ALIGN
#define CMSG_DATA	WSA_CMSG_DATA
#define CMSG_SPACE	WSA_CMSG_SPACE
#define CMSG_LEN	WSA_CMSG_LEN
#else
#define CMSG_ALIGN	WSA_CMSGHDR_ALIGN
#define CMSG_DATA	WSA_CMSG_DATA
#endif

/* "Socket"-level control message types: */
#define	SCM_RIGHTS	0x01		/* access rights (array of int) */
#if __BSD_VISIBLE
#define	SCM_TIMESTAMP	0x02		/* timestamp (struct timeval) */
#define	SCM_CREDS	0x03		/* process creds (struct cmsgcred) */
#define	SCM_BINTIME	0x04		/* timestamp (struct bintime) */
#endif

#if __BSD_VISIBLE
/*
 * 4.3 compat sockaddr, move to compat file later
 */
struct osockaddr {
	unsigned short sa_family;	/* address family */
	char	sa_data[14];		/* up to 14 bytes of direct address */
};

/*
 * 4.3-compat message header (move to compat file later).
 */
struct omsghdr {
	char	*msg_name;		/* optional address */
	int	msg_namelen;		/* size of address */
	struct	iovec *msg_iov;		/* scatter/gather array */
	int	msg_iovlen;		/* # elements in msg_iov */
	char	*msg_accrights;		/* access rights sent/received */
	int	msg_accrightslen;
};
#endif

/*
 * howto arguments for shutdown(2), specified by Posix.1g.
 */
#define	SHUT_RD		0		/* shut down the reading side */
#define	SHUT_WR		1		/* shut down the writing side */
#define	SHUT_RDWR	2		/* shut down both sides */

/* we cheat and use the SHUT_XX defines for these */
#define PRU_FLUSH_RD     SHUT_RD
#define PRU_FLUSH_WR     SHUT_WR
#define PRU_FLUSH_RDWR   SHUT_RDWR


#if __BSD_VISIBLE
/*
 * sendfile(2) header/trailer struct
 */
struct sf_hdtr {
	struct iovec *headers;	/* pointer to an array of header struct iovec's */
	int hdr_cnt;		/* number of header iovec's */
	struct iovec *trailers;	/* pointer to an array of trailer struct iovec's */
	int trl_cnt;		/* number of trailer iovec's */
};

/*
 * Sendfile-specific flag(s)
 */
#define	SF_NODISKIO     0x00000001
#define	SF_MNOWAIT	0x00000002
#define	SF_SYNC		0x00000004
#endif

#ifndef	_KERNEL

#include <sys/cdefs.h>

__BEGIN_DECLS
int	accept(int, struct sockaddr * __restrict, socklen_t * __restrict);
int	bind(int, const struct sockaddr *, socklen_t);
int	connect(int, const struct sockaddr *, socklen_t);
int	getpeername(int, struct sockaddr * __restrict, socklen_t * __restrict);
int	getsockname(int, struct sockaddr * __restrict, socklen_t * __restrict);
int	getsockopt(int, int, int, void * __restrict, socklen_t * __restrict);
int	listen(int, int);
ssize_t	recv(int, void *, size_t, int);
ssize_t	recvfrom(int, void *, size_t, int, struct sockaddr * __restrict, socklen_t * __restrict);
ssize_t	recvmsg(int, struct msghdr *, int);
ssize_t	send(int, const void *, size_t, int);
ssize_t	sendto(int, const void *,
	    size_t, int, const struct sockaddr *, socklen_t);
ssize_t	sendmsg(int, const struct msghdr *, int);
#if __BSD_VISIBLE
int	sendfile(int, int, off_t, size_t, struct sf_hdtr *, off_t *, int);
int	setfib(int);
#endif
int	setsockopt(int, int, int, const void *, socklen_t);
int	shutdown(int, int);
int	sockatmark(int);
int	socket(int, int, int);
int	socketpair(int, int, int, int *);
__END_DECLS

#endif /* !_KERNEL */

#ifdef _KERNEL
struct socket;

struct tcpcb *so_sototcpcb(struct socket *so);
struct inpcb *so_sotoinpcb(struct socket *so);
struct sockbuf *so_sockbuf_snd(struct socket *);
struct sockbuf *so_sockbuf_rcv(struct socket *);

int so_state_get(const struct socket *);
void so_state_set(struct socket *, int);

int so_options_get(const struct socket *);
void so_options_set(struct socket *, int);

int so_error_get(const struct socket *);
void so_error_set(struct socket *, int);

int so_linger_get(const struct socket *);
void so_linger_set(struct socket *, int);

struct protosw *so_protosw_get(const struct socket *);
void so_protosw_set(struct socket *, struct protosw *);

void so_sorwakeup_locked(struct socket *so);
void so_sowwakeup_locked(struct socket *so);

void so_sorwakeup(struct socket *so);
void so_sowwakeup(struct socket *so);

void so_lock(struct socket *so);
void so_unlock(struct socket *so);

void so_listeners_apply_all(struct socket *so, void (*func)(struct socket *, void *), void *arg);

#endif


#endif /* !_SYS_SOCKET_H_ */
