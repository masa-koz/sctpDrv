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
 * $Id: sctp_os_windows.h,v 1.5 2007/04/25 11:49:44 kozuka Exp $
 */
#ifndef __sctp_os_windows_h__
#define __sctp_os_windows_h__
/*
 * includes
 */
#include "globals.h"

#include "mbuf.h"

#include "if.h"
#include "route.h"


#undef TYPE_ALIGNMENT
#define TYPE_ALIGNMENT( t ) __alignof(t)

#define cmsghdr wsacmsghdr
#define CMSG_ALIGN TDI_CMSGHDR_ALIGN
#define CMSGDATA_ALIGN TDI_CMSGDATA_ALIGN
#define CMSG_DATA TDI_CMSG_DATA
#define CMSG_SPACE TDI_CMSG_SPACE
#define CMSG_LEN TDI_CMSG_LEN

struct iovec {
	void	*iov_base;	/* Base address. */
	size_t	iov_len;	/* Length. */
};

enum uio_rw { UIO_READ, UIO_WRITE };

/* Segment flag values. */
enum uio_seg {
	UIO_USERSPACE,		/* from user data space */
	UIO_SYSSPACE,		/* from system space */
	UIO_NOCOPY		/* don't copy, already in object */
};

struct uio {
	PNDIS_BUFFER uio_buffer;
	unsigned int uio_buffer_offset;
	struct	iovec *uio_iov;
	int	uio_iovcnt;
	uint64_t uio_offset;
	int	uio_resid;
	enum	uio_seg uio_segflg;
	enum	uio_rw uio_rw;
	struct	thread *uio_td;
};

int uiomove(void *, unsigned int, struct uio *);

typedef struct route sctp_route_t;
#define NEW_STRUCT_ROUTE

typedef void (*RequestCompleteRoutine)(void *, unsigned int, unsigned int);


/* flags passed to ip_output as last parameter */
#define IP_FORWARDING           0x1             /* most of ip header exists */
#define IP_RAWOUTPUT            0x2             /* raw ip header exists */
#define IP_SENDONES             0x4             /* send all-ones broadcast */
#define IP_ROUTETOIF            SO_DONTROUTE    /* bypass routing tables */
#define IP_ALLOWBROADCAST       SO_BROADCAST    /* can send broadcast packets */

NTSTATUS IPOutput(IN struct mbuf *, IN struct route *);
__inline int
ip_output(
    struct mbuf *m,
    void *opt,
    struct route *ro,
    int flags,
    void *imo)
{
	NTSTATUS status;
	status = IPOutput(m, ro);
	if (status == STATUS_SUCCESS || status == STATUS_PENDING) {
		return 0;
	} else {
		return EINVAL;
	}
}
NTSTATUS IP6Output(IN struct mbuf *, IN struct route *);
__inline int
ip6_output(
    struct mbuf *m0,
    void *opt,
    struct route *ro,
    int flags,
    void *im6o,
    struct ifnet **ifpp)
{
	NTSTATUS status;
	status = IP6Output(m0, ro);
	if (status == STATUS_SUCCESS || status == STATUS_PENDING) {
		return 0;
	} else {
		return EINVAL;
	}
}

extern uint16_t ip_id;

struct proc {
	uint8_t dummy;
};

typedef struct sctp_dgrcv_request {
	BOOLEAN drr_queued;
	STAILQ_ENTRY(sctp_dgrcv_request) drr_entry;
	PNDIS_BUFFER drr_buffer;
	ULONG drr_size;
	PTDI_CONNECTION_INFORMATION drr_conninfo;
	RequestCompleteRoutine drr_complete;
	PVOID drr_context;
} SCTP_DGRCV_REQUEST, *PSCTP_DGRCV_REQUEST;
STAILQ_HEAD(sctp_dgrcv_request_head, sctp_dgrcv_request);

typedef struct sctp_dgsnd_request {
	BOOLEAN dsr_queued;
	STAILQ_ENTRY(sctp_dgsnd_request) dsr_entry;
	PNDIS_BUFFER dsr_buffer;
	ULONG dsr_size;
	struct sockaddr *dsr_addr;
	PTDI_CONNECTION_INFORMATION dsr_conninfo;
	RequestCompleteRoutine dsr_complete;
	PVOID dsr_context;
} SCTP_DGSND_REQUEST, *PSCTP_DGSND_REQUEST;
STAILQ_HEAD(sctp_dgsnd_request_head, sctp_dgsnd_request);

typedef	u_short	sa_family_t;

/*-
 * Locking key to struct socket:
 * (a) constant after allocation, no locking required.
 * (b) locked by SOCK_LOCK(so).
 * (c) locked by SOCKBUF_LOCK(&so->so_rcv).
 * (d) locked by SOCKBUF_LOCK(&so->so_snd).
 * (e) locked by ACCEPT_LOCK().
 * (f) not locked since integer reads/writes are atomic.
 * (g) used only as a sleep/wakeup address, no value.
 * (h) locked by global mutex so_global_mtx.
 */
struct socket {
	int	so_count;		/* (b) reference count */
	short	so_type;		/* (a) generic type, see socket.h */
	short	so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* (b) internal state flags SS_* */
	int	so_qstate;		/* (e) internal state flags SQ_* */
	void	*so_pcb;		/* protocol control block */
/*
 * Variables for connection queuing.
 * Socket where accepts occur is so_head in all subsidiary sockets.
 * If so_head is 0, socket is not related to an accept.
 * For head socket so_incomp queues partially completed connections,
 * while so_comp is a queue of connections ready to be accepted.
 * If a connection is aborted and it has so_head set, then
 * it has to be pulled out of either so_incomp or so_comp.
 * We allow connections to queue up based on current queue lengths
 * and limit on number of queued connections for this socket.
 */
	struct	socket *so_head;	/* (e) back pointer to accept socket */
	TAILQ_HEAD(, socket) so_incomp;	/* (e) queue of partial unaccepted connections */
	TAILQ_HEAD(, socket) so_comp;	/* (e) queue of complete unaccepted connections */
        TAILQ_ENTRY(socket) so_list;    /* (e) list of unaccepted connections */
	u_short	so_qlen;		/* (e) number of unaccepted connections */

	u_short	so_incqlen;		/* (e) number of unaccepted incomplete
					   connections */
	u_short	so_qlimit;		/* (e) max number queued connections */
	short	so_timeo;		/* (g) connection timeout */
	u_short	so_error;		/* (f) error affecting connection */
	struct sigio*so_sigio;		/* [sg] information for async I/O or
					   out of band data (SIGURG) */
	u_long	so_oobmark;		/* (c) chars to oob mark */
	TAILQ_HEAD(, aiocblist) so_aiojobq; /* AIO ops waiting on socket */
/*
 * Variables for socket buffering.
 */
	struct sockbuf {
#if 0
		struct	selinfo sb_sel;	/* process selecting read/write */
#endif
		KMUTEX	sb_mtx;		/* sockbuf lock */
		short	sb_state;	/* (c/d) socket state on sockbuf */
#define sb_startzero	sb_mb
		struct	mbuf *sb_mb;	/* (c/d) the mbuf chain */
		struct	mbuf *sb_mbtail;/* (c/d) the last mbuf in the chain */
		struct	mbuf *sb_lastrecord;/* (c/d) first mbuf of last
					     * record in socket buffer */
		u_int	sb_cc;		/* (c/d) actual chars in buffer */
		u_int	sb_hiwat;	/* (c/d) max actual char count */
		u_int	sb_mbcnt;	/* (c/d) chars of mbufs used */
		u_int	sb_mbmax;	/* (c/d) max chars of mbufs to use */
		u_int	sb_ctl;		/* (c/d) non-data chars in buffer */
		int	sb_lowat;	/* (c/d) low water mark */
		int	sb_timeo;	/* (c/d) timeout for read/write */
		short	sb_flags;	/* (c/d) flags, see below */
	} so_rcv, so_snd;
/*
 * Constants for sb_flags field of struct sockbuf.
 */
#define SB_MAX		(256*1024)	/* default for max chars in sockbuf */
/*
 * Constants for sb_flags field of struct sockbuf.
 */
#define SB_LOCK		0x01		/* lock on data queue */
#define SB_WANT		0x02		/* someone is waiting to lock */
#define SB_WAIT		0x04		/* someone is waiting for data/space */
#define SB_SEL		0x08		/* someone is selecting */
#define SB_ASYNC	0x10		/* ASYNC I/O, need signals */
#define SB_UPCALL	0x20		/* someone wants an upcall */
#define SB_NOINTR	0x40		/* operations not interruptible */
#define SB_AIO		0x80		/* AIO operations queued */
#define SB_KNOTE	0x100		/* kernel note attached */

	struct sctp_dgrcv_request_head	so_dgrcv_reqs;
	PTDI_IND_RECEIVE_DATAGRAM	so_rcvdg;
	void				*so_rcvdgarg;
	struct sctp_dgsnd_request_head	so_dgsnd_reqs;
#if 0
	struct	ucred *so_cred;		/* (a) user credentials */
	struct	label *so_label;	/* (b) MAC label for socket */
	struct	label *so_peerlabel;	/* (b) cached MAC label for peer */
	/* NB: generation count must not be first; easiest to make it last. */
	so_gen_t so_gencnt;		/* (h) generation count */
	void	*so_emuldata;		/* (b) private data for emulators */
	struct so_accf {
		struct	accept_filter *so_accept_filter;
		void	*so_accept_filter_arg;	/* saved filter args */
		char	*so_accept_filter_str;	/* saved user args */
	} *so_accf;
#endif
};

#define	SO_DEBUG	0x0001		/* turn on debugging info recording */
#define	SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */
#define	SO_USELOOPBACK	0x0040		/* bypass hardware when possible */
#define	SO_LINGER	0x0080		/* linger on close if data present */
#define	SO_OOBINLINE	0x0100		/* leave received OOB data in line */
#define	SO_REUSEPORT	0x0200		/* allow local address & port reuse */
#define	SO_TIMESTAMP	0x0400		/* timestamp received dgram traffic */
#define	SO_NOSIGPIPE	0x0800		/* no SIGPIPE from EPIPE */
#define	SO_ACCEPTFILTER	0x1000		/* there is an accept filter */
#define	SO_BINTIME	0x2000		/* timestamp received dgram traffic */

#define SS_NOFDREF              0x0001  /* no file table ref any more */
#define SS_ISCONNECTED          0x0002  /* socket connected to a peer */
#define SS_ISCONNECTING         0x0004  /* in process of connecting to peer */
#define SS_ISDISCONNECTING      0x0008  /* in process of disconnecting */
#define SS_NBIO                 0x0100  /* non-blocking ops */
#define SS_ASYNC                0x0200  /* async i/o notify */
#define SS_ISCONFIRMING         0x0400  /* deciding to accept connection req */
#define SS_ISDISCONNECTED       0x2000  /* socket disconnected from peer */

/*
 * Socket state bits now stored in the socket buffer state field.
 */
#define SBS_CANTSENDMORE        0x0010  /* can't send more data to peer */
#define SBS_CANTRCVMORE         0x0020  /* can't receive more data from peer */
#define SBS_RCVATMARK           0x0040  /* at mark on input */

/*
 * Socket state bits stored in so_qstate.
 */
#define SQ_INCOMP               0x0800  /* unaccepted, incomplete connection */
#define SQ_COMP                 0x1000  /* unaccepted, complete connection */

#define	MSG_OOB		0x1		/* process out-of-band data */
#define	MSG_PEEK	0x2		/* peek at incoming message */
#define	MSG_DONTROUTE	0x4		/* send without using routing tables */
#define	MSG_EOR		0x8		/* data completes record */
#define	MSG_TRUNC	0x1		/* data discarded before delivery */
#define	MSG_CTRUNC	0x20		/* control data lost before delivery */
#define	MSG_WAITALL	0x40		/* wait for full request or error */
#define	MSG_DONTWAIT	0x80		/* this message should be nonblocking */
#define	MSG_EOF		0x100		/* data completes connection */
#define	MSG_NBIO	0x4000		/* FIONBIO mode, used by fifofs */
#define	MSG_COMPAT	0x8000		/* used in sendit() */
#define	MSG_NOTIFICATION 0xf000

#define	sowriteable(_so) 0
#define	soreadable(_so) 0
#define	soisconnecting(_so)
int soreserve(struct socket *, u_long, u_long);
#define	wakeup(_so)

#define sorwakeup(_so) do { \
	SOCKBUF_LOCK(&(_so)->so_rcv); \
	sorwakeup_locked((_so)); \
} while (0)
void sorwakeup_locked(struct socket *);
#define sowwakeup(_so) do { \
	SOCKBUF_LOCK(&(_so)->so_rcv); \
	sowwakeup_locked((_so)); \
} while (0)
void sowwakeup_locked(struct socket *);
int getsockaddr(struct sockaddr **, caddr_t, size_t);
struct sockaddr *sodupsockaddr(struct sockaddr *, int);

#define soisconnected(_so)
#define sonewconn(_so, _connstatus)
#define	socantsendmore(_so)
#define	sbwait(_so)	-1
#define	sbspace(_so) 0

#define	SOCKBUF_LOCK_INIT(_sb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SOCKBUF_LOCK_INIT: sb=%p %s[%d]\n", (_sb), __FILE__, __LINE__); \
	} \
	KeInitializeMutex(&(_sb)->sb_mtx, 0); \
} while (0)

#define	SOCKBUF_LOCK_DESTROY(_sb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SOCKBUF_LOCK_DESTROY: sb=%p %s[%d]\n", (_sb), __FILE__, __LINE__); \
	} \
	if (KeReadStateMutex(&(_sb)->sb_mtx) == 0) { \
		KeReleaseMutex(&(_sb)->sb_mtx, 0); \
	} \
} while (0)

#define	SOCKBUF_LOCK(_sb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SOCKBUF_LOCK: sb=%p %s[%d]\n", (_sb), __FILE__, __LINE__); \
	} \
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) { \
		while (KeWaitForMutexObject(&(_sb)->sb_mtx, Executive, KernelMode, FALSE, &zero_timeout) != STATUS_SUCCESS); \
	} else { \
		KeWaitForMutexObject(&(_sb)->sb_mtx, Executive, KernelMode, FALSE, NULL); \
	} \
} while (0)

#define SOCKBUF_UNLOCK(_sb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SOCKBUF_UNLOCK: sb=%p %s[%d]\n", (_sb), __FILE__, __LINE__); \
	} \
	KeReleaseMutex(&(_sb)->sb_mtx, 0); \
} while (0)

#define	SOCK_LOCK(_so)		SOCKBUF_LOCK(&(_so)->so_rcv)
#define	SOCK_UNLOCK(_so)	SOCKBUF_UNLOCK(&(_so)->so_rcv)
#define	sblock(_so)

#define	SOCK_STREAM	0x01
#define	SOCK_DGRAM	0x02
#define	SOCK_RAW	0x03
#define SOCK_RDM	0x04
#define	SOCK_SEQPACKET	0x05

#define SCTP_SB_LIMIT_RCV(so)	so->so_rcv.sb_hiwat
#define SCTP_SB_LIMIT_SND(so)	so->so_snd.sb_hiwat

struct inpcb {
	struct route	inp_route;
	uint16_t	inp_fport;
	uint16_t	inp_lport;
	int		inp_flags;
	struct socket	*inp_socket;
	u_char		inp_ip_tos;
	struct mbuf	*inp_options;
	VOID 		*inp_moptions;
	struct mbuf	*in6p_options;
	VOID		*in6p_outputopts;
	VOID		*in6p_moptions;
	uint32_t	in6p_flowinfo;
};
#define in6pcb	inpcb
#define	ip_freemoptions(a)
#define	ip6_freepcbopts(a)

/* flags in inp_flags: */
#define	INP_RECVOPTS		0x01	/* receive incoming IP options */
#define	INP_RECVRETOPTS		0x02	/* receive IP options for reply */
#define	INP_RECVDSTADDR		0x04	/* receive IP dst address */
#define	INP_HDRINCL		0x08	/* user supplies entire IP header */
#define	INP_HIGHPORT		0x10	/* user wants "high" port binding */
#define	INP_LOWPORT		0x20	/* user wants "low" port binding */
#define	INP_ANONPORT		0x40	/* port chosen for user */
#define	INP_RECVIF		0x80	/* receive incoming interface */
#define	INP_MTUDISC		0x100	/* user can do MTU discovery */
#define	INP_FAITH		0x200	/* accept FAITH'ed connections */
#define	INP_RECVTTL		0x400	/* receive incoming IP TTL */
#define	INP_DONTFRAG		0x800	/* don't fragment packet */

#define IN6P_IPV6_V6ONLY	0x008000 /* restrict AF_INET6 socket for v6 */

#define	IN6P_PKTINFO		0x010000 /* receive IP6 dst and I/F */
#define	IN6P_HOPLIMIT		0x020000 /* receive hoplimit */
#define	IN6P_HOPOPTS		0x040000 /* receive hop-by-hop options */
#define	IN6P_DSTOPTS		0x080000 /* receive dst options after rthdr */
#define	IN6P_RTHDR		0x100000 /* receive routing header */
#define	IN6P_RTHDRDSTOPTS	0x200000 /* receive dstoptions before rthdr */
#define	IN6P_TCLASS		0x400000 /* receive traffic class value */
#define	IN6P_AUTOFLOWLABEL	0x800000 /* attach flowlabel automatically */
#define	IN6P_RFC2292		0x40000000 /* used RFC2292 API on the socket */
#define	IN6P_MTU		0x80000000 /* receive path MTU */

#define	INP_CONTROLOPTS		(INP_RECVOPTS|INP_RECVRETOPTS|INP_RECVDSTADDR|\
				 INP_RECVIF|INP_RECVTTL|\
				 IN6P_PKTINFO|IN6P_HOPLIMIT|IN6P_HOPOPTS|\
				 IN6P_DSTOPTS|IN6P_RTHDR|IN6P_RTHDRDSTOPTS|\
				 IN6P_TCLASS|IN6P_AUTOFLOWLABEL|IN6P_RFC2292|\
				 IN6P_MTU)
#define	INP_UNMAPPABLEOPTS	(IN6P_HOPOPTS|IN6P_DSTOPTS|IN6P_RTHDR|\
				 IN6P_TCLASS|IN6P_AUTOFLOWLABEL)

 /* for KAME src sync over BSD*'s */
#define	IN6P_HIGHPORT		INP_HIGHPORT
#define	IN6P_LOWPORT		INP_LOWPORT
#define	IN6P_ANONPORT		INP_ANONPORT
#define	IN6P_RECVIF		INP_RECVIF
#define	IN6P_MTUDISC		INP_MTUDISC
#define	IN6P_FAITH		INP_FAITH
#define	IN6P_CONTROLOPTS INP_CONTROLOPTS


/*
 * Local address and interface list handling
 */
#define SCTP_MAX_VRF_ID		0
#define SCTP_SIZE_OF_VRF_HASH	3
#define SCTP_IFNAMSIZ		255
#define SCTP_DEFAULT_VRFID	0
#define SCTP_VRF_HASH_SIZE	16

#define SCTP_IFN_IS_IFT_LOOP(ifn) 0

/*
 * Access to IFN's to help with src-addr-selection
 */
/* This could return VOID if the index works but for BSD we provide both. */
#define SCTP_GET_IFN_VOID_FROM_ROUTE(ro) \
	((ro)->ro_rt != NULL ? (ro)->ro_rt->rt_ifp : NULL)
#define SCTP_GET_IF_INDEX_FROM_ROUTE(ro) \
	((ro)->ro_rt != NULL ? ((ro)->ro_rt->rt_ifp != NULL ? (ro)->ro_rt->rt_ifp->if_index : -1): -1)


extern NDIS_HANDLE SctpBufferPool;

/*
 * flags to malloc.
 */
#define M_NOWAIT	0x0001		/* do not block */
#define M_WAITOK	0x0002		/* ok to block */
#define M_ZERO		0x0100		/* bzero the allocation */
#define M_NOVM		0x0200		/* don't ask VM for pages */
#define M_USE_RESERVE	0x0400		/* can alloc out of reserve memory */
#define	M_NOTIFICATION	0x2000		/* SCTP notification */

#define SCTP_BUF_LEN(m)			(m->m_len)
#define SCTP_BUF_NEXT(m)		(m->m_next)
#define SCTP_BUF_NEXT_PKT(m)		(m->m_nextpkt)
#define SCTP_BUF_RESV_UF(m, size) 	m->m_data += size
#define SCTP_BUF_AT(m, size)		(m->m_data + size)
#define SCTP_BUF_IS_EXTENDED(m)		(m->m_flags & M_EXT)
#define SCTP_BUF_EXTEND_SIZE(m)		(m->m_ext.ext_size)
#define SCTP_BUF_TYPE(m)		(m->m_type)
#define SCTP_BUF_RECVIF(m)		(m->m_pkthdr.rcvif)
#define SCTP_BUF_PREPEND		M_PREPEND

#define SCTP_ALIGN_TO_END(m, len) if(m->m_flags & M_PKTHDR) { \
	MH_ALIGN(m, len); \
	} else if ((m->m_flags & M_EXT) == 0) { \
	M_ALIGN(m, len); \
}

/*************************/
/* These are for logging */
/*************************/
/* return the base ext data pointer */
#define SCTP_BUF_EXTEND_BASE(m)		(m->m_ext.ext_buf)
 /* return the refcnt of the data pointer */
#define SCTP_BUF_EXTEND_REFCNT(m)	(*m->m_ext.ref_cnt)
/* return any buffer related flags, this is
 * used beyond logging for apple only.
 */
#define SCTP_BUF_GET_FLAGS(m)		(m->m_flags)

/* For BSD this just accesses the M_PKTHDR length
 * so it operates on an mbuf with hdr flag. Other
 * O/S's may have seperate packet header and mbuf
 * chain pointers.. thus the macro.
 */
#define SCTP_HEADER_TO_CHAIN(m)		(m)
#define SCTP_HEADER_LEN(m)		(m->m_pkthdr.len)
#define SCTP_GET_HEADER_FOR_OUTPUT(len)	sctp_get_mbuf_for_msg(len, 1, M_DONTWAIT, 1, MT_DATA)

/* Attach the chain of data into the sendable packet. */
#define SCTP_ATTACH_CHAIN(pak, m, packet_length) do { \
	pak->m_next = m; \
	pak->m_pkthdr.len = packet_length; \
} while(0)


/*
 *
 */
#define USER_ADDR_NULL	(NULL)		/* FIX ME: temp */
#define SCTP_LIST_EMPTY(list)	LIST_EMPTY(list)


/*
 * general memory allocation
 */
#define SCTP_MALLOC(var, type, size, name) \
    do { \
	var = (type)ExAllocatePool(NonPagedPool, size); \
    } while (0)

#define SCTP_FREE(var)	ExFreePool(var)

#define SCTP_MALLOC_SONAME(var, type, size) \
    do { \
	var = (type)ExAllocatePool(NonPagedPool, size); \
	if (var != NULL) { \
		RtlZeroMemory(var, size); \
	} \
    } while (0)

#define SCTP_FREE_SONAME(var)	ExFreePool(var)

#define SCTP_PROCESS_STRUCT struct proc *


typedef NPAGED_LOOKASIDE_LIST sctp_zone_t;
#define UMA_ZFLAG_FULL	0x0020
#define SCTP_ZONE_INIT(zone, name, size, number) do { \
	ExInitializeNPagedLookasideList(&(zone), NULL, NULL, 0, (size), \
	    0x64657246, 0); \
} while (0)

/* SCTP_ZONE_GET: allocate element from the zone */
#define SCTP_ZONE_GET(zone, type) \
	(type *)ExAllocateFromNPagedLookasideList(&(zone))

/* SCTP_ZONE_FREE: free element from the zone */
#define SCTP_ZONE_FREE(zone, element) \
	ExFreeToNPagedLookasideList(&(zone), (element))

#define	SCTP_ZONE_DESTROY(zone) do { \
	ExDeleteNPagedLookasideList(&(zone)); \
} while(0)

void *sctp_hashinit_flags(int, struct malloc_type *, u_long *, int);
	
#define HASH_NOWAIT 0x00000001
#define HASH_WAITOK 0x00000002

#define SCTP_HASH_INIT(size, hashmark) sctp_hashinit_flags(size, M_PCB, hashmark, HASH_NOWAIT)
#if 0 /* XXX */
#define SCTP_HASH_FREE(table, hashmark) hashdestroy(table, M_PCB, hashmark)
#else
#define SCTP_HASH_FREE(table, hashmark)
#endif

#define SCTP_M_COPYM	m_copym


/*
 * timers
 */

typedef void (*sctp_timeout_t)(void *);

typedef struct sctp_os_timer {
	BOOLEAN initialized;
	BOOLEAN pending;
	BOOLEAN active;
	KTIMER tmr;
	KDPC dpc;
	int ticks;
	sctp_timeout_t func;
	void *arg;
} sctp_os_timer_t;

VOID CustomTimerDpc(IN struct _KDPC *, IN PVOID, IN PVOID, IN PVOID);

#define SCTP_OS_TIMER_INIT(_tmr)

#define SCTP_OS_TIMER_START(_tmr, _ticks, _func, _arg) do { \
	DbgPrint("SCTP_OS_TIMER_START: tmr=%p,active=%d,pending=%d,on=%d %s[%d]\n", (_tmr), (_tmr)->active, (_tmr)->pending, KeReadStateTimer(&(_tmr)->tmr), __FILE__, __LINE__); \
	if ((_tmr)->initialized == FALSE) { \
		(_tmr)->func = (_func); \
		(_tmr)->arg = (_arg); \
		KeInitializeDpc(&(_tmr)->dpc, CustomTimerDpc, (_tmr)); \
		KeInitializeTimer(&(_tmr)->tmr); \
		(_tmr)->initialized = TRUE; \
	} \
	(_tmr)->ticks = (_ticks); \
	(_tmr)->pending = TRUE; \
	if ((_tmr)->active == FALSE) { \
		LARGE_INTEGER _ExpireTime; \
		KeQuerySystemTime(&_ExpireTime); \
		_ExpireTime.QuadPart += (LONGLONG)(100 * 10000)*(_ticks); \
		KeSetTimer(&(_tmr)->tmr, _ExpireTime, &(_tmr)->dpc); \
	} \
} while (0)

#define SCTP_OS_TIMER_STOP(_tmr) do { \
	DbgPrint("SCTP_OS_TIMER_STOP: tmr=%p,active=%d,pending=%d,on=%d %s[%d]\n", (_tmr), (_tmr)->active, (_tmr)->pending, KeReadStateTimer(&(_tmr)->tmr), __FILE__, __LINE__); \
	DbgPrint("KeCancelTimer=%d\n", KeCancelTimer(&(_tmr)->tmr)); \
	(_tmr)->pending = FALSE; \
} while (0)

#define SCTP_OS_TIMER_PENDING(tmr)	FALSE
#define SCTP_OS_TIMER_ACTIVE(tmr)	TRUE
#define SCTP_OS_TIMER_DEACTIVATE(tmr)


struct timeval {
	long	tv_sec;		/* seconds since Jan. 1, 1970 */
	long	tv_usec;	/* and microseconds */
};

void __inline
timevalfix(struct timeval *t1)
{
	if (t1->tv_usec < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
	if (t1->tv_usec >= 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

void __inline
timevaladd(struct timeval *t1, const struct timeval *t2)
{
	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}

void __inline
timevalsub(struct timeval *t1, const struct timeval *t2)
{
	t1->tv_sec -= t2->tv_sec;
	t1->tv_usec -= t2->tv_usec;
	timevalfix(t1);
}

#define timevalcmp(tvp, uvp, cmp) \
	(((tvp)->tv_sec == (uvp)->tv_sec) ? \
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) : \
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define SCTP_GETTIME_TIMEVAL(x)	do { \
	LARGE_INTEGER SystemTime; \
	KeQuerySystemTime(&SystemTime); \
	(x)->tv_sec = (LONG)(SystemTime.QuadPart/10000000-11644473600); \
	(x)->tv_usec = (LONG)((SystemTime.QuadPart%10000000)/10); \
} while (0)
#define SCTP_GETPTIME_TIMEVAL(x) do { \
	LARGE_INTEGER TickCount, UpTime; \
	KeQueryTickCount(&TickCount); \
	UpTime = TickCount * KeQueryTimeIncrement(); \
	(x)->tv_sec = (LONG)(UpTime.QuadPart/10000000); \
	(x)->tv_usec = (LONG)((UpTime.QuadPart%10000000)/10); \
} while (0)
#define SCTP_CMP_TIMER(x, y, cmp) \
	(((x)->tv_sec == (y)->tv_sec) ? \
	    ((x)->tv_usec cmp (y)->tv_usec) : \
	    ((x)->tv_sec cmp (y)->tv_sec))

#define	hz	1000



/* Other m_pkthdr type things */
#define SCTP_IS_IT_BROADCAST(dst, m) (0) /* XXX */
#define SCTP_IS_IT_LOOPBACK(m) (0) /* XXX */


/* This converts any input packet header
 * into the chain of data holders, for BSD
 * its a NOP.
 */
#define SCTP_PAK_TO_BUF(i_pak) (i_pak)

/* Macro's for getting length from V6/V4 header */
#define SCTP_GET_IPV4_LENGTH(iph) (iph->ip_len)
#define SCTP_GET_IPV6_LENGTH(ip6) (ntohs(ip6->ip6_plen))

/* is the endpoint v6only? */
#define SCTP_IPV6_V6ONLY(inp)	(((struct inpcb *)inp)->inp_flags & IN6P_IPV6_V6ONLY)
/* is the socket non-blocking? */
#define SCTP_SO_IS_NBIO(so)	((so)->so_state & SS_NBIO)
#define SCTP_SET_SO_NBIO(so)	((so)->so_state |= SS_NBIO)
#define SCTP_CLEAR_SO_NBIO(so)	((so)->so_state &= ~SS_NBIO)
/* get the socket type */
#define SCTP_SO_TYPE(so)	((so)->so_type)
/* reserve sb space for a socket */
#define SCTP_SORESERVE(so, send, recv)	soreserve(so, send, recv)
/* clear the socket buffer state */
#define SCTP_SB_CLEAR(sb)	\
	(sb).sb_cc = 0;		\
	(sb).sb_mb = NULL;	\
	(sb).sb_mbcnt = 0;

/*
 * SCTP AUTH
 */

void read_random(uint8_t *, unsigned int);
#define SCTP_READ_RANDOM(buf, len)	read_random(buf, len)

#include <netinet/sctp_sha1.h>

#include <md5.h>
#define	MD5_Init	MD5Init
#define	MD5_Update	MD5Update
#define	MD5_Final	MD5Final

#endif
