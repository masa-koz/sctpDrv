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
 * $Id: sctp_os_windows.h,v 1.2 2007/03/16 12:21:28 kozuka Exp $
 */
#ifndef __sctp_os_windows_h__
#define __sctp_os_windows_h__
/*
 * includes
 */
#include "globals.h"

#if defined(HAVE_SCTP_PEELOFF_SOCKOPT)
#include <sys/file.h>
#include <sys/filedesc.h>
#endif

#if defined(__FreeBSD__)
#ifndef in6pcb
#define in6pcb		inpcb
#endif
#endif

typedef PUCHAR caddr_t;

#define __P(a) a

#define printf	DbgPrint
#define	bzero	RtlZeroMemory
#define bcopy(a, b, c)	RtlCopyMemory(b, a, c)
#define panic(a)
#define malloc(size, type, flags)	ExAllocatePool(NonPagedPool, (size))
#define free(buf)			ExFreePool((buf))

#define M_PCB	NULL

#define EPERM		1		/* Operation not permitted */
#define ENOENT		2		/* No such file or directory */
#define ESRCH		3		/* No such process */
#define EINTR		4		/* Interrupted system call */
#define EIO		5		/* Input/output error */
#define ENXIO		6		/* Device not configured */
#define E2BIG		7		/* Argument list too long */
#define ENOEXEC		8		/* Exec format error */
#define EBADF		9		/* Bad file descriptor */
#define ECHILD		10              /* No child processes */
#define EDEADLK		11              /* Resource deadlock avoided */
					/* 11 was EAGAIN */
#define ENOMEM		12              /* Cannot allocate memory */
#define EACCES		13              /* Permission denied */
#define EFAULT		14              /* Bad address */
#ifndef _POSIX_SOURCE
#define ENOTBLK		15              /* Block device required */
#endif
#define EBUSY		16              /* Device busy */
#define EEXIST		17              /* File exists */
#define EXDEV		18              /* Cross-device link */
#define ENODEV		19              /* Operation not supported by device */
#define ENOTDIR		20              /* Not a directory */
#define EISDIR		21              /* Is a directory */
#define EINVAL		22              /* Invalid argument */
#define ENFILE		23              /* Too many open files in system */
#define EMFILE		24              /* Too many open files */
#define ENOTTY		25              /* Inappropriate ioctl for device */
#ifndef _POSIX_SOURCE
#define ETXTBSY		26              /* Text file busy */
#endif
#define EFBIG		27              /* File too large */
#define ENOSPC		28              /* No space left on device */
#define ESPIPE		29              /* Illegal seek */
#define EROFS		30              /* Read-only filesystem */
#define EMLINK		31              /* Too many links */
#define EPIPE		32              /* Broken pipe */

/* math software */
#define EDOM		33              /* Numerical argument out of domain */
#define ERANGE		34              /* Result too large */

/* non-blocking and interrupt i/o */
#define EAGAIN		35              /* Resource temporarily unavailable */
#ifndef _POSIX_SOURCE
#define EWOULDBLOCK	EAGAIN          /* Operation would block */
#define EINPROGRESS	36              /* Operation now in progress */
#define EALREADY	37              /* Operation already in progress */

/* ipc/network software -- argument errors */
#define ENOTSOCK	38              /* Socket operation on non-socket */
#define EDESTADDRREQ	39              /* Destination address required */
#define EMSGSIZE	40              /* Message too long */
#define EPROTOTYPE	41              /* Protocol wrong type for socket */
#define ENOPROTOOPT	42              /* Protocol not available */
#define EPROTONOSUPPORT	43              /* Protocol not supported */
#define ESOCKTNOSUPPORT	44              /* Socket type not supported */
#define EOPNOTSUPP	45              /* Operation not supported */
#define ENOTSUP		EOPNOTSUPP      /* Operation not supported */
#define EPFNOSUPPORT	46              /* Protocol family not supported */
#define EAFNOSUPPORT	47              /* Address family not supported by protocol family */
#define EADDRINUSE	48              /* Address already in use */
#define EADDRNOTAVAIL	49              /* Can't assign requested address */

/* ipc/network software -- operational errors */
#define ENETDOWN	50              /* Network is down */
#define ENETUNREACH	51              /* Network is unreachable */
#define ENETRESET	52              /* Network dropped connection on reset */
#define ECONNABORTED	53              /* Software caused connection abort */
#define ECONNRESET	54              /* Connection reset by peer */
#define ENOBUFS		55              /* No buffer space available */
#define EISCONN		56              /* Socket is already connected */
#define ENOTCONN	57              /* Socket is not connected */
#define ESHUTDOWN	58              /* Can't send after socket shutdown */
#define ETOOMANYREFS	59              /* Too many references: can't splice */
#define ETIMEDOUT	60              /* Operation timed out */
#define ECONNREFUSED	61              /* Connection refused */

#define ELOOP		62              /* Too many levels of symbolic links */
#endif /* _POSIX_SOURCE */
#define ENAMETOOLONG	63              /* File name too long */

/* should be rearranged */
#ifndef _POSIX_SOURCE
#define EHOSTDOWN	64              /* Host is down */
#define EHOSTUNREACH	65              /* No route to host */
#endif /* _POSIX_SOURCE */
#define ENOTEMPTY	66              /* Directory not empty */

/* quotas & mush */
#ifndef _POSIX_SOURCE
#define EPROCLIM	67              /* Too many processes */
#define EUSERS		68              /* Too many users */
#define EDQUOT		69              /* Disc quota exceeded */

/* Network File System */
#define ESTALE		70              /* Stale NFS file handle */
#define EREMOTE		71              /* Too many levels of remote in path */
#define EBADRPC		72              /* RPC struct is bad */
#define ERPCMISMATCH	73              /* RPC version wrong */
#define EPROGUNAVAIL	74              /* RPC prog. not avail */
#define EPROGMISMATCH	75              /* Program version wrong */
#define EPROCUNAVAIL	76              /* Bad procedure for program */
#endif /* _POSIX_SOURCE */

#define ENOLCK		77              /* No locks available */
#define ENOSYS		78              /* Function not implemented */

#ifndef _POSIX_SOURCE
#define EFTYPE		79              /* Inappropriate file type or format */
#define EAUTH		80              /* Authentication error */
#define ENEEDAUTH	81              /* Need authenticator */
#define EIDRM		82              /* Identifier removed */
#define ENOMSG		83              /* No message of desired type */
#define EOVERFLOW	84              /* Value too large to be stored in datatype */

#define ECANCELED	85              /* Operation canceled */
#define EILSEQ		86              /* Illegal byte sequence */
#define ENOATTR		87              /* Attribute not found */
#define EDOOFUS		88              /* Programming error */
#endif /* _POSIX_SOURCE */

#define EBADMSG		89              /* Bad message */
#define EMULTIHOP	90              /* Multihop attempted */
#define ENOLINK		91              /* Link has been severed */
#define EPROTO		92              /* Protocol error */

#ifndef _POSIX_SOURCE
#define ELAST		92              /* Must be equal largest errno */
#endif /* _POSIX_SOURCE */

typedef	short	sa_family_t;

#define cmsghdr wsacmsghdr

#ifndef CMSG_ALIGN
#ifdef ALIGN
#define CMSG_ALIGN ALIGN
#else
#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#endif
#endif

#ifndef CMSG_SPACE
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#endif

#ifndef CMSG_LEN
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

/*
 * Socket address, internet style.
 */
struct sockaddr_in {
	short	sin_family;
	u_short	sin_port;
	struct in_addr sin_addr;
	char	sin_zero[8];
};

struct sockaddr_in6 {
	short	sin6_family;		/* AF_INET6 */
	u_short	sin6_port;		/* Transport level port number */
	u_long	sin6_flowinfo;		/* IPv6 flow information */
	struct in6_addr sin6_addr;	/* IPv6 address */
	u_long sin6_scope_id;		/* set of interfaces for a scope */
};

/*
 * Structure used by kernel to store most
 * addresses.
 */
struct sockaddr {
	u_short	sa_family;		/* address family */
	char	sa_data[14];		/* up to 14 bytes of direct address */
};

/*
 * Portable socket structure (RFC 2553).
 */

/*
 * Desired design of maximum size and alignment.
 * These are implementation specific.
 */
#define _SS_MAXSIZE 128                  // Maximum size.
#define _SS_ALIGNSIZE (sizeof(__int64))  // Desired alignment.

/*
 * Definitions used for sockaddr_storage structure paddings design.
 */
#define _SS_PAD1SIZE (_SS_ALIGNSIZE - sizeof (short))
#define _SS_PAD2SIZE (_SS_MAXSIZE - (sizeof (short) + _SS_PAD1SIZE \
                                                    + _SS_ALIGNSIZE))

struct sockaddr_storage {
	short	ss_family;		// Address family.
	char	__ss_pad1[_SS_PAD1SIZE];// 6 byte pad, this is to make
					// implementation specific pad up to
					// alignment field that follows explicit
					// in the data structure.
	__int64	__ss_align;		// Field to force desired structure.
	char	__ss_pad2[_SS_PAD2SIZE];// 112 byte pad to achieve desired size;
					// _SS_MAXSIZE value minus size of
					// ss_family, __ss_pad1, and
					// __ss_align fields is 112.
};

struct rtentry {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} rt_nexthop;
	unsigned int rt_flags;
};

struct route {
	struct rtentry *ro_rt;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} ro_dst;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} ro_src;
};

#define RTFREE(a)

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
	struct	protosw *so_proto;	/* (a) protocol handle */
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
	u_short	so_qlen;		/* (e) number of unaccepted connections
*/
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

	void	(*so_upcall)(struct socket *, void *, int);
	void	*so_upcallarg;
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

#define sorwakeup(_so)
#define soisconnected(_so)
#define sonewconn(_so, _connstatus)

/*
 *
 */
#define USER_ADDR_NULL	(NULL)		/* FIX ME: temp */
#define SCTP_LIST_EMPTY(list)	LIST_EMPTY(list)

/*
 * Local address and interface list handling
 */
#define SCTP_MAX_VRF_ID 0
#define SCTP_SIZE_OF_VRF_HASH 3
#define SCTP_IFNAMSIZ IFNAMSIZ
#define SCTP_DEFAULT_VRFID 0

#define SCTP_IFN_IS_IFT_LOOP(ifn) (0) /* XXX */

/*
 * Access to IFN's to help with src-addr-selection
 */
/* This could return VOID if the index works but for BSD we provide both. */
#define SCTP_GET_IFN_VOID_FROM_ROUTE(ro) NULL /* XXX */
#define SCTP_GET_IF_INDEX_FROM_ROUTE(ro) 0 /* XXX */

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

/*
 * zone allocation functions
 */

/* SCTP_ZONE_INIT: initialize the zone */
typedef NPAGED_LOOKASIDE_LIST sctp_zone_t;
#define UMA_ZFLAG_FULL	0x0020
#define SCTP_ZONE_INIT(zone, name, size, number) \
	ExInitializeNPagedLookasideList(&(zone), NULL, NULL, 0, (size), \
	    0x64657246, 0)

/* SCTP_ZONE_GET: allocate element from the zone */
#define SCTP_ZONE_GET(zone, type) \
	(type *)ExAllocateFromNPagedLookasideList(&(zone))

/* SCTP_ZONE_FREE: free element from the zone */
#define SCTP_ZONE_FREE(zone, element) \
	ExFreeToNPagedLookasideList(&(zone), (element))

void *sctp_hashinit_flags(int elements, struct malloc_type *type, 
                    u_long *hashmask, int flags);

#define HASH_NOWAIT 0x00000001
#define HASH_WAITOK 0x00000002

#define SCTP_HASH_INIT(size, hashmark) sctp_hashinit_flags(size, M_PCB, hashmark, HASH_NOWAIT)
#define SCTP_HASH_FREE(table, hashmark) hashdestroy(table, M_PCB, hashmark)


/*
 * timers
 */
typedef struct sctp_os_timer {
	KTIMER tmr;
	KDPC dpc;
	PKDEFERRED_ROUTINE func;
	PVOID arg;
} sctp_os_timer_t;

#define SCTP_OS_TIMER_INIT(_tmr) do { \
	KeInitializeDpc(&(_tmr)->dpc, (_tmr)->func, (_tmr)->arg); \
	KeInitializeTimer(&(_tmr)->tmr); \
} while (0)

#define SCTP_OS_TIMER_START(tmr, ticks, func, arg) do { \
	LARGE_INTEGER InitialWakeUp; \
	InitialWakeUp.QuadPart = -(LONGLONG) MS_PER_TICK * 10000; \
	KeSetTimerEx(&tmr->tmr, InitialWakeUp, ticks, &tmr->dpc); \
} while (0)

#define SCTP_OS_TIMER_STOP(_tmr) do { \
	while (KeCancelTimer(&(_tmr)->tmr) == TRUE) { \
		KeFlushQueuedDpcs(); \
	} \
} while (0)

#define SCTP_OS_TIMER_PENDING(tmr)	FALSE
#define SCTP_OS_TIMER_ACTIVE(tmr)	FALSE
#define SCTP_OS_TIMER_DEACTIVATE(tmr)


struct timeval {
	long	tv_sec;		/* seconds since Jan. 1, 1970 */
	long	tv_usec;	/* and microseconds */
};

#define SCTP_GETTIME_TIMEVAL(x)	\
	KeQuerySystemTime((PLARGE_INTEGER)(x))
#define SCTP_GETPTIME_TIMEVAL(x) \
	KeQuerySystemTime((PLARGE_INTEGER)(x))
#define SCTP_CMP_TIMER(x, y, cmp) \
	(((x)->tv_sec == (y)->tv_sec) ? \
	    ((x)->tv_usec cmp (y)->tv_usec) : \
	    ((x)->tv_sec cmp (y)->tv_sec))

NDIS_HANDLE SctpBufferPool;
NDIS_HANDLE SctpPacketPool;
KMUTEX SctpBufferMutex;

struct m_ext {
	UCHAR	*ext_buf;
	ULONG	ext_size;
	ULONG	ref_cnt;
};

struct mbuf {
	struct mbuf	*m_next;
	struct m_ext	m_ext;
	UCHAR		*m_data;
	ULONG		m_len;
	NDIS_BUFFER	*ndis_buffer;
};

struct mpkt {
	struct mpkt	*pkt_next;
	struct mbuf	*pkt_mbuf;
	ULONG		pkt_len;
	NDIS_PACKET	*ndis_packet;
};

#define	MCLBYTES	2048
/*
 * flags to malloc.
 */
#define M_NOWAIT	0x0001		/* do not block */
#define M_WAITOK	0x0002		/* ok to block */
#define M_ZERO		0x0100		/* bzero the allocation */
#define M_NOVM		0x0200		/* don't ask VM for pages */
#define M_USE_RESERVE	0x0400		/* can alloc out of reserve memory */

#define M_MAGIC         877983977       /* time when first defined :-) */

#define MBTOM(how)      (how)
#define M_DONTWAIT      M_NOWAIT
#define M_TRYWAIT       M_WAITOK
#define M_WAIT          M_WAITOK

#define M_COPYALL	1000000000

/*
 * mbuf types.
 */
#define MT_NOTMBUF      0       /* USED INTERNALLY ONLY! Object is not mbuf */
#define MT_DATA         1       /* dynamic (data) allocation */
#define MT_HEADER       2       /* packet header */
#if 0
#define MT_SOCKET       3       /* socket structure */
#define MT_PCB          4       /* protocol control block */
#define MT_RTABLE       5       /* routing tables */
#define MT_HTABLE       6       /* IMP host tables */
#define MT_ATABLE       7       /* address resolution tables */
#endif
#define MT_SONAME       8       /* socket name */
#if 0
#define MT_SOOPTS       10      /* socket options */
#endif
#define MT_FTABLE       11      /* fragment reassembly header */
#if 0
#define MT_RIGHTS       12      /* access rights */
#define MT_IFADDR       13      /* interface address */
#endif
#define MT_CONTROL      14      /* extra-data protocol message */
#define MT_OOBDATA      15      /* expedited data  */
#define MT_NTYPES       16      /* number of mbuf types for mbtypes[] */

#define MT_NOINIT       255     /* Not a type but a flag to allocate
                                   a non-initialized mbuf */

#define mtod(_m, _type)	(_type)((_m)->m_data)
/*
 * Functions
 */
/* Mbuf manipulation and access macros  */
#define SCTP_BUF_INIT() do { \
	NTSTATUS _status; \
	NdisAllocateBufferPool(&_status, &SctpBufferPool, 100); \
	KeInitializeMutex(&SctpBufferMutex, 0); \
} while (0)

#define SCTP_BUF_ALLOC(m, size) do { \
	NTSTATUS _status; \
	(m) = ExAllocatePool(NonPagedPool, sizeof(*(m))); \
	if (m != NULL) { \
		RtlZeroMemory((m), sizeof(*(m))); \
		(m)->m_ext.ext_size = (size); \
		(m)->m_ext.ref_cnt = 1; \
		(m)->m_ext.ext_buf = ExAllocatePool(NonPagedPool, (size)); \
		if ((m)->m_ext.ext_buf != NULL) { \
			NdisAllocateBuffer(&_status, &(m)->ndis_buffer, \
			    SctpBufferPool, (m)->m_ext.ext_buf, (size)); \
			(m)->m_data = (m)->m_ext.ext_buf; \
			if (_status != NDIS_STATUS_SUCCESS) { \
				ExFreePool((m)->m_ext.ext_buf); \
				ExFreePool((m)); \
				(m) = NULL; \
			} \
		} else { \
			ExFreePool((m)); \
			(m) = NULL; \
		} \
	} \
} while (0)

#define _SCTP_BUF_FREE(n, m) do { \
	(n) = (m)->m_next; \
	NdisFreeBuffer((m)->ndis_buffer); \
	KeWaitForMutexObject(&SctpBufferMutex, Executive, KernelMode, \
	    FALSE, NULL); \
	(m)->m_ext.ref_cnt--; \
	if ((m)->m_ext.ref_cnt == 0) { \
		ExFreePool((m)->m_ext.ext_buf); \
	} \
	KeReleaseMutex(&SctpBufferMutex, FALSE); \
	ExFreePool((m)); \
} while (0)

#ifdef SCTP_MBUF_LOGGING
#define SCTP_BUF_FREE(n, m) do { \
	if (SCTP_BUF_IS_EXTENDED(m)) { \
		sctp_log_mb((m), SCTP_MBUF_IFREE); \
	} \
	_SCTP_BUF_FREE(n, m); \
} while (0)
#else
#define SCTP_BUF_FREE _SCTP_BUF_FREE
#endif

#define SCTP_BUF_FREE_ALL(m) do { \
	struct mbuf *_m, *_n; \
	_n = (m); \
	do { \
		_m = _n; \
		SCTP_BUF_FREE(_n, m); \
	} while (_n != NULL); \
} while (0)

#define SCTP_BUF_SET_LEN(m, len) do { \
	NdisAdjustBufferLength((m)->ndis_buffer, (len)); \
} while (0)

#define SCTP_BUF_SET_NEXT(m, n) do { \
	(m)->m_next = (n); \
	if ((n) != NULL) { \
		NDIS_BUFFER_LINKAGE((m)->ndis_buffer) = (n)->ndis_buffer; \
	} \
} while (0)

#define SCTP_BUF_GET_LEN(m) NdisBufferLength((m)->ndis_buffer)
#define SCTP_BUF_GET_NEXT(m) (m)->m_next
#define SCTP_BUF_NEXT_PKT(m)
#define SCTP_BUF_RESV_UF(m, size) (m)->m_data += size
#define SCTP_BUF_AT(m, size) ((m)->m_data + size)
#define SCTP_BUF_IS_EXTENDED(m) (1)
#define SCTP_BUF_EXTEND_SIZE(m) (m->m_ext.ext_size)
#define SCTP_BUF_TYPE(m)
#define SCTP_BUF_RECVIF(m)
#define SCTP_BUF_PREPEND(m)

#define SCTP_BUF_SPACE(m) ((m)->m_ext.ext_size - NdisBufferLength((m)->ndis_buffer))

#define SCTP_BUF_COPYDATA(m, offset, len, data) \
	RtlCopyMemory((data), SCTP_BUF_AT((m), (offset)), \
	    (SCTP_BUF_LEN((m)) - (offset)) < (len) ? \
		(SCTP_BUF_LEN((m)) - (offset)) : (len))

#define SCTP_BUF_REFCOPY(n, m, offset, len, how) do { \
	NTSTATUS _status; \
	(n) = ExAllocatePool(NonPagedPool, sizeof(*(n))); \
	if ((n) != NULL) { \
		KeWaitForMutexObject(&SctpBufferMutex, Executive, KernelMode, \
		    FALSE, NULL); \
		(m)->m_ext.ref_cnt++; \
		KeReleaseMutex(&SctpBufferMutex, FALSE); \
		(n)->m_ext = (m)->m_ext; \
		(n)->m_data = (m)->m_ext.ext_buf + (offset); \
		NdisAllocateBuffer(&_status, &(n)->ndis_buffer, \
		    SctpBufferPool, (n)->m_data, \
		    ((len) == M_COPYALL) ? (n)->m_ext.ext_size - (offset) : (len)); \
		if (_status != NDIS_STATUS_SUCCESS) { \
			KeWaitForMutexObject(&SctpBufferMutex, \
			    Executive, KernelMode, FALSE, NULL); \
			(n)->m_ext.ref_cnt--; \
			KeReleaseMutex(&SctpBufferMutex, FALSE); \
			ExFreePool((n)); \
		} \
	} \
} while (0)

#define SCTP_BUF_SPLIT(n, m, len, how) do { \
	NTSTATUS _status; \
	ULONG _n_len; \
	if (SCTP_BUF_LEN((m)) >= (len)) { \
		_n_len = SCTP_BUF_LEN((m)) - (len); \
		(n) = ExAllocatePool(NonPagedPool, sizeof(*(n))); \
		if ((n) != NULL) { \
			(n)->m_ext.ext_size = _n_len; \
			(n)->m_ext.ref_cnt = 1; \
			(n)->m_ext.ext_buf = ExAllocatePool(NonPagedPool, \
			    _n_len); \
			if ((n)->m_ext.ext_buf != NULL) { \
				(n)->m_data = (n)->m_ext.ext_buf; \
				RtlCopyMemory((n)->m_data, (m)->m_data, _n_len);\
				NdisAllocateBuffer(&_status, &(n)->ndis_buffer,\
				    SctpBufferPool, (n)->m_data, _n_len); \
				if (_status != NDIS_STATUS_SUCCESS) { \
					ExFreePool((n)->m_ext.ext_buf); \
					ExFreePool((n)); \
					(n) = NULL; \
				} else { \
					(m)->m_data += (len); \
					SCTP_BUF_ADJUST_LEN((m), (len)); \
				} \
			} \
		} \
	} \
} while (0)

#define SCTP_BUF_COPYBACK(m, offset, len, data) do { \
	NTSTATUS _status; \
	ULONG _len, _offset; \
	struct mbuf *_m; \
	UCHAR *_m_data, *_data; \
	if (SCTP_BUF_SPACE((m)) - (offset) >= (len)) { \
		_m = (m); \
		_data = (data); \
		_m_data = SCTP_BUF_AT(_m, offset); \
		_len = (len); \
	} else { \
		_m_data = SCTP_BUF_AT(_m, offset); \
		_len = SCTP_BUF_SPACE((m)) - (offset); \
		RtlCopyMemory(_m_data, data, _len); \
		SCTP_BUF_SET_LEN((m), SCTP_BUF_GET_LEN((m)) + _len); \
		SCTP_BUF_ALLOC(_m, _len); \
		_data = data + _len; \
		_m_data = SCTP_BUF_AT(_m, 0); \
		_len = (len) - _len; \
	} \
	if (_m != NULL) { \
		RtlCopyMemory(_m_data, _data, _len); \
		SCTP_BUF_SET_LEN((_m), SCTP_BUF_GET_LEN((_m)) + _len); \
	} \
} while (0)
/*************************/
/* These are for logging */
/*************************/
/* return the base ext data pointer */
#define SCTP_BUF_EXTEND_BASE(m) (m->m_ext.ext_buf)
 /* return the refcnt of the data pointer */
#define SCTP_BUF_EXTEND_REFCNT(m) (*m->m_ext.ref_cnt)
/* return any buffer related flags, this is
 * used beyond logging for apple only.
 */
#define SCTP_BUF_GET_FLAGS(m) (m->m_flags)

/* For BSD this just accesses the M_PKTHDR length
 * so it operates on an mbuf with hdr flag. Other
 * O/S's may have seperate packet header and mbuf
 * chain pointers.. thus the macro.
 */
#define SCTP_HEADER_INIT() do { \
	NDIS_STATUS _status; \
	NdisAllocatePacketPool(&_status, &SctpPacketPool, 100, 0); \
} while (0)
#define SCTP_HEADER_TO_CHAIN(pkt) (pkt)->pkt_mbuf
__inline ULONG
SCTP_HEADER_LEN(struct mpkt *pkt)
{
	ULONG PhysicalBufferCount;
	ULONG BufferCount;
	PNDIS_BUFFER FirstBuffer;
	ULONG TotalPacketLength;

	NdisQueryPacket(pkt->ndis_packet, &PhysicalBufferCount,
	    &BufferCount, &FirstBuffer, &TotalPacketLength);
	return TotalPacketLength;
}

__inline struct mpkt *
SCTP_GET_HEADER_FOR_OUTPUT(ULONG len)
{
	NDIS_STATUS status;
	struct mpkt *pkt;
	struct mbuf *n;

	pkt = ExAllocatePool(NonPagedPool, sizeof(*pkt));
	if (pkt == NULL) {
		return NULL;
	}
	RtlZeroMemory(pkt, sizeof(*pkt));
	SCTP_BUF_ALLOC(pkt->pkt_mbuf, len);
	if (pkt->pkt_mbuf == NULL) {
		ExFreePool(pkt);
		return NULL;
	}
	NdisAllocatePacket(&status, &pkt->ndis_packet, SctpPacketPool);
	if (status != STATUS_SUCCESS) {
		SCTP_BUF_FREE(n, pkt->pkt_mbuf);
		ExFreePool(pkt);
		return NULL;
	}
	NdisChainBufferAtBack(pkt->ndis_packet, pkt->pkt_mbuf->ndis_buffer);
	
	return pkt;
}

#define SCTP_HEADER_FREE(pkt) do { \
	NdisFreePacket(pkt->ndis_packet); \
	SCTP_BUF_FREE_ALL((pkt)->pkt_mbuf); \
	ExFreePool(pkt); \
} while (0)

/* Attach the chain of data into the sendable packet. */
#define SCTP_ATTACH_CHAIN(pkt, m, packet_length) \
	NdisChainBufferAtBack((pkt)->ndis_packet, (m)->ndis_buffer)

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

/*
 * SCTP AUTH
 */

#if (__FreeBSD_version < 500000)
#define SCTP_READ_RANDOM(buf, len)	read_random_unlimited(buf, len)
#else
#define SCTP_READ_RANDOM(buf, len)	read_random(buf, len)
#endif

#include <netinet/sctp_sha1.h>

#include <md5.h>
#endif
