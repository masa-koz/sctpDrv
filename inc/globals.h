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
 * $Id: globals.h,v 1.6 2007/06/28 13:47:16 kozuka Exp $
 */

/*-
 * Copyright (c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.  All rights reserved.
 */

/*-
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 */

#ifndef __globals_h__
#define __globals_h__

#include <ntddk.h>
#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>

#include <ndis.h>

#undef SLIST_ENTRY
#include "queue.h"

#include <stddef.h>

typedef CHAR   int8_t;
typedef SHORT  int16_t;
typedef LONG   int32_t;
typedef LONGLONG int64_t;
typedef UCHAR  u_int8_t, uint8_t, u_char;
typedef USHORT u_int16_t, uint16_t, u_short;
typedef ULONG  u_int32_t, uint32_t, u_long, u_int;
typedef ULONGLONG uint64_t;

#define IOCTL_TCP_QUERY_INFORMATION_EX 1179651
#define IOCTL_TCP_SET_INFORMATION_EX 1179688

NTSTATUS ZwDeviceIoControlFile(IN HANDLE, IN HANDLE, IN PIO_APC_ROUTINE, IN PVOID, OUT PIO_STATUS_BLOCK,
    IN ULONG, IN PVOID, IN ULONG, OUT PVOID, IN ULONG);

__inline USHORT
ntohs(USHORT x)
{
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}
#define htons ntohs

#define NTOHS(x) \
	(x) = ntohs(x)

__inline ULONG
ntohl(ULONG x)
{
    return (((x & 0xffL) << 24) | ((x & 0xff00L) << 8) |
        ((x & 0xff0000L) >> 8) | ((x &0xff000000L) >> 24));
}
#define htonl ntohl

#define NTOHL(x) \
	(x) = ntohl(x)


char *ip6_sprintf (const struct in6_addr *);


#define LITTLE_ENDIAN 0
#define BIG_ENDIAN 1
#define BYTE_ORDER LITTLE_ENDIAN

#define	IPVERSION	0x04

/*
 * Copied from $FreeBSD: src/sys/netinet/in.h,v 1.90.2.4
 */
typedef uint32_t		in_addr_t;

struct in_addr {
	in_addr_t s_addr;
};

/*
 * Copied from $FreeBSD: src/sys/netinet/ip.h,v 1.29
 * Structure of an internet header, naked of options.
 */
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	u_short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	u_short	ip_off;			/* fragment offset field */
#define IP_RF 0x8000			/* reserved fragment flag */
#define IP_DF 0x4000			/* dont fragment flag */
#define IP_MF 0x2000			/* more fragments flag */
#define IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#define	MAXTTL		255
/*
 * Definitions of bits in internet address integers.
 * On subnets, the decomposition of addresses to host and net parts
 * is done according to subnet mask, not the masks here.
 */
#define IN_CLASSA(i)            (((u_int32_t)(i) & 0x80000000) == 0)
#define IN_CLASSA_NET           0xff000000
#define IN_CLASSA_NSHIFT        24
#define IN_CLASSA_HOST          0x00ffffff
#define IN_CLASSA_MAX           128

#define IN_CLASSB(i)            (((u_int32_t)(i) & 0xc0000000) == 0x80000000)
#define IN_CLASSB_NET           0xffff0000
#define IN_CLASSB_NSHIFT        16
#define IN_CLASSB_HOST          0x0000ffff
#define IN_CLASSB_MAX           65536

#define IN_CLASSC(i)            (((u_int32_t)(i) & 0xe0000000) == 0xc0000000)
#define IN_CLASSC_NET           0xffffff00
#define IN_CLASSC_NSHIFT        8
#define IN_CLASSC_HOST          0x000000ff

#define IN_CLASSD(i)            (((u_int32_t)(i) & 0xf0000000) == 0xe0000000)
#define IN_CLASSD_NET           0xf0000000      /* These ones aren't really */
#define IN_CLASSD_NSHIFT        28              /* net and host fields, but */
#define IN_CLASSD_HOST          0x0fffffff      /* routing needn't know.    */
#define IN_MULTICAST(i)         IN_CLASSD(i)

#define IN_EXPERIMENTAL(i)      (((u_int32_t)(i) & 0xf0000000) == 0xf0000000)
#define IN_BADCLASS(i)          (((u_int32_t)(i) & 0xf0000000) == 0xf0000000)

#define	INADDR_ANY		(u_int32_t)0x00000000

#define	IPV6_VERSION		0x60
#define IPV6_VERSION_MASK	0xf0

/*
 * Copied from $FreeBSD: src/sys/netinet6/in6.h,v 1.36.2.6
 * IPv6 address
 */
struct in6_addr {
	union {
		uint8_t		__u6_addr8[16];
		uint16_t	__u6_addr16[8];
		uint32_t	__u6_addr32[4];
	} __u6_addr;			/* 128-bit IP6 address */
};

#define s6_addr   __u6_addr.__u6_addr8
#ifdef _KERNEL  /* XXX nonstandard */
#define s6_addr8  __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#endif

/*
 * Copied from $FreeBSD: src/sys/netinet/ip6.h,v 1.13.2.2
 * Definition for internet protocol version 6.
 * RFC 2460
 */

struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			u_int32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			u_int16_t ip6_un1_plen;	/* payload length */
			u_int8_t  ip6_un1_nxt;	/* next header */
			u_int8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		u_int8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
};

#define ip6_vfc         ip6_ctlun.ip6_un2_vfc
#define ip6_flow        ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen        ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt         ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim        ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops        ip6_ctlun.ip6_un1.ip6_un1_hlim

struct in6_pktinfo {
    UINT cmsg_len;
    INT cmsg_level;
    INT cmsg_type;
    struct in6_addr ipi6_addr;
    ULONG ipi6_ifindex;
};


#define IN6_ARE_ADDR_EQUAL(a, b) \
	(RtlCompareMemory(&(a)->s6_addr[0], &(b)->s6_addr[0], sizeof(struct in6_addr)) == 0)

/*
 * Unspecified
 */
#define IN6_IS_ADDR_UNSPECIFIED(a)      \
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) == 0))

/*
 * Loopback
 */
#define IN6_IS_ADDR_LOOPBACK(a)         \
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) == ntohl(1)))

/*
 * IPv4 compatible
 */
#define IN6_IS_ADDR_V4COMPAT(a)         \
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) != 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) != ntohl(1)))

/*
 * Mapped
 */
#define IN6_IS_ADDR_V4MAPPED(a)               \
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == ntohl(0x0000ffff)))

/*
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
#define	IN6_IS_ADDR_LINKLOCAL(a)        \
        (((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#define	IN6_IS_ADDR_SITELOCAL(a)        \
        (((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))

/*
 * Multicast
 */
#define	IN6_IS_ADDR_MULTICAST(a)	((a)->s6_addr[0] == 0xff)

#ifdef _KERNEL  /* XXX nonstandard */
#define	IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)
#else
#define	__IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)
#endif

/*
 * Socket address, internet style.
 */
#include <packon.h>
struct sockaddr_in {
	u_short	sin_len;
	u_short	sin_family;
	u_short	sin_port;
	struct in_addr sin_addr;
	char	sin_zero[8];
};
#include <packoff.h>

#define	AF_INET		TDI_ADDRESS_TYPE_IP

struct sockaddr_in6 {
	u_short	sin6_len;
	u_short	sin6_family;
	u_short	sin6_port;		/* Transport level port number */
	u_long	sin6_flowinfo;		/* IPv6 flow information */
	struct in6_addr sin6_addr;	/* IPv6 address */
	u_long sin6_scope_id;		/* set of interfaces for a scope */
};
#define	AF_INET6	TDI_ADDRESS_TYPE_IP6

/*
 * Structure used by kernel to store most
 * addresses.
 */
struct sockaddr {
	u_short	sa_len;
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
	u_short	ss_len;
	u_short	ss_family;		// Address family.
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


struct wsacmsghdr {
  UINT        cmsg_len;
  INT         cmsg_level;
  INT         cmsg_type;
  /* followed by UCHAR cmsg_data[] */
} WSACMSGHDR;

#define	atomic_set_long(p, v)	InterlockedExchange((PLONG)(p), (LONG)(v))
#define	atomic_set_int		atomic_set_long
#define	atomic_set_short	atomic_set_long
#define	atomic_set_char		atomic_set_long

#define	atomic_clear_long(p, v)	InterlockedXor((PLONG)(p), (LONG)(v))
#define	atomic_clear_int	atomic_clear_long
#define	atomic_clear_short	atomic_clear_long
#define	atomic_clear_char	atomic_clear_long

#define	atomic_add_long(p, v)	InterlockedExchangeAdd((PLONG)(p), (LONG)(v))
#define	atomic_add_int		atomic_add_long
#define	atomic_add_short	atomic_add_long
#define	atomic_add_char		atomic_add_long

#define	atomic_fetchadd_long	atomic_add_long
#define	atomic_fetchadd_int	atomic_add_int
#define	atomic_fetchadd_short	atomic_add_short
#define	atomic_fetchadd_char	atomic_add_char

#define	atomic_subtract_long(p, v)	InterlockedExchangeAdd((PLONG)(p), -(LONG)(v))
#define	atomic_subtract_int		atomic_subtract_long
#define	atomic_subtract_short		atomic_subtract_long
#define	atomic_subtract_char		atomic_subtract_long

#define	atomic_cmpset_long(p, c, v)	InterlockedCompareExchange((PLONG)(p), (LONG)v, (LONG)c)
#define	atomic_cmpset_int		atomic_cmpset_long
#define	atomic_cmpset_short		atomic_cmpset_long
#define	atomic_cmpset_char		atomic_cmpset_long

typedef PUCHAR caddr_t;
typedef PUCHAR c_caddr_t;

#define __P(a) a

#define	ip_defttl	128
#define	ip6_defhlim	64

#define KASSERT(a, b)	ASSERT(a)
#define printf	DbgPrint
#define	bzero	RtlZeroMemory
#define bcopy(a, b, c)	RtlCopyMemory(b, a, c)
#define bcmp(a, b, c)	((RtlCompareMemory((a), (b), (c)) == (c)) ? 0 : 1)
__inline void
panic(char *fmt, ...)
{
}
#define malloc(size, type, flags)	ExAllocatePool(NonPagedPool, (size))
#define free(buf)			ExFreePool((buf))

#if _BYTE_ORDER == _BIG_ENDIAN
#define IPV6_ADDR_INT32_ONE	1
#define IPV6_ADDR_INT32_TWO	2
#define IPV6_ADDR_INT32_MNL	0xff010000
#define IPV6_ADDR_INT32_MLL	0xff020000
#define IPV6_ADDR_INT32_SMP	0x0000ffff
#define IPV6_ADDR_INT16_ULL	0xfe80
#define IPV6_ADDR_INT16_USL	0xfec0
#define IPV6_ADDR_INT16_MLL	0xff02
#elif _BYTE_ORDER == _LITTLE_ENDIAN
#define IPV6_ADDR_INT32_ONE	0x01000000
#define IPV6_ADDR_INT32_TWO	0x02000000
#define IPV6_ADDR_INT32_MNL	0x000001ff
#define IPV6_ADDR_INT32_MLL	0x000002ff
#define IPV6_ADDR_INT32_SMP	0xffff0000
#define IPV6_ADDR_INT16_ULL	0x80fe
#define IPV6_ADDR_INT16_USL	0xc0fe
#define IPV6_ADDR_INT16_MLL	0x02ff
#endif

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
#endif
