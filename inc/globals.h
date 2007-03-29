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
 * $Id: globals.h,v 1.3 2007/03/29 07:43:56 kozuka Exp $
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

struct in6_pktinfo_option {
    UCHAR _padding[12];
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

struct wsacmsghdr {
  UINT        cmsg_len;
  INT         cmsg_level;
  INT         cmsg_type;
  /* followed by UCHAR cmsg_data[] */
} WSACMSGHDR;

#endif
