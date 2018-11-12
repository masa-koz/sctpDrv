/*-
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$KAME: in6.h,v 1.89 2001/05/27 13:28:35 itojun Exp $
 */

/*-
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)in.h	8.3 (Berkeley) 1/3/94
 * $FreeBSD: src/sys/netinet6/in6.h,v 1.52 2007/12/10 16:03:37 obrien Exp $
 */

#ifndef _NETINET6_IN6_H_
#define _NETINET6_IN6_H_

#include <in6addr.h>

#include <sys/types.h>
#include <sys/domain.h>
#include <sys/protosw.h>

#define	IPV6_VERSION		0x60
#define IPV6_VERSION_MASK	0xf0


#ifdef _KERNEL
#if BYTE_ORDER == BIG_ENDIAN
#define IPV6_ADDR_INT32_ONE     1
#define IPV6_ADDR_INT32_TWO     2
#define IPV6_ADDR_INT32_MNL     0xff010000
#define IPV6_ADDR_INT32_MLL     0xff020000
#define IPV6_ADDR_INT32_SMP     0x0000ffff
#define IPV6_ADDR_INT16_ULL     0xfe80
#define IPV6_ADDR_INT16_USL     0xfec0
#define IPV6_ADDR_INT16_MLL     0xff02
#elif BYTE_ORDER == LITTLE_ENDIAN
#define IPV6_ADDR_INT32_ONE     0x01000000
#define IPV6_ADDR_INT32_TWO     0x02000000
#define IPV6_ADDR_INT32_MNL     0x000001ff
#define IPV6_ADDR_INT32_MLL     0x000002ff
#define IPV6_ADDR_INT32_SMP     0xffff0000
#define IPV6_ADDR_INT16_ULL     0x80fe
#define IPV6_ADDR_INT16_USL     0xc0fe
#define IPV6_ADDR_INT16_MLL     0x02ff
#endif
#endif


#ifdef _KERNEL  /* XXX nonstandard */
#define s6_addr8	s6_bytes
#define s6_addr16	s6_words
#endif

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

#define	ip6_defhlim	64


struct icmp6_hdr {
	u_int8_t	icmp6_type;
	u_int8_t	icmp6_code;
	u_int16_t	icmp6_cksum;
	u_int32_t	icmp6_mtu;
	struct ip6_hdr	icmp6_ip6;
};

#define ICMP6_DST_UNREACH	1
	#define	ICMP6_DST_UNREACH_NOROUTE	0
	#define ICMP6_DST_UNREACH_ADMIN		1
	#define ICMP6_DST_UNREACH_BEYONDSCOPE	3
	#define ICMP6_DST_UNREACH_ADDR		4
	#define ICMP6_DST_UNREACH_NOPORT	5
#define	ICMP6_PACKET_TOO_BIG	2

struct ip6ctlparam {
	struct mbuf		*ip6c_m;
	struct icmp6_hdr 	*ip6c_icmp6;
	struct ip6_hdr		*ip6c_ip6;
	int			ip6c_off;
	struct sockaddr_in6 	*ip6c_src;
	struct sockaddr_in6	*ip6c_dst;
	struct in6_addr		*ip6c_finaldst;
	void			*ip6c_cmdarg;
	u_int8_t		ip6c_nxt;
};


#define IN6_IS_SCOPE_LINKLOCAL(a) \
	((IN6_IS_ADDR_LINKLOCAL(a)) ||  \
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)))

#define IP6_EXTHDR_GET(val, typ, m, off, len) do { \
	if ((m)->m_len >= (off) + (len)) { \
		(val) = (val) = (typ)(mtod((m), caddr_t) + (off)); \
	} else {\
		m_freem((m)); \
		(m) = NULL; \
	} \
} while (0)

#define IN6_IFF_ANYCAST		0x01
#define IN6_IFF_TENTATIVE	0x02
#define IN6_IFF_DUPLICATED	0x04
#define IN6_IFF_DETACHED	0x08
#define IN6_IFF_DEPRECATED	0x10
#define IN6_IFF_NODAD		0x20
#define IN6_IFF_AUTOCONF	0x40
#define IN6_IFF_TEMPORARY	0x80
#define IN6_IFF_NOPFX		0x8000
#define IN6_IFF_NOTREADY (IN6_IFF_TENTATIVE|IN6_IFF_DUPLICATED)

extern int ip6_v6only;
extern int ip6_use_deprecated;

extern u_char inet6ctlerrmap[PRC_NCMDS];
extern struct domain inet6domain;

void	in6_sin6_2_sin(struct sockaddr_in *, struct sockaddr_in6 *);
void	in6_sin_2_v4mapsin6(struct sockaddr_in *, struct sockaddr_in6 *);
int	ip6_ctloutput(struct socket *, struct sockopt *);
int	in6_embedscope(struct in6_addr *, const struct sockaddr_in6 *);
int	in6_recoverscope(struct sockaddr_in6 *, const struct in6_addr *, struct ifnet *);
int	in6_clearscope(struct in6_addr *);
char*	ip6_sprintf(const struct in6_addr *);

#endif	/* _NETINET6_IN6_H_ */
