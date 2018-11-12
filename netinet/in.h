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
 * $FreeBSD: src/sys/netinet/in.h,v 1.102 2008/04/17 12:50:42 gnn Exp $
 */

#ifndef _NETINET_IN_H_
#define	_NETINET_IN_H_

#include <ws2def.h>
#include <inaddr.h>

#include <sys/types.h>
#include <sys/domain.h>
#include <sys/protosw.h>

#define	IPVERSION	0x04

/* Protocols common to RFC 1700, POSIX, and X/Open. */
#define	IPPROTO_IP		0		/* dummy for IP */
#define	IPPROTO_ICMP		1		/* control message protocol */
#define	IPPROTO_TCP		6		/* tcp */
#define	IPPROTO_UDP		17		/* user datagram protocol */

/*
 * Protocols (RFC 1700)
 */
#define	IPPROTO_HOPOPTS		0		/* IP6 hop-by-hop options */
#define	IPPROTO_IGMP		2		/* group mgmt protocol */
#define	IPPROTO_GGP		3		/* gateway^2 (deprecated) */
#define	IPPROTO_IPV4		4		/* IPv4 encapsulation */
#define	IPPROTO_IPIP		IPPROTO_IPV4	/* for compatibility */
#define	IPPROTO_ST		7		/* Stream protocol II */
#define	IPPROTO_EGP		8		/* exterior gateway protocol */
#define	IPPROTO_PIGP		9		/* private interior gateway */
#define	IPPROTO_RCCMON		10		/* BBN RCC Monitoring */
#define	IPPROTO_NVPII		11		/* network voice protocol*/
#define	IPPROTO_PUP		12		/* pup */
#define	IPPROTO_ARGUS		13		/* Argus */
#define	IPPROTO_EMCON		14		/* EMCON */
#define	IPPROTO_XNET		15		/* Cross Net Debugger */
#define	IPPROTO_CHAOS		16		/* Chaos*/
#define	IPPROTO_MUX		18		/* Multiplexing */
#define	IPPROTO_MEAS		19		/* DCN Measurement Subsystems */
#define	IPPROTO_HMP		20		/* Host Monitoring */
#define	IPPROTO_PRM		21		/* Packet Radio Measurement */
#define	IPPROTO_IDP		22		/* xns idp */
#define	IPPROTO_TRUNK1		23		/* Trunk-1 */
#define	IPPROTO_TRUNK2		24		/* Trunk-2 */
#define	IPPROTO_LEAF1		25		/* Leaf-1 */
#define	IPPROTO_LEAF2		26		/* Leaf-2 */
#define	IPPROTO_RDP		27		/* Reliable Data */
#define	IPPROTO_IRTP		28		/* Reliable Transaction */
#define	IPPROTO_TP		29		/* tp-4 w/ class negotiation */
#define	IPPROTO_BLT		30		/* Bulk Data Transfer */
#define	IPPROTO_NSP		31		/* Network Services */
#define	IPPROTO_INP		32		/* Merit Internodal */
#define	IPPROTO_SEP		33		/* Sequential Exchange */
#define	IPPROTO_3PC		34		/* Third Party Connect */
#define	IPPROTO_IDPR		35		/* InterDomain Policy Routing */
#define	IPPROTO_XTP		36		/* XTP */
#define	IPPROTO_DDP		37		/* Datagram Delivery */
#define	IPPROTO_CMTP		38		/* Control Message Transport */
#define	IPPROTO_TPXX		39		/* TP++ Transport */
#define	IPPROTO_IL		40		/* IL transport protocol */
#define	IPPROTO_IPV6		41		/* IP6 header */
#define	IPPROTO_SDRP		42		/* Source Demand Routing */
#define	IPPROTO_ROUTING		43		/* IP6 routing header */
#define	IPPROTO_FRAGMENT	44		/* IP6 fragmentation header */
#define	IPPROTO_IDRP		45		/* InterDomain Routing*/
#define	IPPROTO_RSVP		46		/* resource reservation */
#define	IPPROTO_GRE		47		/* General Routing Encap. */
#define	IPPROTO_MHRP		48		/* Mobile Host Routing */
#define	IPPROTO_BHA		49		/* BHA */
#define	IPPROTO_ESP		50		/* IP6 Encap Sec. Payload */
#define	IPPROTO_AH		51		/* IP6 Auth Header */
#define	IPPROTO_INLSP		52		/* Integ. Net Layer Security */
#define	IPPROTO_SWIPE		53		/* IP with encryption */
#define	IPPROTO_NHRP		54		/* Next Hop Resolution */
#define	IPPROTO_MOBILE		55		/* IP Mobility */
#define	IPPROTO_TLSP		56		/* Transport Layer Security */
#define	IPPROTO_SKIP		57		/* SKIP */
#define	IPPROTO_ICMPV6		58		/* ICMP6 */
#define	IPPROTO_NONE		59		/* IP6 no next header */
#define	IPPROTO_DSTOPTS		60		/* IP6 destination option */
#define	IPPROTO_AHIP		61		/* any host internal protocol */
#define	IPPROTO_CFTP		62		/* CFTP */
#define	IPPROTO_HELLO		63		/* "hello" routing protocol */
#define	IPPROTO_SATEXPAK	64		/* SATNET/Backroom EXPAK */
#define	IPPROTO_KRYPTOLAN	65		/* Kryptolan */
#define	IPPROTO_RVD		66		/* Remote Virtual Disk */
#define	IPPROTO_IPPC		67		/* Pluribus Packet Core */
#define	IPPROTO_ADFS		68		/* Any distributed FS */
#define	IPPROTO_SATMON		69		/* Satnet Monitoring */
#define	IPPROTO_VISA		70		/* VISA Protocol */
#define	IPPROTO_IPCV		71		/* Packet Core Utility */
#define	IPPROTO_CPNX		72		/* Comp. Prot. Net. Executive */
#define	IPPROTO_CPHB		73		/* Comp. Prot. HeartBeat */
#define	IPPROTO_WSN		74		/* Wang Span Network */
#define	IPPROTO_PVP		75		/* Packet Video Protocol */
#define	IPPROTO_BRSATMON	76		/* BackRoom SATNET Monitoring */
#define	IPPROTO_ND		77		/* Sun net disk proto (temp.) */
#define	IPPROTO_WBMON		78		/* WIDEBAND Monitoring */
#define	IPPROTO_WBEXPAK		79		/* WIDEBAND EXPAK */
#define	IPPROTO_EON		80		/* ISO cnlp */
#define	IPPROTO_VMTP		81		/* VMTP */
#define	IPPROTO_SVMTP		82		/* Secure VMTP */
#define	IPPROTO_VINES		83		/* Banyon VINES */
#define	IPPROTO_TTP		84		/* TTP */
#define	IPPROTO_IGP		85		/* NSFNET-IGP */
#define	IPPROTO_DGP		86		/* dissimilar gateway prot. */
#define	IPPROTO_TCF		87		/* TCF */
#define	IPPROTO_IGRP		88		/* Cisco/GXS IGRP */
#define	IPPROTO_OSPFIGP		89		/* OSPFIGP */
#define	IPPROTO_SRPC		90		/* Strite RPC protocol */
#define	IPPROTO_LARP		91		/* Locus Address Resoloution */
#define	IPPROTO_MTP		92		/* Multicast Transport */
#define	IPPROTO_AX25		93		/* AX.25 Frames */
#define	IPPROTO_IPEIP		94		/* IP encapsulated in IP */
#define	IPPROTO_MICP		95		/* Mobile Int.ing control */
#define	IPPROTO_SCCSP		96		/* Semaphore Comm. security */
#define	IPPROTO_ETHERIP		97		/* Ethernet IP encapsulation */
#define	IPPROTO_ENCAP		98		/* encapsulation header */
#define	IPPROTO_APES		99		/* any private encr. scheme */
#define	IPPROTO_GMTP		100		/* GMTP*/
#define	IPPROTO_IPCOMP		108		/* payload compression (IPComp) */
#define	IPPROTO_SCTP		132		/* SCTP */
/* 101-254: Partly Unassigned */
#define	IPPROTO_PIM		103		/* Protocol Independent Mcast */
#define	IPPROTO_CARP		112		/* CARP */
#define	IPPROTO_PGM		113		/* PGM */
#define	IPPROTO_PFSYNC		240		/* PFSYNC */
/* 255: Reserved */
/* BSD Private, local use, namespace incursion, no longer used */
#define	IPPROTO_OLD_DIVERT	254		/* OLD divert pseudo-proto */
#define	IPPROTO_MAX		256

/* last return value of *_input(), meaning "all job for this pkt is done".  */
#define	IPPROTO_DONE		257


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
#define	ip_defttl	128


#define ICMP_MINLEN	8
struct icmp {
	u_char		icmp_type;
	u_char		icmp_code;
	u_char		icmp_chsum;
	u_short		icmp_void;
	u_short		icmp_nextmtu;
	struct ip	icmp_ip;
};

#define ICMP_UNREACH	3
#define		ICMP_UNREACH_NET		0
#define		ICMP_UNREACH_HOST		1
#define		ICMP_UNREACH_PROTOCOL		2
#define		ICMP_UNREACH_PORT		3
#define		ICMP_UNREACH_NEEDFRAG		4
#define		ICMP_UNREACH_SRCFAIL		5
#define		ICMP_UNREACH_NET_UNKNOWN	6
#define		ICMP_UNREACH_HOST_UNKNOWN	7
#define		ICMP_UNREACH_ISOLATED		8
#define		ICMP_UNREACH_NET_PROHIB		9
#define		ICMP_UNREACH_HOST_PROHIB	10
#define		ICMP_UNREACH_TOSNET		11
#define		ICMP_UNREACH_TOSHOST		12
#define		ICMP_UNREACH_FILTER_PROHIB	13
#define		ICMP_UNREACH_HOST_PRECEDENCE	14
#define		ICMP_UNREACH_PRECEDENCE_CUTOFF	15

extern u_char inetctlerrmap[PRC_NCMDS];
extern struct domain inetdomain;

int	ip_ctloutput(struct socket *, struct sockopt *);
#endif	/* _NETINET_IN_H_ */
