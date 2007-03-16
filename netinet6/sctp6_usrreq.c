/*-
 * Copyright (c) 2001-2007, Cisco Systems, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * a) Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in 
 *   the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its 
 *    contributors may be used to endorse or promote products derived 
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*	$KAME: sctp6_usrreq.c,v 1.38 2005/08/24 08:08:56 suz Exp $	*/
#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/netinet6/sctp6_usrreq.c,v 1.10 2007/02/12 23:24:31 rrs Exp $");
#endif

#include <netinet/sctp_os.h>
#ifdef __FreeBSD__
#include <sys/proc.h>
#endif
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_input.h>
#include <netinet/sctp_bsd_addr.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_auth.h>
#include <netinet6/sctp6_var.h>


#if defined(__APPLE__)
#define APPLE_FILE_NO 9
#endif

#ifdef SCTP_DEBUG
extern uint32_t sctp_debug_on;
#endif /* SCTP_DEBUG */

extern struct protosw inetsw[];


#if !(defined(__FreeBSD__) || defined(__APPLE__))
extern void 
in6_sin_2_v4mapsin6(struct sockaddr_in *sin,
    struct sockaddr_in6 *sin6);
extern void 
in6_sin6_2_sin(struct sockaddr_in *,
    struct sockaddr_in6 *sin6);
extern void in6_sin6_2_sin_in_sock(struct sockaddr *nam);

/*
 * Convert sockaddr_in6 to sockaddr_in.  Original sockaddr_in6 must be
 * v4 mapped addr or v4 compat addr
 */
void
in6_sin6_2_sin(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin, sizeof(*sin));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
	sin->sin_addr.s_addr = sin6->sin6_addr.s6_addr32[3];
}

/* Convert sockaddr_in to sockaddr_in6 in v4 mapped addr format. */
void
in6_sin_2_v4mapsin6(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sin->sin_port;
	sin6->sin6_addr.s6_addr32[0] = 0;
	sin6->sin6_addr.s6_addr32[1] = 0;
	sin6->sin6_addr.s6_addr32[2] = IPV6_ADDR_INT32_SMP;
	sin6->sin6_addr.s6_addr32[3] = sin->sin_addr.s_addr;
}

/* Convert sockaddr_in6 into sockaddr_in. */
void
in6_sin6_2_sin_in_sock(struct sockaddr *nam)
{
	struct sockaddr_in *sin_p;
	struct sockaddr_in6 sin6;

	/* save original sockaddr_in6 addr and convert it to sockaddr_in  */
	sin6 = *(struct sockaddr_in6 *)nam;
	sin_p = (struct sockaddr_in *)nam;
	in6_sin6_2_sin(sin_p, &sin6);
}

#endif				/* !(__FreeBSD__ || __APPLE__) */

extern int sctp_no_csum_on_loopback;

int
#if defined(__APPLE__)
sctp6_input(mp, offp)
#else
sctp6_input(mp, offp, proto)
#endif
	struct mbuf **mp;
	int *offp;

#ifndef __APPLE__
	int proto;

#endif
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct sctphdr *sh;
	struct sctp_inpcb *in6p = NULL;
	struct sctp_nets *net;
	int refcount_up = 0;
	u_int32_t check, calc_check;
	struct inpcb *in6p_ip;
	struct sctp_chunkhdr *ch;
	int length, mlen, offset, iphlen;
	u_int8_t ecn_bits;
	struct sctp_tcb *stcb = NULL;
	int off = *offp;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif

	m = SCTP_HEADER_TO_CHAIN(*mp);

	ip6 = mtod(m, struct ip6_hdr *);
#ifndef PULLDOWN_TEST
	/* If PULLDOWN_TEST off, must be in a single mbuf. */
	IP6_EXTHDR_CHECK(m, off, (int)(sizeof(*sh) + sizeof(*ch)), IPPROTO_DONE);
	sh = (struct sctphdr *)((caddr_t)ip6 + off);
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(*sh));
#else
	/* Ensure that (sctphdr + sctp_chunkhdr) in a row. */
	IP6_EXTHDR_GET(sh, struct sctphdr *, m, off, sizeof(*sh) + sizeof(*ch));
	if (sh == NULL) {
		SCTP_STAT_INCR(sctps_hdrops);
		return IPPROTO_DONE;
	}
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(struct sctphdr));
#endif

	iphlen = off;
	offset = iphlen + sizeof(*sh) + sizeof(*ch);

#if defined(NFAITH) && NFAITH > 0
#if defined(__FreeBSD_cc_version) && __FreeBSD_cc_version <= 430000
#if defined(NFAITH) && 0 < NFAITH
	if (faithprefix(&ip6h->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		goto bad;
	}
#endif
#else

#ifdef __FreeBSD__
	if (faithprefix_p != NULL && (*faithprefix_p) (&ip6->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		goto bad;
	}
#else
	if (faithprefix(&ip6->ip6_dst))
		goto bad;
#endif
#endif				/* __FreeBSD_cc_version */

#endif				/* NFAITH defined and > 0 */
	SCTP_STAT_INCR(sctps_recvpackets);
	SCTP_STAT_INCR_COUNTER64(sctps_inpackets);
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INPUT1) {
		printf("V6 input gets a packet iphlen:%d pktlen:%d\n", iphlen, SCTP_HEADER_LEN((*mp)));
	}
#endif
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		/* No multi-cast support in SCTP */
		goto bad;
	}
	/* destination port of 0 is illegal, based on RFC2960. */
	if (sh->dest_port == 0)
		goto bad;
	if ((sctp_no_csum_on_loopback == 0) ||
	    (!SCTP_IS_IT_LOOPBACK(m))) {
		/*
		 * we do NOT validate things from the loopback if the sysctl
		 * is set to 1.
		 */
		check = sh->checksum;	/* save incoming checksum */
		if ((check == 0) && (sctp_no_csum_on_loopback)) {
			/*
			 * special hook for where we got a local address
			 * somehow routed across a non IFT_LOOP type
			 * interface
			 */
			if (IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &ip6->ip6_dst))
				goto sctp_skip_csum;
		}
		sh->checksum = 0;	/* prepare for calc */
		calc_check = sctp_calculate_sum(m, &mlen, iphlen);
		if (calc_check != check) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INPUT1) {
				printf("Bad CSUM on SCTP packet calc_check:%x check:%x  m:%p mlen:%d iphlen:%d\n",
				    calc_check, check, m,
				    mlen, iphlen);
			}
#endif
			stcb = sctp_findassociation_addr(m, iphlen, offset - sizeof(*ch),
			    sh, ch, &in6p, &net);
			/* in6p's ref-count increased && stcb locked */
			if ((in6p) && (stcb)) {
				sctp_send_packet_dropped(stcb, net, m, iphlen, 1);
				sctp_chunk_output((struct sctp_inpcb *)in6p, stcb, 2);
#if defined(SCTP_PER_SOCKET_LOCKING)
				SCTP_SOCKET_UNLOCK(SCTP_INP_SO(in6p), 1);
#endif
			} else if ((in6p != NULL) && (stcb == NULL)) {
#if defined(SCTP_PER_SOCKET_LOCKING)
				SCTP_SOCKET_UNLOCK(SCTP_INP_SO(in6p), 1);
#endif
				refcount_up = 1;
			}
			SCTP_STAT_INCR(sctps_badsum);
			SCTP_STAT_INCR_COUNTER32(sctps_checksumerrors);
			goto bad;
		}
		sh->checksum = calc_check;
	} 
sctp_skip_csum:
	net = NULL;
	/*
	 * Locate pcb and tcb for datagram sctp_findassociation_addr() wants
	 * IP/SCTP/first chunk header...
	 */
	stcb = sctp_findassociation_addr(m, iphlen, offset - sizeof(*ch),
	    sh, ch, &in6p, &net);
	/* in6p's ref-count increased */
	if (in6p == NULL) {
		struct sctp_init_chunk *init_chk, chunk_buf;

		SCTP_STAT_INCR(sctps_noport);
		if (ch->chunk_type == SCTP_INITIATION) {
			/*
			 * we do a trick here to get the INIT tag, dig in
			 * and get the tag from the INIT and put it in the
			 * common header.
			 */
			init_chk = (struct sctp_init_chunk *)sctp_m_getptr(m,
			    iphlen + sizeof(*sh), sizeof(*init_chk),
			    (u_int8_t *) & chunk_buf);
			sh->v_tag = init_chk->init.initiate_tag;
		}
		if (ch->chunk_type == SCTP_SHUTDOWN_ACK) {
			sctp_send_shutdown_complete2(m, iphlen, sh);
 			goto bad;
		}
		if (ch->chunk_type == SCTP_SHUTDOWN_COMPLETE) {
			goto bad;
		}

		if (ch->chunk_type != SCTP_ABORT_ASSOCIATION)
			sctp_send_abort(m, iphlen, sh, 0, NULL);
		goto bad;
	} else if (stcb == NULL) {
		refcount_up = 1;
	}
	in6p_ip = (struct inpcb *)in6p;
#ifdef IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
#ifdef __OpenBSD__
	{
		struct inpcb *i_inp;
		struct m_tag *mtag;
		struct tdb_ident *tdbi;
		struct tdb *tdb;
#if defined(__NetBSD__) || defined(__OpenBSD__)
		int s;
#endif
		int error;

		/* Find most recent IPsec tag */
		i_inp = (struct inpcb *)in6p;
		mtag = m_tag_find(m, PACKET_TAG_IPSEC_IN_DONE, NULL);
		s = splsoftnet();
		if (mtag != NULL) {
			tdbi = (struct tdb_ident *)(mtag + 1);
			tdb = gettdb(tdbi->spi, &tdbi->dst, tdbi->proto);
		} else
			tdb = NULL;

		ipsp_spd_lookup(m, af, iphlen, &error, IPSP_DIRECTION_IN,
		    tdb, i_inp);
		if (error) {
			splx(s);
			goto bad;
		}
		/* Latch SA */
		if (i_inp->inp_tdb_in != tdb) {
			if (tdb) {
				tdb_add_inp(tdb, i_inp, 1);
				if (i_inp->inp_ipo == NULL) {
					i_inp->inp_ipo = ipsec_add_policy(i_inp,
					    af, IPSP_DIRECTION_OUT);
					if (i_inp->inp_ipo == NULL) {
						splx(s);
						goto bad;
					}
				}
				if (i_inp->inp_ipo->ipo_dstid == NULL &&
				    tdb->tdb_srcid != NULL) {
					i_inp->inp_ipo->ipo_dstid =
					    tdb->tdb_srcid;
					tdb->tdb_srcid->ref_count++;
				}
				if (i_inp->inp_ipsec_remotecred == NULL &&
				    tdb->tdb_remote_cred != NULL) {
					i_inp->inp_ipsec_remotecred =
					    tdb->tdb_remote_cred;
					tdb->tdb_remote_cred->ref_count++;
				}
				if (i_inp->inp_ipsec_remoteauth == NULL &&
				    tdb->tdb_remote_auth != NULL) {
					i_inp->inp_ipsec_remoteauth =
					    tdb->tdb_remote_auth;
					tdb->tdb_remote_auth->ref_count++;
				}
			} else {/* Just reset */
				TAILQ_REMOVE(&i_inp->inp_tdb_in->tdb_inp_in,
				    i_inp, binp_tdb_in_next);
				i_inp->inp_tdb_in = NULL;
			}
		}
		splx(s);
	}
#else
	if (in6p_ip && (ipsec6_in_reject(m, in6p_ip))) {
/* XXX */
#ifdef __APPLE__
		/* FIX ME: need to find right stat for __APPLE__ */
#endif
#ifndef __APPLE__
		ipsec6stat.in_polvio++;
#endif
		goto bad;
	}
#endif
#endif				/* IPSEC */

#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(SCTP_INP_SO(in6p));
#endif

	/*
	 * CONTROL chunk processing
	 */
	offset -= sizeof(*ch);
	ecn_bits = ((ntohl(ip6->ip6_flow) >> 20) & 0x000000ff);

	/* Length now holds the total packet length payload + iphlen */
	length = ntohs(ip6->ip6_plen) + iphlen;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	(void)sctp_common_input_processing(&m, iphlen, offset, length, sh, ch,
	    in6p, stcb, net, ecn_bits);
	/* inp's ref-count reduced && stcb unlocked */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	/* XXX this stuff below gets moved to appropriate parts later... */
	if (m)
		m_freem(m);
	if ((in6p) && refcount_up) {
		/* reduce ref-count */
		SCTP_INP_WLOCK(in6p);
		SCTP_INP_DECR_REF(in6p);
		SCTP_INP_WUNLOCK(in6p);
	}
#if defined(SCTP_PER_SOCKET_LOCKING)
	SCTP_SOCKET_UNLOCK(SCTP_INP_SO(in6p), 1);
#endif

	return IPPROTO_DONE;

bad:
	if (stcb)
		SCTP_TCB_UNLOCK(stcb);

	if ((in6p) && refcount_up) {
		/* reduce ref-count */
		SCTP_INP_WLOCK(in6p);
		SCTP_INP_DECR_REF(in6p);
		SCTP_INP_WUNLOCK(in6p);
	}
	if (m)
		m_freem(m);
	return IPPROTO_DONE;
}


static void
sctp6_notify_mbuf(struct sctp_inpcb *inp,
    struct icmp6_hdr *icmp6,
    struct sctphdr *sh,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	u_int32_t nxtsz;

	if ((inp == NULL) || (stcb == NULL) || (net == NULL) ||
	    (icmp6 == NULL) || (sh == NULL)) {
		goto out;
	}
	/* First do we even look at it? */
	if (ntohl(sh->v_tag) != (stcb->asoc.peer_vtag))
		goto out;

	if (icmp6->icmp6_type != ICMP6_PACKET_TOO_BIG) {
		/* not PACKET TO BIG */
		goto out;
	}
	/*
	 * ok we need to look closely. We could even get smarter and look at
	 * anyone that we sent to in case we get a different ICMP that tells
	 * us there is no way to reach a host, but for this impl, all we
	 * care about is MTU discovery.
	 */
	nxtsz = ntohl(icmp6->icmp6_mtu);
	/* Stop any PMTU timer */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, NULL, SCTP_FROM_SCTP6_USRREQ+SCTP_LOC_1);

	/* Adjust destination size limit */
	if (net->mtu > nxtsz) {
		net->mtu = nxtsz;
	}
	/* now what about the ep? */
	if (stcb->asoc.smallest_mtu > nxtsz) {
		struct sctp_tmit_chunk *chk;

		/* Adjust that too */
		stcb->asoc.smallest_mtu = nxtsz;
		/* now off to subtract IP_DF flag if needed */

		TAILQ_FOREACH(chk, &stcb->asoc.send_queue, sctp_next) {
			if ((u_int32_t) (chk->send_size + IP_HDR_SIZE) > nxtsz) {
				chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
			}
		}
		TAILQ_FOREACH(chk, &stcb->asoc.sent_queue, sctp_next) {
			if ((u_int32_t) (chk->send_size + IP_HDR_SIZE) > nxtsz) {
				/*
				 * For this guy we also mark for immediate
				 * resend since we sent to big of chunk
				 */
				chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
				if (chk->sent != SCTP_DATAGRAM_RESEND)
					stcb->asoc.sent_queue_retran_cnt++;
				chk->sent = SCTP_DATAGRAM_RESEND;
				chk->rec.data.doing_fast_retransmit = 0;

				chk->sent = SCTP_DATAGRAM_RESEND;
				/* Clear any time so NO RTT is being done */
				chk->sent_rcv_time.tv_sec = 0;
				chk->sent_rcv_time.tv_usec = 0;
				stcb->asoc.total_flight -= chk->send_size;
				net->flight_size -= chk->send_size;
			}
		}
	}
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, NULL);
out:
	if (stcb)
		SCTP_TCB_UNLOCK(stcb);
}


void
sctp6_ctlinput(cmd, pktdst, d)
	int cmd;
	struct sockaddr *pktdst;
	void *d;
{
	struct sctphdr sh;
	struct ip6ctlparam *ip6cp = NULL;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int cm;

	if (pktdst->sa_family != AF_INET6 ||
	    pktdst->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd)) {
		d = NULL;
	} else if (inet6ctlerrmap[cmd] == 0) {
		return;
	}
	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
	} else {
		ip6cp = (struct ip6ctlparam *)NULL;
	}

	if (ip6cp) {
		/*
		 * XXX: We assume that when IPV6 is non NULL, M and OFF are
		 * valid.
		 */
		/* check if we can safely examine src and dst ports */
		struct sctp_inpcb *inp = NULL;
		struct sctp_tcb *stcb = NULL;
		struct sctp_nets *net = NULL;
		struct sockaddr_in6 final;

		if (ip6cp->ip6c_m == NULL)
			return;

		bzero(&sh, sizeof(sh));
		bzero(&final, sizeof(final));
		inp = NULL;
		net = NULL;
		m_copydata(ip6cp->ip6c_m, ip6cp->ip6c_off, sizeof(sh),
		    (caddr_t)&sh);
		ip6cp->ip6c_src->sin6_port = sh.src_port;
		final.sin6_len = sizeof(final);
		final.sin6_family = AF_INET6;
#if defined(__FreeBSD__) && __FreeBSD_cc_version < 440000
		final.sin6_addr = *ip6cp->ip6c_finaldst;
#else
		final.sin6_addr = ((struct sockaddr_in6 *)pktdst)->sin6_addr;
#endif				/* __FreeBSD_cc_version */
		final.sin6_port = sh.dest_port;
#if defined(__NetBSD__) || defined(__OpenBSD__)
		s = splsoftnet();
#endif
		stcb = sctp_findassociation_addr_sa((struct sockaddr *)ip6cp->ip6c_src,
		    (struct sockaddr *)&final,
		    &inp, &net, 1);
		/* inp's ref-count increased && stcb locked */
		if (stcb != NULL && inp && (inp->sctp_socket != NULL)) {
			if (cmd == PRC_MSGSIZE) {
				sctp6_notify_mbuf(inp,
				    ip6cp->ip6c_icmp6,
				    &sh,
				    stcb,
				    net);
				/* inp's ref-count reduced && stcb unlocked */
			} else {
				if (cmd == PRC_HOSTDEAD) {
					cm = EHOSTUNREACH;
				} else {
					cm = inet6ctlerrmap[cmd];
				}
				sctp_notify(inp, cm, &sh,
				    (struct sockaddr *)&final,
				    stcb, net);
				/* inp's ref-count reduced && stcb unlocked */
			}
		} else {
			if (PRC_IS_REDIRECT(cmd) && inp) {
#ifdef __OpenBSD__
				in_rtchange((struct inpcb *)inp,
				    inetctlerrmap[cmd]);
#else
				in6_rtchange((struct in6pcb *)inp,
				    inet6ctlerrmap[cmd]);
#endif
			}
			if (inp) {
				/* reduce inp's ref-count */
				SCTP_INP_WLOCK(inp);
				SCTP_INP_DECR_REF(inp);
				SCTP_INP_WUNLOCK(inp);
			}
			if (stcb)
				SCTP_TCB_UNLOCK(stcb);
		}
#if defined(SCTP_PER_SOCKET_LOCKING)
		if (inp != NULL) {
			SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
		}
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
	}
}

/*
 * this routine can probably be collasped into the one in sctp_userreq.c
 * since they do the same thing and now we lookup with a sockaddr
 */
#ifdef __FreeBSD__
static int
sctp6_getcred(SYSCTL_HANDLER_ARGS)
{
	struct xucred xuc;
	struct sockaddr_in6 addrs[2];
	struct sctp_inpcb *inp;
	struct sctp_nets *net;
	struct sctp_tcb *stcb;
	int error;

#if defined(__FreeBSD__) && __FreeBSD_version > 602000
	/*
	 * XXXRW: Other instances of getcred use SUSER_ALLOWJAIL, as socket
	 * visibility is scoped using cr_canseesocket(), which it is not
	 * here.
	 */
	error = priv_check_cred(req->td->td_ucred, PRIV_NETINET_RESERVEDPORT,
	    0);
#elif defined(__FreeBSD__) && __FreeBSD_version >= 500000
	error = suser(req->td);
#else
	error = suser(req->p);
#endif
	if (error)
		return (error);

	if (req->newlen != sizeof(addrs))
		return (EINVAL);
	if (req->oldlen != sizeof(struct ucred))
		return (EINVAL);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);

	stcb = sctp_findassociation_addr_sa(sin6tosa(&addrs[0]),
	    sin6tosa(&addrs[1]),
	    &inp, &net, 1);
	if (stcb == NULL || inp == NULL || inp->sctp_socket == NULL) {
		if ((inp != NULL) && (stcb == NULL)) {
			/* reduce ref-count */
			SCTP_INP_WLOCK(inp);
			SCTP_INP_DECR_REF(inp);
			goto cred_can_cont;
		}
		error = ENOENT;
		goto out;
	}
	SCTP_TCB_UNLOCK(stcb);
	/* We use the write lock here, only
	 * since in the error leg we need it.
	 * If we used RLOCK, then we would have
	 * to wlock/decr/unlock/rlock. Which
	 * in theory could create a hole. Better
	 * to use higher wlock.
	 */
	SCTP_INP_WLOCK(inp);	
 cred_can_cont:
	error = cr_canseesocket(req->td->td_ucred, inp->sctp_socket);
	if (error) {
		SCTP_INP_WUNLOCK(inp);
		goto out;
	}
	cru2x(inp->sctp_socket->so_cred, &xuc);
	SCTP_INP_WUNLOCK(inp);
	error = SYSCTL_OUT(req, &xuc, sizeof(struct xucred));
out:
	return (error);
}

SYSCTL_PROC(_net_inet6_sctp6, OID_AUTO, getcred, CTLTYPE_OPAQUE | CTLFLAG_RW,
    0, 0,
    sctp6_getcred, "S,ucred", "Get the ucred of a SCTP6 connection");

#endif

/* This is the same as the sctp_abort() could be made common */
#if defined(__FreeBSD__) && __FreeBSD_version > 690000
static void
#elif defined(__Panda__)
int
#else
static int
#endif
sctp6_abort(struct socket *so)
{
	struct sctp_inpcb *inp;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	uint32_t flags;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
#if defined(__FreeBSD__) && __FreeBSD_version > 690000
		return;
#else
		return EINVAL;
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
 sctp_must_try_again:
	flags = inp->sctp_flags;
#ifdef SCTP_LOG_CLOSING
	sctp_log_closing(inp, NULL, 17);
#endif
	if (((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) &&
	    (atomic_cmpset_int(&inp->sctp_flags, flags, (flags | SCTP_PCB_FLAGS_SOCKET_GONE | SCTP_PCB_FLAGS_CLOSE_IP)))) {
#ifdef SCTP_LOG_CLOSING
		sctp_log_closing(inp, NULL, 16);
#endif
		sctp_inpcb_free(inp, 1, 0);
		SOCK_LOCK(so);
		so->so_snd.sb_cc = 0;
		so->so_snd.sb_mb = NULL;
		so->so_snd.sb_mbcnt = 0;
		
		/* same for the rcv ones, they are only
		 * here for the accounting/select.
		 */
		so->so_rcv.sb_cc = 0;
		so->so_rcv.sb_mb = NULL;
		so->so_rcv.sb_mbcnt = 0;
		/* Now null out the reference, we are
		 * completely detached.
		 */
#if !defined(SCTP_APPLE_FINE_GRAINED_LOCKING)
		so->so_pcb = NULL;
#endif
		SOCK_UNLOCK(so);
	} else {
		flags = inp->sctp_flags;
		if ((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) {
			goto sctp_must_try_again;
		}
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
#if defined(__FreeBSD__) && __FreeBSD_version > 690000
	return;
#else
	return (0);
#endif
}

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
static int
sctp6_attach(struct socket *so, int proto, struct thread *p)
#elif defined(__Panda__)
int
sctp6_attach(struct socket *so, int proto, uint32_t vrfid)
#else
static int
sctp6_attach(struct socket *so, int proto, struct proc *p)
#endif
{
	struct in6pcb *inp6;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int error;
	struct sctp_inpcb *inp;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp != NULL)
		return EINVAL;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, sctp_sendspace, sctp_recvspace);
		if (error)
			return error;
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	error = sctp_inpcb_alloc(so);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	if (error)
		return error;
	inp = (struct sctp_inpcb *)so->so_pcb;
	inp->sctp_flags |= SCTP_PCB_FLAGS_BOUND_V6;	/* I'm v6! */
	inp6 = (struct in6pcb *)inp;

#if defined(__FreeBSD__) || defined(__APPLE__)
	inp6->inp_vflag |= INP_IPV6;
#else
#if defined(__OpenBSD__)
	inp->ip_inp.inp.inp_flags |= INP_IPV6;
#else
	inp->inp_vflag |= INP_IPV6;
#endif
#endif
#if defined(__NetBSD__)
	if (ip6_v6only) {
		inp6->in6p_flags |= IN6P_IPV6_V6ONLY;
	}
	so->so_send = sctp_sosend;
#endif
	inp6->in6p_hops = -1;	/* use kernel default */
	inp6->in6p_cksum = -1;	/* just to be sure */
#ifdef INET
	/*
	 * XXX: ugly!! IPv4 TTL initialization is necessary for an IPv6
	 * socket as well, because the socket may be bound to an IPv6
	 * wildcard address, which may match an IPv4-mapped IPv6 address.
	 */
#if defined(__FreeBSD__) || defined(__APPLE__)
	inp6->inp_ip_ttl = ip_defttl;
#else
	inp->inp_ip_ttl = ip_defttl;
#endif
#endif
	/*
	 * Hmm what about the IPSEC stuff that is missing here but in
	 * sctp_attach()?
	 */
	return 0;
}

static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp6_bind(struct socket *so, struct sockaddr *addr, struct thread *p)
{
#else
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp6_bind(struct socket *so, struct sockaddr *addr, struct proc *p)
{
#else
sctp6_bind(struct socket *so, struct mbuf *nam, struct proc *p)
{
	struct sockaddr *addr = nam ? mtod(nam, struct sockaddr *): NULL;

#endif
#endif
	struct sctp_inpcb *inp;
	struct in6pcb *inp6;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int error;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;

	inp6 = (struct in6pcb *)inp;
#if defined(__FreeBSD__) || defined(__APPLE__)
	inp6->inp_vflag &= ~INP_IPV4;
	inp6->inp_vflag |= INP_IPV6;
#else
#if defined(__OpenBSD__)
	inp->ip_inp.inp.inp_flags &= ~INP_IPV4;
	inp->ip_inp.inp.inp_flags |= INP_IPV6;
#else
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
#endif
#endif
	if ((addr != NULL) && (SCTP_IPV6_V6ONLY(inp6) == 0)) {
		if (addr->sa_family == AF_INET) {
			/* binding v4 addr to v6 socket, so reset flags */
#if defined(__FreeBSD__) || defined(__APPLE__)
			inp6->inp_vflag |= INP_IPV4;
			inp6->inp_vflag &= ~INP_IPV6;
#else
#if defined(__OpenBSD__)
			inp->ip_inp.inp.inp_flags |= INP_IPV4;
			inp->ip_inp.inp.inp_flags &= ~INP_IPV6;
#else
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
#endif
#endif
		} else {
			struct sockaddr_in6 *sin6_p;

			sin6_p = (struct sockaddr_in6 *)addr;

			if (IN6_IS_ADDR_UNSPECIFIED(&sin6_p->sin6_addr)) {
#if defined(__FreeBSD__) || defined(__APPLE__)
				inp6->inp_vflag |= INP_IPV4;
#else
#if defined(__OpenBSD__)
				inp->ip_inp.inp.inp_flags |= INP_IPV4;
#else
				inp->inp_vflag |= INP_IPV4;
#endif
#endif
			} else if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
				struct sockaddr_in sin;

				in6_sin6_2_sin(&sin, sin6_p);
#if defined(__FreeBSD__) || defined(__APPLE__)
				inp6->inp_vflag |= INP_IPV4;
				inp6->inp_vflag &= ~INP_IPV6;
#else
#if defined(__OpenBSD__)
				inp->ip_inp.inp.inp_flags |= INP_IPV4;
				inp->ip_inp.inp.inp_flags &= ~INP_IPV6;

#else
				inp->inp_vflag |= INP_IPV4;
				inp->inp_vflag &= ~INP_IPV6;
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
				s = splsoftnet();
#endif
				error = sctp_inpcb_bind(so, (struct sockaddr *)&sin, p);
#if defined(__NetBSD__) || defined(__OpenBSD__)
				splx(s);
#endif
				return error;
			}
		}
	} else if (addr != NULL) {
		/* IPV6_V6ONLY socket */
		if (addr->sa_family == AF_INET) {
			/* can't bind v4 addr to v6 only socket! */
			return EINVAL;
		} else {
			struct sockaddr_in6 *sin6_p;

			sin6_p = (struct sockaddr_in6 *)addr;

			if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr))
				/* can't bind v4-mapped addrs either! */
				/* NOTE: we don't support SIIT */
				return EINVAL;
		}
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	error = sctp_inpcb_bind(so, addr, p);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return error;
}

#if defined(__FreeBSD__) && __FreeBSD_version > 690000

static void	
sctp6_close(struct socket *so)
{
	struct sctp_inpcb *inp;
	uint32_t flags;
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return;

	/* Inform all the lower layer assoc that we
	 * are done.
	 */
 sctp_must_try_again:
	flags = inp->sctp_flags;
#ifdef SCTP_LOG_CLOSING
	sctp_log_closing(inp, NULL, 17);
#endif
	if (((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) &&
	    (atomic_cmpset_int(&inp->sctp_flags, flags, (flags | SCTP_PCB_FLAGS_SOCKET_GONE | SCTP_PCB_FLAGS_CLOSE_IP)))) {
		if (((so->so_options & SO_LINGER) && (so->so_linger == 0)) ||
		    (so->so_rcv.sb_cc > 0)) {
#ifdef SCTP_LOG_CLOSING
			sctp_log_closing(inp, NULL, 13);
#endif
			sctp_inpcb_free(inp, 1, 1);
		} else {
#ifdef SCTP_LOG_CLOSING
			sctp_log_closing(inp, NULL, 14);
#endif
			sctp_inpcb_free(inp, 0, 1);
		}
		/* The socket is now detached, no matter what
		 * the state of the SCTP association.
		 */
		SOCK_LOCK(so);
		so->so_snd.sb_cc = 0;
		so->so_snd.sb_mb = NULL;
		so->so_snd.sb_mbcnt = 0;
		
		/* same for the rcv ones, they are only
		 * here for the accounting/select.
		 */
		so->so_rcv.sb_cc = 0;
		so->so_rcv.sb_mb = NULL;
		so->so_rcv.sb_mbcnt = 0;
		/* Now null out the reference, we are
		 * completely detached.
		 */
#if !defined(SCTP_APPLE_FINE_GRAINED_LOCKING)
		so->so_pcb = NULL;
#endif
		SOCK_UNLOCK(so);
	} else {
		flags = inp->sctp_flags;
		if ((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) {
			goto sctp_must_try_again;
		}
	}
	return;

}

/* This could be made common with sctp_detach() since they are identical */
#elif defined(__Panda__)
int
sctp6_detach(struct socket *so)
#else
static int
sctp6_detach(struct socket *so)
{
	struct sctp_inpcb *inp;
	uint32_t flags;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
 sctp_must_try_again:
	flags = inp->sctp_flags;
#ifdef SCTP_LOG_CLOSING
	sctp_log_closing(inp, NULL, 17);
#endif
	if (((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) &&
	    (atomic_cmpset_int(&inp->sctp_flags, flags, (flags | SCTP_PCB_FLAGS_SOCKET_GONE | SCTP_PCB_FLAGS_CLOSE_IP)))) {
		if (((so->so_options & SO_LINGER) && (so->so_linger == 0)) ||
		    (so->so_rcv.sb_cc > 0)) {
#ifdef SCTP_LOG_CLOSING
			sctp_log_closing(inp, NULL, 13);
#endif
			sctp_inpcb_free(inp, 1, 1);
		} else {
#ifdef SCTP_LOG_CLOSING
			sctp_log_closing(inp, NULL, 14);
#endif
			sctp_inpcb_free(inp, 0, 1);
		}
		
		/* The socket is now detached, no matter what
		 * the state of the SCTP association.
		 */
		SOCK_LOCK(so);
		so->so_snd.sb_cc = 0;
		so->so_snd.sb_mb = NULL;
		so->so_snd.sb_mbcnt = 0;
		
		/* same for the rcv ones, they are only
		 * here for the accounting/select.
		 */
		so->so_rcv.sb_cc = 0;
		so->so_rcv.sb_mb = NULL;
		so->so_rcv.sb_mbcnt = 0;
		/* Now null out the reference, we are
		 * completely detached.
		 */
		/* Now disconnect */
#if !defined(SCTP_APPLE_FINE_GRAINED_LOCKING)
		/* MT FIXME: Is there anything to do here for Tiger ? */
		so->so_pcb = NULL;
#endif
		SOCK_UNLOCK(so);
	} else {
		flags = inp->sctp_flags;
		if ((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) {
			goto sctp_must_try_again;
		}
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return (0);
}
#endif

static int
sctp6_disconnect(struct socket *so)
{
	struct sctp_inpcb *inp;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
	s = splsoftnet();
#endif

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (ENOTCONN);
	}
	SCTP_INP_RLOCK(inp);
	if (inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		if (SCTP_LIST_EMPTY(&inp->sctp_asoc_list)) {
			/* No connection */
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			SCTP_INP_RUNLOCK(inp);
			return (ENOTCONN);
		} else {
			int some_on_streamwheel = 0;
			struct sctp_association *asoc;
			struct sctp_tcb *stcb;

			stcb = LIST_FIRST(&inp->sctp_asoc_list);
			if (stcb == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
				splx(s);
#endif
				SCTP_INP_RUNLOCK(inp);
				return (EINVAL);
			}
			SCTP_TCB_LOCK(stcb);
			asoc = &stcb->asoc;
			if (((so->so_options & SO_LINGER) &&
			    (so->so_linger == 0)) ||
			    (so->so_rcv.sb_cc > 0)) {
				if (SCTP_GET_STATE(asoc) !=
				    SCTP_STATE_COOKIE_WAIT) {
					/* Left with Data unread */
					struct mbuf *err;

					err = NULL;
					MGET(err, M_DONTWAIT, MT_DATA);
					if (err) {
						/*
						 * Fill in the user
						 * initiated abort
						 */
						struct sctp_paramhdr *ph;

						ph = mtod(err, struct sctp_paramhdr *);
						SCTP_BUF_LEN(err) = sizeof(struct sctp_paramhdr);
						ph->param_type = htons(SCTP_CAUSE_USER_INITIATED_ABT);
						ph->param_length = htons(SCTP_BUF_LEN(err));
					}
					sctp_send_abort_tcb(stcb, err);
					SCTP_STAT_INCR_COUNTER32(sctps_aborted);
				}
				SCTP_INP_RUNLOCK(inp);
				if ((SCTP_GET_STATE(&stcb->asoc) == SCTP_STATE_OPEN) ||
				    (SCTP_GET_STATE(&stcb->asoc) == SCTP_STATE_SHUTDOWN_RECEIVED)) {
					SCTP_STAT_DECR_GAUGE32(sctps_currestab);
				}
				sctp_free_assoc(inp, stcb, SCTP_DONOT_SETSCOPE,
						SCTP_FROM_SCTP6_USRREQ+SCTP_LOC_2);
				/* No unlock tcb assoc is gone */
#if defined(__NetBSD__) || defined(__OpenBSD__)
				splx(s);
#endif
				return (0);
			}
			if (!TAILQ_EMPTY(&asoc->out_wheel)) {
				/* Check to see if some data queued */
				struct sctp_stream_out *outs;

				TAILQ_FOREACH(outs, &asoc->out_wheel,
				    next_spoke) {
					if (!TAILQ_EMPTY(&outs->outqueue)) {
						some_on_streamwheel = 1;
						break;
					}
				}
			}
			if (TAILQ_EMPTY(&asoc->send_queue) &&
			    TAILQ_EMPTY(&asoc->sent_queue) &&
			    (some_on_streamwheel == 0)) {
				/* nothing queued to send, so I'm done... */
				if ((SCTP_GET_STATE(asoc) !=
				    SCTP_STATE_SHUTDOWN_SENT) &&
				    (SCTP_GET_STATE(asoc) !=
				    SCTP_STATE_SHUTDOWN_ACK_SENT)) {
					/* only send SHUTDOWN the first time */
					sctp_send_shutdown(stcb, stcb->asoc.primary_destination);
					sctp_chunk_output(stcb->sctp_ep, stcb, 1);
					if ((SCTP_GET_STATE(asoc) == SCTP_STATE_OPEN) ||
					    (SCTP_GET_STATE(asoc) == SCTP_STATE_SHUTDOWN_RECEIVED)) {
						SCTP_STAT_DECR_GAUGE32(sctps_currestab);
					}
					asoc->state = SCTP_STATE_SHUTDOWN_SENT;
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN,
					    stcb->sctp_ep, stcb,
					    asoc->primary_destination);
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD,
					    stcb->sctp_ep, stcb,
					    asoc->primary_destination);
				}
			} else {
				/*
				 * we still got (or just got) data to send,
				 * so set SHUTDOWN_PENDING
				 */
				/*
				 * XXX sockets draft says that MSG_EOF
				 * should be sent with no data.  currently,
				 * we will allow user data to be sent first
				 * and move to SHUTDOWN-PENDING
				 */
				asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
			}
			SCTP_TCB_UNLOCK(stcb);
			SCTP_INP_RUNLOCK(inp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (0);
		}
	} else {
		/* UDP model does not support this */
		SCTP_INP_RUNLOCK(inp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return EOPNOTSUPP;
	}
}

int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct thread *p);

#else
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct proc *p);

#endif


static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct thread *p)
{
#else
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct proc *p)
{
#else
sctp6_send(struct socket *so, int flags, struct mbuf *m, struct mbuf *nam,
    struct mbuf *control, struct proc *p)
{
	struct sockaddr *addr = nam ? mtod(nam, struct sockaddr *): NULL;

#endif
#endif
	struct sctp_inpcb *inp;
	struct inpcb *in_inp;
	struct in6pcb *inp6;

#ifdef INET
	struct sockaddr_in6 *sin6;

#endif				/* INET */
	/* No SPL needed since sctp_output does this */

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
		if (control) {
			m_freem(control);
			control = NULL;
		}
		m_freem(m);
		return EINVAL;
	}
	in_inp = (struct inpcb *)inp;
	inp6 = (struct in6pcb *)inp;
	/*
	 * For the TCP model we may get a NULL addr, if we are a connected
	 * socket thats ok.
	 */
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) &&
	    (addr == NULL)) {
		goto connected_type;
	}
	if (addr == NULL) {
		m_freem(m);
		if (control) {
			m_freem(control);
			control = NULL;
		}
		return (EDESTADDRREQ);
	}
#ifdef INET
	sin6 = (struct sockaddr_in6 *)addr;
	if (SCTP_IPV6_V6ONLY(inp6)) {
		/*
		 * if IPV6_V6ONLY flag, we discard datagrams destined to a
		 * v4 addr or v4-mapped addr
		 */
		if (addr->sa_family == AF_INET) {
			return EINVAL;
		}
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			return EINVAL;
		}
	}
	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		if (!ip6_v6only) {
			struct sockaddr_in sin;

			/* convert v4-mapped into v4 addr and send */
			in6_sin6_2_sin(&sin, sin6);
			return sctp_sendm(so, flags, m, (struct sockaddr *)&sin,
			    control, p);
		} else {
			/* mapped addresses aren't enabled */
			return EINVAL;
		}
	}
#endif				/* INET */
connected_type:
	/* now what about control */
	if (control) {
		if (inp->control) {
			printf("huh? control set?\n");
			m_freem(inp->control);
			inp->control = NULL;
		}
		inp->control = control;
	}
	/* Place the data */
	if (inp->pkt) {
		SCTP_BUF_NEXT(inp->pkt_last) = m;
		inp->pkt_last = m;
	} else {
		inp->pkt_last = inp->pkt = m;
	}
	if (
#if defined(__FreeBSD__) || defined(__APPLE__)
	/* FreeBSD and MacOSX uses a flag passed */
	    ((flags & PRUS_MORETOCOME) == 0)
#elif defined(__NetBSD__)
	/* NetBSD uses the so_state field */
	    ((so->so_state & SS_MORETOCOME) == 0)
#else
	    1			/* Open BSD does not have any "more to come"
				 * indication */
#endif
	    ) {
		/*
		 * note with the current version this code will only be used
		 * by OpenBSD, NetBSD and FreeBSD have methods for
		 * re-defining sosend() to use sctp_sosend().  One can
		 * optionaly switch back to this code (by changing back the
		 * defininitions but this is not advisable.
		 */
		int ret;

		ret = sctp_output(inp, inp->pkt, addr, inp->control, p, flags);
		inp->pkt = NULL;
		inp->control = NULL;
		return (ret);
	} else {
		return (0);
	}
}

static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp6_connect(struct socket *so, struct sockaddr *addr, struct thread *p)
{
#else
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp6_connect(struct socket *so, struct sockaddr *addr, struct proc *p)
{
#else
sctp6_connect(struct socket *so, struct mbuf *nam, struct proc *p)
{
	struct sockaddr *addr = mtod(nam, struct sockaddr *);

#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#endif
	uint32_t vrf_id;
	int error = 0;
	struct sctp_inpcb *inp;
	struct in6pcb *inp6;
	struct sctp_tcb *stcb;

#ifdef INET
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage ss;

#endif				/* INET */

	inp6 = (struct in6pcb *)so->so_pcb;
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (ECONNRESET);	/* I made the same as TCP since we are
					 * not setup? */
	}
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
	vrf_id = SCTP_DEFAULT_VRFID;
#else
	vrf_id = panda_get_vrf_from_call(); /* from socket option call? */
#endif
	SCTP_ASOC_CREATE_LOCK(inp);
	SCTP_INP_RLOCK(inp);
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) ==
	    SCTP_PCB_FLAGS_UNBOUND) {
		/* Bind a ephemeral port */
		SCTP_INP_RUNLOCK(inp);
		error = sctp6_bind(so, NULL, p);
		if (error) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			SCTP_ASOC_CREATE_UNLOCK(inp);

			return (error);
		}
		SCTP_INP_RLOCK(inp);
	}
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		SCTP_INP_RUNLOCK(inp);
		SCTP_ASOC_CREATE_UNLOCK(inp);
		return (EADDRINUSE);
	}
#ifdef INET
	sin6 = (struct sockaddr_in6 *)addr;
	if (SCTP_IPV6_V6ONLY(inp6)) {
		/*
		 * if IPV6_V6ONLY flag, ignore connections destined to a v4
		 * addr or v4-mapped addr
		 */
		if (addr->sa_family == AF_INET) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			SCTP_INP_RUNLOCK(inp);
			SCTP_ASOC_CREATE_UNLOCK(inp);
			return EINVAL;
		}
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			SCTP_INP_RUNLOCK(inp);
			SCTP_ASOC_CREATE_UNLOCK(inp);
			return EINVAL;
		}
	}
	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		if (!ip6_v6only) {
			/* convert v4-mapped into v4 addr */
			in6_sin6_2_sin((struct sockaddr_in *)&ss, sin6);
			addr = (struct sockaddr *)&ss;
		} else {
			/* mapped addresses aren't enabled */
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			SCTP_INP_RUNLOCK(inp);
			SCTP_ASOC_CREATE_UNLOCK(inp);
			return EINVAL;
		}
	} else
#endif				/* INET */
		addr = addr;	/* for true v6 address case */

	/* Now do we connect? */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
		stcb = LIST_FIRST(&inp->sctp_asoc_list);
		if (stcb)
			SCTP_TCB_UNLOCK(stcb);
		SCTP_INP_RUNLOCK(inp);
	} else {
		SCTP_INP_RUNLOCK(inp);
		SCTP_INP_WLOCK(inp);
		SCTP_INP_INCR_REF(inp);
		SCTP_INP_WUNLOCK(inp);
		stcb = sctp_findassociation_ep_addr(&inp, addr, NULL, NULL, NULL);
		if (stcb == NULL) {
			SCTP_INP_WLOCK(inp);
			SCTP_INP_DECR_REF(inp);
			SCTP_INP_WUNLOCK(inp);
		}
	}

	if (stcb != NULL) {
		/* Already have or am bring up an association */
		SCTP_ASOC_CREATE_UNLOCK(inp);
		SCTP_TCB_UNLOCK(stcb);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (EALREADY);
	}
	/* We are GOOD to go */
	stcb = sctp_aloc_assoc(inp, addr, 1, &error, 0, vrf_id);
	SCTP_ASOC_CREATE_UNLOCK(inp);
	if (stcb == NULL) {
		/* Gak! no memory */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (error);
	}
	if (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		stcb->sctp_ep->sctp_flags |= SCTP_PCB_FLAGS_CONNECTED;
		/* Set the connected flag so we can queue data */
		soisconnecting(so);
	}
	stcb->asoc.state = SCTP_STATE_COOKIE_WAIT;
	SCTP_GETTIME_TIMEVAL(&stcb->asoc.time_entered);

	/* initialize authentication parameters for the assoc */
	sctp_initialize_auth_params(inp, stcb);

	sctp_send_initiate(inp, stcb);
	SCTP_TCB_UNLOCK(stcb);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return error;
}

static int
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp6_getaddr(struct socket *so, struct sockaddr **addr)
{
	struct sockaddr_in6 *sin6;
#elif defined(__Panda__)
sctp6_getaddr(struct socket *so, struct sockaddr *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
#else
sctp6_getaddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr_in6 *sin6 = mtod(nam, struct sockaddr_in6 *);
#endif
	struct sctp_inpcb *inp;
	uint32_t vrf_id;
	struct sctp_ifa *sctp_ifa;

#ifdef SCTP_KAME
	int error;
#endif				/* SCTP_KAME */

	/*
	 * Do the malloc first in case it blocks.
	 */
#if defined(__FreeBSD__) || defined(__APPLE__)
	SCTP_MALLOC_SONAME(sin6, struct sockaddr_in6 *, sizeof *sin6);
#elif defined(__Panda__)
	bzero(sin6, sizeof(*sin6));
#else
	SCTP_BUF_LEN(nam) = sizeof(*sin6);
	bzero(sin6, sizeof(*sin6));
#endif
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin6);
#endif
		return ECONNRESET;
	}
	SCTP_INP_RLOCK(inp);
	sin6->sin6_port = inp->sctp_lport;
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* For the bound all case you get back 0 */
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
			struct sctp_tcb *stcb;
			struct sockaddr_in6 *sin_a6;
			struct sctp_nets *net;
			int fnd;

			stcb = LIST_FIRST(&inp->sctp_asoc_list);
			if (stcb == NULL) {
				goto notConn6;
			}
			fnd = 0;
			sin_a6 = NULL;
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				sin_a6 = (struct sockaddr_in6 *)&net->ro._l_addr;
				if (sin_a6 == NULL)
					/* this will make coverity happy */
					continue;

				if (sin_a6->sin6_family == AF_INET6) {
					fnd = 1;
					break;
				}
			}
			if ((!fnd) || (sin_a6 == NULL)) {
				/* punt */
				goto notConn6;
			}
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
			vrf_id = SCTP_DEFAULT_VRFID;
#else
			vrf_id = panda_get_vrf_from_call(); /* from socket option call? */
#endif

			sctp_ifa = sctp_source_address_selection(inp, stcb, (struct route *)&net->ro, net, 0, vrf_id);
			if (sctp_ifa) {
				sin6->sin6_addr = sctp_ifa->address.sin6.sin6_addr;
			}
		} else {
			/* For the bound all case you get back 0 */
	notConn6:
			memset(&sin6->sin6_addr, 0, sizeof(sin6->sin6_addr));
		}
	} else {
		/* Take the first IPv6 address in the list */
		struct sctp_laddr *laddr;
		int fnd = 0;

		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa->address.sa.sa_family == AF_INET6) {
				struct sockaddr_in6 *sin_a;

				sin_a = (struct sockaddr_in6 *)&laddr->ifa->address.sin6;
				sin6->sin6_addr = sin_a->sin6_addr;
				fnd = 1;
				break;
			}
		}
		if (!fnd) {
#if defined(__FreeBSD__) || defined(__APPLE__)
			SCTP_FREE_SONAME(sin6);
#endif
			SCTP_INP_RUNLOCK(inp);
			return ENOENT;
		}
	}
	SCTP_INP_RUNLOCK(inp);
	/* Scoping things for v6 */
#ifdef SCTP_EMBEDDED_V6_SCOPE
#ifdef SCTP_KAME
	if ((error = sa6_recoverscope(sin6)) != 0) {
		SCTP_FREE_SONAME(sin6);
		return (error);
	}
#else
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		/* skip ifp check below */
		in6_recoverscope(sin6, &sin6->sin6_addr, NULL);
	else
		sin6->sin6_scope_id = 0;	/* XXX */
#endif /* SCTP_KAME */
#endif /* SCTP_EMBEDDED_V6_SCOPE */
#if defined(__FreeBSD__) || defined(__APPLE__)
	(*addr) = (struct sockaddr *)sin6;
#endif
	return (0);
}

static int
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp6_peeraddr(struct socket *so, struct sockaddr **addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)*addr;
#elif defined(__Panda__)
sctp6_peeraddr(struct socket *so, struct sockaddr *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
#else
sctp6_peeraddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr_in6 *sin6 = mtod(nam, struct sockaddr_in6 *);
#endif
	int fnd;
	struct sockaddr_in6 *sin_a6;
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb;
	struct sctp_nets *net;

#ifdef SCTP_KAME
	int error;
#endif				/* SCTP_KAME */

	/*
	 * Do the malloc first in case it blocks.
	 */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0) {
		/* UDP type and listeners will drop out here */
		return (ENOTCONN);
	}
#if defined(__FreeBSD__) || defined(__APPLE__)
	SCTP_MALLOC_SONAME(sin6, struct sockaddr_in6 *, sizeof *sin6);
#elif defined(__Panda__)
	bzero(sin6, sizeof(*sin6));
	*addrlen = sizeof(*sin6);
#else
	SCTP_BUF_LEN(nam) = sizeof(*sin6);
	bzero(sin6, sizeof(*sin6));
#endif
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);

	/* We must recapture incase we blocked */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin6);
#endif
		return ECONNRESET;
	}
	SCTP_INP_RLOCK(inp);
	stcb = LIST_FIRST(&inp->sctp_asoc_list);
	if (stcb)
		SCTP_TCB_LOCK(stcb);
	SCTP_INP_RUNLOCK(inp);
	if (stcb == NULL) {
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin6);
#endif
		return ECONNRESET;
	}
	fnd = 0;
	TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
		sin_a6 = (struct sockaddr_in6 *)&net->ro._l_addr;
		if (sin_a6->sin6_family == AF_INET6) {
			fnd = 1;
			sin6->sin6_port = stcb->rport;
			sin6->sin6_addr = sin_a6->sin6_addr;
			break;
		}
	}
	SCTP_TCB_UNLOCK(stcb);
	if (!fnd) {
		/* No IPv4 address */
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin6);
#endif
		return ENOENT;
	}
#ifdef SCTP_EMBEDDED_V6_SCOPE
#ifdef SCTP_KAME
	if ((error = sa6_recoverscope(sin6)) != 0)
		return (error);
#else
	in6_recoverscope(sin6, &sin6->sin6_addr, NULL);
#endif /* SCTP_KAME */
#endif /* SCTP_EMBEDDED_V6_SCOPE */
#if defined(__FreeBSD__) || defined(__APPLE__)
	*addr = (struct sockaddr *)sin6;
#endif
	return (0);
}

#if defined(__FreeBSD__) || defined(__APPLE__)
static int
sctp6_in6getaddr(struct socket *so, struct sockaddr **nam)
{
	struct sockaddr *addr;
#elif defined(__Panda__)
int
sctp6_in6getaddr(struct socket *so, struct sockaddr *nam, uint32_t *namelen)
{
	struct sockaddr *addr = nam;
#else
static int
sctp6_in6getaddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
#endif
	struct in6pcb *inp6 = sotoin6pcb(so);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int error;

	if (inp6 == NULL)
		return EINVAL;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	/* allow v6 addresses precedence */
	error = sctp6_getaddr(so, nam);
	if (error) {
		/* try v4 next if v6 failed */
		error = sctp_ingetaddr(so, nam);
		if (error) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (error);
		}
#if defined(__FreeBSD__) || defined(__APPLE__)
		addr = *nam;
#endif
		/* if I'm V6ONLY, convert it to v4-mapped */
		if (SCTP_IPV6_V6ONLY(inp6)) {
			struct sockaddr_in6 sin6;

			in6_sin_2_v4mapsin6((struct sockaddr_in *)addr, &sin6);
			memcpy(addr, &sin6, sizeof(struct sockaddr_in6));
#if !(defined(__FreeBSD__) || defined(__APPLE__))
			SCTP_BUF_LEN(nam) = sizeof(sin6);
#endif
#if !(defined(__FreeBSD__) || defined(__APPLE__))
		} else {
			SCTP_BUF_LEN(nam) = sizeof(struct sockaddr_in);
#endif
		}
#if !(defined(__FreeBSD__) || defined(__APPLE__))
	} else {
		SCTP_BUF_LEN(nam) = sizeof(struct sockaddr_in6);
#endif
	}
#if defined(__Panda__)
	*namelen = nam->sa_len;
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return (error);
}


#if defined(__FreeBSD__) || defined(__APPLE__)
static int
sctp6_getpeeraddr(struct socket *so, struct sockaddr **nam)
{
	struct sockaddr *addr = *nam;
#elif defined(__Panda__)
int
sctp6_getpeeraddr(struct socket *so, struct sockaddr *nam, uint32_t *namelen)
{
	struct sockaddr *addr = (struct sockaddr *)nam;
#else
static int
sctp6_getpeeraddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr *addr = mtod(nam, struct sockaddr *);

#endif
	struct in6pcb *inp6 = sotoin6pcb(so);
	int error;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif

	if (inp6 == NULL)
		return EINVAL;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	/* allow v6 addresses precedence */
	error = sctp6_peeraddr(so, nam);
	if (error) {
		/* try v4 next if v6 failed */
		error = sctp_peeraddr(so, nam);
		if (error) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (error);
		}
		/* if I'm V6ONLY, convert it to v4-mapped */
		if (SCTP_IPV6_V6ONLY(inp6)) {
			struct sockaddr_in6 sin6;

			in6_sin_2_v4mapsin6((struct sockaddr_in *)addr, &sin6);
			memcpy(addr, &sin6, sizeof(struct sockaddr_in6));
#if !(defined(__FreeBSD__) || defined(__APPLE__))
			SCTP_BUF_LEN(nam) = sizeof(sin6);
#endif
#if !(defined(__FreeBSD__) || defined(__APPLE__))
		} else {
			SCTP_BUF_LEN(nam) = sizeof(struct sockaddr_in);
#endif
		}
#if !(defined(__FreeBSD__) || defined(__APPLE__))
	} else {
		SCTP_BUF_LEN(nam) = sizeof(struct sockaddr_in6);
#endif
	}
#if defined(__Panda__)
	*namelen = nam->sa_len;
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return error;
}

#if defined(__FreeBSD__) || defined(__APPLE__)
struct pr_usrreqs sctp6_usrreqs = {
#if __FreeBSD_version >= 600000
	.pru_abort = sctp6_abort,
	.pru_accept = sctp_accept,
	.pru_attach = sctp6_attach,
	.pru_bind = sctp6_bind,
	.pru_connect = sctp6_connect,
	.pru_control = in6_control,
#if __FreeBSD_version >= 690000
	.pru_close = sctp6_close,
	.pru_detach = sctp6_close,
	.pru_sopoll = sopoll_generic,
#else
	.pru_detach = sctp6_detach,
	.pru_sopoll = sopoll,
#endif
	.pru_disconnect = sctp6_disconnect,
	.pru_listen = sctp_listen,
	.pru_peeraddr = sctp6_getpeeraddr,
	.pru_send = sctp6_send,
	.pru_shutdown = sctp_shutdown,
	.pru_sockaddr = sctp6_in6getaddr,
	.pru_sosend = sctp_sosend,
	.pru_soreceive = sctp_soreceive
#else
	sctp6_abort,
	sctp_accept,
	sctp6_attach,
	sctp6_bind,
	sctp6_connect,
	pru_connect2_notsupp,
	in6_control,
	sctp6_detach,
	sctp6_disconnect,
	sctp_listen,
	sctp6_getpeeraddr,
	NULL,
	pru_rcvoob_notsupp,
	sctp6_send,
	pru_sense_null,
	sctp_shutdown,
	sctp6_in6getaddr,
	sctp_sosend,
	sctp_soreceive,
	sopoll
#endif
};

#else

int
sctp6_usrreq(so, req, m, nam, control, p)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
	struct proc *p;
{
	int s;
	int error = 0;
	int family;
	uint32_t vrf_id;
#if defined(__OpenBSD__)
	p = curproc;
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	family = so->so_proto->pr_domain->dom_family;

	if (req == PRU_CONTROL) {
		switch (family) {
		case PF_INET:
			error = in_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control
#if defined(__NetBSD__)
			    ,p
#endif
			    );
#ifdef INET6
		case PF_INET6:
			error = in6_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control, p);
#endif
		default:
			error = EAFNOSUPPORT;
		}
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (error);
	}
#ifdef __NetBSD__
	if (req == PRU_PURGEIF) {
		struct ifnet *ifn;
		struct sctp_ifn *sctp_ifn;
		struct sctp_ifa *sctp_ifa;

		ifn = (struct ifnet *)control;
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
		vrf = SCTP_DEFAULT_VRFID;
#else
		vrf = panda_get_vrf_from_call(); /* from socket option call? */
#endif
		sctp_ifn = sctp_find_ifn(vrf, (void *)ifn, ifn->if_index);
		LIST_FOREACH(sctp_ifa, &sctp_ifn->ifalist, next_ifa) {		
			if (sctp_ifa->address.sa.sa_family == family) {
				sctp_delete_ip_address(sctp_ifa);
			}
		}
		switch (family) {
		case PF_INET:
			in_purgeif(ifn);
			break;
#ifdef INET6
		case PF_INET6:
			in6_purgeif(ifn);
			break;
#endif
		default:
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (EAFNOSUPPORT);
		}
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (0);
	}
#endif
	switch (req) {
	case PRU_ATTACH:
		error = sctp6_attach(so, family, p);
		break;
	case PRU_DETACH:
		error = sctp6_detach(so);
		break;
	case PRU_BIND:
		if (nam == NULL)
			return (EINVAL);
		error = sctp6_bind(so, nam, p);
		break;
	case PRU_LISTEN:
		error = sctp_listen(so, p);
		break;
	case PRU_CONNECT:
		if (nam == NULL)
			return (EINVAL);
		error = sctp6_connect(so, nam, p);
		break;
	case PRU_DISCONNECT:
		error = sctp6_disconnect(so);
		break;
	case PRU_ACCEPT:
		if (nam == NULL)
			return (EINVAL);
		error = sctp_accept(so, nam);
		break;
	case PRU_SHUTDOWN:
		error = sctp_shutdown(so);
		break;

	case PRU_RCVD:
		/*
		 * For OpenBSD and NetBSD, this is real ugly. The (mbuf *)
		 * nam that is passed (by soreceive()) is the int flags cast
		 * as a (mbuf *) yuck!
		 */
		error = sctp_usr_recvd(so, (int)((long)nam));
		break;

	case PRU_SEND:
		/* Flags are ignored */
		error = sctp6_send(so, 0, m, nam, control, p);
		break;
	case PRU_ABORT:
		error = sctp6_abort(so);
		break;

	case PRU_SENSE:
		error = 0;
		break;
	case PRU_RCVOOB:
		error = EAFNOSUPPORT;
		break;
	case PRU_SENDOOB:
		error = EAFNOSUPPORT;
		break;
	case PRU_PEERADDR:
		error = sctp6_getpeeraddr(so, nam);
		break;
	case PRU_SOCKADDR:
		error = sctp6_in6getaddr(so, nam);
		break;
	case PRU_SLOWTIMO:
		error = 0;
		break;
	default:
		break;
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return (error);
}

#endif
