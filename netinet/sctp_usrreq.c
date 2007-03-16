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

/* $KAME: sctp_usrreq.c,v 1.48 2005/03/07 23:26:08 itojun Exp $	 */

#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/netinet/sctp_usrreq.c,v 1.11 2007/02/12 23:24:31 rrs Exp $");
#endif
#include <netinet/sctp_os.h>
#ifdef __FreeBSD__
#include <sys/proc.h>
#endif
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_output.h>
#if 0
#include <netinet/sctp_bsd_addr.h>
#endif
#include <netinet/sctp_uio.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_auth.h>
#if defined(HAVE_SCTP_PEELOFF_SOCKOPT)
#include <netinet/sctp_peeloff.h>
#endif				/* HAVE_SCTP_PEELOFF_SOCKOPT */

#if defined(__APPLE__)
#define APPLE_FILE_NO 7
#endif


/*
 * sysctl tunable variables
 */
int sctp_sendspace = (128 * 1024);
int sctp_recvspace = 128 * (1024 +
#ifdef INET6
    sizeof(struct sockaddr_in6)
#else
    sizeof(struct sockaddr_in)
#endif
);
int sctp_mbuf_threshold_count = SCTP_DEFAULT_MBUFS_IN_CHAIN;
int sctp_auto_asconf = SCTP_DEFAULT_AUTO_ASCONF;
int sctp_ecn_enable = 1;
int sctp_ecn_nonce = 0;
int sctp_strict_sacks = 0;
int sctp_no_csum_on_loopback = 1;
int sctp_strict_init = 1;
int sctp_abort_if_one_2_one_hits_limit = 0;
int sctp_strict_data_order = 0;

int sctp_peer_chunk_oh = sizeof(struct mbuf);
int sctp_max_burst_default = SCTP_DEF_MAX_BURST;
int sctp_use_cwnd_based_maxburst = 1;
int sctp_do_drain = 1;
int sctp_hb_maxburst = SCTP_DEF_MAX_BURST;

unsigned int sctp_max_chunks_on_queue = SCTP_ASOC_MAX_CHUNKS_ON_QUEUE;
unsigned int sctp_delayed_sack_time_default = SCTP_RECV_MSEC;
unsigned int sctp_sack_freq_default = SCTP_DEFAULT_SACK_FREQ;
unsigned int sctp_heartbeat_interval_default = SCTP_HB_DEFAULT_MSEC;
unsigned int sctp_pmtu_raise_time_default = SCTP_DEF_PMTU_RAISE_SEC;
unsigned int sctp_shutdown_guard_time_default = SCTP_DEF_MAX_SHUTDOWN_SEC;
unsigned int sctp_secret_lifetime_default = SCTP_DEFAULT_SECRET_LIFE_SEC;
unsigned int sctp_rto_max_default = SCTP_RTO_UPPER_BOUND;
unsigned int sctp_rto_min_default = SCTP_RTO_LOWER_BOUND;
unsigned int sctp_rto_initial_default = SCTP_RTO_INITIAL;
unsigned int sctp_init_rto_max_default = SCTP_RTO_UPPER_BOUND;
unsigned int sctp_valid_cookie_life_default = SCTP_DEFAULT_COOKIE_LIFE;
unsigned int sctp_init_rtx_max_default = SCTP_DEF_MAX_INIT;
unsigned int sctp_assoc_rtx_max_default = SCTP_DEF_MAX_SEND;
unsigned int sctp_path_rtx_max_default = SCTP_DEF_MAX_PATH_RTX;
unsigned int sctp_nr_outgoing_streams_default = SCTP_OSTREAM_INITIAL;
unsigned int sctp_add_more_threshold = SCTP_DEFAULT_ADD_MORE;
uint32_t sctp_asoc_free_resc_limit = SCTP_DEF_ASOC_RESC_LIMIT;
uint32_t sctp_system_free_resc_limit = SCTP_DEF_SYSTEM_RESC_LIMIT;

int sctp_min_split_point=SCTP_DEFAULT_SPLIT_POINT_MIN;
int sctp_pcbtblsize = SCTP_PCBHASHSIZE;
int sctp_hashtblsize = SCTP_TCBHASHSIZE;
int sctp_chunkscale = SCTP_CHUNKQUEUE_SCALE;

unsigned int sctp_cmt_on_off = 0;
unsigned int sctp_cmt_sockopt_on_off = 0;
unsigned int sctp_cmt_use_dac = 0;

int sctp_L2_abc_variable = 1;
unsigned int sctp_early_fr = 0;
unsigned int sctp_early_fr_msec = SCTP_MINFR_MSEC_TIMER;
unsigned int sctp_use_rttvar_cc = 0;
int sctp_says_check_for_deadlock = 0;
uint32_t sctp_asconf_auth_nochk = 0;
uint32_t sctp_nat_friendly = 1;
uint32_t sctp_auth_disable = 0;
uint32_t sctp_auth_random_len = SCTP_AUTH_RANDOM_SIZE_DEFAULT;
uint32_t sctp_auth_hmac_id_default = SCTP_AUTH_HMAC_ID_SHA1;
struct sctpstat sctpstat;

#if defined(__APPLE__)
unsigned int sctp_main_timer = SCTP_MAIN_TIMER_DEFAULT;
#endif
#ifdef SCTP_DEBUG
extern uint32_t sctp_debug_on;
#endif				/* SCTP_DEBUG */


void
sctp_init(void)
{
#ifdef __OpenBSD__
#define nmbclusters	nmbclust
#endif
	/* Init the SCTP pcb in sctp_pcb.c */
	u_long sb_max_adj;

	SCTP_BUF_INIT();
	SCTP_HEADER_INIT();
	SCTP_STAT_INIT();

	sctp_pcb_init();

#if !defined(__Windows__)
#ifndef __OpenBSD__
	if ((nmbclusters / 8) > SCTP_ASOC_MAX_CHUNKS_ON_QUEUE)
		sctp_max_chunks_on_queue = (nmbclusters / 8);
#else
	if ((nmbclust / 8) > SCTP_ASOC_MAX_CHUNKS_ON_QUEUE)
		sctp_max_chunks_on_queue = nmbclust / 8;
#endif
	/*
	 * Allow a user to take no more than 1/2 the number of clusters or
	 * the SB_MAX whichever is smaller for the send window.
	 */
	sb_max_adj = (u_long)((u_quad_t) (SB_MAX) * MCLBYTES / (MSIZE + MCLBYTES));
	sctp_sendspace = min((min(SB_MAX, sb_max_adj)),
#ifndef __OpenBSD__
	    ((nmbclusters / 2) * SCTP_DEFAULT_MAXSEGMENT));
#else
	    ((nmbclust / 2) * SCTP_DEFAULT_MAXSEGMENT));
#endif
	/*
	 * Now for the recv window, should we take the same amount? or
	 * should I do 1/2 the SB_MAX instead in the SB_MAX min above. For
	 * now I will just copy.
	 */
	sctp_recvspace = sctp_sendspace;
#endif

#ifdef __OpenBSD__
#undef nmbclusters
#endif

#if defined(__APPLE__)
	/* start the main timer */
	sctp_start_main_timer();
#endif
}

#ifdef SCTP_APPLE_FINE_GRAINED_LOCKING
void
sctp_finish(void)
{
	sctp_pcb_finish();
}
#endif

#if 0
/*
 * cleanup of the sctppcbinfo structure.
 * Assumes that the sctppcbinfo lock is held.
 */
void
sctp_pcbinfo_cleanup(void)
{
	/* free the hash tables */
	if (sctppcbinfo.sctp_asochash != NULL)
		SCTP_HASH_FREE(sctppcbinfo.sctp_asochash, sctppcbinfo.hashasocmark);
	if (sctppcbinfo.sctp_ephash != NULL)
		SCTP_HASH_FREE(sctppcbinfo.sctp_ephash, sctppcbinfo.hashmark);
	if (sctppcbinfo.sctp_tcpephash != NULL)
		SCTP_HASH_FREE(sctppcbinfo.sctp_tcpephash, sctppcbinfo.hashtcpmark);
	if (sctppcbinfo.sctp_restarthash != NULL)
		SCTP_HASH_FREE(sctppcbinfo.sctp_restarthash, sctppcbinfo.hashrestartmark);
}

#ifdef INET6
void
ip_2_ip6_hdr(struct ip6_hdr *ip6, struct ip *ip)
{
	bzero(ip6, sizeof(*ip6));

	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = ip->ip_len;
	ip6->ip6_nxt = ip->ip_p;
	ip6->ip6_hlim = ip->ip_ttl;
	ip6->ip6_src.s6_addr32[2] = ip6->ip6_dst.s6_addr32[2] =
	    IPV6_ADDR_INT32_SMP;
	ip6->ip6_src.s6_addr32[3] = ip->ip_src.s_addr;
	ip6->ip6_dst.s6_addr32[3] = ip->ip_dst.s_addr;
}

#endif				/* INET6 */


static void
sctp_pathmtu_adustment(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net,
    uint16_t nxtsz)
{
	struct sctp_tmit_chunk *chk;
	/* Adjust that too */
	stcb->asoc.smallest_mtu = nxtsz;
	/* now off to subtract IP_DF flag if needed */

	TAILQ_FOREACH(chk, &stcb->asoc.send_queue, sctp_next) {
		if ((chk->send_size + IP_HDR_SIZE) > nxtsz) {
			chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
		}
	}
	TAILQ_FOREACH(chk, &stcb->asoc.sent_queue, sctp_next) {
		if ((chk->send_size + IP_HDR_SIZE) > nxtsz) {
			/*
			 * For this guy we also mark for immediate resend
			 * since we sent to big of chunk
			 */
			chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
			if (chk->sent != SCTP_DATAGRAM_RESEND) {
				sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
			}
			chk->sent = SCTP_DATAGRAM_RESEND;
			chk->rec.data.doing_fast_retransmit = 0;

			/* Clear any time so NO RTT is being done */
			chk->do_rtt = 0;
			if (stcb->asoc.total_flight >= chk->book_size)
				stcb->asoc.total_flight -= chk->book_size;
			else
				stcb->asoc.total_flight = 0;
			if (stcb->asoc.total_flight_count > 0)
				stcb->asoc.total_flight_count--;
			if (net->flight_size >= chk->book_size)
				net->flight_size -= chk->book_size;
			else
				net->flight_size = 0;
		}
	}
}

static void
sctp_notify_mbuf(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net,
    struct ip *ip,
    struct sctphdr *sh)
{
	struct icmp *icmph;
	int totsz, tmr_stopped = 0;
	uint16_t nxtsz;

	/* protection */
	if ((inp == NULL) || (stcb == NULL) || (net == NULL) ||
	    (ip == NULL) || (sh == NULL)) {
		if (stcb != NULL)
			SCTP_TCB_UNLOCK(stcb);
		return;
	}
	/* First job is to verify the vtag matches what I would send */
	if (ntohl(sh->v_tag) != (stcb->asoc.peer_vtag)) {
		SCTP_TCB_UNLOCK(stcb);
		return;
	}
	icmph = (struct icmp *)((caddr_t)ip - (sizeof(struct icmp) -
	    sizeof(struct ip)));
	if (icmph->icmp_type != ICMP_UNREACH) {
		/* We only care about unreachable */
		SCTP_TCB_UNLOCK(stcb);
		return;
	}
	if (icmph->icmp_code != ICMP_UNREACH_NEEDFRAG) {
		/* not a unreachable message due to frag. */
		SCTP_TCB_UNLOCK(stcb);
		return;
	}
	totsz = ip->ip_len;

	nxtsz = ntohs(icmph->icmp_seq);
	if (nxtsz == 0) {
		/*
		 * old type router that does not tell us what the next size
		 * mtu is. Rats we will have to guess (in a educated fashion
		 * of course)
		 */
		nxtsz = find_next_best_mtu(totsz);
	}
	/* Stop any PMTU timer */
	if (SCTP_OS_TIMER_PENDING(&net->pmtu_timer.timer)) {
		tmr_stopped = 1;
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, net, 
				SCTP_FROM_SCTP_USRREQ+SCTP_LOC_1);
	}
	/* Adjust destination size limit */
	if (net->mtu > nxtsz) {
		net->mtu = nxtsz;
	}
	/* now what about the ep? */
	if (stcb->asoc.smallest_mtu > nxtsz) {
		sctp_pathmtu_adustment(inp, stcb, net, nxtsz);
	}
	if (tmr_stopped)
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, net);

	SCTP_TCB_UNLOCK(stcb);
}


void
sctp_notify(struct sctp_inpcb *inp,
    int errno,
    struct sctphdr *sh,
    struct sockaddr *to,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	/* protection */
	if ((inp == NULL) || (stcb == NULL) || (net == NULL) ||
	    (sh == NULL) || (to == NULL)) {
		return;
	}
	/* First job is to verify the vtag matches what I would send */
	if (ntohl(sh->v_tag) != (stcb->asoc.peer_vtag)) {
		return;
	}
	/* FIX ME FIX ME PROTOPT i.e. no SCTP should ALWAYS be an ABORT */

	if ((errno == EHOSTUNREACH) ||	/* Host is not reachable */
	    (errno == EHOSTDOWN) ||	/* Host is down */
	    (errno == ECONNREFUSED) ||	/* Host refused the connection, (not
					 * an abort?) */
	    (errno == ENOPROTOOPT)	/* SCTP is not present on host */
	    ) {
		/*
		 * Hmm reachablity problems we must examine closely. If its
		 * not reachable, we may have lost a network. Or if there is
		 * NO protocol at the other end named SCTP. well we consider
		 * it a OOTB abort.
		 */
		if ((errno == EHOSTUNREACH) || (errno == EHOSTDOWN)) {
			if (net->dest_state & SCTP_ADDR_REACHABLE) {
				/* Ok that destination is NOT reachable */
				printf("ICMP (thresh %d/%d) takes interface %p down\n",
				       net->error_count,
				       net->failure_threshold,
				       net);

				net->dest_state &= ~SCTP_ADDR_REACHABLE;
				net->dest_state |= SCTP_ADDR_NOT_REACHABLE;
				net->error_count = net->failure_threshold + 1;
				sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_DOWN,
				    stcb, SCTP_FAILED_THRESHOLD,
				    (void *)net);
			}
			if (stcb)
				SCTP_TCB_UNLOCK(stcb);
		} else {
			/*
			 * Here the peer is either playing tricks on us,
			 * including an address that belongs to someone who
			 * does not support SCTP OR was a userland
			 * implementation that shutdown and now is dead. In
			 * either case treat it like a OOTB abort with no
			 * TCB
			 */
			sctp_abort_notification(stcb, SCTP_PEER_FAULTY);
			sctp_free_assoc(inp, stcb, SCTP_NORMAL_PROC, SCTP_FROM_SCTP_USRREQ+SCTP_LOC_2);
			/* no need to unlock here, since the TCB is gone */
		}
	} else {
		/* Send all others to the app */
		if (stcb)
			SCTP_TCB_UNLOCK(stcb);


		if (inp->sctp_socket) {
#ifdef SCTP_LOCK_LOGGING
			sctp_log_lock(inp, stcb, SCTP_LOG_LOCK_SOCK);
#endif
			SOCK_LOCK(inp->sctp_socket);
			inp->sctp_socket->so_error = errno;
			sctp_sowwakeup(inp, inp->sctp_socket);
			SOCK_UNLOCK(inp->sctp_socket);
		}
	}
}

#if defined(__FreeBSD__) || defined(__APPLE__)
void
#else
void *
#endif
sctp_ctlinput(cmd, sa, vip)
	int cmd;
	struct sockaddr *sa;
	void *vip;
{
	struct ip *ip = vip;
	struct sctphdr *sh;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif

	if (sa->sa_family != AF_INET ||
	    ((struct sockaddr_in *)sa)->sin_addr.s_addr == INADDR_ANY) {
#if defined(__FreeBSD__) || defined(__APPLE__)
		return;
#else
		return (NULL);
#endif
	}
	if (PRC_IS_REDIRECT(cmd)) {
		ip = 0;
	} else if ((unsigned)cmd >= PRC_NCMDS || inetctlerrmap[cmd] == 0) {
#if defined(__FreeBSD__) || defined(__APPLE__)
		return;
#else
		return (NULL);
#endif
	}
	if (ip) {
		struct sctp_inpcb *inp = NULL;
		struct sctp_tcb *stcb = NULL;
		struct sctp_nets *net = NULL;
		struct sockaddr_in to, from;

		sh = (struct sctphdr *)((caddr_t)ip + (ip->ip_hl << 2));
		bzero(&to, sizeof(to));
		bzero(&from, sizeof(from));
		from.sin_family = to.sin_family = AF_INET;
		from.sin_len = to.sin_len = sizeof(to);
		from.sin_port = sh->src_port;
		from.sin_addr = ip->ip_src;
		to.sin_port = sh->dest_port;
		to.sin_addr = ip->ip_dst;

		/*
		 * 'to' holds the dest of the packet that failed to be sent.
		 * 'from' holds our local endpoint address. Thus we reverse
		 * the to and the from in the lookup.
		 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		s = splsoftnet();
#endif
		stcb = sctp_findassociation_addr_sa((struct sockaddr *)&from,
		    (struct sockaddr *)&to,
		    &inp, &net, 1);
		if (stcb != NULL && inp && (inp->sctp_socket != NULL)) {
			if (cmd != PRC_MSGSIZE) {
				int cm;

				if (cmd == PRC_HOSTDEAD) {
					cm = EHOSTUNREACH;
				} else {
					cm = inetctlerrmap[cmd];
				}
				sctp_notify(inp, cm, sh,
				    (struct sockaddr *)&to, stcb,
				    net);
			} else {
				/* handle possible ICMP size messages */
				sctp_notify_mbuf(inp, stcb, net, ip, sh);
			}
		} else {
#if defined(__FreeBSD__) && __FreeBSD_version < 500000
			/*
			 * XXX must be fixed for 5.x and higher, leave for
			 * 4.x
			 */
			if (PRC_IS_REDIRECT(cmd) && inp) {
				in_rtchange((struct inpcb *)inp,
				    inetctlerrmap[cmd]);
			}
#endif
			if ((stcb == NULL) && (inp != NULL)) {
				/* reduce ref-count */
				SCTP_INP_WLOCK(inp);
				SCTP_INP_DECR_REF(inp);
				SCTP_INP_WUNLOCK(inp);
			}
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
#if defined(__FreeBSD__) || defined(__APPLE__)
	return;
#else
	return (NULL);
#endif
}

#if defined(__FreeBSD__)
static int
sctp_getcred(SYSCTL_HANDLER_ARGS)
{
	struct xucred xuc;
	struct sockaddr_in addrs[2];
	struct sctp_inpcb *inp;
	struct sctp_nets *net;
	struct sctp_tcb *stcb;
	int error;

#if __FreeBSD_version > 602000
	/*
	 * XXXRW: Other instances of getcred use SUSER_ALLOWJAIL, as socket
	 * visibility is scoped using cr_canseesocket(), which it is not
	 * here.
	 */
	error = priv_check_cred(req->td->td_ucred, PRIV_NETINET_GETCRED, 0);
#elif __FreeBSD_version >= 500000
	error = suser(req->td);
#else
	error = suser(req->p);
#endif
	if (error)
		return (error);

	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);

	stcb = sctp_findassociation_addr_sa(sintosa(&addrs[0]),
	    sintosa(&addrs[1]),
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
	if(error) {
		SCTP_INP_WUNLOCK(inp);
		goto out;
	}
	cru2x(inp->sctp_socket->so_cred, &xuc);
	SCTP_INP_WUNLOCK(inp);
	error = SYSCTL_OUT(req, &xuc, sizeof(struct xucred));
out:
	return (error);
}

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, getcred, CTLTYPE_OPAQUE | CTLFLAG_RW,
    0, 0, sctp_getcred, "S,ucred", "Get the ucred of a SCTP connection");
#endif				/* #if defined(__FreeBSD__) */

#if defined (__APPLE__) || defined (__FreeBSD__)
static int
#if defined (__APPLE__)
sctp_assoclist SYSCTL_HANDLER_ARGS
#else
sctp_assoclist(SYSCTL_HANDLER_ARGS)
#endif
{
	unsigned int number_of_endpoints;
	unsigned int number_of_local_addresses;
	unsigned int number_of_associations;
	unsigned int number_of_remote_addresses;
	unsigned int n;
	int error;
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb;
	struct sctp_nets *net;
	struct sctp_laddr *laddr;
	struct xsctp_inpcb xinpcb;
	struct xsctp_tcb xstcb;
/*	struct xsctp_laddr xladdr; */
	struct xsctp_raddr xraddr;
	
	number_of_endpoints = 0;
	number_of_local_addresses = 0;
	number_of_associations = 0;
	number_of_remote_addresses = 0;
	
#if defined(SCTP_PER_SOCKET_LOCKING)
	SCTP_LOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
	SCTP_INP_INFO_RLOCK();
	if (req->oldptr == USER_ADDR_NULL) {
		LIST_FOREACH(inp, &sctppcbinfo.listhead, sctp_list) {
#if defined(SCTP_PER_SOCKET_LOCKING)
			SCTP_SOCKET_LOCK(SCTP_INP_SO(inp), 1);
#endif
			SCTP_INP_RLOCK(inp);
			number_of_endpoints++;
			/* FIXME MT */
			LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
				number_of_local_addresses++;
			}
			LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
				number_of_associations++;
				TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
					number_of_remote_addresses++;
				}
			}
#if defined(SCTP_PER_SOCKET_LOCKING)
			SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
#endif
			SCTP_INP_RUNLOCK(inp);
		}
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
		SCTP_INP_INFO_RUNLOCK();
		n = (number_of_endpoints + 1) * sizeof(struct xsctp_inpcb) +
		    number_of_local_addresses * sizeof(struct xsctp_laddr) +
		    number_of_associations * sizeof(struct xsctp_tcb) +
		    number_of_remote_addresses * sizeof(struct xsctp_raddr);
#ifdef SCTP_DEBUG
		printf("inps = %u, stcbs = %u, laddrs = %u, raddrs = %u\n", 
		       number_of_endpoints, number_of_associations,
		       number_of_local_addresses,  number_of_remote_addresses);
#endif
		/* request some more memory than needed */
		req->oldidx = (n + n/8);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
		SCTP_INP_INFO_RUNLOCK();
		return EPERM;
	}

	LIST_FOREACH(inp, &sctppcbinfo.listhead, sctp_list) {
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_SOCKET_LOCK(SCTP_INP_SO(inp), 1);
#endif
		SCTP_INP_RLOCK(inp);
		number_of_local_addresses = 0;
		number_of_associations = 0;
		/*
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			number_of_local_addresses++;
		}
		*/
		LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
			number_of_associations++;
		}
		xinpcb.last                   = 0;
		xinpcb.local_port             = ntohs(inp->sctp_lport);
		xinpcb.number_local_addresses = number_of_local_addresses;
		xinpcb.number_associations    = number_of_associations;
		xinpcb.flags                  = inp->sctp_flags;
		xinpcb.features               = inp->sctp_features;
		xinpcb.total_sends            = inp->total_sends;
		xinpcb.total_recvs            = inp->total_recvs;
		xinpcb.total_nospaces         = inp->total_nospaces;
		SCTP_INP_INCR_REF(inp);
		SCTP_INP_RUNLOCK(inp);
		SCTP_INP_INFO_RUNLOCK();
		error = SYSCTL_OUT(req, &xinpcb, sizeof(struct xsctp_inpcb));
		if (error) {
#if defined(SCTP_PER_SOCKET_LOCKING)
			SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
			SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
			return error;
		}
		SCTP_INP_INFO_RLOCK();
		SCTP_INP_RLOCK(inp);
		/* FIXME MT */
		/*
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			error = SYSCTL_OUT(req, &xladdr, sizeof(struct xsctp_laddr));
			if (error) {
#if defined(SCTP_PER_SOCKET_LOCKING)
				SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
				SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
				SCTP_INP_RUNLOCK(inp);
				SCTP_INP_INFO_RUNLOCK();
				return error;
			}			
		}
		*/
		LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
			SCTP_TCB_LOCK(stcb);
			atomic_add_int(&stcb->asoc.refcnt, 1);
			SCTP_TCB_UNLOCK(stcb);
			number_of_local_addresses = 0;
			number_of_remote_addresses = 0;
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				number_of_remote_addresses++;
			}
			xstcb.LocalPort = ntohs(inp->sctp_lport);
			xstcb.RemPort = ntohs(stcb->rport);
			if (stcb->asoc.primary_destination != NULL)
				xstcb.RemPrimAddr = stcb->asoc.primary_destination->ro._l_addr;
			xstcb.HeartBeatInterval = stcb->asoc.heart_beat_delay;
			xstcb.State = SCTP_GET_STATE(&stcb->asoc); /* FIXME */
			xstcb.InStreams = stcb->asoc.streamincnt;
			xstcb.OutStreams = stcb->asoc.streamoutcnt;
			xstcb.MaxRetr = stcb->asoc.overall_error_count;
			xstcb.PrimProcess = 0; /* not really supported yet */
			xstcb.T1expireds = stcb->asoc.timoinit + stcb->asoc.timocookie;
			xstcb.T2expireds = stcb->asoc.timoshutdown + stcb->asoc.timoshutdownack;
			xstcb.RtxChunks = stcb->asoc.marked_retrans;
			xstcb.StartTime = stcb->asoc.start_time;
			xstcb.DiscontinuityTime = stcb->asoc.discontinuity_time;

			xstcb.number_local_addresses = number_of_local_addresses;
			xstcb.number_remote_addresses = number_of_remote_addresses;
			xstcb.total_sends = stcb->total_sends;
			xstcb.total_recvs = stcb->total_recvs;
			xstcb.local_tag = stcb->asoc.my_vtag;
			xstcb.remote_tag = stcb->asoc.peer_vtag;
			xstcb.initial_tsn = stcb->asoc.init_seq_number;
			xstcb.highest_tsn = stcb->asoc.sending_seq - 1;
			xstcb.cumulative_tsn = stcb->asoc.last_acked_seq;
			xstcb.cumulative_tsn_ack = stcb->asoc.cumulative_tsn;
			SCTP_INP_RUNLOCK(inp);
			SCTP_INP_INFO_RUNLOCK();
			error = SYSCTL_OUT(req, &xstcb, sizeof(struct xsctp_tcb));
			if (error) {
#if defined(SCTP_PER_SOCKET_LOCKING)
				SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
				SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
				atomic_add_int(&stcb->asoc.refcnt, -1);
				return error;
			}
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				xraddr.RemAddr = net->ro._l_addr;
				xraddr.RemAddrActive = ((net->dest_state & SCTP_ADDR_REACHABLE) == SCTP_ADDR_REACHABLE);
				xraddr.RemAddrConfirmed = ((net->dest_state & SCTP_ADDR_UNCONFIRMED) == 0);
				xraddr.RemAddrHBActive = ((net->dest_state & SCTP_ADDR_NOHB) == 0);
				xraddr.RemAddrRTO = net->RTO;
				xraddr.RemAddrMaxPathRtx = net->failure_threshold;
				xraddr.RemAddrRtx = net->marked_retrans;
				xraddr.RemAddrErrorCounter = net->error_count;
				xraddr.RemAddrCwnd = net->cwnd;
				xraddr.RemAddrFlightSize = net->flight_size;
				xraddr.RemAddrStartTime = net->start_time;
				error = SYSCTL_OUT(req, &xraddr, sizeof(struct xsctp_raddr));
				if (error) {
#if defined(SCTP_PER_SOCKET_LOCKING)
					SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
					SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
					atomic_add_int(&stcb->asoc.refcnt, -1);
					return error;
				}			
			}			
			atomic_add_int(&stcb->asoc.refcnt, -1);
			SCTP_INP_INFO_RLOCK();
			SCTP_INP_RLOCK(inp);
		}
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
#endif
		SCTP_INP_DECR_REF(inp);
		SCTP_INP_RUNLOCK(inp);
	}
#if defined(SCTP_PER_SOCKET_LOCKING)
	SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
	SCTP_INP_INFO_RUNLOCK();
	
	xinpcb.last = 1;
	xinpcb.local_port = 0;
	xinpcb.number_local_addresses = 0;
	xinpcb.number_associations = 0;
	xinpcb.flags = 0;
	xinpcb.features = 0;
	error = SYSCTL_OUT(req, &xinpcb, sizeof(struct xsctp_inpcb));
	return error;
}
#endif

/*
 * sysctl definitions
 */
#if defined(__FreeBSD__) || defined (__APPLE__)

SYSCTL_INT(_net_inet_sctp, OID_AUTO, sendspace, CTLFLAG_RW,
    &sctp_sendspace, 0, "Maximum outgoing SCTP buffer size");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, recvspace, CTLFLAG_RW,
    &sctp_recvspace, 0, "Maximum incoming SCTP buffer size");

#if defined(__FreeBSD__) || defined(SCTP_APPLE_AUTO_ASCONF)
SYSCTL_INT(_net_inet_sctp, OID_AUTO, auto_asconf, CTLFLAG_RW,
    &sctp_auto_asconf, 0, "Enable SCTP Auto-ASCONF");
#endif

SYSCTL_INT(_net_inet_sctp, OID_AUTO, ecn_enable, CTLFLAG_RW,
    &sctp_ecn_enable, 0, "Enable SCTP ECN");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, ecn_nonce, CTLFLAG_RW,
    &sctp_ecn_nonce, 0, "Enable SCTP ECN Nonce");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, strict_sacks, CTLFLAG_RW,
    &sctp_strict_sacks, 0, "Enable SCTP Strict SACK checking");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, loopback_nocsum, CTLFLAG_RW,
    &sctp_no_csum_on_loopback, 0,
    "Enable NO Csum on packets sent on loopback");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, strict_init, CTLFLAG_RW,
    &sctp_strict_init, 0,
    "Enable strict INIT/INIT-ACK singleton enforcement");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, peer_chkoh, CTLFLAG_RW,
    &sctp_peer_chunk_oh, 0,
    "Amount to debit peers rwnd per chunk sent");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, maxburst, CTLFLAG_RW,
    &sctp_max_burst_default, 0,
    "Default max burst for sctp endpoints");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, maxchunks, CTLFLAG_RW,
    &sctp_max_chunks_on_queue, 0,
    "Default max chunks on queue per asoc");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, tcbhashsize, CTLFLAG_RW,
    &sctp_hashtblsize, 0,
    "Tuneable for Hash table sizes");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, min_split_point, CTLFLAG_RW,
    &sctp_min_split_point, 0,
    "Minimum size when splitting a chunk");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, pcbhashsize, CTLFLAG_RW,
    &sctp_pcbtblsize, 0,
    "Tuneable for PCB Hash table sizes");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, sys_resource, CTLFLAG_RW,
    &sctp_system_free_resc_limit, 0,
    "Max number of cached resources in the system");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, asoc_resource, CTLFLAG_RW,
    &sctp_asoc_free_resc_limit, 0,
    "Max number of cached resources in an asoc");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, chunkscale, CTLFLAG_RW,
    &sctp_chunkscale, 0,
    "Tuneable for Scaling of number of chunks and messages");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, delayed_sack_time, CTLFLAG_RW,
    &sctp_delayed_sack_time_default, 0,
    "Default delayed SACK timer in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, sack_freq, CTLFLAG_RW,
    &sctp_sack_freq_default, 0,
    "Default SACK frequency");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, heartbeat_interval, CTLFLAG_RW,
    &sctp_heartbeat_interval_default, 0,
    "Default heartbeat interval in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, pmtu_raise_time, CTLFLAG_RW,
    &sctp_pmtu_raise_time_default, 0,
    "Default PMTU raise timer in sec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, shutdown_guard_time, CTLFLAG_RW,
    &sctp_shutdown_guard_time_default, 0,
    "Default shutdown guard timer in sec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, secret_lifetime, CTLFLAG_RW,
    &sctp_secret_lifetime_default, 0,
    "Default secret lifetime in sec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, rto_max, CTLFLAG_RW,
    &sctp_rto_max_default, 0,
    "Default maximum retransmission timeout in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, rto_min, CTLFLAG_RW,
    &sctp_rto_min_default, 0,
    "Default minimum retransmission timeout in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, rto_initial, CTLFLAG_RW,
    &sctp_rto_initial_default, 0,
    "Default initial retransmission timeout in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, init_rto_max, CTLFLAG_RW,
    &sctp_init_rto_max_default, 0,
    "Default maximum retransmission timeout during association setup in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, valid_cookie_life, CTLFLAG_RW,
    &sctp_valid_cookie_life_default, 0,
    "Default cookie lifetime in sec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, init_rtx_max, CTLFLAG_RW,
    &sctp_init_rtx_max_default, 0,
    "Default maximum number of retransmission for INIT chunks");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, assoc_rtx_max, CTLFLAG_RW,
    &sctp_assoc_rtx_max_default, 0,
    "Default maximum number of retransmissions per association");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, path_rtx_max, CTLFLAG_RW,
    &sctp_path_rtx_max_default, 0,
    "Default maximum of retransmissions per path");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, add_more_on_output, CTLFLAG_RW,
    &sctp_add_more_threshold, 0,
    "When space wise is it worthwhile to try to add more to a socket send buffer");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, nr_outgoing_streams, CTLFLAG_RW,
    &sctp_nr_outgoing_streams_default, 0,
    "Default number of outgoing streams");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, cmt_on_off, CTLFLAG_RW,
    &sctp_cmt_on_off, 0,
    "CMT ON/OFF flag");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, cwnd_maxburst, CTLFLAG_RW,
    &sctp_use_cwnd_based_maxburst, 0,
    "Use a CWND adjusting maxburst");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, early_fast_retran, CTLFLAG_RW,
    &sctp_early_fr, 0,
    "Early Fast Retransmit with Timer");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, use_rttvar_congctrl, CTLFLAG_RW,
    &sctp_use_rttvar_cc, 0,
    "Use congestion control via rtt variation");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, deadlock_detect, CTLFLAG_RW,
    &sctp_says_check_for_deadlock, 0,
    "SMP Deadlock detection on/off");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, early_fast_retran_msec, CTLFLAG_RW,
    &sctp_early_fr_msec, 0,
    "Early Fast Retransmit minimum timer value");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, asconf_auth_nochk, CTLFLAG_RW,
    &sctp_asconf_auth_nochk, 0,
    "Disable SCTP ASCONF AUTH requirement");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, auth_disable, CTLFLAG_RW,
    &sctp_auth_disable, 0,
    "Disable SCTP AUTH chunk requirement/function");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, auth_random_len, CTLFLAG_RW,
    &sctp_auth_random_len, 0,
    "Length of AUTH RANDOMs");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, auth_hmac_id, CTLFLAG_RW,
    &sctp_auth_hmac_id_default, 0,
    "Default HMAC Id for SCTP AUTHenthication");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, abc_l_var, CTLFLAG_RW,
    &sctp_L2_abc_variable, 0,
    "SCTP ABC max increase per SACK (L)");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, max_chained_mbufs, CTLFLAG_RW,
    &sctp_mbuf_threshold_count, 0,
    "Default max number of small mbufs on a chain");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, cmt_use_dac, CTLFLAG_RW,
    &sctp_cmt_use_dac, 0,
    "CMT DAC ON/OFF flag");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, do_sctp_drain, CTLFLAG_RW,
    &sctp_do_drain, 0,
    "Should SCTP respond to the drain calls");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, hb_max_burst, CTLFLAG_RW,
    &sctp_hb_maxburst, 0,
    "Confirmation Hearbeat max burst?");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, abort_at_limit, CTLFLAG_RW,
    &sctp_abort_if_one_2_one_hits_limit, 0,
    "When one-2-one hits qlimit abort");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, strict_data_order, CTLFLAG_RW,
    &sctp_strict_data_order, 0,
    "Enforce strict data ordering, abort if control inside data");

SYSCTL_STRUCT(_net_inet_sctp, OID_AUTO, stats, CTLFLAG_RW,
    &sctpstat, sctpstat,
    "SCTP statistics (struct sctps_stat, netinet/sctp.h");

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, assoclist, CTLFLAG_RD,
    0, 0, sctp_assoclist,
    "S,xassoc", "List of active SCTP associations");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, nat_friendly, CTLFLAG_RW,
    &sctp_nat_friendly, 0,
    "SCTP NAT friendly operation");

#ifdef SCTP_DEBUG
SYSCTL_INT(_net_inet_sctp, OID_AUTO, debug, CTLFLAG_RW,
    &sctp_debug_on, 0, "Configure debug output");
#endif				/* SCTP_DEBUG */
#if defined(__APPLE__)
SYSCTL_INT(_net_inet_sctp, OID_AUTO, main_timer, CTLFLAG_RW,
    &sctp_main_timer, 0, "Main timer interval in ms");
#endif
#endif

#if defined(__FreeBSD__) && __FreeBSD_version > 690000
static void
#else
static int
#endif
sctp_abort(struct socket *so)
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
		if((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) {
			goto sctp_must_try_again;
		}
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
#if defined(__FreeBSD__) && __FreeBSD_version > 690000
	return;
#else
	return(0);
#endif
}

#if defined(__Panda__)
int
#else
static int
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_attach(struct socket *so, int proto, struct thread *p)
#elif defined(__Panda__)
sctp_attach(struct socket *so, int proto, uint32_t vrfid)
#else
sctp_attach(struct socket *so, int proto, struct proc *p)
#endif
{
	struct sctp_inpcb *inp;
	struct inpcb *ip_inp;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int error;
#ifdef IPSEC	
	uint32_t flags;
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp != 0) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return EINVAL;
	}
	error = soreserve(so, sctp_sendspace, sctp_recvspace);
	if (error) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return error;
	}
	error = sctp_inpcb_alloc(so);
	if (error) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return error;
	}
	inp = (struct sctp_inpcb *)so->so_pcb;
	SCTP_INP_WLOCK(inp);

	inp->sctp_flags &= ~SCTP_PCB_FLAGS_BOUND_V6;	/* I'm not v6! */
	ip_inp = &inp->ip_inp.inp;
#if defined(__FreeBSD__) || defined(__APPLE__)
	ip_inp->inp_vflag |= INP_IPV4;
	ip_inp->inp_ip_ttl = ip_defttl;
#else
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = ip_defttl;
#endif

#ifdef IPSEC
#if !(defined(__OpenBSD__) || defined(__APPLE__))
	error = ipsec_init_pcbpolicy(so, &ip_inp->inp_sp);
#ifdef SCTP_LOG_CLOSING
	sctp_log_closing(inp, NULL, 17);
#endif
	if (error != 0) {
		flags = inp->sctp_flags;
		if (((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) &&
		    (atomic_cmpset_int(&inp->sctp_flags, flags, (flags | SCTP_PCB_FLAGS_SOCKET_GONE | SCTP_PCB_FLAGS_CLOSE_IP)))) {
#ifdef SCTP_LOG_CLOSING
			sctp_log_closing(inp, NULL, 15);
#endif
			sctp_inpcb_free(inp, 1, 0);
		}
		return error;
	}
#endif
#endif				/* IPSEC */
	SCTP_INP_WUNLOCK(inp);
#if defined(__NetBSD__)
	so->so_send = sctp_sosend;
	so->so_receive = sctp_soreceive;
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return 0;
}

static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_bind(struct socket *so, struct sockaddr *addr, struct thread *p)
{
#elif defined(__FreeBSD__) || defined(__APPLE__)
	sctp_bind(struct socket *so, struct sockaddr *addr, struct proc *p){
#else
sctp_bind(struct socket *so, struct mbuf *nam, struct proc *p)
{
	struct sockaddr *addr = nam ? mtod(nam, struct sockaddr *): NULL;

#endif
	struct sctp_inpcb *inp;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int error;

#ifdef INET6
	if (addr && addr->sa_family != AF_INET)
		/* must be a v4 address! */
		return EINVAL;
#endif				/* INET6 */

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;

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
sctp_close(struct socket *so)
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
		if((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) {
			goto sctp_must_try_again;
		}
	}
	return;
}

#else

#if defined(__FreeBSD__) && __FreeBSD_version > 690000
static void
#else
static int
#endif
sctp_detach(struct socket *so)
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
		if (((so->so_options & SO_LINGER) && (so->so_linger == 0)) ||
		    (so->so_rcv.sb_cc > 0)) {
#ifdef SCTP_LOG_CLOSING
			sctp_log_closing(inp, NULL, 13);
#endif
			sctp_inpcb_free(inp, 1, 1);
		} else {
#ifdef SCTP_LOG_CLOSING
			sctp_log_closing(inp, NULL, 13);
#endif
			sctp_inpcb_free(inp, 0, 1);
		}
		/* The socket is now detached, no matter what
		 * the state of the SCTP association.
		 */
		so->so_snd.sb_cc = 0;
		so->so_snd.sb_mb = NULL;
		so->so_snd.sb_mbcnt = 0;
		/* same for the rcv ones, they are only
		 * here for the accounting/select.
		 */
		so->so_rcv.sb_cc = 0;
		so->so_rcv.sb_mb = NULL;
		so->so_rcv.sb_mbcnt = 0;
		/* Now disconnect */
#if !defined(SCTP_APPLE_FINE_GRAINED_LOCKING)
		so->so_pcb = NULL;
#endif
	} else {
		flags = inp->sctp_flags;
		if((flags & SCTP_PCB_FLAGS_SOCKET_GONE) == 0) {
			goto sctp_must_try_again;
		}
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
#if defined(__FreeBSD__) && __FreeBSD_version > 690000
	return;
#else
	return(0);
#endif
}

#endif

int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct thread *p);

#else
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct proc *p);

#endif

int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct thread *p)
{
#else
sctp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct proc *p)
{
#endif
	struct sctp_inpcb *inp;
	int error;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		if (control) {
			sctp_m_freem(control);
			control = NULL;
		}
		sctp_m_freem(m);
		return EINVAL;
	}
	/* Got to have an to address if we are NOT a connected socket */
	if ((addr == NULL) &&
	    ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) ||
	    (inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE))
	    ) {
		goto connected_type;
	} else if (addr == NULL) {
		error = EDESTADDRREQ;
		sctp_m_freem(m);
		if (control) {
			sctp_m_freem(control);
			control = NULL;
		}
		return (error);
	}
#ifdef INET6
	if (addr->sa_family != AF_INET) {
		/* must be a v4 address! */
		sctp_m_freem(m);
		if (control) {
			sctp_m_freem(control);
			control = NULL;
		}
		error = EDESTADDRREQ;
		return EINVAL;
	}
#endif				/* INET6 */
connected_type:
	/* now what about control */
	if (control) {
		if (inp->control) {
			printf("huh? control set?\n");
			sctp_m_freem(inp->control);
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
#if defined (__FreeBSD__) || defined(__APPLE__)
	/* FreeBSD uses a flag passed */
	    ((flags & PRUS_MORETOCOME) == 0)
#elif defined( __NetBSD__)
	/* NetBSD uses the so_state field */
	    ((so->so_state & SS_MORETOCOME) == 0)
#else
	    1			/* Open BSD does not have any "more to come"
				 * indication */
#endif
	    ) {
		/*
		 * note with the current version this code will only be used
		 * by OpenBSD-- NetBSD, FreeBSD, and MacOS have methods for
		 * re-defining sosend to use the sctp_sosend. One can
		 * optionally switch back to this code (by changing back the
		 * definitions) but this is not advisable. This code is used
		 * by FreeBSD when sending a file with sendfile() though.
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

#if defined(__Panda__)
int
#else
static int
#endif
sctp_disconnect(struct socket *so)
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
			return (0);
		} else {
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
			if(stcb->asoc.state & SCTP_STATE_ABOUT_TO_BE_FREED) {
				/* We are about to be freed, out of here */
				SCTP_TCB_UNLOCK(stcb);
				SCTP_INP_RUNLOCK(inp);
				return (0);
			}
			if (((so->so_options & SO_LINGER) &&
			    (so->so_linger == 0)) ||
			    (so->so_rcv.sb_cc > 0)) {
				if (SCTP_GET_STATE(asoc) !=
				    SCTP_STATE_COOKIE_WAIT) {
					/* Left with Data unread */
					struct mbuf *err;

					err = sctp_get_mbuf_for_msg(sizeof(struct sctp_paramhdr), 0, M_DONTWAIT, 1, MT_DATA);
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
				sctp_free_assoc(inp, stcb, SCTP_NORMAL_PROC, SCTP_FROM_SCTP_USRREQ+SCTP_LOC_3);
				/* No unlock tcb assoc is gone */
#if defined(__NetBSD__) || defined(__OpenBSD__)
				splx(s);
#endif
				return (0);
			}
			if (TAILQ_EMPTY(&asoc->send_queue) &&
			    TAILQ_EMPTY(&asoc->sent_queue) &&
			    (asoc->stream_queue_cnt == 0)) {
				/* there is nothing queued to send, so done */
				if (asoc->locked_on_sending) {
					goto abort_anyway;
				}
				if ((SCTP_GET_STATE(asoc) != SCTP_STATE_SHUTDOWN_SENT) &&
				    (SCTP_GET_STATE(asoc) != SCTP_STATE_SHUTDOWN_ACK_SENT)) {
					/* only send SHUTDOWN 1st time thru */
					sctp_stop_timers_for_shutdown(stcb);
					sctp_send_shutdown(stcb,
					    stcb->asoc.primary_destination);
					sctp_chunk_output(stcb->sctp_ep, stcb, SCTP_OUTPUT_FROM_T3);
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
				 * XXX sockets draft says that SCTP_EOF
				 * should be sent with no data. currently,
				 * we will allow user data to be sent first
				 * and move to SHUTDOWN-PENDING
				 */
				asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
				sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD, stcb->sctp_ep, stcb,
						 asoc->primary_destination);
				if (asoc->locked_on_sending) {
					/* Locked to send out the data */
					struct sctp_stream_queue_pending *sp;
					sp = TAILQ_LAST(&asoc->locked_on_sending->outqueue, sctp_streamhead);
					if(sp == NULL) {
						printf("Error, sp is NULL, locked on sending is non-null strm:%d\n",
						       asoc->locked_on_sending->stream_no);
					} else {
						if ((sp->length == 0) && (sp->msg_is_complete == 0))
							asoc->state |= SCTP_STATE_PARTIAL_MSG_LEFT;
					}
				}
				if (TAILQ_EMPTY(&asoc->send_queue) &&
				    TAILQ_EMPTY(&asoc->sent_queue) &&
				    (asoc->state & SCTP_STATE_PARTIAL_MSG_LEFT)){
					struct mbuf *op_err;
				abort_anyway:
					op_err = sctp_get_mbuf_for_msg((sizeof(struct sctp_paramhdr) + sizeof(uint32_t)),
								       0, M_DONTWAIT, 1, MT_DATA);
					if (op_err) {
						/* Fill in the user initiated abort */
						struct sctp_paramhdr *ph;
						uint32_t *ippp;

						SCTP_BUF_LEN(op_err) =
							(sizeof(struct sctp_paramhdr) + sizeof(uint32_t));
						ph = mtod(op_err,
							  struct sctp_paramhdr *);
						ph->param_type = htons(
							SCTP_CAUSE_USER_INITIATED_ABT);
						ph->param_length = htons(SCTP_BUF_LEN(op_err));
						ippp = (uint32_t *) (ph + 1);
						*ippp = htonl(SCTP_FROM_SCTP_USRREQ+SCTP_LOC_4);
					}
					stcb->sctp_ep->last_abort_code = SCTP_FROM_SCTP_USRREQ+SCTP_LOC_4;
					sctp_send_abort_tcb(stcb, op_err);
					SCTP_STAT_INCR_COUNTER32(sctps_aborted);
					if ((SCTP_GET_STATE(&stcb->asoc) == SCTP_STATE_OPEN) ||
					    (SCTP_GET_STATE(&stcb->asoc) == SCTP_STATE_SHUTDOWN_RECEIVED)) {
						SCTP_STAT_DECR_GAUGE32(sctps_currestab);
					}
					SCTP_INP_RUNLOCK(inp);
					sctp_free_assoc(inp, stcb, SCTP_NORMAL_PROC, SCTP_FROM_SCTP_USRREQ+SCTP_LOC_5);
#if defined(__NetBSD__) || defined(__OpenBSD__)
					splx(s);
#endif
					return (0);
				}
			}
			SCTP_TCB_UNLOCK(stcb);
			SCTP_INP_RUNLOCK(inp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (0);
		}
		/* not reached */
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
sctp_shutdown(struct socket *so)
{
	struct sctp_inpcb *inp;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
	s = splsoftnet();
#endif

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return EINVAL;
	}
	SCTP_INP_RLOCK(inp);
	/* For UDP model this is a invalid call */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) {
		/* Restore the flags that the soshutdown took away. */
#if defined(__FreeBSD__) && __FreeBSD_version >= 502115
		so->so_rcv.sb_state &= ~SBS_CANTRCVMORE;
#else
		so->so_state &= ~SS_CANTRCVMORE;
#endif
		/* This proc will wakeup for read and do nothing (I hope) */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		SCTP_INP_RUNLOCK(inp);
		return (EOPNOTSUPP);
	}
	/*
	 * Ok if we reach here its the TCP model and it is either a SHUT_WR
	 * or SHUT_RDWR. This means we put the shutdown flag against it.
	 */
	{
		struct sctp_tcb *stcb;
		struct sctp_association *asoc;

		socantsendmore(so);

		stcb = LIST_FIRST(&inp->sctp_asoc_list);
		if (stcb == NULL) {
			/*
			 * Ok we hit the case that the shutdown call was
			 * made after an abort or something. Nothing to do
			 * now.
			 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (0);
		}
		SCTP_TCB_LOCK(stcb);
		asoc = &stcb->asoc;
		if (TAILQ_EMPTY(&asoc->send_queue) &&
		    TAILQ_EMPTY(&asoc->sent_queue) &&
		    (asoc->stream_queue_cnt == 0)) {
			if (asoc->locked_on_sending) {
				goto abort_anyway;
			}
			/* there is nothing queued to send, so I'm done... */
			if (SCTP_GET_STATE(asoc) != SCTP_STATE_SHUTDOWN_SENT) {
				/* only send SHUTDOWN the first time through */
				sctp_stop_timers_for_shutdown(stcb);
				sctp_send_shutdown(stcb,
				    stcb->asoc.primary_destination);
				sctp_chunk_output(stcb->sctp_ep, stcb, SCTP_OUTPUT_FROM_T3);
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
			 * we still got (or just got) data to send, so set
			 * SHUTDOWN_PENDING
			 */
			asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
			sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD, stcb->sctp_ep, stcb,
					 asoc->primary_destination);

			if (asoc->locked_on_sending) {
				/* Locked to send out the data */
				struct sctp_stream_queue_pending *sp;
				sp = TAILQ_LAST(&asoc->locked_on_sending->outqueue, sctp_streamhead);
				if(sp == NULL) {
					printf("Error, sp is NULL, locked on sending is non-null strm:%d\n",
					       asoc->locked_on_sending->stream_no);
				} else {
					if ((sp->length == 0)  && (sp-> msg_is_complete == 0)) {
						asoc->state |= SCTP_STATE_PARTIAL_MSG_LEFT;
					}
				}
			}
			if(TAILQ_EMPTY(&asoc->send_queue) &&
			    TAILQ_EMPTY(&asoc->sent_queue) &&
			    (asoc->state & SCTP_STATE_PARTIAL_MSG_LEFT)) {
				struct mbuf *op_err;
			abort_anyway:
				op_err = sctp_get_mbuf_for_msg((sizeof(struct sctp_paramhdr) + sizeof(uint32_t)),
							       0, M_DONTWAIT, 1, MT_DATA);
				if (op_err) {
					/* Fill in the user initiated abort */
					struct sctp_paramhdr *ph;
					uint32_t *ippp;

					SCTP_BUF_LEN(op_err) =
						sizeof(struct sctp_paramhdr) + sizeof(uint32_t);
					ph = mtod(op_err,
						  struct sctp_paramhdr *);
					ph->param_type = htons(
						SCTP_CAUSE_USER_INITIATED_ABT);
					ph->param_length = htons(SCTP_BUF_LEN(op_err));
					ippp = (uint32_t *) (ph + 1);
					*ippp = htonl(SCTP_FROM_SCTP_USRREQ+SCTP_LOC_6);
				}
				stcb->sctp_ep->last_abort_code = SCTP_FROM_SCTP_USRREQ+SCTP_LOC_6;
				sctp_abort_an_association(stcb->sctp_ep, stcb,
							  SCTP_RESPONSE_TO_USER_REQ,
							  op_err);
				goto skip_unlock;
			}
		}
		SCTP_TCB_UNLOCK(stcb);
	}
 skip_unlock:
	SCTP_INP_RUNLOCK(inp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return 0;
}

/*
 * copies a "user" presentable address and removes embedded scope, etc.
 * returns 0 on success, 1 on error
 */
static uint32_t
sctp_fill_user_address(struct sockaddr_storage *ss, struct sockaddr *sa)
{
	struct sockaddr_in6 lsa6;

#if defined(SCTP_EMBEDDED_V6_SCOPE)
	sa = (struct sockaddr *)sctp_recover_scope((struct sockaddr_in6 *)sa,
	    &lsa6);
#endif
	memcpy(ss, sa, sa->sa_len);
	return (0);
}


#if defined(__NetBSD__) || defined(__OpenBSD__)
/*
 * On NetBSD and OpenBSD in6_sin_2_v4mapsin6() not used and not exported, so
 * we have to export it here.
 */
void in6_sin_2_v4mapsin6
__P((struct sockaddr_in *sin,
    struct sockaddr_in6 *sin6));

#endif

static size_t
sctp_fill_up_addresses(struct sctp_inpcb *inp,
                       struct sctp_tcb *stcb,
                       size_t limit,
                       struct sockaddr_storage *sas, 
		       uint32_t vrf_id)
{
	struct sctp_ifn *sctp_ifn;
	struct sctp_ifa *sctp_ifa;
	int loopback_scope, ipv4_local_scope, local_scope, site_scope;
	size_t actual;
	int ipv4_addr_legal, ipv6_addr_legal;
	struct sctp_vrf *vrf;

	actual = 0;
	if (limit <= 0)
		return (actual);

	if (stcb) {
		/* Turn on all the appropriate scope */
		loopback_scope = stcb->asoc.loopback_scope;
		ipv4_local_scope = stcb->asoc.ipv4_local_scope;
		local_scope = stcb->asoc.local_scope;
		site_scope = stcb->asoc.site_scope;
	} else {
		/* Turn on ALL scope, since we look at the EP */
		loopback_scope = ipv4_local_scope = local_scope =
			site_scope = 1;
	}
	ipv4_addr_legal = ipv6_addr_legal = 0;
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
		ipv6_addr_legal = 1;
		if (SCTP_IPV6_V6ONLY(inp) == 0) {
			ipv4_addr_legal = 1;
		}
	} else {
		ipv4_addr_legal = 1;
	}
	vrf = sctp_find_vrf(vrf_id);
	if(vrf == NULL) {
		return(0);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		LIST_FOREACH(sctp_ifn, &vrf->ifnlist, next_ifn) {
			if ((loopback_scope == 0) &&
			    SCTP_IFN_IS_IFT_LOOP(sctp_ifn)) {
				/* Skip loopback if loopback_scope not set */
				continue;
			}
			LIST_FOREACH(sctp_ifa, &sctp_ifn->ifalist, next_ifa) {
				if (stcb) {
					/*
					 * For the BOUND-ALL case, the list
					 * associated with a TCB is Always
					 * considered a reverse list.. i.e.
					 * it lists addresses that are NOT
					 * part of the association. If this
					 * is one of those we must skip it.
					 */
					if (sctp_is_addr_restricted(stcb,
								    sctp_ifa)) {
						continue;
					}
				}
				if ((sctp_ifa->address.sa.sa_family == AF_INET) &&
				    (ipv4_addr_legal)) {
					struct sockaddr_in *sin;

					sin = (struct sockaddr_in *)&sctp_ifa->address.sa;
					if (sin->sin_addr.s_addr == 0) {
						/*
						 * we skip unspecifed
						 * addresses
						 */
						continue;
					}
					if ((ipv4_local_scope == 0) &&
					    (IN4_ISPRIVATE_ADDRESS(&sin->sin_addr))) {
						continue;
					}
					if (inp->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4) {
						in6_sin_2_v4mapsin6(sin, (struct sockaddr_in6 *)sas);
						((struct sockaddr_in6 *)sas)->sin6_port = inp->sctp_lport;
						sas = (struct sockaddr_storage *)((caddr_t)sas + sizeof(struct sockaddr_in6));
						actual += sizeof(sizeof(struct sockaddr_in6));
					} else {
						memcpy(sas, sin, sizeof(*sin));
						((struct sockaddr_in *)sas)->sin_port = inp->sctp_lport;
						sas = (struct sockaddr_storage *)((caddr_t)sas + sizeof(*sin));
						actual += sizeof(*sin);
					}
					if (actual >= limit) {
						return (actual);
					}
				} else if ((sctp_ifa->address.sa.sa_family == AF_INET6) &&
					   (ipv6_addr_legal)) {
					struct sockaddr_in6 *sin6;

#ifndef SCTP_KAME
					struct sockaddr_in6 lsa6;

#endif
					sin6 = (struct sockaddr_in6 *)&sctp_ifa->address.sa;
					if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
						/*
						 * we skip unspecifed
						 * addresses
						 */
						continue;
					}
					if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
						if (local_scope == 0)
							continue;
						if (sin6->sin6_scope_id == 0) {
#ifdef SCTP_KAME
							if (sa6_recoverscope(sin6) != 0)
								/*
								 * bad link
								 * local
								 * address
								 */
								continue;
#else
							lsa6 = *sin6;
							if (in6_recoverscope(&lsa6,
									     &lsa6.sin6_addr,
									     NULL))
								/*
								 * bad link
								 * local
								 * address
								 */
								continue;
							sin6 = &lsa6;
#endif				/* SCTP_KAME */
						}
					}
					if ((site_scope == 0) &&
					    (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr))) {
						continue;
					}
					memcpy(sas, sin6, sizeof(*sin6));
					((struct sockaddr_in6 *)sas)->sin6_port = inp->sctp_lport;
					sas = (struct sockaddr_storage *)((caddr_t)sas + sizeof(*sin6));
					actual += sizeof(*sin6);
					if (actual >= limit) {
						return (actual);
					}
				}
			}
		}
	} else {
		struct sctp_laddr *laddr;
		/* The list is a NEGATIVE list */
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (stcb) {
				if (sctp_is_addr_restricted(stcb, laddr->ifa)) {
					continue;
				}
			}
			if (sctp_fill_user_address(sas, &laddr->ifa->address.sa))
				continue;

			((struct sockaddr_in6 *)sas)->sin6_port = inp->sctp_lport;
			sas = (struct sockaddr_storage *)((caddr_t)sas +
							  laddr->ifa->address.sa.sa_len);
			actual += laddr->ifa->address.sa.sa_len;
			if (actual >= limit) {
				return (actual);
			}
		}
	}
	return (actual);
}

static int
sctp_count_max_addresses(struct sctp_inpcb *inp, uint32_t vrf_id)
{
	int cnt = 0;
	struct sctp_vrf *vrf = NULL;
	/*
	 * In both sub-set bound an bound_all cases we return the MAXIMUM
	 * number of addresses that you COULD get. In reality the sub-set
	 * bound may have an exclusion list for a given TCB OR in the
	 * bound-all case a TCB may NOT include the loopback or other
	 * addresses as well.
	 */
	vrf = sctp_find_vrf(vrf_id);
	if(vrf == NULL) {
		return(0);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		struct sctp_ifn *sctp_ifn;
		struct sctp_ifa *sctp_ifa;

		LIST_FOREACH(sctp_ifn, &vrf->ifnlist, next_ifn) {
			LIST_FOREACH(sctp_ifa, &sctp_ifn->ifalist, next_ifa) {
				/* Count them if they are the right type */
				if (sctp_ifa->address.sa.sa_family == AF_INET) {
					if (inp->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4)
						cnt += sizeof(struct sockaddr_in6);
					else
						cnt += sizeof(struct sockaddr_in);

				} else if (sctp_ifa->address.sa.sa_family == AF_INET6)
					cnt += sizeof(struct sockaddr_in6);
			}
		}
	} else {
		struct sctp_laddr *laddr;

		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa->address.sa.sa_family == AF_INET) {
				if (inp->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4)
					cnt += sizeof(struct sockaddr_in6);
				else
					cnt += sizeof(struct sockaddr_in);

			} else if (laddr->ifa->address.sa.sa_family == AF_INET6)
				cnt += sizeof(struct sockaddr_in6);
		}
	}
	return (cnt);
}


static int
sctp_do_connect_x(struct socket *so, struct sctp_inpcb *inp, void *optval,
		  size_t optsize, void *p, int delay)
{
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#endif
	int error = 0;
	int creat_lock_on = 0;
	struct sctp_tcb *stcb = NULL;
	struct sockaddr *sa;
	int num_v6 = 0, num_v4 = 0, *totaddrp, totaddr, i;
	size_t incr, at;
	uint32_t vrf_id;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Connectx called\n");
	}
#endif				/* SCTP_DEBUG */

	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (EADDRINUSE);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return(EINVAL);
	}

	if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
		SCTP_INP_RLOCK(inp);
		stcb = LIST_FIRST(&inp->sctp_asoc_list);
		SCTP_INP_RUNLOCK(inp);
	}
	if (stcb) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (EALREADY);
	}
	SCTP_INP_INCR_REF(inp);
	SCTP_ASOC_CREATE_LOCK(inp);
	creat_lock_on = 1;
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_SOCKET_ALLGONE) ||
	    (inp->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)) {
		error = EFAULT;
		goto out_now;
	}
	totaddrp = (int *)optval;
	totaddr = *totaddrp;
	sa = (struct sockaddr *)(totaddrp + 1);
	at = incr = 0;
	/* account and validate addresses */
	for (i = 0; i < totaddr; i++) {
		if (sa->sa_family == AF_INET) {
			num_v4++;
			incr = sizeof(struct sockaddr_in);
		} else if (sa->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)sa;
			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
				/* Must be non-mapped for connectx */
				error = EINVAL;
				goto out_now;
			}
			num_v6++;
			incr = sizeof(struct sockaddr_in6);
		} else {
			totaddr = i;
			break;
		}
		stcb = sctp_findassociation_ep_addr(&inp, sa, NULL, NULL, NULL);
		if (stcb != NULL) {
			/* Already have or am bring up an association */
			SCTP_ASOC_CREATE_UNLOCK(inp);
			creat_lock_on = 0;
			SCTP_TCB_UNLOCK(stcb);
			error = EALREADY;
			goto out_now;
		}
		if ((at + incr) > optsize) {
			totaddr = i;
			break;
		}
		sa = (struct sockaddr *)((caddr_t)sa + incr);
	}
	sa = (struct sockaddr *)(totaddrp + 1);
#ifdef INET6
	if (((inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) == 0) &&
	    (num_v6 > 0)) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		error = EINVAL;
		goto out_now;
	}
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) &&
	    (num_v4 > 0)) {
		struct in6pcb *inp6;

		inp6 = (struct in6pcb *)inp;
		if (SCTP_IPV6_V6ONLY(inp6)) {
			/*
			 * if IPV6_V6ONLY flag, ignore connections destined
			 * to a v4 addr or v4-mapped addr
			 */
			error = EINVAL;
			goto out_now;
		}
	}
#endif				/* INET6 */
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) ==
	    SCTP_PCB_FLAGS_UNBOUND) {
		/* Bind a ephemeral port */
		SCTP_INP_WUNLOCK(inp);
		error = sctp_inpcb_bind(so, NULL, p);
		if (error) {
			goto out_now;
		}
	} else {
		SCTP_INP_WUNLOCK(inp);
	}

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
	vrf_id = SCTP_DEFAULT_VRFID;
#else
	vrf_id = panda_get_vrf_from_call(); /* from connectx call? */
#endif
	/* We are GOOD to go */
	stcb = sctp_aloc_assoc(inp, sa, 1, &error, 0, vrf_id);
	if (stcb == NULL) {
		/* Gak! no memory */
		goto out_now;
	}
	/* move to second address */
	if (sa->sa_family == AF_INET)
		sa = (struct sockaddr *)((caddr_t)sa + sizeof(struct sockaddr_in));
	else
		sa = (struct sockaddr *)((caddr_t)sa + sizeof(struct sockaddr_in6));

	for (i = 1; i < totaddr; i++) {
		if (sa->sa_family == AF_INET) {
			incr = sizeof(struct sockaddr_in);
			if (sctp_add_remote_addr(stcb, sa, SCTP_DONOT_SETSCOPE, SCTP_ADDR_IS_CONFIRMED)) {
				/* assoc gone no un-lock */
				sctp_free_assoc(inp, stcb, SCTP_NORMAL_PROC, SCTP_FROM_SCTP_USRREQ+SCTP_LOC_7);
				error = ENOBUFS;
				goto out_now;
			}
		} else if (sa->sa_family == AF_INET6) {
			incr = sizeof(struct sockaddr_in6);
			if (sctp_add_remote_addr(stcb, sa, SCTP_DONOT_SETSCOPE, SCTP_ADDR_IS_CONFIRMED)) {
				/* assoc gone no un-lock */
				sctp_free_assoc(inp, stcb, SCTP_NORMAL_PROC, SCTP_FROM_SCTP_USRREQ+SCTP_LOC_8);
				error = ENOBUFS;
				goto out_now;
			}
		}
		sa = (struct sockaddr *)((caddr_t)sa + incr);
	}
	stcb->asoc.state = SCTP_STATE_COOKIE_WAIT;

	/* initialize authentication parameters for the assoc */
	sctp_initialize_auth_params(inp, stcb);

	if (delay) {
		/* doing delayed connection */
		stcb->asoc.delayed_connection = 1;
		sctp_timer_start(SCTP_TIMER_TYPE_INIT, inp, stcb, stcb->asoc.primary_destination);
	} else {
		SCTP_GETTIME_TIMEVAL(&stcb->asoc.time_entered);
		sctp_send_initiate(inp, stcb);
	}
	SCTP_TCB_UNLOCK(stcb);
	if (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		stcb->sctp_ep->sctp_flags |= SCTP_PCB_FLAGS_CONNECTED;
		/* Set the connected flag so we can queue data */
		soisconnecting(so);
	}
 out_now:
	if (creat_lock_on)
		SCTP_ASOC_CREATE_UNLOCK(inp);
	SCTP_INP_DECR_REF(inp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return error;
}

#define SCTP_FIND_STCB(inp, stcb, assoc_id) \
	if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) { \
		SCTP_INP_RLOCK(inp); \
		stcb = LIST_FIRST(&inp->sctp_asoc_list); \
		if (stcb) \
			SCTP_TCB_LOCK(stcb); \
		SCTP_INP_RUNLOCK(inp); \
	} else if (assoc_id != 0) { \
		stcb = sctp_findassociation_ep_asocid(inp, assoc_id, 1); \
		if (stcb == NULL) { \
			error = ENOENT; \
			break; \
		} \
	} else { \
		stcb = NULL; \
	}

#define SCTP_CHECK_AND_CAST(destp, srcp, type, size) \
	if (size < sizeof(type)) { \
		error = EINVAL; \
		break; \
	} else { \
		destp = (type *)srcp; \
	}

#if defined(__Panda__)
int
#else
static int
#endif
sctp_getopt(struct socket *so, int optname, void *optval, size_t *optsize,
	    void *p) {
	struct sctp_inpcb *inp;
	int error, val = 0;
	uint32_t vrf_id;
	struct sctp_tcb *stcb = NULL;

	if (optval == NULL) {
		return (EINVAL);
	}

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
	vrf_id = SCTP_DEFAULT_VRFID;
#else
	vrf_id = panda_get_vrf_from_call(); /* from socket option call? */
#endif

	error = 0;

	switch (optname) {
	case SCTP_NODELAY:
	case SCTP_AUTOCLOSE:
	case SCTP_EXPLICIT_EOR:
	case SCTP_AUTO_ASCONF:
	case SCTP_DISABLE_FRAGMENTS:
	case SCTP_I_WANT_MAPPED_V4_ADDR:
	case SCTP_USE_EXT_RCVINFO:
		SCTP_INP_RLOCK(inp);
		switch (optname) {
		case SCTP_DISABLE_FRAGMENTS:
			val = sctp_is_feature_on(inp, SCTP_PCB_FLAGS_NO_FRAGMENT);
			break;
		case SCTP_I_WANT_MAPPED_V4_ADDR:
			val = sctp_is_feature_on(inp, SCTP_PCB_FLAGS_NEEDS_MAPPED_V4);
			break;
		case SCTP_AUTO_ASCONF:
			val = sctp_is_feature_on(inp, SCTP_PCB_FLAGS_AUTO_ASCONF);
			break;
		case SCTP_EXPLICIT_EOR:
			val = sctp_is_feature_on(inp, SCTP_PCB_FLAGS_EXPLICIT_EOR);
			break;
		case SCTP_NODELAY:
			val = sctp_is_feature_on(inp, SCTP_PCB_FLAGS_NODELAY);
			break;
		case SCTP_USE_EXT_RCVINFO:			
			val = sctp_is_feature_on(inp, SCTP_PCB_FLAGS_EXT_RCVINFO);
			break;
		case SCTP_AUTOCLOSE:
			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_AUTOCLOSE))
				val = TICKS_TO_SEC(inp->sctp_ep.auto_close_time);
			else
				val = 0;
			break;

		default:
			error = ENOPROTOOPT;
		} /* end switch (sopt->sopt_name) */
		if (optname != SCTP_AUTOCLOSE) {
			/* make it an "on/off" value */
			val = (val != 0);
		}
		if (*optsize < sizeof(val)) {
			error = EINVAL;
		}
		SCTP_INP_RUNLOCK(inp);
		if (error == 0) {
			/* return the option value */
			*(int *)optval = val;
			*optsize = sizeof(val);
		}
		break;
	case SCTP_PARTIAL_DELIVERY_POINT:
		{
			uint32_t *value;
		
			SCTP_CHECK_AND_CAST(value, optval, uint32_t, *optsize);
			*value = inp->partial_delivery_point;
			*optsize = sizeof(uint32_t);
		}
		break;
	case SCTP_FRAGMENT_INTERLEAVE:
		{
			uint32_t *value;
		
			SCTP_CHECK_AND_CAST(value, optval, uint32_t, *optsize);
			*value = sctp_is_feature_on(inp, SCTP_PCB_FLAGS_FRAG_INTERLEAVE);
			*optsize = sizeof(uint32_t);
		}
		break;
	case SCTP_CMT_ON_OFF:
		{
			struct sctp_assoc_value *av;

			SCTP_CHECK_AND_CAST(av, optval, struct sctp_assoc_value, *optsize);
			if (sctp_cmt_on_off) {
				SCTP_FIND_STCB(inp, stcb, av->assoc_id);
				if (stcb) {
					av->assoc_value = stcb->asoc.sctp_cmt_on_off;
					SCTP_TCB_UNLOCK(stcb);

				} else {
					error = ENOTCONN;
				}
			} else {
				error = ENOPROTOOPT;
			}
			*optsize = sizeof(*av); 
		}
		break;
	case SCTP_GET_ADDR_LEN:
		{
			struct sctp_assoc_value *av;

			SCTP_CHECK_AND_CAST(av, optval, struct sctp_assoc_value, *optsize);
			error = EINVAL;
#ifdef INET
			if (av->assoc_value == AF_INET) {
				av->assoc_value = sizeof(struct sockaddr_in);
				error = 0;
			}
#endif
#ifdef INET6
			if (av->assoc_value == AF_INET6) {
				av->assoc_value = sizeof(struct sockaddr_in6);
				error = 0;
			}
#endif
			*optsize = sizeof(*av); 
		}
		break;
	case SCTP_GET_ASOC_ID_LIST:
		{
			struct sctp_assoc_ids *ids;
			int cnt, at;
			uint16_t orig;

			SCTP_CHECK_AND_CAST(ids, optval, struct sctp_assoc_ids, *optsize);
			cnt = 0;
			SCTP_INP_RLOCK(inp);
			stcb = LIST_FIRST(&inp->sctp_asoc_list);
			if (stcb == NULL) {
		none_out_now:
				ids->asls_numb_present = 0;
				ids->asls_more_to_get = 0;
				SCTP_INP_RUNLOCK(inp);
				break;
			}
			orig = ids->asls_assoc_start;
			stcb = LIST_FIRST(&inp->sctp_asoc_list);
			while (orig) {
				stcb = LIST_NEXT(stcb, sctp_tcblist);
				orig--;
				cnt--;
				if (stcb == NULL)
					goto none_out_now;
			}
			if (stcb == NULL)
				goto none_out_now;

			at = 0;
			ids->asls_numb_present = 0;
			ids->asls_more_to_get = 1;
			while (at < MAX_ASOC_IDS_RET) {
				ids->asls_assoc_id[at] = sctp_get_associd(stcb);
				at++;
				ids->asls_numb_present++;
				stcb = LIST_NEXT(stcb, sctp_tcblist);
				if (stcb == NULL) {
					ids->asls_more_to_get = 0;
					break;
				}
			}
			SCTP_INP_RUNLOCK(inp);
		}
		break;
	case SCTP_CONTEXT:
		{
			struct sctp_assoc_value *av;

			SCTP_CHECK_AND_CAST(av, optval, struct sctp_assoc_value, *optsize);
			SCTP_FIND_STCB(inp, stcb, av->assoc_id);

			if (stcb) {
				av->assoc_value = stcb->asoc.context;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_RLOCK(inp);				
				av->assoc_value = inp->sctp_context;
				SCTP_INP_RUNLOCK(inp);
			}
			*optsize = sizeof(*av);
		}
		break;
	case SCTP_GET_NONCE_VALUES:
		{
			struct sctp_get_nonce_values *gnv;

			SCTP_CHECK_AND_CAST(gnv, optval, struct sctp_get_nonce_values, *optsize);
			SCTP_FIND_STCB(inp, stcb, gnv->gn_assoc_id);

			if (stcb) {
				gnv->gn_peers_tag = stcb->asoc.peer_vtag;
				gnv->gn_local_tag = stcb->asoc.my_vtag;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				error = ENOTCONN;
			}
			*optsize = sizeof(*gnv);
		}
		break;
	case SCTP_DELAYED_ACK_TIME:
		{
			struct sctp_assoc_value *tm;

			SCTP_CHECK_AND_CAST(tm, optval, struct sctp_assoc_value, *optsize);
			SCTP_FIND_STCB(inp, stcb, tm->assoc_id);
			
			if (stcb) {
				tm->assoc_value = stcb->asoc.delayed_ack;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_RLOCK(inp);				
				tm->assoc_value = TICKS_TO_MSEC(inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_RECV]);
				SCTP_INP_RUNLOCK(inp);				
			}
			*optsize = sizeof(*tm);
		}
		break;

	case SCTP_GET_SNDBUF_USE:
		{
			struct sctp_sockstat *ss;
			
			SCTP_CHECK_AND_CAST(ss, optval, struct sctp_sockstat, *optsize);
			SCTP_FIND_STCB(inp, stcb, ss->ss_assoc_id);
			
			if (stcb) {
				ss->ss_total_sndbuf = stcb->asoc.total_output_queue_size;
				ss->ss_total_recv_buf = (stcb->asoc.size_on_reasm_queue +
				                         stcb->asoc.size_on_all_streams);
				SCTP_TCB_UNLOCK(stcb);
			} else {
				error = ENOTCONN;
			}
			*optsize = sizeof(struct sctp_sockstat);
		}
		break;
	case SCTP_MAXBURST:
		{
			uint8_t *value;
			
			SCTP_CHECK_AND_CAST(value, optval, uint8_t, *optsize);

			SCTP_INP_RLOCK(inp);
			*value = inp->sctp_ep.max_burst;
			SCTP_INP_RUNLOCK(inp);
			*optsize = sizeof(uint8_t);
		}
		break;
	case SCTP_MAXSEG:
		{
			struct sctp_assoc_value *av;
			int ovh;

			SCTP_CHECK_AND_CAST(av, optval, struct sctp_assoc_value, *optsize);
			SCTP_FIND_STCB(inp, stcb, av->assoc_id);

			if (stcb) {
				av->assoc_value = sctp_get_frag_point(stcb, &stcb->asoc);
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_RLOCK(inp);				
				if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
					ovh = SCTP_MED_OVERHEAD;
				} else {
					ovh = SCTP_MED_V4_OVERHEAD;
				}
				av->assoc_value = inp->sctp_frag_point - ovh;
				SCTP_INP_RUNLOCK(inp);				
			}
			*optsize = sizeof(struct sctp_assoc_value);
		}
		break;
	case SCTP_GET_STAT_LOG:
#ifdef SCTP_STAT_LOGGING
		error = sctp_fill_stat_log(optval, optsize);
#else
		error = EOPNOTSUPP;
#endif
		break;
	case SCTP_EVENTS:
		{
			struct sctp_event_subscribe *events;

			SCTP_CHECK_AND_CAST(events, optval, struct sctp_event_subscribe, *optsize);
			memset(events, 0, sizeof(*events));
			SCTP_INP_RLOCK(inp);
			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_RECVDATAIOEVNT))
				events->sctp_data_io_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_RECVASSOCEVNT))
				events->sctp_association_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_RECVPADDREVNT))
				events->sctp_address_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_RECVSENDFAILEVNT))
				events->sctp_send_failure_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_RECVPEERERR))
				events->sctp_peer_error_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT))
				events->sctp_shutdown_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_PDAPIEVNT))
				events->sctp_partial_delivery_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_ADAPTATIONEVNT))
				events->sctp_adaptation_layer_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_AUTHEVNT))
				events->sctp_authentication_event = 1;

			if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_STREAM_RESETEVNT))
				events->sctp_stream_reset_events = 1;
			SCTP_INP_RUNLOCK(inp);
			*optsize = sizeof(struct sctp_event_subscribe);
		}
		break;

	case SCTP_ADAPTATION_LAYER:
		{
			uint32_t *value;
			
			SCTP_CHECK_AND_CAST(value, optval, uint32_t, *optsize);

			SCTP_INP_RLOCK(inp);
			*value = inp->sctp_ep.adaptation_layer_indicator;
			SCTP_INP_RUNLOCK(inp);
			*optsize = sizeof(uint32_t);
		}
		break;
	case SCTP_SET_INITIAL_DBG_SEQ:
		{
			uint32_t *value;
			
			SCTP_CHECK_AND_CAST(value, optval, uint32_t, *optsize);
			SCTP_INP_RLOCK(inp);
			*value = inp->sctp_ep.initial_sequence_debug;
			SCTP_INP_RUNLOCK(inp);
			*optsize = sizeof(uint32_t);
		}
		break;
	case SCTP_GET_LOCAL_ADDR_SIZE:
		{
			uint32_t *value;
			
			SCTP_CHECK_AND_CAST(value, optval, uint32_t, *optsize);
			SCTP_INP_RLOCK(inp);
			*value = sctp_count_max_addresses(inp, vrf_id);
			SCTP_INP_RUNLOCK(inp);
			*optsize = sizeof(uint32_t);
		}
		break;
	case SCTP_GET_REMOTE_ADDR_SIZE:
		{
			uint32_t *value;
			size_t size;
			struct sctp_nets *net;

			SCTP_CHECK_AND_CAST(value, optval, uint32_t, *optsize);
			/* FIXME MT: change to sctp_assoc_value? */
			SCTP_FIND_STCB(inp, stcb, (sctp_assoc_t) *value);

			if (stcb) {
				size = 0;
				/* Count the sizes */
				TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
					if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4) ||
					    (((struct sockaddr *)&net->ro._l_addr)->sa_family == AF_INET6)) {
						size += sizeof(struct sockaddr_in6);
					} else if (((struct sockaddr *)&net->ro._l_addr)->sa_family == AF_INET) {
						size += sizeof(struct sockaddr_in);
					} else {
						/* huh */
						break;
					}
				}
				SCTP_TCB_UNLOCK(stcb);
				*value = (uint32_t) size;
			} else {
				error = ENOTCONN;
			}
			*optsize = sizeof(uint32_t);
		}
		break;
	case SCTP_GET_PEER_ADDRESSES:
		/*
		 * Get the address information, an array is passed in to
		 * fill up we pack it.
		 */
		{
			size_t cpsz, left;
			struct sockaddr_storage *sas;
			struct sctp_nets *net;
			struct sctp_getaddresses *saddr;
			
			SCTP_CHECK_AND_CAST(saddr, optval, struct sctp_getaddresses, *optsize);
			SCTP_FIND_STCB(inp, stcb, saddr->sget_assoc_id);

			if (stcb) {
				left = (*optsize) - sizeof(struct sctp_getaddresses);
				*optsize = sizeof(struct sctp_getaddresses);
				sas = (struct sockaddr_storage *)&saddr->addr[0];

				TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
					if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4) ||
					    (((struct sockaddr *)&net->ro._l_addr)->sa_family == AF_INET6)) {
						cpsz = sizeof(struct sockaddr_in6);
					} else if (((struct sockaddr *)&net->ro._l_addr)->sa_family == AF_INET) {
						cpsz = sizeof(struct sockaddr_in);
					} else {
						/* huh */
						break;
					}
					if (left < cpsz) {
						/* not enough room. */
						break;
					}
					if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4) &&
					    (((struct sockaddr *)&net->ro._l_addr)->sa_family == AF_INET)) {
						/* Must map the address */
						in6_sin_2_v4mapsin6((struct sockaddr_in *)&net->ro._l_addr,
						    (struct sockaddr_in6 *)sas);
					} else {
						memcpy(sas, &net->ro._l_addr, cpsz);
					}
					((struct sockaddr_in *)sas)->sin_port = stcb->rport;

					sas = (struct sockaddr_storage *)((caddr_t)sas + cpsz);
					left -= cpsz;
					*optsize += cpsz;
				}
				SCTP_TCB_UNLOCK(stcb);
			} else {
				error = ENOENT;
			}
		}
		break;
	case SCTP_GET_LOCAL_ADDRESSES:
		{
			size_t limit, actual;
			struct sockaddr_storage *sas;
			struct sctp_getaddresses *saddr;

			SCTP_CHECK_AND_CAST(saddr, optval, struct sctp_getaddresses, *optsize);
			SCTP_FIND_STCB(inp, stcb, saddr->sget_assoc_id);

			sas = (struct sockaddr_storage *)&saddr->addr[0];
			limit = *optsize - sizeof(sctp_assoc_t);
			actual = sctp_fill_up_addresses(inp, stcb, limit, sas, vrf_id);
			if (stcb)
				SCTP_TCB_UNLOCK(stcb);
			*optsize = sizeof(struct sockaddr_storage) + actual;
		}
		break;
	case SCTP_PEER_ADDR_PARAMS:
		{
			struct sctp_paddrparams *paddrp;
			struct sctp_nets *net;

			SCTP_CHECK_AND_CAST(paddrp, optval, struct sctp_paddrparams, *optsize);
			SCTP_FIND_STCB(inp, stcb, paddrp->spp_assoc_id);
			
			net = NULL;
			if (stcb) {
				net = sctp_findnet(stcb, (struct sockaddr *)&paddrp->spp_address);
			} else {
				/* We increment here since sctp_findassociation_ep_addr() wil
				 * do a decrement if it finds the stcb as long as the locked
				 * tcb (last argument) is NOT a TCB.. aka NULL.
				 */
				SCTP_INP_INCR_REF(inp); 
				stcb = sctp_findassociation_ep_addr(&inp, (struct sockaddr *)&paddrp->spp_address, &net, NULL, NULL);
				if (stcb == NULL) {
					SCTP_INP_DECR_REF(inp);
				}
			}
				
			if (stcb) {
				/* Applys to the specific association */
				paddrp->spp_flags = 0;
				if (net) {
					paddrp->spp_pathmaxrxt = net->failure_threshold;
					paddrp->spp_pathmtu = net->mtu;
					/* get flags for HB */
					if (net->dest_state & SCTP_ADDR_NOHB)
						paddrp->spp_flags |= SPP_HB_DISABLE;
					else
						paddrp->spp_flags |= SPP_HB_ENABLE;
					/* get flags for PMTU */
					if (SCTP_OS_TIMER_PENDING(&net->pmtu_timer.timer)) {
						paddrp->spp_flags |= SPP_PMTUD_ENABLE;
					} else {
						paddrp->spp_flags |= SPP_PMTUD_DISABLE;
					}
#ifdef INET
					if (net->ro._l_addr.sin.sin_family == AF_INET) {
						paddrp->spp_ipv4_tos = net->tos_flowlabel & 0x000000fc;
						paddrp->spp_flags |= SPP_IPV4_TOS;
					}
#endif
#ifdef INET6
					if (net->ro._l_addr.sin6.sin6_family == AF_INET6) {
						paddrp->spp_ipv6_flowlabel = net->tos_flowlabel;
						paddrp->spp_flags |= SPP_IPV6_FLOWLABEL;
					}
#endif
				} else {
					/*
					 * No destination so return default
					 * value
					 */
					paddrp->spp_pathmaxrxt = stcb->asoc.def_net_failure;
					paddrp->spp_pathmtu = sctp_get_frag_point(stcb, &stcb->asoc);
#ifdef INET
					paddrp->spp_ipv4_tos = stcb->asoc.default_tos & 0x000000fc;
					paddrp->spp_flags |= SPP_IPV4_TOS;
#endif
#ifdef INET6
					paddrp->spp_ipv6_flowlabel = stcb->asoc.default_flowlabel;
					paddrp->spp_flags |= SPP_IPV6_FLOWLABEL;
#endif
					/* default settings should be these */
					if (sctp_is_hb_timer_running(stcb)) {
						paddrp->spp_flags |= SPP_HB_ENABLE;
					}
				}
				paddrp->spp_hbinterval = stcb->asoc.heart_beat_delay;
				paddrp->spp_assoc_id = sctp_get_associd(stcb);
				SCTP_TCB_UNLOCK(stcb);
			} else {
				/* Use endpoint defaults */
				SCTP_INP_RLOCK(inp);
				paddrp->spp_pathmaxrxt = inp->sctp_ep.def_net_failure;
				paddrp->spp_hbinterval = TICKS_TO_MSEC(inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_HEARTBEAT]);
				paddrp->spp_assoc_id = (sctp_assoc_t) 0;
				/* get inp's default */
#ifdef INET
#if defined(__FreeBSD__) || defined(__APPLE__)
				paddrp->spp_ipv4_tos = inp->ip_inp.inp.inp_ip_tos;
#elif defined(__NetBSD__)
				paddrp->spp_ipv4_tos = inp->ip_inp.inp.inp_ip.ip_tos;
#else
				paddrp->spp_ipv4_tos = inp->inp_ip_tos;
#endif
				paddrp->spp_flags |= SPP_IPV4_TOS;
#endif
#ifdef INET6
				if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
					paddrp->spp_ipv6_flowlabel = ((struct in6pcb *)inp)->in6p_flowinfo;
					paddrp->spp_flags |= SPP_IPV6_FLOWLABEL;
				}
#endif
				/* can't return this */
				paddrp->spp_pathmaxrxt = 0;
				paddrp->spp_pathmtu = 0;
				/* default behavior, no stcb */
				paddrp->spp_flags = SPP_HB_ENABLE | SPP_PMTUD_ENABLE;

				SCTP_INP_RUNLOCK(inp);
			}
			*optsize = sizeof(struct sctp_paddrparams);
		}
		break;
	case SCTP_GET_PEER_ADDR_INFO:
		{
			struct sctp_paddrinfo *paddri;
			struct sctp_nets *net;

			SCTP_CHECK_AND_CAST(paddri, optval, struct sctp_paddrinfo, *optsize);
			SCTP_FIND_STCB(inp, stcb, paddri->spinfo_assoc_id);
			
			net = NULL;
			if (stcb) {
				net = sctp_findnet(stcb, (struct sockaddr *)&paddri->spinfo_address);
			} else {
				/* We increment here since sctp_findassociation_ep_addr() wil
				 * do a decrement if it finds the stcb as long as the locked
				 * tcb (last argument) is NOT a TCB.. aka NULL.
				 */
				SCTP_INP_INCR_REF(inp);
				stcb = sctp_findassociation_ep_addr(&inp, (struct sockaddr *)&paddri->spinfo_address, &net, NULL, NULL);
				if (stcb == NULL) {
					SCTP_INP_DECR_REF(inp);
				}
			}

			if ((stcb) && (net)) {
				paddri->spinfo_state = net->dest_state & (SCTP_REACHABLE_MASK | SCTP_ADDR_NOHB);
				paddri->spinfo_cwnd = net->cwnd;
				paddri->spinfo_srtt = ((net->lastsa >> 2) + net->lastsv) >> 1;
				paddri->spinfo_rto = net->RTO;
				paddri->spinfo_assoc_id = sctp_get_associd(stcb);
				SCTP_TCB_UNLOCK(stcb);
			} else {
				if (stcb) {
					SCTP_TCB_UNLOCK(stcb);
				}
				error = ENOENT;
			}
			*optsize = sizeof(struct sctp_paddrinfo);
		}
		break;
	case SCTP_PCB_STATUS:
		{
			struct sctp_pcbinfo *spcb;

			SCTP_CHECK_AND_CAST(spcb, optval, struct sctp_pcbinfo, *optsize);
#if defined(SCTP_PER_SOCKET_LOCKING)
			if (!SCTP_TRYLOCK_SHARED(sctppcbinfo.ipi_ep_mtx)) {
				SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 0);
				SCTP_LOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
				SCTP_SOCKET_LOCK(SCTP_INP_SO(inp), 0);
			}
#endif
			sctp_fill_pcbinfo(spcb);
#if defined(SCTP_PER_SOCKET_LOCKING)
			SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx);
#endif
			*optsize = sizeof(struct sctp_pcbinfo);
		}
		break;
	case SCTP_STATUS:
		{
			struct sctp_nets *net;
			struct sctp_status *sstat;

			SCTP_CHECK_AND_CAST(sstat, optval, struct sctp_status, *optsize);
			SCTP_FIND_STCB(inp, stcb, sstat->sstat_assoc_id);

			if (stcb == NULL) {
				error = EINVAL;
				break;
			}
			/*
			 * I think passing the state is fine since
			 * sctp_constants.h will be available to the user
			 * land.
			 */
			sstat->sstat_state = stcb->asoc.state;
			sstat->sstat_rwnd = stcb->asoc.peers_rwnd;
			sstat->sstat_unackdata = stcb->asoc.sent_queue_cnt;
			/*
			 * We can't include chunks that have been passed to
			 * the socket layer. Only things in queue.
			 */
			sstat->sstat_penddata = (stcb->asoc.cnt_on_reasm_queue +
			    stcb->asoc.cnt_on_all_streams);


			sstat->sstat_instrms = stcb->asoc.streamincnt;
			sstat->sstat_outstrms = stcb->asoc.streamoutcnt;
			sstat->sstat_fragmentation_point = sctp_get_frag_point(stcb, &stcb->asoc);
			memcpy(&sstat->sstat_primary.spinfo_address,
			    &stcb->asoc.primary_destination->ro._l_addr,
			    ((struct sockaddr *)(&stcb->asoc.primary_destination->ro._l_addr))->sa_len);
			net = stcb->asoc.primary_destination;
			((struct sockaddr_in *)&sstat->sstat_primary.spinfo_address)->sin_port = stcb->rport;
			/*
			 * Again the user can get info from sctp_constants.h
			 * for what the state of the network is.
			 */
			sstat->sstat_primary.spinfo_state = net->dest_state & SCTP_REACHABLE_MASK;
			sstat->sstat_primary.spinfo_cwnd = net->cwnd;
			sstat->sstat_primary.spinfo_srtt = net->lastsa;
			sstat->sstat_primary.spinfo_rto = net->RTO;
			sstat->sstat_primary.spinfo_mtu = net->mtu;
			sstat->sstat_primary.spinfo_assoc_id = sctp_get_associd(stcb);
			SCTP_TCB_UNLOCK(stcb);
			*optsize = sizeof(*sstat);
		}
		break;
	case SCTP_RTOINFO:
		{
			struct sctp_rtoinfo *srto;
			
			SCTP_CHECK_AND_CAST(srto, optval, struct sctp_rtoinfo, *optsize);
			SCTP_FIND_STCB(inp, stcb, srto->srto_assoc_id);
			
			if (stcb) {
				srto->srto_initial = stcb->asoc.initial_rto;
				srto->srto_max = stcb->asoc.maxrto;
				srto->srto_min = stcb->asoc.minrto;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_RLOCK(inp);
				srto->srto_initial = inp->sctp_ep.initial_rto;
				srto->srto_max = inp->sctp_ep.sctp_maxrto;
				srto->srto_min = inp->sctp_ep.sctp_minrto;
				SCTP_INP_RUNLOCK(inp);
			}
			*optsize = sizeof(*srto);
		}
		break;
	case SCTP_ASSOCINFO:
		{
			struct sctp_assocparams *sasoc;

			SCTP_CHECK_AND_CAST(sasoc, optval, struct sctp_assocparams, *optsize);
			SCTP_FIND_STCB(inp, stcb, sasoc->sasoc_assoc_id);

			if (stcb) {
				sasoc->sasoc_asocmaxrxt = stcb->asoc.max_send_times;
				sasoc->sasoc_number_peer_destinations = stcb->asoc.numnets;
				sasoc->sasoc_peer_rwnd = stcb->asoc.peers_rwnd;
				sasoc->sasoc_local_rwnd = stcb->asoc.my_rwnd;
				sasoc->sasoc_cookie_life = stcb->asoc.cookie_life;
				sasoc->sasoc_sack_delay = stcb->asoc.delayed_ack;
				sasoc->sasoc_sack_freq = stcb->asoc.sack_freq;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_RLOCK(inp);
				sasoc->sasoc_asocmaxrxt = inp->sctp_ep.max_send_times;
				sasoc->sasoc_number_peer_destinations = 0;
				sasoc->sasoc_peer_rwnd = 0;
				sasoc->sasoc_local_rwnd = sbspace(&inp->sctp_socket->so_rcv);
				sasoc->sasoc_cookie_life = inp->sctp_ep.def_cookie_life;
				sasoc->sasoc_sack_delay = TICKS_TO_MSEC(inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_RECV]);
				sasoc->sasoc_sack_freq = inp->sctp_ep.sctp_sack_freq;
				SCTP_INP_RUNLOCK(inp);
			}
			*optsize = sizeof(*sasoc);
		}
		break;
	case SCTP_DEFAULT_SEND_PARAM:
		{
			struct sctp_sndrcvinfo *s_info;

			SCTP_CHECK_AND_CAST(s_info, optval, struct sctp_sndrcvinfo, *optsize);
			SCTP_FIND_STCB(inp, stcb, s_info->sinfo_assoc_id);
			
			if (stcb) {
				*s_info = stcb->asoc.def_send;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_RLOCK(inp);
				*s_info = inp->def_send;
				SCTP_INP_RUNLOCK(inp);
			}
			*optsize = sizeof(*s_info);
		}
		break;
	case SCTP_INITMSG:
		{
			struct sctp_initmsg *sinit;

			SCTP_CHECK_AND_CAST(sinit, optval, struct sctp_initmsg, *optsize);
			SCTP_INP_RLOCK(inp);
			sinit->sinit_num_ostreams = inp->sctp_ep.pre_open_stream_count;
			sinit->sinit_max_instreams = inp->sctp_ep.max_open_streams_intome;
			sinit->sinit_max_attempts = inp->sctp_ep.max_init_times;
			sinit->sinit_max_init_timeo = inp->sctp_ep.initial_init_rto_max;
			SCTP_INP_RUNLOCK(inp);
			*optsize = sizeof(*sinit);
		}
		break;
	case SCTP_PRIMARY_ADDR:
		/* we allow a "get" operation on this */
		{
			struct sctp_setprim *ssp;

			SCTP_CHECK_AND_CAST(ssp, optval, struct sctp_setprim, *optsize);
			SCTP_FIND_STCB(inp, stcb, ssp->ssp_assoc_id);
			
			if (stcb) {
				/* simply copy out the sockaddr_storage... */
				memcpy(&ssp->ssp_addr,  &stcb->asoc.primary_destination->ro._l_addr,
				    ((struct sockaddr *)&stcb->asoc.primary_destination->ro._l_addr)->sa_len);
				SCTP_TCB_UNLOCK(stcb);
			} else {
				error = EINVAL;
			}
			*optsize = sizeof(*ssp);
		}
		break;

	case SCTP_HMAC_IDENT:
		{
			struct sctp_hmacalgo *shmac;
			sctp_hmaclist_t *hmaclist;
			uint32_t size;
			int i;

			SCTP_CHECK_AND_CAST(shmac, optval, struct sctp_hmacalgo, *optsize);

			SCTP_INP_RLOCK(inp);
			hmaclist = inp->sctp_ep.local_hmacs;
			if (hmaclist == NULL) {
				/* no HMACs to return */
				*optsize = sizeof(*shmac);
				break;
			}
			/* is there room for all of the hmac ids? */
			size = sizeof(*shmac) + (hmaclist->num_algo *
			    sizeof(shmac->shmac_idents[0]));
			if ((size_t)(*optsize) < size) {
				error = EINVAL;
				SCTP_INP_RUNLOCK(inp);
				break;
			}
			/* copy in the list */
			for (i = 0; i < hmaclist->num_algo; i++)
				shmac->shmac_idents[i] = hmaclist->hmac[i];
			SCTP_INP_RUNLOCK(inp);
			*optsize = size;
			break;
		}
	case SCTP_AUTH_ACTIVE_KEY:
		{
			struct sctp_authkeyid *scact;

			SCTP_CHECK_AND_CAST(scact, optval, struct sctp_authkeyid, *optsize);
			SCTP_FIND_STCB(inp, stcb, scact->scact_assoc_id);

			if (stcb) {
				/* get the active key on the assoc */
				scact->scact_keynumber = stcb->asoc.authinfo.assoc_keyid;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				/* get the endpoint active key */
				SCTP_INP_RLOCK(inp);
				scact->scact_keynumber = inp->sctp_ep.default_keyid;
				SCTP_INP_RUNLOCK(inp);
			}
			*optsize = sizeof(*scact);
			break;
		}
	case SCTP_LOCAL_AUTH_CHUNKS:
		{
			struct sctp_authchunks *sac;
			sctp_auth_chklist_t *chklist = NULL;
			size_t size = 0;

			SCTP_CHECK_AND_CAST(sac, optval, struct sctp_authchunks, *optsize);
			SCTP_FIND_STCB(inp, stcb, sac->gauth_assoc_id);

			if (stcb) {
				/* get off the assoc */
				chklist = stcb->asoc.local_auth_chunks;
				/* is there enough space? */
				size = sctp_auth_get_chklist_size(chklist);
				if (*optsize < (sizeof(struct sctp_authchunks) + size)) {
					error = EINVAL;
				} else {
					/* copy in the chunks */
					sctp_serialize_auth_chunks(chklist, sac->gauth_chunks);
				}
				SCTP_TCB_UNLOCK(stcb);
			} else {
				/* get off the endpoint */
				SCTP_INP_RLOCK(inp);
				chklist = inp->sctp_ep.local_auth_chunks;
				/* is there enough space? */
				size = sctp_auth_get_chklist_size(chklist);
				if (*optsize < (sizeof(struct sctp_authchunks) + size)) {
					error = EINVAL;
				} else {
					/* copy in the chunks */
					sctp_serialize_auth_chunks(chklist, sac->gauth_chunks);
				}
				SCTP_INP_RUNLOCK(inp);
			}
			*optsize = sizeof(struct sctp_authchunks) + size;
			break;
		}
	case SCTP_PEER_AUTH_CHUNKS:
		{
			struct sctp_authchunks *sac;
			sctp_auth_chklist_t *chklist = NULL;
			size_t size = 0;

			SCTP_CHECK_AND_CAST(sac, optval, struct sctp_authchunks, *optsize);
			SCTP_FIND_STCB(inp, stcb, sac->gauth_assoc_id);

			if (stcb) {
				/* get off the assoc */
				chklist = stcb->asoc.peer_auth_chunks;
				/* is there enough space? */
				size = sctp_auth_get_chklist_size(chklist);
				if (*optsize < (sizeof(struct sctp_authchunks) + size)) {
					error = EINVAL;
				} else {
					/* copy in the chunks */
					sctp_serialize_auth_chunks(chklist, sac->gauth_chunks);
				}
				SCTP_TCB_UNLOCK(stcb);
			} else {
				error = ENOENT;
			}
			*optsize = sizeof(struct sctp_authchunks) + size;
			break;
		}

#if defined(HAVE_SCTP_PEELOFF_SOCKOPT)
	case SCTP_PEELOFF:
		{
			struct sctp_peeloff_opt *peeloff;

			SCTP_CHECK_AND_CAST(peeloff, optval, struct sctp_peeloff_opt, *optsize);
			/* do the peeloff */
			error = sctp_peeloff_option(p, peeloff);
			*optsize = sizeof(*peeloff);
		}
		break;
#endif /* HAVE_SCTP_PEELOFF_SOCKOPT */

	default:
		error = ENOPROTOOPT;
		*optsize = 0;
		break;
	} /* end switch (sopt->sopt_name) */
	return (error);
}

#if defined(__Panda__)
int
#else
static int
#endif
sctp_setopt(struct socket *so, int optname, void *optval, size_t optsize,
	    void *p)
{
	int error, set_opt;
	uint32_t *mopt;
	struct sctp_tcb *stcb = NULL;
	struct sctp_inpcb *inp;
	uint32_t vrf_id;

#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(so);
#endif
	if (optval == NULL) {
		printf("optval is NULL\n");
		return (EINVAL);
	}
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		printf("inp is NULL?\n");
		return EINVAL;
	}
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
	vrf_id = SCTP_DEFAULT_VRFID;
#else
	vrf_id = panda_get_vrf_from_call();
#endif

	error = 0;
	switch (optname) {
	case SCTP_NODELAY:
	case SCTP_AUTOCLOSE:
	case SCTP_AUTO_ASCONF:
	case SCTP_EXPLICIT_EOR:
	case SCTP_DISABLE_FRAGMENTS:
	case SCTP_USE_EXT_RCVINFO:
	case SCTP_I_WANT_MAPPED_V4_ADDR:
		/* copy in the option value */
		SCTP_CHECK_AND_CAST(mopt, optval, uint32_t, optsize);
		set_opt = 0;
		if (error)
			break;
		switch (optname) {
		case SCTP_DISABLE_FRAGMENTS:
			set_opt = SCTP_PCB_FLAGS_NO_FRAGMENT;
			break;
		case SCTP_AUTO_ASCONF:
			set_opt = SCTP_PCB_FLAGS_AUTO_ASCONF;
			break;
		case SCTP_EXPLICIT_EOR:
			set_opt = SCTP_PCB_FLAGS_EXPLICIT_EOR;
			break;
		case SCTP_USE_EXT_RCVINFO:			
			set_opt = SCTP_PCB_FLAGS_EXT_RCVINFO;
			break;
		case SCTP_I_WANT_MAPPED_V4_ADDR:
			if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
				set_opt = SCTP_PCB_FLAGS_NEEDS_MAPPED_V4;
			} else {
				return (EINVAL);
			}
			break;
		case SCTP_NODELAY:
			set_opt = SCTP_PCB_FLAGS_NODELAY;
			break;
		case SCTP_AUTOCLOSE:
			set_opt = SCTP_PCB_FLAGS_AUTOCLOSE;
			/*
			 * The value is in ticks. Note this does not effect
			 * old associations, only new ones.
			 */
			inp->sctp_ep.auto_close_time = SEC_TO_TICKS(*mopt);
			break;
		}
		SCTP_INP_WLOCK(inp);
		if (*mopt != 0) {
			sctp_feature_on(inp, set_opt);
		} else {
			sctp_feature_off(inp, set_opt);
		}
		SCTP_INP_WUNLOCK(inp);
		break;
	case SCTP_PARTIAL_DELIVERY_POINT:
		{
			uint32_t *value;

			SCTP_CHECK_AND_CAST(value, optval, uint32_t, optsize);
			inp->partial_delivery_point = *value;
		}
		break;
	case SCTP_FRAGMENT_INTERLEAVE:
		/* not yet until we re-write sctp_recvmsg() */
		{
			uint32_t *on_off;

			SCTP_CHECK_AND_CAST(on_off, optval, uint32_t, optsize);
			if (*on_off) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_FRAG_INTERLEAVE);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_FRAG_INTERLEAVE);
			}
		}
		break;
	case SCTP_CMT_ON_OFF:
		{
			struct sctp_assoc_value *av;

			SCTP_CHECK_AND_CAST(av, optval, struct sctp_assoc_value, optsize);
			if (sctp_cmt_on_off) {
				SCTP_FIND_STCB(inp, stcb, av->assoc_id);
				if (stcb) {
					stcb->asoc.sctp_cmt_on_off = (uint8_t) av->assoc_value;
					SCTP_TCB_UNLOCK(stcb);
				} else {
					error = ENOTCONN;
				}
			} else {
				error = ENOPROTOOPT;
			}
		}
		break;
	case SCTP_CLR_STAT_LOG:
#ifdef SCTP_STAT_LOGGING
		sctp_clr_stat_log();
#else
		error = EOPNOTSUPP;
#endif
		break;
	case SCTP_CONTEXT:
		{
			struct sctp_assoc_value *av;

			SCTP_CHECK_AND_CAST(av, optval, struct sctp_assoc_value, optsize);
			SCTP_FIND_STCB(inp, stcb, av->assoc_id);

			if (stcb) {
				stcb->asoc.context = av->assoc_value;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_WLOCK(inp);
				inp->sctp_context = av->assoc_value;
				SCTP_INP_WUNLOCK(inp);
			}
		}
		break;
	case SCTP_DELAYED_ACK_TIME:
		{
			struct sctp_assoc_value *tm;

			SCTP_CHECK_AND_CAST(tm, optval, struct sctp_assoc_value, optsize);
			SCTP_FIND_STCB(inp, stcb, tm->assoc_id);

			if (stcb) {
				stcb->asoc.delayed_ack = tm->assoc_value;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_WLOCK(inp);
				inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_RECV] = MSEC_TO_TICKS(tm->assoc_value);
				SCTP_INP_WUNLOCK(inp);
			}
			break;
		}
	case SCTP_AUTH_CHUNK:
		{
			struct sctp_authchunk *sauth;

			SCTP_CHECK_AND_CAST(sauth, optval, struct sctp_authchunk, optsize);

			SCTP_INP_WLOCK(inp);
			if (sctp_auth_add_chunk(sauth->sauth_chunk, inp->sctp_ep.local_auth_chunks))
				error = EINVAL;
			SCTP_INP_WUNLOCK(inp);
			break;
		}
	case SCTP_AUTH_KEY:
		{
			struct sctp_authkey *sca;
			struct sctp_keyhead *shared_keys;
			sctp_sharedkey_t *shared_key;
			sctp_key_t *key = NULL;
			size_t size;

			SCTP_CHECK_AND_CAST(sca, optval, struct sctp_authkey, optsize);
			SCTP_FIND_STCB(inp, stcb, sca->sca_assoc_id)
			size = optsize - sizeof(*sca);

			if (stcb) {
				/* set it on the assoc */
				shared_keys = &stcb->asoc.shared_keys;
				/* clear the cached keys for this key id */
				sctp_clear_cachedkeys(stcb, sca->sca_keynumber);
				/*
				 * create the new shared key and
				 * insert/replace it
				 */
				if (size > 0) {
					key = sctp_set_key(sca->sca_key, (uint32_t) size);
					if (key == NULL) {
						error = ENOMEM;
						SCTP_TCB_UNLOCK(stcb);
						break;
					}
				}
				shared_key = sctp_alloc_sharedkey();
				if (shared_key == NULL) {
					sctp_free_key(key);
					error = ENOMEM;
					SCTP_TCB_UNLOCK(stcb);
					break;
				}
				shared_key->key = key;
				shared_key->keyid = sca->sca_keynumber;
				sctp_insert_sharedkey(shared_keys, shared_key);
				SCTP_TCB_UNLOCK(stcb);
			} else {
				/* set it on the endpoint */
				SCTP_INP_WLOCK(inp);
				shared_keys = &inp->sctp_ep.shared_keys;
				/*
				 * clear the cached keys on all assocs for
				 * this key id
				 */
				sctp_clear_cachedkeys_ep(inp, sca->sca_keynumber);
				/*
				 * create the new shared key and
				 * insert/replace it
				 */
				if (size > 0) {
					key = sctp_set_key(sca->sca_key, (uint32_t) size);
					if (key == NULL) {
						error = ENOMEM;
						SCTP_INP_WUNLOCK(inp);
						break;
					}
				}
				shared_key = sctp_alloc_sharedkey();
				if (shared_key == NULL) {
					sctp_free_key(key);
					error = ENOMEM;
					SCTP_INP_WUNLOCK(inp);
					break;
				}
				shared_key->key = key;
				shared_key->keyid = sca->sca_keynumber;
				sctp_insert_sharedkey(shared_keys, shared_key);
				SCTP_INP_WUNLOCK(inp);
			}
			break;
		}
	case SCTP_HMAC_IDENT:
		{
			struct sctp_hmacalgo *shmac;
			sctp_hmaclist_t *hmaclist;
			uint32_t hmacid;
			size_t size, i;

			SCTP_CHECK_AND_CAST(shmac, optval, struct sctp_hmacalgo, optsize);
			size = (optsize - sizeof(*shmac)) / sizeof(shmac->shmac_idents[0]);
			hmaclist = sctp_alloc_hmaclist(size);
			if (hmaclist == NULL) {
				error = ENOMEM;
				break;
			}
			for (i = 0; i < size; i++) {
				hmacid = shmac->shmac_idents[i];
				if (sctp_auth_add_hmacid(hmaclist, (uint16_t) hmacid)) {
					/* invalid HMACs were found */;
					error = EINVAL;
					sctp_free_hmaclist(hmaclist);
					goto sctp_set_hmac_done;
				}
			}
			/* set it on the endpoint */
			SCTP_INP_WLOCK(inp);
			if (inp->sctp_ep.local_hmacs)
				sctp_free_hmaclist(inp->sctp_ep.local_hmacs);
			inp->sctp_ep.local_hmacs = hmaclist;
			SCTP_INP_WUNLOCK(inp);
		sctp_set_hmac_done:
			break;
		}
	case SCTP_AUTH_ACTIVE_KEY:
		{
			struct sctp_authkeyid *scact;

			SCTP_CHECK_AND_CAST(scact, optval, struct sctp_authkeyid, optsize);
			SCTP_FIND_STCB(inp, stcb, scact->scact_assoc_id);

			/* set the active key on the right place */
			if (stcb) {
				/* set the active key on the assoc */
				if (sctp_auth_setactivekey(stcb, scact->scact_keynumber))
					error = EINVAL;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				/* set the active key on the endpoint */
				SCTP_INP_WLOCK(inp);
				if (sctp_auth_setactivekey_ep(inp, scact->scact_keynumber))
					error = EINVAL;
				SCTP_INP_WUNLOCK(inp);
			}
			break;
		}
	case SCTP_AUTH_DELETE_KEY:
		{
			struct sctp_authkeyid *scdel;

			SCTP_CHECK_AND_CAST(scdel, optval, struct sctp_authkeyid, optsize);
			SCTP_FIND_STCB(inp, stcb, scdel->scact_assoc_id);

			/* delete the key from the right place */
			if (stcb) {
				if (sctp_delete_sharedkey(stcb, scdel->scact_keynumber))
					error = EINVAL;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_WLOCK(inp);
				if (sctp_delete_sharedkey_ep(inp, scdel->scact_keynumber))
					error = EINVAL;
				SCTP_INP_WUNLOCK(inp);
			}
			break;
		}

	case SCTP_RESET_STREAMS:
		{
			struct sctp_stream_reset *strrst;
			uint8_t send_in = 0, send_tsn = 0, send_out = 0;
			int i;

			SCTP_CHECK_AND_CAST(strrst, optval, struct sctp_stream_reset, optsize);
			SCTP_FIND_STCB(inp, stcb, strrst->strrst_assoc_id);

			if (stcb == NULL) {
				error = ENOENT;
				break;
			}
			if (stcb->asoc.peer_supports_strreset == 0) {
				/*
				 * Peer does not support it, we return
				 * protocol not supported since this is true
				 * for this feature and this peer, not the
				 * socket request in general.
				 */
				error = EPROTONOSUPPORT;
				SCTP_TCB_UNLOCK(stcb);
				break;
			}
			if (stcb->asoc.stream_reset_outstanding) {
				error = EALREADY;
				SCTP_TCB_UNLOCK(stcb);
				break;
			}
			if (strrst->strrst_flags == SCTP_RESET_LOCAL_RECV) {
				send_in = 1;
			} else if (strrst->strrst_flags == SCTP_RESET_LOCAL_SEND) {
				send_out = 1;
			} else if (strrst->strrst_flags == SCTP_RESET_BOTH) {
				send_in = 1;
				send_out = 1;
			} else if (strrst->strrst_flags == SCTP_RESET_TSN) {
				send_tsn = 1;
			} else {
				error = EINVAL;
				SCTP_TCB_UNLOCK(stcb);
				break;
			}
			for (i = 0; i < strrst->strrst_num_streams; i++) {
				if ((send_in) &&

				    (strrst->strrst_list[i] > stcb->asoc.streamincnt)) {
					error = EINVAL;
					goto get_out;
				}
				if ((send_out) &&
				    (strrst->strrst_list[i] > stcb->asoc.streamoutcnt)) {
					error = EINVAL;
					goto get_out;
				}
			}
			if (error) {
		get_out:
				SCTP_TCB_UNLOCK(stcb);
				break;
			}
			error = sctp_send_str_reset_req(stcb, strrst->strrst_num_streams,
			    strrst->strrst_list,
			    send_out, (stcb->asoc.str_reset_seq_in - 3),
			    send_in, send_tsn);

#if defined(__NetBSD__) || defined(__OpenBSD__)
			s = splsoftnet();
#endif
			sctp_chunk_output(inp, stcb, SCTP_OUTPUT_FROM_STRRST_REQ);
			SCTP_TCB_UNLOCK(stcb);
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
		}
		break;

	case SCTP_CONNECT_X:
		if (optsize < (sizeof(int) + sizeof(struct sockaddr_in))) {
			error = EINVAL;
			break;
		}
		error = sctp_do_connect_x(so, inp, optval, optsize, p, 0);
		break;

	case SCTP_CONNECT_X_DELAYED:
		if (optsize < (sizeof(int) + sizeof(struct sockaddr_in))) {
			error = EINVAL;
			break;
		}
		error = sctp_do_connect_x(so, inp, optval, optsize, p, 1);
		break;

	case SCTP_CONNECT_X_COMPLETE:
		{
			struct sockaddr *sa;
			struct sctp_nets *net;

			/* FIXME MT: check correct? */
			SCTP_CHECK_AND_CAST(sa, optval, struct sockaddr, optsize);

			/* find tcb */
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
				SCTP_INP_RLOCK(inp);
				stcb = LIST_FIRST(&inp->sctp_asoc_list);
				if (stcb) {
					SCTP_TCB_LOCK(stcb);
					net = sctp_findnet(stcb, sa);
				}
				SCTP_INP_RUNLOCK(inp);
			} else {
				/* We increment here since sctp_findassociation_ep_addr() wil
				 * do a decrement if it finds the stcb as long as the locked
				 * tcb (last argument) is NOT a TCB.. aka NULL.
				 */
				SCTP_INP_INCR_REF(inp);
				stcb = sctp_findassociation_ep_addr(&inp, sa, &net, NULL, NULL);
				if (stcb == NULL) {
					SCTP_INP_DECR_REF(inp);
				}
			}

			if (stcb == NULL) {
				error = ENOENT;
				break;
			}
			if (stcb->asoc.delayed_connection == 1) {
				stcb->asoc.delayed_connection = 0;
				SCTP_GETTIME_TIMEVAL(&stcb->asoc.time_entered);
				sctp_timer_stop(SCTP_TIMER_TYPE_INIT, inp, stcb, 
						stcb->asoc.primary_destination,
						SCTP_FROM_SCTP_USRREQ+SCTP_LOC_9);
				sctp_send_initiate(inp, stcb);
			} else {
				/*
				 * already expired or did not use delayed
				 * connectx
				 */
				error = EALREADY;
			}
			SCTP_TCB_UNLOCK(stcb);
		}
		break;
	case SCTP_MAXBURST:
		{
			uint8_t *burst;

			SCTP_CHECK_AND_CAST(burst, optval, uint8_t, optsize);

			SCTP_INP_WLOCK(inp);
			if (*burst) {
				inp->sctp_ep.max_burst = *burst;
			}
			SCTP_INP_WUNLOCK(inp);
		}
		break;
	case SCTP_MAXSEG:
		{
			struct sctp_assoc_value *av;
			int ovh;

			SCTP_CHECK_AND_CAST(av, optval, struct sctp_assoc_value, optsize);
			SCTP_FIND_STCB(inp, stcb, av->assoc_id);

			if (stcb) {
				error = EINVAL;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_WLOCK(inp);
				if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
					ovh = SCTP_MED_OVERHEAD;
				} else {
					ovh = SCTP_MED_V4_OVERHEAD;
				}
				/* FIXME MT: I think this is not in tune with the API ID */
				if (av->assoc_value) {
					inp->sctp_frag_point = (av->assoc_value + ovh);
				} else {
					error = EINVAL;
				}
				SCTP_INP_WUNLOCK(inp);
			}
		}
		break;
	case SCTP_EVENTS:
		{
			struct sctp_event_subscribe *events;

			SCTP_CHECK_AND_CAST(events, optval, struct sctp_event_subscribe, optsize);

			SCTP_INP_WLOCK(inp);
			if (events->sctp_data_io_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_RECVDATAIOEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_RECVDATAIOEVNT);
			}

			if (events->sctp_association_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_RECVASSOCEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_RECVASSOCEVNT);
			}

			if (events->sctp_address_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_RECVPADDREVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_RECVPADDREVNT);
			}

			if (events->sctp_send_failure_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_RECVSENDFAILEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_RECVSENDFAILEVNT);
			}

			if (events->sctp_peer_error_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_RECVPEERERR);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_RECVPEERERR);
			}

			if (events->sctp_shutdown_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT);
			}

			if (events->sctp_partial_delivery_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_PDAPIEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_PDAPIEVNT);
			}

			if (events->sctp_adaptation_layer_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_ADAPTATIONEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_ADAPTATIONEVNT);
			}

			if (events->sctp_authentication_event) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_AUTHEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_AUTHEVNT);
			}

			if (events->sctp_stream_reset_events) {
				sctp_feature_on(inp, SCTP_PCB_FLAGS_STREAM_RESETEVNT);
			} else {
				sctp_feature_off(inp, SCTP_PCB_FLAGS_STREAM_RESETEVNT);
			}
			SCTP_INP_WUNLOCK(inp);
		}
		break;

	case SCTP_ADAPTATION_LAYER:
		{
			struct sctp_setadaptation *adap_bits;
			
			SCTP_CHECK_AND_CAST(adap_bits, optval, struct sctp_setadaptation, optsize);
			SCTP_INP_WLOCK(inp);
			inp->sctp_ep.adaptation_layer_indicator = adap_bits->ssb_adaptation_ind;
			SCTP_INP_WUNLOCK(inp);
		}
		break;
#ifdef SCTP_DEBUG 
	case SCTP_SET_INITIAL_DBG_SEQ:
		{
			uint32_t *vvv;

			SCTP_CHECK_AND_CAST(vvv, optval, uint32_t, optsize);
			SCTP_INP_WLOCK(inp);
			inp->sctp_ep.initial_sequence_debug = *vvv;
			SCTP_INP_WUNLOCK(inp);
		}
		break;
#endif
	case SCTP_DEFAULT_SEND_PARAM:
	{
			struct sctp_sndrcvinfo *s_info;

			SCTP_CHECK_AND_CAST(s_info, optval, struct sctp_sndrcvinfo, optsize);
			SCTP_FIND_STCB(inp, stcb, s_info->sinfo_assoc_id);

			if (stcb) {
				if (s_info->sinfo_stream <= stcb->asoc.streamoutcnt) {
					stcb->asoc.def_send = *s_info;
				} else {
					error = EINVAL;
				}
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_WLOCK(inp);
				inp->def_send = *s_info;
				SCTP_INP_WUNLOCK(inp);
			}
		}
		break;
	case SCTP_PEER_ADDR_PARAMS:
		/* Applys to the specific association */
		{
			struct sctp_paddrparams *paddrp;
			struct sctp_nets *net;

			SCTP_CHECK_AND_CAST(paddrp, optval, struct sctp_paddrparams, optsize);
			SCTP_FIND_STCB(inp, stcb, paddrp->spp_assoc_id);
			net = NULL;
			if (stcb) {
				net = sctp_findnet(stcb, (struct sockaddr *)&paddrp->spp_address);
			} else {
				/* We increment here since sctp_findassociation_ep_addr() wil
				 * do a decrement if it finds the stcb as long as the locked
				 * tcb (last argument) is NOT a TCB.. aka NULL.
				 */
				SCTP_INP_INCR_REF(inp);
				stcb = sctp_findassociation_ep_addr(&inp,
				                                    (struct sockaddr *)&paddrp->spp_address,
				                                    &net, NULL, NULL);
				if (stcb == NULL) {
					SCTP_INP_DECR_REF(inp);
				}
			}


			if (stcb) {
				/************************TCB SPECIFIC SET ******************/
				/*
				 * do we change the timer for HB, we run
				 * only one?
				 */
				if (paddrp->spp_hbinterval)
					stcb->asoc.heart_beat_delay = paddrp->spp_hbinterval;
				else if (paddrp->spp_flags & SPP_HB_TIME_IS_ZERO)
					stcb->asoc.heart_beat_delay = 0;

				/* network sets ? */
				if (net) {
					/************************NET SPECIFIC SET ******************/
					if (paddrp->spp_flags & SPP_HB_DEMAND) {
						/* on demand HB */
						sctp_send_hb(stcb, 1, net);
					}
					if (paddrp->spp_flags & SPP_HB_DISABLE) {
						net->dest_state |= SCTP_ADDR_NOHB;
					}
					if (paddrp->spp_flags & SPP_HB_ENABLE) {
						net->dest_state &= ~SCTP_ADDR_NOHB;
					}
					if (paddrp->spp_flags & SPP_PMTUD_DISABLE) {
						if (SCTP_OS_TIMER_PENDING(&net->pmtu_timer.timer)) {
							sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, net,
SCTP_FROM_SCTP_USRREQ+SCTP_LOC_10);
						}
						if (paddrp->spp_pathmtu > SCTP_DEFAULT_MINSEGMENT) {
							net->mtu = paddrp->spp_pathmtu;
							if (net->mtu < stcb->asoc.smallest_mtu)
								sctp_pathmtu_adustment(inp, stcb, net, net->mtu);
						}
					}
					if (paddrp->spp_flags & SPP_PMTUD_ENABLE) {
						if (SCTP_OS_TIMER_PENDING(&net->pmtu_timer.timer)) {
							sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, net);
						}
					}
					if (paddrp->spp_pathmaxrxt)
						net->failure_threshold = paddrp->spp_pathmaxrxt;
#ifdef INET
					if (paddrp->spp_flags & SPP_IPV4_TOS) {
						if (net->ro._l_addr.sin.sin_family == AF_INET) {
							net->tos_flowlabel = paddrp->spp_ipv4_tos & 0x000000fc;
						}
					}
#endif
#ifdef INET6
					if (paddrp->spp_flags & SPP_IPV6_FLOWLABEL) {
						if (net->ro._l_addr.sin6.sin6_family == AF_INET6) {
							net->tos_flowlabel = paddrp->spp_ipv6_flowlabel;
						}
					}
#endif
				} else {
					/************************ASSOC ONLY -- NO NET SPECIFIC SET ******************/
					if (paddrp->spp_pathmaxrxt)
						stcb->asoc.def_net_failure = paddrp->spp_pathmaxrxt;

					if (paddrp->spp_flags & SPP_HB_ENABLE) {
						/* Turn back on the timer */
						stcb->asoc.hb_is_disabled = 0;
						sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, net);
					}
					if (paddrp->spp_flags & SPP_HB_DISABLE) {
						int cnt_of_unconf = 0;
						struct sctp_nets *lnet;

						stcb->asoc.hb_is_disabled = 1;
						TAILQ_FOREACH(lnet, &stcb->asoc.nets, sctp_next) {
							if (lnet->dest_state & SCTP_ADDR_UNCONFIRMED) {
								cnt_of_unconf++;
							}
						}
						/*
						 * stop the timer ONLY if we
						 * have no unconfirmed
						 * addresses
						 */
						if (cnt_of_unconf == 0) {
							sctp_timer_stop(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, net, SCTP_FROM_SCTP_USRREQ+SCTP_LOC_11);
						}
					}
					if (paddrp->spp_flags & SPP_HB_ENABLE) {
						/* start up the timer. */
						sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, net);
					}
#ifdef INET
					if (paddrp->spp_flags & SPP_IPV4_TOS)
						stcb->asoc.default_tos = paddrp->spp_ipv4_tos & 0x000000fc;
#endif
#ifdef INET6
					if (paddrp->spp_flags & SPP_IPV6_FLOWLABEL)
						stcb->asoc.default_flowlabel = paddrp->spp_ipv6_flowlabel;
#endif

				}
				SCTP_TCB_UNLOCK(stcb);
			} else {
				/************************NO TCB, SET TO default stuff ******************/
				SCTP_INP_WLOCK(inp);
				/*
				 * For the TOS/FLOWLABEL stuff you set it
				 * with the options on the socket
				 */
				if (paddrp->spp_pathmaxrxt) {
					inp->sctp_ep.def_net_failure = paddrp->spp_pathmaxrxt;
				}
				if (paddrp->spp_flags & SPP_HB_ENABLE) {
					inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_HEARTBEAT] = MSEC_TO_TICKS(paddrp->spp_hbinterval);
					sctp_feature_off(inp, SCTP_PCB_FLAGS_DONOT_HEARTBEAT);
				} else if (paddrp->spp_flags & SPP_HB_DISABLE) {
					sctp_feature_on(inp, SCTP_PCB_FLAGS_DONOT_HEARTBEAT);
				}
				SCTP_INP_WUNLOCK(inp);
			}
		}
		break;
	case SCTP_RTOINFO:
		{
			struct sctp_rtoinfo *srto;

			SCTP_CHECK_AND_CAST(srto, optval, struct sctp_rtoinfo, optsize);
			SCTP_FIND_STCB(inp, stcb, srto->srto_assoc_id);

			if (stcb) {
				/* Set in ms we hope :-) */
				if (srto->srto_initial)
					stcb->asoc.initial_rto = srto->srto_initial;
				if (srto->srto_max)
					stcb->asoc.maxrto = srto->srto_max;
				if (srto->srto_min)
					stcb->asoc.minrto = srto->srto_min;
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_WLOCK(inp);
				/*
				 * If we have a null asoc, its default for
				 * the endpoint
				 */
				if (srto->srto_initial)
					inp->sctp_ep.initial_rto = srto->srto_initial;
				if (srto->srto_max)
					inp->sctp_ep.sctp_maxrto = srto->srto_max;
				if (srto->srto_min)
					inp->sctp_ep.sctp_minrto = srto->srto_min;
				SCTP_INP_WUNLOCK(inp);
			}
		}
		break;
	case SCTP_ASSOCINFO:
		{
			struct sctp_assocparams *sasoc;

			SCTP_CHECK_AND_CAST(sasoc, optval, struct sctp_assocparams, optsize);
			SCTP_FIND_STCB(inp, stcb, sasoc->sasoc_assoc_id);

			if (stcb) {
				if (sasoc->sasoc_asocmaxrxt)
					stcb->asoc.max_send_times = sasoc->sasoc_asocmaxrxt;
				sasoc->sasoc_number_peer_destinations = stcb->asoc.numnets;
				sasoc->sasoc_peer_rwnd = 0;
				sasoc->sasoc_local_rwnd = 0;
				if (stcb->asoc.cookie_life)
					stcb->asoc.cookie_life = sasoc->sasoc_cookie_life;
				stcb->asoc.delayed_ack = sasoc->sasoc_sack_delay;
				if(sasoc->sasoc_sack_freq) {
					stcb->asoc.sack_freq = sasoc->sasoc_sack_freq;
				}
				SCTP_TCB_UNLOCK(stcb);
			} else {
				SCTP_INP_WLOCK(inp);
				if (sasoc->sasoc_asocmaxrxt)
					inp->sctp_ep.max_send_times = sasoc->sasoc_asocmaxrxt;
				sasoc->sasoc_number_peer_destinations = 0;
				sasoc->sasoc_peer_rwnd = 0;
				sasoc->sasoc_local_rwnd = 0;
				if (sasoc->sasoc_cookie_life)
					inp->sctp_ep.def_cookie_life = sasoc->sasoc_cookie_life;
				inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_RECV] = MSEC_TO_TICKS(sasoc->sasoc_sack_delay);
				if(sasoc->sasoc_sack_freq) {
					inp->sctp_ep.sctp_sack_freq = sasoc->sasoc_sack_freq;
				}
				SCTP_INP_WUNLOCK(inp);
			}
		}
		break;
	case SCTP_INITMSG:
		{
			struct sctp_initmsg *sinit;

			SCTP_CHECK_AND_CAST(sinit, optval, struct sctp_initmsg, optsize);
			SCTP_INP_WLOCK(inp);
			if (sinit->sinit_num_ostreams)
				inp->sctp_ep.pre_open_stream_count = sinit->sinit_num_ostreams;

			if (sinit->sinit_max_instreams)
				inp->sctp_ep.max_open_streams_intome = sinit->sinit_max_instreams;

			if (sinit->sinit_max_attempts)
				inp->sctp_ep.max_init_times = sinit->sinit_max_attempts;

			if (sinit->sinit_max_init_timeo)
				inp->sctp_ep.initial_init_rto_max = sinit->sinit_max_init_timeo;
			SCTP_INP_WUNLOCK(inp);
		}
		break;
	case SCTP_PRIMARY_ADDR:
		{
			struct sctp_setprim *spa;
			struct sctp_nets *net, *lnet;

			SCTP_CHECK_AND_CAST(spa, optval, struct sctp_setprim, optsize);
			SCTP_FIND_STCB(inp, stcb, spa->ssp_assoc_id);
	
			net = NULL;
			if (stcb) {
				net = sctp_findnet(stcb, (struct sockaddr *)&spa->ssp_addr);
			} else {
				/* We increment here since sctp_findassociation_ep_addr() wil
				 * do a decrement if it finds the stcb as long as the locked
				 * tcb (last argument) is NOT a TCB.. aka NULL.
				 */
				SCTP_INP_INCR_REF(inp);
				stcb = sctp_findassociation_ep_addr(&inp,
				                                    (struct sockaddr *)&spa->ssp_addr,
				                                    &net, NULL, NULL);
				if (stcb == NULL) {
					SCTP_INP_DECR_REF(inp);
				}
			}
			
			if ((stcb) && (net)) {
				if ((net != stcb->asoc.primary_destination) &&
				    (!(net->dest_state & SCTP_ADDR_UNCONFIRMED))) {
					/* Ok we need to set it */
					lnet = stcb->asoc.primary_destination;
					if (sctp_set_primary_addr(stcb, (struct sockaddr *)NULL, net) == 0) {
						if (net->dest_state & SCTP_ADDR_SWITCH_PRIMARY) {
							net->dest_state |= SCTP_ADDR_DOUBLE_SWITCH;
						}
						net->dest_state |= SCTP_ADDR_SWITCH_PRIMARY;
					}
				}
			} else {
				error = EINVAL;
			}
			if (stcb) {
				SCTP_TCB_UNLOCK(stcb);
			}
		}
		break;
	case SCTP_SET_DYNAMIC_PRIMARY:
	{
		union sctp_sockstore *ss;
#if defined(__NetBSD__) || defined(__APPLE__)
		struct proc *proc;
#endif
#ifdef __FreeBSD__
#if __FreeBSD_version > 602000
		error = priv_check(curthread, PRIV_NETINET_RESERVEDPORT);
#elif __FreeBSD_version >= 500000
		error = suser((struct thread *)p);
#else
		error = suser(p);
#endif
#elif defined(__NetBSD__) || defined(__APPLE__)
		proc = (struct proc *)p;
		if (p) {
			error = suser(proc->p_ucred, &proc->p_acflag);
		} else {
			break;
		}
#else
		error = suser(p, 0);
#endif
		if(error) 
			break;

		SCTP_CHECK_AND_CAST(ss, optval, union sctp_sockstore, optsize);
		/* SUPER USER CHECK? */
		error = sctp_dynamic_set_primary(&ss->sa, vrf_id);
	}
	break;
	case SCTP_SET_PEER_PRIMARY_ADDR:
		{
			struct sctp_setpeerprim *sspp;

			SCTP_CHECK_AND_CAST(sspp, optval, struct sctp_setpeerprim, optsize);
			SCTP_FIND_STCB(inp, stcb, sspp->sspp_assoc_id);

			if (stcb) {
				if (sctp_set_primary_ip_address_sa(stcb, (struct sockaddr *)&sspp->sspp_addr) != 0) {
					error = EINVAL;
				}
			} else {
				error = EINVAL;
			}
			SCTP_TCB_UNLOCK(stcb);
		}
		break;
	case SCTP_BINDX_ADD_ADDR:
		{
			struct sctp_getaddresses *addrs;
			struct sockaddr *addr_touse;
			struct sockaddr_in sin;

			SCTP_CHECK_AND_CAST(addrs, optval, struct sctp_getaddresses, optsize);

			/* see if we're bound all already! */
			if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
				error = EINVAL;
				break;
			}
			addr_touse = addrs->addr;
			if (addrs->addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin6;

				sin6 = (struct sockaddr_in6 *)addr_touse;
				if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
					in6_sin6_2_sin(&sin, sin6);
					addr_touse = (struct sockaddr *)&sin;
				}
			}
			if (inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) {
				if (p == NULL) {
					/* Can't get proc for Net/Open BSD */
					error = EINVAL;
					break;
				}
				error = sctp_inpcb_bind(so, addr_touse, p);
				break;
			}
			/*
			 * No locks required here since bind and mgmt_ep_sa
			 * all do their own locking. If we do something for
			 * the FIX: below we may need to lock in that case.
			 */
			if (addrs->sget_assoc_id == 0) {
				/* add the address */
				struct sctp_inpcb *lep;

				((struct sockaddr_in *)addr_touse)->sin_port = inp->sctp_lport;
#if defined(SCTP_PER_SOCKET_LOCKING)
				SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 0);
#endif
				lep = sctp_pcb_findep(addr_touse, 1, 0);
#if defined(SCTP_PER_SOCKET_LOCKING)
				SCTP_SOCKET_LOCK(SCTP_INP_SO(inp), 0);
#endif
				if (lep != NULL) {
					/*
					 * We must decrement the refcount
					 * since we have the ep already and
					 * are binding. No remove going on
					 * here.
					 */
					SCTP_INP_DECR_REF(inp);
				}
				if (lep == inp) {
					/* already bound to it.. ok */
					break;
				} else if (lep == NULL) {
					((struct sockaddr_in *)addr_touse)->sin_port = 0;
					error = sctp_addr_mgmt_ep_sa(inp, addr_touse,
					    SCTP_ADD_IP_ADDRESS, vrf_id);
				} else {
					error = EADDRNOTAVAIL;
				}
				if (error)
					break;

			} else {
				/*
				 * FIX: decide whether we allow assoc based
				 * bindx
				 */
			}
		}
		break;
	case SCTP_BINDX_REM_ADDR:
		{
			struct sctp_getaddresses *addrs;
			struct sockaddr *addr_touse;
			struct sockaddr_in sin;

			SCTP_CHECK_AND_CAST(addrs, optval, struct sctp_getaddresses, optsize);
			/* see if we're bound all already! */
			if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
				error = EINVAL;
				break;
			}
			addr_touse = addrs->addr;
			if (addrs->addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin6;

				sin6 = (struct sockaddr_in6 *)addr_touse;
				if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
					in6_sin6_2_sin(&sin, sin6);
					addr_touse = (struct sockaddr *)&sin;
				}
			}
			/*
			 * No lock required mgmt_ep_sa does its own locking.
			 * If the FIX: below is ever changed we may need to
			 * lock before calling association level binding.
			 */
			if (addrs->sget_assoc_id == 0) {
				/* delete the address */
				sctp_addr_mgmt_ep_sa(inp, addr_touse,
				    SCTP_DEL_IP_ADDRESS, vrf_id);
			} else {
				/*
				 * FIX: decide whether we allow assoc based
				 * bindx
				 */
			}
		}
		break;
#ifdef __APPLE__
	case SCTP_LISTEN_FIX:
		/* only applies to one-to-many sockets */
		if (inp->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) {
			/* make sure the ACCEPTCONN flag is OFF */
			so->so_options &= ~SO_ACCEPTCONN;
		} else {
			/* otherwise, not allowed */
			error = EINVAL;
		}
		break;
#endif				/* __APPLE__ */
	default:
		error = ENOPROTOOPT;
		break;
	} /* end switch (opt) */
	return (error);
}


#if defined(__FreeBSD__) || defined(__APPLE__)

extern int sctp_chatty_mbuf;

int
sctp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	void *optval = NULL;
	size_t optsize = 0;
	struct sctp_inpcb *inp;
	void *p;
	int error = 0;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		/* I made the same as TCP since we are not setup? */
		return (ECONNRESET);
	}
	if (sopt->sopt_level != IPPROTO_SCTP) {
		/* wrong proto level... send back up to IP */
#ifdef INET6
		if (INP_CHECK_SOCKAF(so, AF_INET6))
			error = ip6_ctloutput(so, sopt);
		else
#endif				/* INET6 */
			error = ip_ctloutput(so, sopt);
		return (error);
	}
	optsize = sopt->sopt_valsize;
	if (optsize) {
		SCTP_MALLOC(optval, void *, optsize, "SCTPSockOpt");
		if (optval == NULL) {
			return (ENOBUFS);
		}
		error = sooptcopyin(sopt, optval, optsize, optsize);
		if (error) {
			SCTP_FREE(optval);
			goto out;
		}
	}
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	p = (void *)sopt->sopt_td;
#else
	p = (void *)sopt->sopt_p;
#endif
	if (sopt->sopt_dir == SOPT_SET) {
		error = sctp_setopt(so, sopt->sopt_name, optval, optsize, p);
	} else if (sopt->sopt_dir == SOPT_GET) {
		error = sctp_getopt(so, sopt->sopt_name, optval, &optsize, p);
	} else {
		error = EINVAL;
	}
	if ((error == 0) && (optval != NULL)) {
		error = sooptcopyout(sopt, optval, optsize);
		SCTP_FREE(optval);
	} else if (optval != NULL) {
		SCTP_FREE(optval);
	}
out:
	return (error);
}

#else
/* NetBSD and OpenBSD */
int
sctp_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int error;
	struct inpcb *inp;

#ifdef INET6
	struct in6pcb *in6p;

#endif
	int family;		/* family of the socket */
	void *optval;
	size_t optsize;

	family = so->so_proto->pr_domain->dom_family;
	error = 0;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	switch (family) {
	case PF_INET:
		inp = sotoinpcb(so);
#ifdef INET6
		in6p = NULL;
#endif
		break;
#ifdef INET6
	case PF_INET6:
		inp = NULL;
		in6p = sotoin6pcb(so);
		break;
#endif
	default:
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return EAFNOSUPPORT;
	}
#ifndef INET6
	if (inp == NULL)
#else
	if (inp == NULL && in6p == NULL)
#endif
	{
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		if (op == PRCO_SETOPT && *mp)
			(void)sctp_m_free(*mp);
		return (ECONNRESET);
	}
	if (level != IPPROTO_SCTP) {
		switch (family) {
		case PF_INET:
			error = ip_ctloutput(op, so, level, optname, mp);
			break;
#ifdef INET6
		case PF_INET6:
			error = ip6_ctloutput(op, so, level, optname, mp);
			break;
#endif
		}
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (error);
	}
	/* Ok if we reach here it is a SCTP option we hope */
	optval = mtod(*mp, void *);
	optsize = SCTP_BUF_LEN(*mp);
	if (op == PRCO_SETOPT) {
		error = sctp_setopt(so, optname, optval, optsize,
				    (struct proc *)NULL);
		if (*mp)
			(void)sctp_m_free(*mp);
	} else if (op == PRCO_GETOPT) {
		error = sctp_getopt(so, optname, optval, optsize,
				    (struct proc *)NULL);
	} else {
		error = EINVAL;
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return (error);
}

#endif

static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_connect(struct socket *so, struct sockaddr *addr, struct thread *p)
{
#else
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp_connect(struct socket *so, struct sockaddr *addr, struct proc *p)
{
#else
sctp_connect(struct socket *so, struct mbuf *nam, struct proc *p)
{
	struct sockaddr *addr = mtod(nam, struct sockaddr *);

#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#endif
	int error = 0;
	int create_lock_on = 0;
	uint32_t vrf_id;
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb=NULL;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		/* I made the same as TCP since we are not setup? */
		return (ECONNRESET);
	}
	SCTP_ASOC_CREATE_LOCK(inp);
	create_lock_on = 1;

	SCTP_INP_INCR_REF(inp);
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_SOCKET_ALLGONE) ||
	    (inp->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)) {
		/* Should I really unlock ? */
	        error = EFAULT;
		goto out_now;
	}
#ifdef INET6
	if (((inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) == 0) &&
	    (addr->sa_family == AF_INET6)) {
		error = EINVAL;
		goto out_now;
	}
#endif				/* INET6 */
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) ==
	    SCTP_PCB_FLAGS_UNBOUND) {
		/* Bind a ephemeral port */
		error = sctp_inpcb_bind(so, NULL, p);
		if (error) {
			goto out_now;
		}
	}
	/* Now do we connect? */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL) {
		error = EINVAL;
		goto out_now;
	}

	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
		error = EADDRINUSE;
		goto out_now;
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
		SCTP_INP_RLOCK(inp);
		stcb = LIST_FIRST(&inp->sctp_asoc_list);
		if (stcb)
			SCTP_TCB_UNLOCK(stcb);
		SCTP_INP_RUNLOCK(inp);
	} else {
		/* We increment here since sctp_findassociation_ep_addr() wil
		 * do a decrement if it finds the stcb as long as the locked
		 * tcb (last argument) is NOT a TCB.. aka NULL.
		 */
		SCTP_INP_INCR_REF(inp);
		stcb = sctp_findassociation_ep_addr(&inp, addr, NULL, NULL, NULL);
		if (stcb == NULL) {
			SCTP_INP_DECR_REF(inp);
		}
	}
	if (stcb != NULL) {
		/* Already have or am bring up an association */
		error = EALREADY;
		goto out_now;
	}
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
	vrf_id = SCTP_DEFAULT_VRFID;
#else
	vrf_id = panda_get_vrf_from_call(); /* from connect call? */
#endif
	/* We are GOOD to go */
	stcb = sctp_aloc_assoc(inp, addr, 1, &error, 0, vrf_id);
	if (stcb == NULL) {
		/* Gak! no memory */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		goto out_now;
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
 out_now:
	if (create_lock_on)
		SCTP_ASOC_CREATE_UNLOCK(inp);

	if (stcb)
		SCTP_TCB_UNLOCK(stcb);
	SCTP_INP_DECR_REF(inp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return error;
}

int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
#if __FreeBSD_version >= 700000
sctp_listen(struct socket *so, int backlog, struct thread *p)
#else
sctp_listen(struct socket *so, struct thread *p)
#endif
#else
sctp_listen(struct socket *so, struct proc *p)
#endif
{
	/*
	 * Note this module depends on the protocol processing being called
	 * AFTER any socket level flags and backlog are applied to the
	 * socket. The traditional way that the socket flags are applied is
	 * AFTER protocol processing. We have made a change to the
	 * sys/kern/uipc_socket.c module to reverse this but this MUST be in
	 * place if the socket API for SCTP is to work properly.
	 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#endif

	int error = 0;
	struct sctp_inpcb *inp;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		/* I made the same as TCP since we are not setup? */
		return (ECONNRESET);
	}
	SCTP_INP_RLOCK(inp);
#ifdef SCTP_LOCK_LOGGING
	sctp_log_lock(inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_SOCK);
#endif
	SOCK_LOCK(so);
#if defined(__FreeBSD__) && __FreeBSD_version > 500000
	error = solisten_proto_check(so);
	if (error) {
		SOCK_UNLOCK(so);
		return (error);
	}
#endif
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		SCTP_INP_RUNLOCK(inp);
		SOCK_UNLOCK(so);
		return (EADDRINUSE);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) {
		/* We must do a bind. */
		SOCK_UNLOCK(so);
		SCTP_INP_RUNLOCK(inp);
		if ((error = sctp_inpcb_bind(so, NULL, p))) {
			/* bind error, probably perm */
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (error);
		}
		SOCK_LOCK(so);
	} else {
		SCTP_INP_RUNLOCK(inp);
	}
#if defined(__FreeBSD__) && __FreeBSD_version > 500000
#if __FreeBSD_version >= 700000
	/* It appears for 7.0 and on, we must always call this. */
	solisten_proto(so, backlog);
#else
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) == 0) {
		solisten_proto(so);
	}
#endif
#endif

	if (inp->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) {
		/* remove the ACCEPTCONN flag for one-to-many sockets */
		so->so_options &= ~SO_ACCEPTCONN;
	}
#if __FreeBSD_version >= 700000
	if (backlog == 0) {
		/* turning off listen */
		so->so_options &= ~SO_ACCEPTCONN;
	}
#endif
	SOCK_UNLOCK(so);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return (error);
}

static int sctp_defered_wakeup_cnt = 0;

int
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp_accept(struct socket *so, struct sockaddr **addr)
{
#elif defined(__Panda__)
sctp_accept(struct socket *so, struct sockaddr *addr, int *namelen,
	    void *accept_info, int *accept_info_len)
{
#else
sctp_accept(struct socket *so, struct mbuf *nam)
{
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#endif
	struct sctp_tcb *stcb;
	struct sctp_inpcb *inp;
	union sctp_sockstore store;

#ifdef SCTP_KAME
	int error;
#endif /* SCTP_KAME */

	inp = (struct sctp_inpcb *)so->so_pcb;

	if (inp == 0) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		return (ECONNRESET);
	}
	SCTP_INP_RLOCK(inp);
	if (inp->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) {
		return (ENOTSUP);
	}
	if (so->so_state & SS_ISDISCONNECTED) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		SCTP_INP_RUNLOCK(inp);
		return (ECONNABORTED);
	}
	stcb = LIST_FIRST(&inp->sctp_asoc_list);
	if (stcb == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
		SCTP_INP_RUNLOCK(inp);
		return (ECONNRESET);
	}
	SCTP_TCB_LOCK(stcb);
	SCTP_INP_RUNLOCK(inp);
	store = stcb->asoc.primary_destination->ro._l_addr;
	SCTP_TCB_UNLOCK(stcb);
	if (store.sa.sa_family == AF_INET) {
		struct sockaddr_in *sin;

#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_MALLOC_SONAME(sin, struct sockaddr_in *, sizeof *sin);
#else
		sin = (struct sockaddr_in *)addr;
		bzero((caddr_t)sin, sizeof(*sin));
#endif
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_port = ((struct sockaddr_in *)&store)->sin_port;
		sin->sin_addr = ((struct sockaddr_in *)&store)->sin_addr;
#if defined(__FreeBSD__) || defined(__APPLE__)
		*addr = (struct sockaddr *)sin;
#else
		SCTP_BUF_LEN(nam) = sizeof(*sin);
#endif
	} else {
		struct sockaddr_in6 *sin6;

#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_MALLOC_SONAME(sin6, struct sockaddr_in6 *, sizeof *sin6);
#else
		sin6 = (struct sockaddr_in6 *)addr;
		bzero((caddr_t)sin6, sizeof(*sin6));
#endif
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_port = ((struct sockaddr_in6 *)&store)->sin6_port;

		sin6->sin6_addr = ((struct sockaddr_in6 *)&store)->sin6_addr;
#if defined(SCTP_EMBEDDED_V6_SCOPE)
#ifdef SCTP_KAME
		if ((error = sa6_recoverscope(sin6)) != 0) {
			SCTP_FREE_SONAME(sin6);
			return (error);
		}
#else
		if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
			/*
			 * sin6->sin6_scope_id =
			 * ntohs(sin6->sin6_addr.s6_addr16[1]);
			 */
			in6_recoverscope(sin6, &sin6->sin6_addr, NULL);	/* skip ifp check */
		else
			sin6->sin6_scope_id = 0;	/* XXX */
#endif /* SCTP_KAME */
#endif /* SCTP_EMBEDDED_V6_SCOPE */
#if defined(__FreeBSD__) || defined (__APPLE__)
		*addr = (struct sockaddr *)sin6;
#else
		SCTP_BUF_LEN(nam) = sizeof(*sin6);
#endif
	}
	/* Wake any delayed sleep action */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) {
		SCTP_INP_WLOCK(inp);
		inp->sctp_flags &= ~SCTP_PCB_FLAGS_DONT_WAKE;
		if (inp->sctp_flags & SCTP_PCB_FLAGS_WAKEOUTPUT) {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_WAKEOUTPUT;
			SCTP_INP_WUNLOCK(inp);
			SOCKBUF_LOCK(&inp->sctp_socket->so_snd);
			if (sowriteable(inp->sctp_socket)) {
#if defined(__FreeBSD__)
				sowwakeup_locked(inp->sctp_socket);
#else
				sowwakeup(inp->sctp_socket);
#endif
			} else {
				SOCKBUF_UNLOCK(&inp->sctp_socket->so_snd);
			}
			SCTP_INP_WLOCK(inp);
		}
		if (inp->sctp_flags & SCTP_PCB_FLAGS_WAKEINPUT) {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_WAKEINPUT;
			SCTP_INP_WUNLOCK(inp);
			SOCKBUF_LOCK(&inp->sctp_socket->so_rcv);
			if (soreadable(inp->sctp_socket)) {
				sctp_defered_wakeup_cnt++;
#if defined(__FreeBSD__)
				sorwakeup_locked(inp->sctp_socket);
#else
				sorwakeup(inp->sctp_socket);
#endif
			} else {
				SOCKBUF_UNLOCK(&inp->sctp_socket->so_rcv);
			}
			SCTP_INP_WLOCK(inp);
		}
		SCTP_INP_WUNLOCK(inp);
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
	return (0);
}

int
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp_ingetaddr(struct socket *so, struct sockaddr **addr)
{
	struct sockaddr_in *sin;
#elif defined(__Panda__)
sctp_ingetaddr(struct socket *so, struct sockaddr *addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
#else
sctp_ingetaddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr_in *sin = mtod(nam, struct sockaddr_in *);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	uint32_t vrf_id;
	struct sctp_inpcb *inp;

	/*
	 * Do the malloc first in case it blocks.
	 */
#if defined(__FreeBSD__) || defined(__APPLE__)
	SCTP_MALLOC_SONAME(sin, struct sockaddr_in *, sizeof *sin);
#elif defined(__Panda__)
	bzero(sin, sizeof(*sin));
#else
	SCTP_BUF_LEN(nam)n = sizeof(*sin);
	memset(sin, 0, sizeof(*sin));
#endif
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (!inp) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin);
#endif
		return ECONNRESET;
	}
	SCTP_INP_RLOCK(inp);
	struct sctp_ifa *sctp_ifa;
	sin->sin_port = inp->sctp_lport;
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
			struct sctp_tcb *stcb;
			struct sockaddr_in *sin_a;
			struct sctp_nets *net;
			int fnd;

			stcb = LIST_FIRST(&inp->sctp_asoc_list);
			if (stcb == NULL) {
				goto notConn;
			}
			fnd = 0;
			sin_a = NULL;
			SCTP_TCB_LOCK(stcb);
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				sin_a = (struct sockaddr_in *)&net->ro._l_addr;
				if(sin_a == NULL)
					/* this will make coverity happy */
					continue;

				if (sin_a->sin_family == AF_INET) {
					fnd = 1;
					break;
				}
			}
			if ((!fnd) || (sin_a == NULL)) {
				/* punt */
				SCTP_TCB_UNLOCK(stcb);
				goto notConn;
			}
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
			vrf_id = SCTP_DEFAULT_VRFID;
#else
			vrf_id = panda_get_vrf_from_call(); /* from socket option call? */
#endif

			sctp_ifa = sctp_source_address_selection(inp,
								 stcb, 
								 (struct route *)&net->ro, 
								 net, 0, vrf_id);
			if(sctp_ifa) {
				sin->sin_addr = sctp_ifa->address.sin.sin_addr;
				sctp_free_ifa(sctp_ifa);
			}
			SCTP_TCB_UNLOCK(stcb);
		} else {
			/* For the bound all case you get back 0 */
	notConn:
			sin->sin_addr.s_addr = 0;
		}

	} else {
		/* Take the first IPv4 address in the list */
		struct sctp_laddr *laddr;
		int fnd = 0;

		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa->address.sa.sa_family == AF_INET) {
				struct sockaddr_in *sin_a;

				sin_a = (struct sockaddr_in *)&laddr->ifa->address.sa;
				sin->sin_addr = sin_a->sin_addr;
				fnd = 1;
				break;
			}
		}
		if (!fnd) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
			SCTP_FREE_SONAME(sin);
#endif
			SCTP_INP_RUNLOCK(inp);
			return ENOENT;
		}
	}
	SCTP_INP_RUNLOCK(inp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
	(*addr) = (struct sockaddr *)sin;
#endif
	return (0);
}

int
#if defined(__FreeBSD__) || defined(__APPLE__)
sctp_peeraddr(struct socket *so, struct sockaddr **addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)*addr;
#elif defined(__Panda__)
sctp_peeraddr(struct socket *so, struct sockaddr *addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
#else
sctp_peeraddr(struct socket *so, struct mbuf *nam)
{
	struct sockaddr_in *sin = mtod(nam, struct sockaddr_in *);

#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	int fnd;
	struct sockaddr_in *sin_a;
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb;
	struct sctp_nets *net;

	/* Do the malloc first in case it blocks. */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if ((inp == NULL) ||
	    ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0)) {
		/* UDP type and listeners will drop out here */
		return (ENOTCONN);
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
	SCTP_MALLOC_SONAME(sin, struct sockaddr_in *, sizeof *sin);
#elif defined(__Panda__)
	memset(sin, 0, sizeof(*sin));
#else
	SCTP_BUF_LEN(nam) = sizeof(*sin);
	memset(sin, 0, sizeof(*sin));
#endif
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);

	/* We must recapture incase we blocked */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (!inp) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin);
#endif
		return ECONNRESET;
	}
	SCTP_INP_RLOCK(inp);
	stcb = LIST_FIRST(&inp->sctp_asoc_list);
	if (stcb)
		SCTP_TCB_LOCK(stcb);
	SCTP_INP_RUNLOCK(inp);
	if (stcb == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin);
#endif
		return ECONNRESET;
	}
	fnd = 0;
	TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
		sin_a = (struct sockaddr_in *)&net->ro._l_addr;
		if (sin_a->sin_family == AF_INET) {
			fnd = 1;
			sin->sin_port = stcb->rport;
			sin->sin_addr = sin_a->sin_addr;
			break;
		}
	}
	SCTP_TCB_UNLOCK(stcb);
	if (!fnd) {
		/* No IPv4 address */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		splx(s);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
		SCTP_FREE_SONAME(sin);
#endif
		return ENOENT;
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	splx(s);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
	(*addr) = (struct sockaddr *)sin;
#endif
	return (0);
}

#if defined(__FreeBSD__) || defined(__APPLE__)
struct pr_usrreqs sctp_usrreqs = {
#if __FreeBSD_version >= 600000
	.pru_abort = sctp_abort,
	.pru_accept = sctp_accept,
	.pru_attach = sctp_attach,
	.pru_bind = sctp_bind,
	.pru_connect = sctp_connect,
	.pru_control = in_control,
#if __FreeBSD_version >= 690000
	.pru_close = sctp_close,
	.pru_detach = sctp_close,
	.pru_sopoll = sopoll_generic,
#else
	.pru_detach = sctp_detach,
	.pru_sopoll = sopoll,
#endif
	.pru_disconnect = sctp_disconnect,
	.pru_listen = sctp_listen,
	.pru_peeraddr = sctp_peeraddr,
	.pru_send = sctp_sendm,
	.pru_shutdown = sctp_shutdown,
	.pru_sockaddr = sctp_ingetaddr,
	.pru_sosend = sctp_sosend,
	.pru_soreceive = sctp_soreceive
#else
	sctp_abort,
	sctp_accept,
	sctp_attach,
	sctp_bind,
	sctp_connect,
	pru_connect2_notsupp,
	in_control,
	sctp_detach,
	sctp_disconnect,
	sctp_listen,
	sctp_peeraddr,
	NULL,
	pru_rcvoob_notsupp,
	sctp_sendm,
	pru_sense_null,
	sctp_shutdown,
	sctp_ingetaddr,
	sctp_sosend,
	sctp_soreceive,
	sopoll
#endif
};

#else
#if defined(__NetBSD__)
int
sctp_usrreq(so, req, m, nam, control, p)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
	struct proc *p;
{
#else
int
sctp_usrreq(so, req, m, nam, control)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
{
	struct proc *p = curproc;
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s;
#endif
	uint32_t vrf_id;
	struct sctp_vrf *vrf;
	int error;
	int family;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#endif

	error = 0;
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
			break;
#ifdef INET6
		case PF_INET6:
			error = in6_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control, p);
			break;
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
		vrf_id = SCTP_DEFAULT_VRFID;
#else
		vrf_id = panda_get_vrf_from_call(); /* from socket option call? */
#endif
		vrf = sctp_find_vrf(vrf_id);
		if(vrf == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (EINVAL);
			
		}
		sctp_ifn = sctp_find_ifn(vrf_id, ifn, ifn->if_index);
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
#endif				/* INET6 */
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
		error = sctp_attach(so, family, p);
		break;
	case PRU_DETACH:
		error = sctp_detach(so);
		break;
	case PRU_BIND:
		if (nam == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (EINVAL);
		}
		error = sctp_bind(so, nam, p);
		break;
	case PRU_LISTEN:
		error = sctp_listen(so, p);
		break;
	case PRU_CONNECT:
		if (nam == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (EINVAL);
		}
		error = sctp_connect(so, nam, p);
		break;
	case PRU_DISCONNECT:
		error = sctp_disconnect(so);
		break;
	case PRU_ACCEPT:
		if (nam == NULL) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
			splx(s);
#endif
			return (EINVAL);
		}
		error = sctp_accept(so, nam);
		break;
	case PRU_SHUTDOWN:
		error = sctp_shutdown(so);
		break;

	case PRU_RCVD:
		/*
		 * For Open and Net BSD, this is real ugly. The mbuf *nam
		 * that is passed (by soreceive()) is the int flags c ast as
		 * a (mbuf *) yuck!
		 */
		break;

	case PRU_SEND:
		/* Flags are ignored */
		{
			struct sockaddr *addr;

			if (nam == NULL)
				addr = NULL;
			else
				addr = mtod(nam, struct sockaddr *);

			error = sctp_sendm(so, 0, m, addr, control, p);
		}
		break;
	case PRU_ABORT:
		error = sctp_abort(so);
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
		error = sctp_peeraddr(so, nam);
		break;
	case PRU_SOCKADDR:
		error = sctp_ingetaddr(so, nam);
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

#if __OpenBSD__
/*
 * Sysctl for sctp variables.
 */
int
sctp_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	uint32_t namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{

	/* All sysctl names at this level are terminal. */
	if (namelen != 1)
		return (ENOTDIR);
	/* ?? whats this ?? sysctl_int(); */

	switch (name[0]) {
	case SCTPCTL_MAXDGRAM:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_sendspace));
	case SCTPCTL_RECVSPACE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_recvspace));
	case SCTPCTL_AUTOASCONF:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_auto_asconf));
	case SCTPCTL_ECN_ENABLE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_ecn_enable));
	case SCTPCTL_ECN_NONCE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_ecn_nonce));
	case SCTPCTL_STRICT_SACK:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_strict_sacks));
	case SCTPCTL_NOCSUM_LO:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_no_csum_on_loopback));
	case SCTPCTL_STRICT_INIT:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_strict_init));
	case SCTPCTL_PEER_CHK_OH:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_peer_chunk_oh));
	case SCTPCTL_MAXBURST:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_max_burst_default));
	case SCTPCTL_MAXCHUNKONQ:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_max_chunks_on_queue));

	case SCTPCTL_TCBHASHSIZE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_hashtblsize));
	case SCTPCTL_PCBHASHSIZE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_pcbtblsize));
	case SCTPCTL_MINSPLIT:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_min_split_point));
	case SCTPCTL_CHUNKSCALE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_chunkscale));
	case SCTPCTL_ASOC_RESC:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_asoc_free_resc_limit));
	case SCTPCTL_SYS_RESC:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_system_free_resc_limit));
	case SCTPCTL_DELAYED_SACK:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_delayed_sack_time_default));
	case SCTPCTL_SACK_FREQ:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_sack_freq_default));
	case SCTPCTL_HB_INTERVAL:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_heartbeat_interval_default));
	case SCTPCTL_PMTU_RAISE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_pmtu_raise_time_default));
	case SCTPCTL_SHUTDOWN_GUARD:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_shutdown_guard_time_default));
	case SCTPCTL_SECRET_LIFETIME:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_secret_lifetime_default));
	case SCTPCTL_RTO_MAX:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_rto_max_default));
	case SCTPCTL_RTO_MIN:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_rto_min_default));
	case SCTPCTL_RTO_INITIAL:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_rto_initial_default));
	case SCTPCTL_INIT_RTO_MAX:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_init_rto_max_default));
	case SCTPCTL_COOKIE_LIFE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_valid_cookie_life_default));
	case SCTPCTL_INIT_RTX_MAX:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_init_rtx_max_default));
	case SCTPCTL_ASSOC_RTX_MAX:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_assoc_rtx_max_default));
	case SCTPCTL_PATH_RTX_MAX:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_path_rtx_max_default));
	case SCTPCTL_ADD_MORE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_add_more_threshold));
	case SCTPCTL_NR_OUTGOING_STREAMS:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_nr_outgoing_streams_default));
	case SCTPCTL_CMT_ON_OFF:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_cmt_on_off));
	case SCTPCTL_CWND_MAXBURST:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_use_cwnd_based_maxburst));
	case SCTPCTL_EARLY_FR:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_early_fr));
	case SCTPCTL_RTTVAR_CC:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_use_rttvar_cc));
	case SCTPCTL_DEADLOCK_DET:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_says_check_for_deadlock));
	case SCTPCTL_EARLY_FR_MSEC:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_early_fr_msec));
	case SCTPCTL_ASCONF_AUTH_NOCHK:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_auth_disable));
	case SCTPCTL_AUTH_DISABLE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_auth_disable));
	case SCTPCTL_AUTH_RANDOM_LEN:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_auth_random_len));
	case SCTPCTL_AUTH_HMAC_ID:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_auth_hmac_id_default));
	case SCTPCTL_ABC_L_VAR:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_L2_abc_variable));
	case SCTPCTL_MAX_MBUF_CHAIN:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_max_mbuf_threshold_count));
	case SCTPCTL_CMT_USE_DAC:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_cmt_use_dac));
	case SCTPCTL_DO_DRAIN:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_do_drain));
	case SCTPCTL_HB_MAXBURST:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_hb_maxburst));
	case SCTPCTL_QLIMIT_ABORT:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_abort_if_one_2_one_hits_limit));
	case SCTPCTL_STRICT_ORDER:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_strict_data_order));
	case SCTPCTL_NAT_FRIENDLY:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_nat_friendly));

#ifdef SCTP_DEBUG
	case SCTPCTL_DEBUG:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_debug_on));
#endif
	default:
		return (ENOPROTOOPT);
	}
	/* NOTREACHED */
}

#endif
#if __NetBSD__
/*
 * Sysctl for sctp variables.
 */
SYSCTL_SETUP(sysctl_net_inet_sctp_setup, "sysctl net.inet.sctp subtree setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "net", NULL,
	    NULL, 0, NULL, 0,
	    CTL_NET, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "inet", NULL,
	    NULL, 0, NULL, 0,
	    CTL_NET, PF_INET, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "sctp",
	    SYSCTL_DESCR("sctp related settings"),
	    NULL, 0, NULL, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "maxdgram",
	    SYSCTL_DESCR("Maximum outgoing SCTP buffer size"),
	    NULL, 0, &sctp_sendspace, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_MAXDGRAM,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "recvspace",
	    SYSCTL_DESCR("Maximum incoming SCTP buffer size"),
	    NULL, 0, &sctp_recvspace, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_RECVSPACE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "autoasconf",
	    SYSCTL_DESCR("Enable SCTP Auto-ASCONF"),
	    NULL, 0, &sctp_auto_asconf, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_AUTOASCONF,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "ecn_enable",
	    SYSCTL_DESCR("Enable SCTP ECN"),
	    NULL, 0, &sctp_ecn_enable, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_ECN_ENABLE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "ecn_nonce",
	    SYSCTL_DESCR("Enable SCTP ECN Nonce"),
	    NULL, 0, &sctp_ecn_nonce, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_ECN_NONCE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "strict_sack",
	    SYSCTL_DESCR("Enable SCTP Strict SACK checking"),
	    NULL, 0, &sctp_strict_sacks, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_STRICT_SACK,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "loopback_nocsum",
	    SYSCTL_DESCR("Enable NO Csum on packets sent on loopback"),
	    NULL, 0, &sctp_no_csum_on_loopback, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_NOCSUM_LO,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "strict_init",
	    SYSCTL_DESCR("Enable strict INIT/INIT-ACK singleton enforcement"),
	    NULL, 0, &sctp_strict_init, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_STRICT_INIT,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "peer_chkoh",
	    SYSCTL_DESCR("Amount to debit peers rwnd per chunk sent"),
	    NULL, 0, &sctp_peer_chunk_oh, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_PEER_CHK_OH,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "maxburst",
	    SYSCTL_DESCR("Default max burst for sctp endpoints"),
	    NULL, 0, &sctp_max_burst_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_MAXBURST,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "maxchunks",
	    SYSCTL_DESCR("Default max chunks on queue per asoc"),
	    NULL, 0, &sctp_max_chunks_on_queue, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_MAXCHUNKONQ,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "tcbhashsize",
	    SYSCTL_DESCR("Tuneable for Hash table sizes"),
	    NULL, 0, &sctp_hashtblsize, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_TCBHASHSIZE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "pcbhashsize",
	    SYSCTL_DESCR("Tuneable for PCB Hash table sizes"),
	    NULL, 0, &sctp_pcbtblsize, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_PCBHASHSIZE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "min_split_point",
	    SYSCTL_DESCR("Minimum size when splitting a chunk"),
	    NULL, 0, &sctp_min_split_point, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_MINSPLIT,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "chunkscale",
	    SYSCTL_DESCR("Tuneable for Scaling of number of chunks and messages"),
	    NULL, 0, &sctp_chunscale, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_CHUNKSCALE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "delayed_sack_time",
	    SYSCTL_DESCR("Default delayed SACK timer in msec"),
	    NULL, 0, &sctp_delayed_sack_time_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_DELAYED_SACK,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "sack_freq",
	    SYSCTL_DESCR("Default SACK frequency"),
	    NULL, 0, &sctp_sack_freq_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_SACK_FREQ,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "sys_resource",
	    SYSCTL_DESCR("Max number of cached resources in the system"),
	    NULL, 0, &sctp_system_free_resc_limit, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_SYS_RESC,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "asoc_resource",
	    SYSCTL_DESCR("Max number of cached resources in an asoc"),
	    NULL, 0, &sctp_asoc_free_resc_limit, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_ASOC_RESC,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "heartbeat_interval",
	    SYSCTL_DESCR("Default heartbeat interval in msec"),
	    NULL, 0, &sctp_heartbeat_interval_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_HB_INTERVAL,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "pmtu_raise_time",
	    SYSCTL_DESCR("Default PMTU raise timer in sec"),
	    NULL, 0, &sctp_pmtu_raise_time_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_PMTU_RAISE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "shutdown_guard_time",
	    SYSCTL_DESCR("Default shutdown guard timer in sec"),
	    NULL, 0, &sctp_shutdown_guard_time_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_SHUTDOWN_GUARD,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "secret_lifetime",
	    SYSCTL_DESCR("Default secret liftime in sec"),
	    NULL, 0, &sctp_secret_lifetime_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_SECRET_LIFETIME,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "rto_max",
	    SYSCTL_DESCR("Default maximum retransmission timeout in msec"),
	    NULL, 0, &sctp_rto_max_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_RTO_MAX,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "rto_min",
	    SYSCTL_DESCR("Default minimum retransmission timeout in msec"),
	    NULL, 0, &sctp_rto_min_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_RTO_MIN,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "rto_initial",
	    SYSCTL_DESCR("Default initial retransmission timeout in msec"),
	    NULL, 0, &sctp_rto_initial_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_RTO_INITIAL,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "init_rto_max",
	    SYSCTL_DESCR("Default maximum retransmission timeout during association setup in msec"),
	    NULL, 0, &sctp_init_rto_max_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_INIT_RTO_MAX,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "valid_cookie_life",
	    SYSCTL_DESCR("Default cookie lifetime in sec"),
	    NULL, 0, &sctp_valid_cookie_life_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_COOKIE_LIFE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "init_rtx_max",
	    SYSCTL_DESCR("Default maximum number of retransmission for INIT chunks"),
	    NULL, 0, &sctp_init_rtx_max_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_INIT_RTX_MAX,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "assoc_rtx_max",
	    SYSCTL_DESCR("Default maximum number of retransmissions per association"),
	    NULL, 0, &sctp_assoc_rtx_max_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_ASSOC_RTX_MAX,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "path_rtx_max",
	    SYSCTL_DESCR("Default maximum of retransmissions per path"),
	    NULL, 0, &sctp_path_rtx_max_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_PATH_RTX_MAX,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "add_more_on_output",
	    SYSCTL_DESCR("When space wise is it worthwhile to try to add more to a socket send buffer"),
	    NULL, 0, &sctp_add_more_threshold, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_ADD_MORE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "nr_outgoing_streams",
	    SYSCTL_DESCR("Default outgoing streams"),
	    NULL, 0, &sctp_nr_outgoing_streams_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_NR_OUTGOING_STREAMS,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "cmt_on_off",
	    SYSCTL_DESCR("CMT on-off flag"),
	    NULL, 0, &sctp_cmt_on_off, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_CMT_ON_OFF,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "cwnd_maxburst",
	    SYSCTL_DESCR("Use a CWND adjusting maxburst"),
	    NULL, 0, &sctp_use_cwnd_based_maxburst, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_CWND_MAXBURST,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "early_fast_retran",
	    SYSCTL_DESCR("Early Fast Retransmit with Timer"),
	    NULL, 0, &sctp_early_fr, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_EARLY_FR,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "use_rttvar_congctrl",
	    SYSCTL_DESCR("Use Congestion Control via rtt variation"),
	    NULL, 0, &sctp_use_rttvar_cc, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_RTTVAR_CC,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "deadlock_detect",
	    SYSCTL_DESCR("SMP Deadlock detection on/off"),
	    NULL, 0, &sctp_says_check_for_deadlock, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_DEADLOCK_DET,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "early_fast_retran_msec",
	    SYSCTL_DESCR("Early Fast Retransmit minimum Timer value"),
	    NULL, 0, &sctp_early_fr_msec, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_EARLY_FR_MSEC,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "asconf_auth_nochk",
	    SYSCTL_DESCR("Disable SCTP ASCONF AUTH requirement"),
	    NULL, 0, &sctp_asconf_auth_nochk, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_ASCONF_AUTH_NOCHK,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "auth_disable",
	    SYSCTL_DESCR("Disable SCTP AUTH requirement/function"),
	    NULL, 0, &sctp_auth_disable, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_AUTH_DISABLE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "auth_random_len",
	    SYSCTL_DESCR("Length of AUTH RANDOMs"),
	    NULL, 0, &sctp_auth_random_len, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_AUTH_RANDOM_LEN,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "auth_hmac_id",
	    SYSCTL_DESCR("Default HMAC Id for SCTP AUTHentication"),
	    NULL, 0, &sctp_auth_hmac_id_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_AUTH_HMAC_ID,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "abc_l_var",
	    SYSCTL_DESCR("SCTP ABC max increase per SACK (L)"),
	    NULL, 0, &sctp_L2_abc_variable, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_ABC_L_VAR,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "max_chained_mbufs",
	    SYSCTL_DESCR("Default max number of small mbufs on a chain"),
	    NULL, 0, &sctp_mbuf_threshold_count, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_MAX_MBUF_CHAIN,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "cmt_use_dac",
	    SYSCTL_DESCR("CMT DAC on-off flag"),
	    NULL, 0, &sctp_cmt_use_dac, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_CMT_USE_DAC,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "do_sctp_drain",
	    SYSCTL_DESCR("Should SCTP respond to the drain calls"),
	    NULL, 0, &sctp_do_drain, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_DO_DRAIN,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "hb_max_burst",
	    SYSCTL_DESCR("Confirmation Heartbeat max burst?"),
	    NULL, 0, &sctp_hb_maxburst, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_HB_MAXBURST,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "abort_at_limit",
	    SYSCTL_DESCR("When one-2-one hits qlimit abort"),
	    NULL, 0, &sctp_abort_if_one_2_one_hits_limit, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_QLIMIT_ABORT,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "strict_data_order",
	    SYSCTL_DESCR("Enforce strict data ordering, abort if control inside data"),
	    NULL, 0, &sctp_strict_data_order, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_STRICT_ORDER,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "nat_friendly",
	    SYSCTL_DESCR("SCTP NAT friendly operation"),
	    NULL, 0, &sctp_auth_hmac_id_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_NAT_FRIENDLY,
	    CTL_EOL);

#ifdef SCTP_DEBUG
	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "debug",
	    SYSCTL_DESCR("Configure debug output"),
	    NULL, 0, &sctp_debug_on, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_DEBUG,
	    CTL_EOL);
#endif				/* SCTP_DEBUG */

}

#endif				/* __NetBSD__ */
#endif
