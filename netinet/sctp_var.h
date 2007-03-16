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

/* $KAME: sctp_var.h,v 1.24 2005/03/06 16:04:19 itojun Exp $	 */

#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/netinet/sctp_var.h,v 1.5 2007/02/12 23:24:31 rrs Exp $");
#endif

#ifndef _NETINET_SCTP_VAR_H_
#define _NETINET_SCTP_VAR_H_


#include <netinet/sctp_uio.h>

/* SCTP Kernel structures */

/*
 * Names for SCTP sysctl objects
 */
#ifndef __APPLE__
#define	SCTPCTL_MAXDGRAM	    1	/* max datagram size */
#define	SCTPCTL_RECVSPACE	    2	/* default receive buffer space */
#define SCTPCTL_AUTOASCONF          3	/* auto asconf enable/disable flag */
#define SCTPCTL_ECN_ENABLE          4	/* Is ecn allowed */
#define SCTPCTL_ECN_NONCE           5	/* Is ecn nonce allowed */
#define SCTPCTL_STRICT_SACK         6	/* strictly require sack'd TSN's to be
					 * smaller than sndnxt. */
#define SCTPCTL_NOCSUM_LO           7	/* Require that the Loopback NOT have
					 * the crc32 checksum on packets
					 * routed over it. */
#define SCTPCTL_STRICT_INIT         8
#define SCTPCTL_PEER_CHK_OH         9
#define SCTPCTL_MAXBURST            10
#define SCTPCTL_MAXCHUNKONQ         11
#define SCTPCTL_DELAYED_SACK        12
#define SCTPCTL_SACK_FREQ           13
#define SCTPCTL_HB_INTERVAL         14
#define SCTPCTL_PMTU_RAISE          15
#define SCTPCTL_SHUTDOWN_GUARD      16
#define SCTPCTL_SECRET_LIFETIME     17
#define SCTPCTL_RTO_MAX             18
#define SCTPCTL_RTO_MIN             19
#define SCTPCTL_RTO_INITIAL         20
#define SCTPCTL_INIT_RTO_MAX        21
#define SCTPCTL_COOKIE_LIFE         22
#define SCTPCTL_INIT_RTX_MAX        23
#define SCTPCTL_ASSOC_RTX_MAX       24
#define SCTPCTL_PATH_RTX_MAX        25
#define SCTPCTL_NR_OUTGOING_STREAMS 26
#define SCTPCTL_CMT_ON_OFF          27
#define SCTPCTL_CWND_MAXBURST       28
#define SCTPCTL_EARLY_FR            29
#define SCTPCTL_RTTVAR_CC           30
#define SCTPCTL_DEADLOCK_DET        31
#define SCTPCTL_EARLY_FR_MSEC       32
#define SCTPCTL_ASCONF_AUTH_NOCHK   33
#define SCTPCTL_AUTH_DISABLE        34
#define SCTPCTL_AUTH_RANDOM_LEN     35
#define SCTPCTL_AUTH_HMAC_ID        36
#define SCTPCTL_ABC_L_VAR           37
#define SCTPCTL_MAX_MBUF_CHAIN      38
#define SCTPCTL_CMT_USE_DAC         39
#define SCTPCTL_DO_DRAIN            40
#define SCTPCTL_HB_MAXBURST         41
#define SCTPCTL_QLIMIT_ABORT        42
#define SCTPCTL_STRICT_ORDER        43
#define SCTPCTL_TCBHASHSIZE         44
#define SCTPCTL_PCBHASHSIZE         45
#define SCTPCTL_CHUNKSCALE          46
#define SCTPCTL_MINSPLIT            47
#define SCTPCTL_ADD_MORE            48
#define SCTPCTL_SYS_RESC            49
#define SCTPCTL_ASOC_RESC           50
#define SCTPCTL_NAT_FRIENDLY	    51
#ifdef SCTP_DEBUG
#define SCTPCTL_DEBUG               52
#define SCTPCTL_MAXID		    52
#else
#define SCTPCTL_MAXID		    51
#endif
#endif

#ifdef SCTP_DEBUG
#define SCTPCTL_NAMES { \
	{ 0, 0 }, \
	{ "sendspace", CTLTYPE_INT }, \
	{ "recvspace", CTLTYPE_INT }, \
	{ "autoasconf", CTLTYPE_INT }, \
	{ "ecn_enable", CTLTYPE_INT }, \
	{ "ecn_nonce", CTLTYPE_INT }, \
	{ "strict_sack", CTLTYPE_INT }, \
	{ "looback_nocsum", CTLTYPE_INT }, \
	{ "strict_init", CTLTYPE_INT }, \
	{ "peer_chkoh", CTLTYPE_INT }, \
	{ "maxburst", CTLTYPE_INT }, \
	{ "maxchunks", CTLTYPE_INT }, \
	{ "delayed_sack_time", CTLTYPE_INT }, \
	{ "sack_freq", CTLTYPE_INT }, \
	{ "heartbeat_interval", CTLTYPE_INT }, \
	{ "pmtu_raise_time", CTLTYPE_INT }, \
	{ "shutdown_guard_time", CTLTYPE_INT }, \
	{ "secret_lifetime", CTLTYPE_INT }, \
	{ "rto_max", CTLTYPE_INT }, \
	{ "rto_min", CTLTYPE_INT }, \
	{ "rto_initial", CTLTYPE_INT }, \
	{ "init_rto_max", CTLTYPE_INT }, \
	{ "valid_cookie_life", CTLTYPE_INT }, \
	{ "init_rtx_max", CTLTYPE_INT }, \
	{ "assoc_rtx_max", CTLTYPE_INT }, \
	{ "path_rtx_max", CTLTYPE_INT }, \
	{ "nr_outgoing_streams", CTLTYPE_INT }, \
	{ "cmt_on_off", CTLTYPE_INT }, \
	{ "cwnd_maxburst", CTLTYPE_INT }, \
	{ "early_fast_retran", CTLTYPE_INT }, \
	{ "use_rttvar_congctrl", CTLTYPE_INT }, \
	{ "deadlock_detect", CTLTYPE_INT }, \
	{ "early_fast_retran_msec", CTLTYPE_INT }, \
	{ "asconf_auth_nochk", CTLTYPE_INT }, \
	{ "auth_disable", CTLTYPE_INT }, \
	{ "auth_random_len", CTLTYPE_INT }, \
	{ "auth_hmac_id", CTLTYPE_INT }, \
	{ "abc_l_var", CTLTYPE_INT }, \
	{ "max_mbuf_chain", CTLTYPE_INT }, \
	{ "cmt_use_dac", CTLTYPE_INT }, \
	{ "do_sctp_drain", CTLTYPE_INT }, \
	{ "warm_crc_table", CTLTYPE_INT }, \
	{ "abort_at_limit", CTLTYPE_INT }, \
	{ "strict_data_order", CTLTYPE_INT }, \
	{ "tcbhashsize", CTLTYPE_INT }, \
	{ "pcbhashsize", CTLTYPE_INT }, \
	{ "chunkscale", CTLTYPE_INT }, \
	{ "min_split_point", CTLTYPE_INT }, \
	{ "add_more_on_output", CTLTYPE_INT }, \
	{ "sys_resource", CTLTYPE_INT }, \
	{ "asoc_resource", CTLTYPE_INT }, \
	{ "nat_friendly", CTLTYPE_INT }, \
	{ "debug", CTLTYPE_INT }, \
}
#else
#define SCTPCTL_NAMES { \
	{ 0, 0 }, \
	{ "sendspace", CTLTYPE_INT }, \
	{ "recvspace", CTLTYPE_INT }, \
	{ "autoasconf", CTLTYPE_INT }, \
	{ "ecn_enable", CTLTYPE_INT }, \
	{ "ecn_nonce", CTLTYPE_INT }, \
	{ "strict_sack", CTLTYPE_INT }, \
	{ "looback_nocsum", CTLTYPE_INT }, \
	{ "strict_init", CTLTYPE_INT }, \
	{ "peer_chkoh", CTLTYPE_INT }, \
	{ "maxburst", CTLTYPE_INT }, \
	{ "maxchunks", CTLTYPE_INT }, \
	{ "delayed_sack_time", CTLTYPE_INT }, \
	{ "sack_freq", CTLTYPE_INT }, \
	{ "heartbeat_interval", CTLTYPE_INT }, \
	{ "pmtu_raise_time", CTLTYPE_INT }, \
	{ "shutdown_guard_time", CTLTYPE_INT }, \
	{ "secret_lifetime", CTLTYPE_INT }, \
	{ "rto_max", CTLTYPE_INT }, \
	{ "rto_min", CTLTYPE_INT }, \
	{ "rto_initial", CTLTYPE_INT }, \
	{ "init_rto_max", CTLTYPE_INT }, \
	{ "valid_cookie_life", CTLTYPE_INT }, \
	{ "init_rtx_max", CTLTYPE_INT }, \
	{ "assoc_rtx_max", CTLTYPE_INT }, \
	{ "path_rtx_max", CTLTYPE_INT }, \
	{ "nr_outgoing_streams", CTLTYPE_INT }, \
	{ "cmt_on_off", CTLTYPE_INT }, \
	{ "cwnd_maxburst", CTLTYPE_INT }, \
	{ "early_fast_retran", CTLTYPE_INT }, \
	{ "use_rttvar_congctrl", CTLTYPE_INT }, \
	{ "deadlock_detect", CTLTYPE_INT }, \
	{ "early_fast_retran_msec", CTLTYPE_INT }, \
	{ "asconf_auth_nochk", CTLTYPE_INT }, \
	{ "auth_disable", CTLTYPE_INT }, \
	{ "auth_random_len", CTLTYPE_INT }, \
	{ "auth_hmac_id", CTLTYPE_INT }, \
	{ "abc_l_var", CTLTYPE_INT }, \
	{ "max_mbuf_chain", CTLTYPE_INT }, \
	{ "cmt_use_dac", CTLTYPE_INT }, \
	{ "do_sctp_drain", CTLTYPE_INT }, \
	{ "warm_crc_table", CTLTYPE_INT }, \
	{ "abort_at_limit", CTLTYPE_INT }, \
	{ "strict_data_order", CTLTYPE_INT }, \
	{ "tcbhashsize", CTLTYPE_INT }, \
	{ "pcbhashsize", CTLTYPE_INT }, \
	{ "chunkscale", CTLTYPE_INT }, \
	{ "min_split_point", CTLTYPE_INT }, \
	{ "add_more_on_output", CTLTYPE_INT }, \
	{ "sys_resource", CTLTYPE_INT }, \
	{ "asoc_resource", CTLTYPE_INT }, \
	{ "nat_friendly", CTLTYPE_INT }, \
}
#endif


#if defined(_KERNEL)

#if defined(__FreeBSD__) || defined(__APPLE__)
#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet_sctp);
#endif
extern struct pr_usrreqs sctp_usrreqs;

#elif defined(__NetBSD__)
int sctp_usrreq
__P((struct socket *, int, struct mbuf *, struct mbuf *,
    struct mbuf *, struct proc *));

#else
int sctp_usrreq
__P((struct socket *, int, struct mbuf *, struct mbuf *,
    struct mbuf *));

#endif

#define sctp_feature_on(inp, feature)  (inp->sctp_features |= feature)
#define sctp_feature_off(inp, feature) (inp->sctp_features &= ~feature)
#define sctp_is_feature_on(inp, feature) (inp->sctp_features & feature)
#define sctp_is_feature_off(inp, feature) ((inp->sctp_features & feature) == 0)

#define	sctp_sbspace(asoc, sb) ((long) (((sb)->sb_hiwat > (asoc)->sb_cc) ? ((sb)->sb_hiwat - (asoc)->sb_cc) : 0))

#define	sctp_sbspace_failedmsgs(sb) ((long) (((sb)->sb_hiwat > (sb)->sb_cc) ? ((sb)->sb_hiwat - (sb)->sb_cc) : 0))

#define sctp_sbspace_sub(a,b) ((a > b) ? (a - b) : 0)

extern uint32_t sctp_asoc_free_resc_limit;
extern uint32_t sctp_system_free_resc_limit;

/* I tried to cache the readq entries at one
 * point. But the reality is that it did not
 * add any performance since this meant
 * we had to lock the STCB on read. And at that point
 * once you have to do an extra lock, it really does
 * not matter if the lock is in the ZONE stuff or
 * in our code. Note that this same problem would
 * occur with an mbuf cache as well so it is
 * not really worth doing, at least right now :-D
 */

#define sctp_free_a_readq(_stcb, _readq) { \
	SCTP_ZONE_FREE(sctppcbinfo.ipi_zone_readq, (_readq)); \
	SCTP_DECR_READQ_COUNT(); \
}

#define sctp_alloc_a_readq(_stcb, _readq) { \
	(_readq) = SCTP_ZONE_GET(sctppcbinfo.ipi_zone_readq, struct sctp_queued_to_read); \
	if ((_readq)) { \
 	     SCTP_INCR_READQ_COUNT(); \
	} \
}

#define sctp_free_a_strmoq(_stcb, _strmoq) { \
	if (((_stcb)->asoc.free_strmoq_cnt > sctp_asoc_free_resc_limit) || \
	    (sctppcbinfo.ipi_free_strmoq > sctp_system_free_resc_limit)) { \
		SCTP_ZONE_FREE(sctppcbinfo.ipi_zone_strmoq, (_strmoq)); \
		SCTP_DECR_STRMOQ_COUNT(); \
	} else { \
		TAILQ_INSERT_TAIL(&(_stcb)->asoc.free_strmoq, (_strmoq), next); \
		(_stcb)->asoc.free_strmoq_cnt++; \
		SCTP_INCR_TCB_FREE_STRMOQ_COUNT(_stcb); \
		SCTP_INCR_FREE_STRMOQ_COUNT(); \
	} \
}

#define sctp_alloc_a_strmoq(_stcb, _strmoq) { \
	if (TAILQ_EMPTY(&(_stcb)->asoc.free_strmoq))  { \
		(_strmoq) = SCTP_ZONE_GET(sctppcbinfo.ipi_zone_strmoq, struct sctp_stream_queue_pending); \
		if ((_strmoq)) { \
			SCTP_INCR_STRMOQ_COUNT(); \
		} \
	} else { \
		(_strmoq) = TAILQ_FIRST(&(_stcb)->asoc.free_strmoq); \
		TAILQ_REMOVE(&(_stcb)->asoc.free_strmoq, (_strmoq), next); \
		SCTP_DECR_TCB_FREE_STRMOQ_COUNT(_stcb); \
		SCTP_DECR_FREE_STRMOQ_COUNT(); \
	} \
}


#define sctp_free_a_chunk(_stcb, _chk) { \
	if (((_stcb)->asoc.free_chunk_cnt > sctp_asoc_free_resc_limit) || \
	    (sctppcbinfo.ipi_free_chunks > sctp_system_free_resc_limit)) { \
		SCTP_ZONE_FREE(sctppcbinfo.ipi_zone_chunk, (_chk)); \
		SCTP_DECR_CHK_COUNT(); \
	} else { \
		TAILQ_INSERT_TAIL(&(_stcb)->asoc.free_chunks, (_chk), sctp_next); \
		SCTP_INCR_TCB_FREE_CHK_COUNT(_stcb); \
		SCTP_INCR_FREE_CHK_COUNT(); \
	} \
}

#define sctp_alloc_a_chunk(_stcb, _chk) { \
	if (TAILQ_EMPTY(&(_stcb)->asoc.free_chunks))  { \
		(_chk) = SCTP_ZONE_GET(sctppcbinfo.ipi_zone_chunk, struct sctp_tmit_chunk); \
		if ((_chk)) { \
			SCTP_INCR_CHK_COUNT(); \
		} \
	} else { \
		(_chk) = TAILQ_FIRST(&(_stcb)->asoc.free_chunks); \
		TAILQ_REMOVE(&(_stcb)->asoc.free_chunks, (_chk), sctp_next); \
		SCTP_DECR_TCB_FREE_CHK_COUNT(_stcb); \
		SCTP_DECR_FREE_CHK_COUNT(); \
	} \
}


#if defined(__FreeBSD__) && __FreeBSD_version > 500000

#define sctp_free_remote_addr(__net) { \
	if ((__net)) {  \
		if (atomic_fetchadd_int(&(__net)->ref_count, -1) == 1) { \
			SCTP_OS_TIMER_STOP(&(__net)->rxt_timer.timer); \
			SCTP_OS_TIMER_STOP(&(__net)->pmtu_timer.timer); \
			SCTP_OS_TIMER_STOP(&(__net)->fr_timer.timer); \
                        if ((__net)->ro.ro_rt) { \
				RTFREE((__net)->ro.ro_rt); \
				(__net)->ro.ro_rt = NULL; \
                        } \
			if ((__net)->src_addr_selected) { \
				sctp_free_ifa((__net)->ro._s_addr); \
				(__net)->ro._s_addr = NULL; \
			} \
                        (__net)->src_addr_selected = 0; \
			(__net)->dest_state = SCTP_ADDR_NOT_REACHABLE; \
			SCTP_ZONE_FREE(sctppcbinfo.ipi_zone_net, (__net)); \
			SCTP_DECR_RADDR_COUNT(); \
		} \
	} \
}

#define sctp_sbfree(ctl, stcb, sb, m) { \
	uint32_t val; \
	val = atomic_fetchadd_int(&(sb)->sb_cc,-(SCTP_BUF_LEN((m)))); \
	if (val < SCTP_BUF_LEN((m))) { \
	   panic("sb_cc goes negative"); \
	} \
	val = atomic_fetchadd_int(&(sb)->sb_mbcnt,-(MSIZE)); \
	if (val < MSIZE) { \
	    panic("sb_mbcnt goes negative"); \
	} \
	if (SCTP_BUF_IS_EXTENDED(m)) { \
		val = atomic_fetchadd_int(&(sb)->sb_mbcnt,-(SCTP_BUF_EXTEND_SIZE(m))); \
		if (val < SCTP_BUF_EXTEND_SIZE(m)) { \
		    panic("sb_mbcnt goes negative2"); \
		} \
	} \
	if (((ctl)->do_not_ref_stcb == 0) && stcb) {\
	  val = atomic_fetchadd_int(&(stcb)->asoc.sb_cc,-(SCTP_BUF_LEN((m)))); \
	  if (val < SCTP_BUF_LEN((m))) {\
	     panic("stcb->sb_cc goes negative"); \
	  } \
	  val = atomic_fetchadd_int(&(stcb)->asoc.sb_mbcnt,-(MSIZE)); \
	  if (val < MSIZE) { \
	     panic("asoc->mbcnt goes negative"); \
	  } \
	  if (SCTP_BUF_IS_EXTENDED(m)) { \
		val = atomic_fetchadd_int(&(stcb)->asoc.sb_mbcnt,-(SCTP_BUF_EXTEND_SIZE(m))); \
		if (val < SCTP_BUF_EXTEND_SIZE(m)) { \
		   panic("assoc stcb->mbcnt would go negative"); \
		} \
	  } \
	} \
	if (SCTP_BUF_TYPE(m) != MT_DATA && SCTP_BUF_TYPE(m) != MT_HEADER && \
	    SCTP_BUF_TYPE(m) != MT_OOBDATA) \
		atomic_subtract_int(&(sb)->sb_ctl,SCTP_BUF_LEN((m))); \
}


#define sctp_sballoc(stcb, sb, m) { \
	atomic_add_int(&(sb)->sb_cc,SCTP_BUF_LEN((m))); \
	atomic_add_int(&(sb)->sb_mbcnt, MSIZE); \
	if (SCTP_BUF_IS_EXTENDED(m)) \
		atomic_add_int(&(sb)->sb_mbcnt,SCTP_BUF_EXTEND_SIZE(m)); \
	if (stcb) { \
		atomic_add_int(&(stcb)->asoc.sb_cc,SCTP_BUF_LEN((m))); \
		atomic_add_int(&(stcb)->asoc.sb_mbcnt, MSIZE); \
		if (SCTP_BUF_IS_EXTENDED(m)) \
			atomic_add_int(&(stcb)->asoc.sb_mbcnt,SCTP_BUF_EXTEND_SIZE(m)); \
	} \
	if (SCTP_BUF_TYPE(m) != MT_DATA && SCTP_BUF_TYPE(m) != MT_HEADER && \
	    SCTP_BUF_TYPE(m) != MT_OOBDATA) \
		atomic_add_int(&(sb)->sb_ctl,SCTP_BUF_LEN((m))); \
}

#else				/* FreeBSD Version <= 500000 or non-FreeBSD */


#define sctp_free_remote_addr(__net) do { \
	if ((__net)) { \
		SCTP_RADDR_DECR_REF(__net); \
		if ((__net)->ref_count == 0) { \
			SCTP_OS_TIMER_STOP(&(__net)->rxt_timer.timer); \
			SCTP_OS_TIMER_STOP(&(__net)->pmtu_timer.timer); \
			SCTP_OS_TIMER_STOP(&(__net)->fr_timer.timer); \
			(__net)->dest_state = SCTP_ADDR_NOT_REACHABLE; \
			SCTP_ZONE_FREE(sctppcbinfo.ipi_zone_net, (__net)); \
			SCTP_DECR_RADDR_COUNT(); \
		} \
	} \
} while (0)

#define sctp_sbfree(ctl, stcb, sb, m) { \
	if ((sb)->sb_cc >= (uint32_t)SCTP_BUF_LEN((m))) { \
		atomic_subtract_int(&(sb)->sb_cc, SCTP_BUF_LEN((m))); \
	} else { \
		(sb)->sb_cc = 0; \
	} \
	if (((ctl)->do_not_ref_stcb == 0) && stcb) { \
		if ((stcb)->asoc.sb_cc >= (uint32_t)SCTP_BUF_LEN((m))) { \
			atomic_subtract_int(&(stcb)->asoc.sb_cc, SCTP_BUF_LEN((m))); \
		} else { \
			(stcb)->asoc.sb_cc = 0; \
		} \
		if ((stcb)->asoc.sb_mbcnt >= MSIZE) { \
			atomic_subtract_int(&(stcb)->asoc.sb_mbcnt, MSIZE); \
		} \
		if (SCTP_BUF_IS_EXTENDED(m)) { \
			if ((stcb)->asoc.sb_mbcnt >= SCTP_BUF_EXTEND_SIZE(m)) { \
				atomic_subtract_int(&(stcb)->asoc.sb_mbcnt, SCTP_BUF_EXTEND_SIZE(m)); \
			} else { \
				panic("assoc stcb->mbcnt would go negative"); \
				(stcb)->asoc.sb_mbcnt = 0; \
			} \
		} \
	} \
	if ((sb)->sb_mbcnt >= MSIZE) { \
		atomic_subtract_int(&(sb)->sb_mbcnt, MSIZE); \
		if (SCTP_BUF_IS_EXTENDED(m)) { \
			if ((sb)->sb_mbcnt >= (uint32_t)SCTP_BUF_EXTEND_SIZE(m)) { \
				atomic_subtract_int(&(sb)->sb_mbcnt, SCTP_BUF_EXTEND_SIZE(m)); \
			} else { \
				(sb)->sb_mbcnt = 0; \
			} \
		} \
	} else { \
		(sb)->sb_mbcnt = 0; \
	} \
}

#define sctp_sballoc(stcb, sb, m) { \
	atomic_add_int(&(sb)->sb_cc, SCTP_BUF_LEN((m))); \
	atomic_add_int(&(sb)->sb_mbcnt, MSIZE); \
	if (stcb) { \
		atomic_add_int(&(stcb)->asoc.sb_cc, SCTP_BUF_LEN((m))); \
		atomic_add_int(&(stcb)->asoc.sb_mbcnt, MSIZE); \
		if (SCTP_BUF_IS_EXTENDED(m)) \
			atomic_add_int(&(stcb)->asoc.sb_mbcnt, SCTP_BUF_EXTEND_SIZE(m)); \
	} \
	if (SCTP_BUF_IS_EXTENDED(m)) \
		atomic_add_int(&(sb)->sb_mbcnt, SCTP_BUF_EXTEND_SIZE(m)); \
}

#endif

#define sctp_ucount_incr(val) { \
	val++; \
}

#define sctp_ucount_decr(val) { \
	if (val > 0) { \
		val--; \
	} else { \
		val = 0; \
	} \
}

#define sctp_mbuf_crush(data) do { \
	struct mbuf *_m; \
	_m = (data); \
	while(_m && (SCTP_BUF_LEN(_m) == 0)) { \
		(data)  = SCTP_BUF_NEXT(_m); \
		SCTP_BUF_NEXT(_m) = NULL; \
		sctp_m_free(_m); \
		_m = (data); \
	} \
} while (0)


/*
 * some sysctls
 */
extern int sctp_sendspace;
extern int sctp_recvspace;
extern int sctp_ecn_enable;
extern int sctp_ecn_nonce;
extern int sctp_use_cwnd_based_maxburst;
extern unsigned int sctp_cmt_on_off;
extern unsigned int sctp_cmt_use_dac;
extern unsigned int sctp_cmt_sockopt_on_off;
extern uint32_t sctp_nat_friendly;

struct sctp_nets;
struct sctp_inpcb;
struct sctp_tcb;
struct sctphdr;

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__Windows__)
void sctp_ctlinput __P((int, struct sockaddr *, void *));
int sctp_ctloutput __P((struct socket *, struct sockopt *));
#if defined(__Windows__)
void sctp_input __P((struct mpkt *, int));
#else
void sctp_input __P((struct mbuf *, int));
#endif
#else
void *sctp_ctlinput __P((int, struct sockaddr *, void *));
int sctp_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
void sctp_input __P((struct mbuf *,...));
#endif
void sctp_drain __P((void));
void sctp_init __P((void));

#ifdef SCTP_APPLE_FINE_GRAINED_LOCKING
void sctp_finish(void);
#endif

void sctp_pcbinfo_cleanup(void);

int sctp_shutdown __P((struct socket *));
void sctp_notify __P((struct sctp_inpcb *, int, struct sctphdr *,
		struct sockaddr *, struct sctp_tcb *,
		struct sctp_nets *));

#if defined(INET6)
void ip_2_ip6_hdr __P((struct ip6_hdr *, struct ip *));
#endif

int sctp_bindx(struct socket *, int, struct sockaddr_storage *,
	int, int, struct proc *);

/* can't use sctp_assoc_t here */
int sctp_peeloff(struct socket *, struct socket *, int, caddr_t, int *);

sctp_assoc_t sctp_getassocid(struct sockaddr *);


int sctp_ingetaddr(struct socket *,
#if defined(__FreeBSD__) || defined(__APPLE__)
	struct sockaddr **
#elif defined(__Panda__)
	struct sockaddr *
#else
	struct mbuf *
#endif
);

int sctp_peeraddr(struct socket *,
#if defined(__FreeBSD__) || defined(__APPLE__)
	struct sockaddr **
#elif defined(__Panda__)
	struct sockaddr *
#else
	struct mbuf *
#endif
);

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
#if __FreeBSD_version >= 700000
int sctp_listen(struct socket *, int, struct thread *);
#else
int sctp_listen(struct socket *, struct thread *);
#endif
#else
int sctp_listen(struct socket *, struct proc *);
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
int sctp_accept(struct socket *, struct sockaddr **);
#elif defined(__Panda__)
int sctp_accept(struct socket *, struct sockaddr *, int *, void *, int *);
#else
int sctp_accept(struct socket *, struct mbuf *);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
int sctp_sysctl(int *, uint32_t, void *, size_t *, void *, size_t);
#endif

#endif				/* _KERNEL */

#endif				/* !_NETINET_SCTP_VAR_H_ */
