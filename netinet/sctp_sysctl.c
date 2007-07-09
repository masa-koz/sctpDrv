/*-
 * Copyright (c) 2007, Cisco Systems, Inc. All rights reserved.
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

#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/netinet/sctp_sysctl.c,v 1.3 2007/04/03 11:15:32 rrs Exp $");
#endif

#include <netinet/sctp_os.h>
#include <netinet/sctp_constants.h>
#include <netinet/sctp_sysctl.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>

/*
 * sysctl tunable variables
 */
uint32_t sctp_sendspace = (128 * 1024);
uint32_t sctp_recvspace = 128 * (1024 +
#ifdef INET6
    sizeof(struct sockaddr_in6)
#else
    sizeof(struct sockaddr_in)
#endif
);
uint32_t sctp_mbuf_threshold_count = SCTP_DEFAULT_MBUFS_IN_CHAIN;
uint32_t sctp_auto_asconf = SCTP_DEFAULT_AUTO_ASCONF;
uint32_t sctp_ecn_enable = 1;
uint32_t sctp_ecn_nonce = 0;
uint32_t sctp_strict_sacks = 0;
uint32_t sctp_no_csum_on_loopback = 1;
uint32_t sctp_strict_init = 1;
uint32_t sctp_abort_if_one_2_one_hits_limit = 0;
uint32_t sctp_strict_data_order = 0;

uint32_t sctp_peer_chunk_oh = sizeof(struct mbuf);
uint32_t sctp_max_burst_default = SCTP_DEF_MAX_BURST;
uint32_t sctp_use_cwnd_based_maxburst = 1;
uint32_t sctp_do_drain = 1;
uint32_t sctp_hb_maxburst = SCTP_DEF_MAX_BURST;

uint32_t sctp_max_chunks_on_queue = SCTP_ASOC_MAX_CHUNKS_ON_QUEUE;
uint32_t sctp_delayed_sack_time_default = SCTP_RECV_MSEC;
uint32_t sctp_sack_freq_default = SCTP_DEFAULT_SACK_FREQ;
uint32_t sctp_heartbeat_interval_default = SCTP_HB_DEFAULT_MSEC;
uint32_t sctp_pmtu_raise_time_default = SCTP_DEF_PMTU_RAISE_SEC;
uint32_t sctp_shutdown_guard_time_default = SCTP_DEF_MAX_SHUTDOWN_SEC;
uint32_t sctp_secret_lifetime_default = SCTP_DEFAULT_SECRET_LIFE_SEC;
uint32_t sctp_rto_max_default = SCTP_RTO_UPPER_BOUND;
uint32_t sctp_rto_min_default = SCTP_RTO_LOWER_BOUND;
uint32_t sctp_rto_initial_default = SCTP_RTO_INITIAL;
uint32_t sctp_init_rto_max_default = SCTP_RTO_UPPER_BOUND;
uint32_t sctp_valid_cookie_life_default = SCTP_DEFAULT_COOKIE_LIFE;
uint32_t sctp_init_rtx_max_default = SCTP_DEF_MAX_INIT;
uint32_t sctp_assoc_rtx_max_default = SCTP_DEF_MAX_SEND;
uint32_t sctp_path_rtx_max_default = SCTP_DEF_MAX_PATH_RTX;
uint32_t sctp_nr_outgoing_streams_default = SCTP_OSTREAM_INITIAL;
uint32_t sctp_add_more_threshold = SCTP_DEFAULT_ADD_MORE;
uint32_t sctp_asoc_free_resc_limit = SCTP_DEF_ASOC_RESC_LIMIT;
uint32_t sctp_system_free_resc_limit = SCTP_DEF_SYSTEM_RESC_LIMIT;

uint32_t sctp_min_split_point = SCTP_DEFAULT_SPLIT_POINT_MIN;
uint32_t sctp_pcbtblsize = SCTP_PCBHASHSIZE;
uint32_t sctp_hashtblsize = SCTP_TCBHASHSIZE;
uint32_t sctp_chunkscale = SCTP_CHUNKQUEUE_SCALE;

uint32_t sctp_cmt_on_off = 0;
uint32_t sctp_cmt_use_dac = 0;
uint32_t sctp_max_retran_chunk = SCTPCTL_MAX_RETRAN_CHUNK_DEFAULT;


uint32_t sctp_L2_abc_variable = 1;
uint32_t sctp_early_fr = 0;
uint32_t sctp_early_fr_msec = SCTP_MINFR_MSEC_TIMER;
uint32_t sctp_says_check_for_deadlock = 0;
uint32_t sctp_asconf_auth_nochk = 0;
uint32_t sctp_auth_disable = 0;
uint32_t sctp_nat_friendly = 1;
uint32_t sctp_min_residual = SCTPCTL_MIN_RESIDUAL_DEFAULT;;


struct sctpstat sctpstat;

#ifdef SCTP_DEBUG
uint32_t sctp_debug_on = 0x7ff3ffff;
#endif

#if defined(__APPLE__)
uint32_t sctp_main_timer = SCTP_MAIN_TIMER_DEFAULT;
#endif

/*
 * sysctl functions
 */
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

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, outgoing_streams, CTLFLAG_RW,
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
    "Early Fast Retransmit with timer");

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
    "Disable SCTP AUTH function");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, nat_friendly, CTLFLAG_RW,
    &sctp_nat_friendly, 0,
    "SCTP NAT friendly operation");

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
    "Confirmation Heartbeat max burst?");

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

SYSCTL_INT(_net_inet_sctp, OID_AUTO, min_residual, CTLFLAG_RW,
	   &sctp_min_residual, 0,
	   SCTPCTL_MIN_RESIDUAL_DESC);

SYSCTL_INT(_net_inet_sctp, OID_AUTO, max_retran_chunk, CTLFLAG_RW,
	   &sctp_max_retran_chunk, 0,
	   SCTPCTL_MAX_RETRAN_CHUNK_DESC);

#ifdef SCTP_DEBUG
SYSCTL_INT(_net_inet_sctp, OID_AUTO, debug, CTLFLAG_RW,
    &sctp_debug_on, 0, "Configure debug output");
#endif				/* SCTP_DEBUG */
#if defined(__APPLE__)
SYSCTL_INT(_net_inet_sctp, OID_AUTO, main_timer, CTLFLAG_RW,
    &sctp_main_timer, 0, "Main timer interval in ms");
#endif

#elif defined(__OpenBSD__)
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
	case SCTPCTL_NAT_FRIENDLY:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &sctp_nat_friendly));
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

#elif defined(__NetBSD__)
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
	    CTLTYPE_INT, "strict_sacks",
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
	    NULL, 0, &sctp_chunkscale, 0,
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
	    SYSCTL_DESCR("Default secret lifetime in sec"),
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
	    CTLTYPE_INT, "outgoing_streams",
	    SYSCTL_DESCR("Default number of outgoing streams"),
	    NULL, 0, &sctp_nr_outgoing_streams_default, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_NR_OUTGOING_STREAMS,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "cmt_on_off",
	    SYSCTL_DESCR("CMT on/off flag"),
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
	    SYSCTL_DESCR("Early Fast Retransmit with timer"),
	    NULL, 0, &sctp_early_fr, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_EARLY_FR,
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
	    SYSCTL_DESCR("Early Fast Retransmit minimum timer value"),
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
	    SYSCTL_DESCR("Disable SCTP AUTH function"),
	    NULL, 0, &sctp_auth_disable, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_AUTH_DISABLE,
	    CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "nat_friendly",
	    SYSCTL_DESCR("SCTP NAT friendly operation"),
	    NULL, 0, &sctp_nat_friendly, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_NAT_FRIENDLY,
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
	    SYSCTL_DESCR("CMT DAC on/off flag"),
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

#ifdef SCTP_DEBUG
	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "debug",
	    SYSCTL_DESCR("Configure debug output"),
	    NULL, 0, &sctp_debug_on, 0,
	    CTL_NET, PF_INET, IPPROTO_SCTP, SCTPCTL_DEBUG,
	    CTL_EOL);
#endif /* SCTP_DEBUG */
}

#endif
