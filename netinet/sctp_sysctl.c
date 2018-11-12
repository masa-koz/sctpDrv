/*-
 * Copyright (c) 2007, by Cisco Systems, Inc. All rights reserved.
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
__FBSDID("$FreeBSD: head/sys/netinet/sctp_sysctl.c 185694 2008-12-06 13:19:54Z rrs $");
#endif

#include <netinet/sctp_os.h>
#include <netinet/sctp.h>
#include <netinet/sctp_constants.h>
#include <netinet/sctp_sysctl.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_output.h>

/*
 * sysctl tunable variables
 */

void
sctp_init_sysctls()
{
	SCTP_BASE_SYSCTL(sctp_sendspace) = SCTPCTL_MAXDGRAM_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_recvspace) = SCTPCTL_RECVSPACE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_auto_asconf) = SCTPCTL_AUTOASCONF_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_multiple_asconfs) = SCTPCTL_MULTIPLEASCONFS_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_ecn_enable) = SCTPCTL_ECN_ENABLE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_ecn_nonce) = SCTPCTL_ECN_NONCE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_strict_sacks) = SCTPCTL_STRICT_SACKS_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_no_csum_on_loopback) = SCTPCTL_LOOPBACK_NOCSUM_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_strict_init) = SCTPCTL_STRICT_INIT_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_peer_chunk_oh) = SCTPCTL_PEER_CHKOH_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_max_burst_default) = SCTPCTL_MAXBURST_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_max_chunks_on_queue) = SCTPCTL_MAXCHUNKS_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_hashtblsize) = SCTPCTL_TCBHASHSIZE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_pcbtblsize) = SCTPCTL_PCBHASHSIZE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_min_split_point) = SCTPCTL_MIN_SPLIT_POINT_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_chunkscale) = SCTPCTL_CHUNKSCALE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_delayed_sack_time_default) = SCTPCTL_DELAYED_SACK_TIME_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_sack_freq_default) = SCTPCTL_SACK_FREQ_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_system_free_resc_limit) = SCTPCTL_SYS_RESOURCE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_asoc_free_resc_limit) = SCTPCTL_ASOC_RESOURCE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_heartbeat_interval_default) = SCTPCTL_HEARTBEAT_INTERVAL_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_pmtu_raise_time_default) = SCTPCTL_PMTU_RAISE_TIME_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_shutdown_guard_time_default) = SCTPCTL_SHUTDOWN_GUARD_TIME_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_secret_lifetime_default) = SCTPCTL_SECRET_LIFETIME_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_rto_max_default) = SCTPCTL_RTO_MAX_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_rto_min_default) = SCTPCTL_RTO_MIN_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_rto_initial_default) = SCTPCTL_RTO_INITIAL_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_init_rto_max_default) = SCTPCTL_INIT_RTO_MAX_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_valid_cookie_life_default) = SCTPCTL_VALID_COOKIE_LIFE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_init_rtx_max_default) = SCTPCTL_INIT_RTX_MAX_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_assoc_rtx_max_default) = SCTPCTL_ASSOC_RTX_MAX_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_path_rtx_max_default) = SCTPCTL_PATH_RTX_MAX_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_add_more_threshold) = SCTPCTL_ADD_MORE_ON_OUTPUT_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_nr_outgoing_streams_default) = SCTPCTL_OUTGOING_STREAMS_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_cmt_on_off) = SCTPCTL_CMT_ON_OFF_DEFAULT;
	/* EY */
	SCTP_BASE_SYSCTL(sctp_nr_sack_on_off) = SCTPCTL_NR_SACK_ON_OFF_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_cmt_use_dac) = SCTPCTL_CMT_USE_DAC_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_cmt_pf) = SCTPCTL_CMT_PF_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_use_cwnd_based_maxburst) = SCTPCTL_CWND_MAXBURST_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_early_fr) = SCTPCTL_EARLY_FAST_RETRAN_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_early_fr_msec) = SCTPCTL_EARLY_FAST_RETRAN_MSEC_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_asconf_auth_nochk) = SCTPCTL_ASCONF_AUTH_NOCHK_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_auth_disable) = SCTPCTL_AUTH_DISABLE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_nat_friendly) = SCTPCTL_NAT_FRIENDLY_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_L2_abc_variable) = SCTPCTL_ABC_L_VAR_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_mbuf_threshold_count) = SCTPCTL_MAX_CHAINED_MBUFS_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_do_drain) = SCTPCTL_DO_SCTP_DRAIN_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_hb_maxburst) = SCTPCTL_HB_MAX_BURST_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_abort_if_one_2_one_hits_limit) = SCTPCTL_ABORT_AT_LIMIT_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_strict_data_order) = SCTPCTL_STRICT_DATA_ORDER_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_min_residual) = SCTPCTL_MIN_RESIDUAL_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_max_retran_chunk) = SCTPCTL_MAX_RETRAN_CHUNK_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_logging_level) = SCTPCTL_LOGGING_LEVEL_DEFAULT;
	/* JRS - Variable for default congestion control module */
	SCTP_BASE_SYSCTL(sctp_default_cc_module) = SCTPCTL_DEFAULT_CC_MODULE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_default_frag_interleave) = SCTPCTL_DEFAULT_FRAG_INTERLEAVE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_mobility_base) = SCTPCTL_MOBILITY_BASE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_mobility_fasthandoff) = SCTPCTL_MOBILITY_FASTHANDOFF_DEFAULT;
#if defined(SCTP_LOCAL_TRACE_BUF)
#if defined(__Windows__)
	MALLOC(SCTP_BASE_SYSCTL(sctp_log), struct sctp_log *, sizeof(struct sctp_log), M_SYSCTL, M_ZERO);
#else
	memset(&SCTP_BASE_SYSCTL(sctp_log), 0, sizeof(struct sctp_log));
#endif
#endif
	SCTP_BASE_SYSCTL(sctp_udp_tunneling_for_client_enable) = SCTPCTL_UDP_TUNNELING_FOR_CLIENT_ENABLE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_udp_tunneling_port) = SCTPCTL_UDP_TUNNELING_PORT_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_enable_sack_immediately) = SCTPCTL_SACK_IMMEDIATELY_ENABLE_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_inits_include_nat_friendly) = SCTPCTL_NAT_FRIENDLY_DEFAULT;	
#if defined(SCTP_DEBUG)
	SCTP_BASE_SYSCTL(sctp_debug_on) = SCTPCTL_DEBUG_DEFAULT;
#endif
#if defined(__APPLE__)
	SCTP_BASE_SYSCTL(sctp_ignore_vmware_interfaces) = SCTPCTL_IGNORE_VMWARE_INTERFACES_DEFAULT;
	SCTP_BASE_SYSCTL(sctp_main_timer) = SCTPCTL_MAIN_TIMER_DEFAULT;
#endif
#if defined(__APPLE__) || defined(SCTP_SO_LOCK_TESTING)
	SCTP_BASE_SYSCTL(sctp_output_unlocked) = SCTPCTL_OUTPUT_UNLOCKED_DEFAULT;
#endif
}

#if defined(__Windows__)
void
sctp_finish_sysctls()
{
#if defined(SCTP_LOCAL_TRACE_BUF)
	if (SCTP_BASE_SYSCTL(sctp_log) != NULL) {
		FREE(SCTP_BASE_SYSCTL(sctp_log), M_SYSCTL);
		SCTP_BASE_SYSCTL(sctp_log) = NULL;
	}
#endif
}
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__Windows__)
/* It returns an upper limit. No filtering is done here */
static unsigned int
number_of_addresses(struct sctp_inpcb *inp)
{
	int cnt;
	struct sctp_vrf *vrf;
	struct sctp_ifn *sctp_ifn;
	struct sctp_ifa *sctp_ifa;
	struct sctp_laddr *laddr;

	cnt = 0;
	/* neither Mac OS X nor FreeBSD support mulitple routing functions */
	if ((vrf = sctp_find_vrf(inp->def_vrf_id)) == NULL) {
		return(0);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		LIST_FOREACH(sctp_ifn, &vrf->ifnlist, next_ifn) {
			LIST_FOREACH(sctp_ifa, &sctp_ifn->ifalist, next_ifa) {
				if ((sctp_ifa->address.sa.sa_family == AF_INET) ||
				    (sctp_ifa->address.sa.sa_family == AF_INET6)) {
					cnt++;
				}
			}
		}
	} else {
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if ((laddr->ifa->address.sa.sa_family == AF_INET) ||
			    (laddr->ifa->address.sa.sa_family == AF_INET6)) {
				cnt++;
			}
		}
	}
	return (cnt);
}

static int
#if !defined(__Windows__)
copy_out_local_addresses(struct sctp_inpcb *inp, struct sctp_tcb *stcb, struct sysctl_req *req)
#else
copy_out_local_addresses(struct sctp_inpcb *inp, struct sctp_tcb *stcb, struct sysctl_req *req, KIRQL oldIrql)
#endif
{
	struct sctp_ifn *sctp_ifn;
	struct sctp_ifa *sctp_ifa;
	int loopback_scope, ipv4_local_scope, local_scope, site_scope;
	int ipv4_addr_legal, ipv6_addr_legal;
	struct sctp_vrf *vrf;
	struct xsctp_laddr xladdr;
	struct sctp_laddr *laddr;
	int error;

	/* Turn on all the appropriate scope */
	if (stcb) {
		/* use association specific values */
		loopback_scope = stcb->asoc.loopback_scope;
		ipv4_local_scope = stcb->asoc.ipv4_local_scope;
		local_scope = stcb->asoc.local_scope;
		site_scope = stcb->asoc.site_scope;
	} else {
		/* use generic values for endpoints */
		loopback_scope = 1;
		ipv4_local_scope = 1;
		local_scope = 1;
		site_scope = 1;
	}

	/* use only address families of interest */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
		ipv6_addr_legal = 1;
		if (SCTP_IPV6_V6ONLY(inp)) {
			ipv4_addr_legal = 0;
		} else {
			ipv4_addr_legal = 1;
		}
	} else {
		ipv4_addr_legal = 1;
		ipv6_addr_legal = 0;
	}

	error = 0;

	/* neither Mac OS X nor FreeBSD support mulitple routing functions */
	if ((vrf = sctp_find_vrf(inp->def_vrf_id)) == NULL) {
		SCTP_INP_RUNLOCK(inp);
		SCTP_INP_INFO_RUNLOCK();
		return (-1);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		LIST_FOREACH(sctp_ifn, &vrf->ifnlist, next_ifn) {
			if ((loopback_scope == 0) && SCTP_IFN_IS_IFT_LOOP(sctp_ifn))
				/* Skip loopback if loopback_scope not set */
				continue;
			LIST_FOREACH(sctp_ifa, &sctp_ifn->ifalist, next_ifa) {
				if (stcb) {
					/* ignore if blacklisted at association level */
					if (sctp_is_addr_restricted(stcb, sctp_ifa))
						continue;
				}
				switch (sctp_ifa->address.sa.sa_family) {
				case AF_INET:
					if (ipv4_addr_legal) {
						struct sockaddr_in *sin;

						sin = (struct sockaddr_in *)&sctp_ifa->address.sa;
						if (sin->sin_addr.s_addr == 0)
							continue;
						if ((ipv4_local_scope == 0) && (IN4_ISPRIVATE_ADDRESS(&sin->sin_addr)))
							continue;
					} else {
						continue;
					}
					break;
#ifdef INET6
				case AF_INET6:
					if (ipv6_addr_legal) {
						struct sockaddr_in6 *sin6;

#if defined(SCTP_EMBEDDED_V6_SCOPE) && !defined(SCTP_KAME)
						struct sockaddr_in6 lsa6;
#endif
						sin6 = (struct sockaddr_in6 *)&sctp_ifa->address.sa;
						if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
							continue;
						if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
							if (local_scope == 0)
								continue;
#if defined(SCTP_EMBEDDED_V6_SCOPE)
							if (sin6->sin6_scope_id == 0) {
#ifdef SCTP_KAME
								/* bad link local address */
								if (sa6_recoverscope(sin6) != 0)
									continue;
#else
								lsa6 = *sin6;
								/* bad link local address */
								if (in6_recoverscope(&lsa6, &lsa6.sin6_addr, NULL))
									continue;
								sin6 = &lsa6;
#endif				/* SCTP_KAME */
							}
#endif /* SCTP_EMBEDDED_V6_SCOPE */
						}
						if ((site_scope == 0) && (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)))
							continue;
					} else {
						continue;
					}
					break;
#endif
				default:
					continue;
				}
				memset((void *)&xladdr, 0, sizeof(struct xsctp_laddr));
				memcpy((void *)&xladdr.address, (const void *)&sctp_ifa->address, sizeof(union sctp_sockstore));
				SCTP_INP_RUNLOCK(inp);
				SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
				KeLowerIrql(oldIrql);
#endif
				error = SYSCTL_OUT(req, &xladdr, sizeof(struct xsctp_laddr));
#if defined(__Windows__)
				KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
				if (error) {
					return (error);
				} else {
					SCTP_INP_INFO_RLOCK();
					SCTP_INP_RLOCK(inp);
				}
			}
		}
	} else {
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			/* ignore if blacklisted at association level */
			if (stcb && sctp_is_addr_restricted(stcb, laddr->ifa))
				continue;
			memset((void *)&xladdr, 0, sizeof(struct xsctp_laddr));
			memcpy((void *)&xladdr.address, (const void *)&laddr->ifa->address, sizeof(union sctp_sockstore));
			xladdr.start_time.tv_sec = (uint32_t)laddr->start_time.tv_sec;
			xladdr.start_time.tv_usec = (uint32_t)laddr->start_time.tv_usec;
			SCTP_INP_RUNLOCK(inp);
			SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
			KeLowerIrql(oldIrql);
#endif
			error = SYSCTL_OUT(req, &xladdr, sizeof(struct xsctp_laddr));
#if defined(__Windows__)
			KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
			if (error) {
				return (error);
			} else {
				SCTP_INP_INFO_RLOCK();
				SCTP_INP_RLOCK(inp);
			}
		}
	}
	memset((void *)&xladdr, 0, sizeof(struct xsctp_laddr));
	xladdr.last = 1;
	SCTP_INP_RUNLOCK(inp);
	SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
	KeLowerIrql(oldIrql);
#endif
	error = SYSCTL_OUT(req, &xladdr, sizeof(struct xsctp_laddr));
#if defined(__Windows__)
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif

	if (error) {
		return (error);
	} else {
		SCTP_INP_INFO_RLOCK();
		SCTP_INP_RLOCK(inp);
		return (0);
	}
}

/*
 * sysctl functions
 */
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
	struct xsctp_inpcb xinpcb;
	struct xsctp_tcb xstcb;
	struct xsctp_raddr xraddr;
#if defined(__Windows__)
	KIRQL oldIrql;
#endif

	number_of_endpoints = 0;
	number_of_local_addresses = 0;
	number_of_associations = 0;
	number_of_remote_addresses = 0;

#if defined(__Windows__)
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
	SCTP_INP_INFO_RLOCK();
#if !defined(__Windows__)
	if (req->oldptr == USER_ADDR_NULL) {
#else
	if (req->data == NULL) {
#endif
		LIST_FOREACH(inp, &SCTP_BASE_INFO(listhead), sctp_list) {
			SCTP_INP_RLOCK(inp);
			number_of_endpoints++;
			number_of_local_addresses += number_of_addresses(inp);
			LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
				number_of_associations++;
			        number_of_local_addresses += number_of_addresses(inp);
				TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
					number_of_remote_addresses++;
				}
			}
			SCTP_INP_RUNLOCK(inp);
		}
		SCTP_INP_INFO_RUNLOCK();
		n = (number_of_endpoints + 1) * sizeof(struct xsctp_inpcb) +
		    (number_of_local_addresses + number_of_endpoints + number_of_associations) * sizeof(struct xsctp_laddr) +
		    (number_of_associations + number_of_endpoints) * sizeof(struct xsctp_tcb) +
		    (number_of_remote_addresses + number_of_associations) * sizeof(struct xsctp_raddr);

		/* request some more memory than needed */
#if !defined(__Windows__)
		req->oldidx = (n + n/8);
#else
		req->dataidx = (n + n/8);
		KeLowerIrql(oldIrql);
#endif
		return 0;
	}

#if !defined(__Windows__)
	if (req->newptr != USER_ADDR_NULL) {
#else
	if (req->new_data != NULL) {
#endif
		SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
		KeLowerIrql(oldIrql);
#endif
		SCTP_LTRACE_ERR_RET(NULL, NULL, NULL, SCTP_FROM_SCTP_SYSCTL, EPERM);
		return EPERM;
	}

	LIST_FOREACH(inp, &SCTP_BASE_INFO(listhead), sctp_list) {
		SCTP_INP_RLOCK(inp);
		xinpcb.last                   = 0;
		xinpcb.local_port             = ntohs(inp->sctp_lport);
		xinpcb.flags                  = inp->sctp_flags;
		xinpcb.features               = inp->sctp_features;
		xinpcb.total_sends            = inp->total_sends;
		xinpcb.total_recvs            = inp->total_recvs;
		xinpcb.total_nospaces         = inp->total_nospaces;
		xinpcb.fragmentation_point    = inp->sctp_frag_point;
		if ((inp->sctp_flags & SCTP_PCB_FLAGS_SOCKET_ALLGONE) ||
		    (inp->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)) {
			xinpcb.qlen                   = 0;
			xinpcb.maxqlen                = 0;
		} else {
			xinpcb.qlen                   = inp->sctp_socket->so_qlen;
			xinpcb.maxqlen                = inp->sctp_socket->so_qlimit;
		}
		SCTP_INP_INCR_REF(inp);
		SCTP_INP_RUNLOCK(inp);
		SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
		KeLowerIrql(oldIrql);
#endif
		error = SYSCTL_OUT(req, &xinpcb, sizeof(struct xsctp_inpcb));
#if defined(__Windows__)
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
		if (error) {
			SCTP_INP_DECR_REF(inp);
#if defined(__Windows__)
			KeLowerIrql(oldIrql);
#endif
			return error;
		}
		SCTP_INP_INFO_RLOCK();
		SCTP_INP_RLOCK(inp);
#if !defined(__Windows__)
		error = copy_out_local_addresses(inp, NULL, req);
#else
		error = copy_out_local_addresses(inp, NULL, req, oldIrql);
#endif
		if (error) {
			SCTP_INP_DECR_REF(inp);
#if defined(__Windows__)
			KeLowerIrql(oldIrql);
#endif
			return error;
		}
		LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
			SCTP_TCB_LOCK(stcb);
			atomic_add_int(&stcb->asoc.refcnt, 1);
			SCTP_TCB_UNLOCK(stcb);
			xstcb.last = 0;
			xstcb.local_port = ntohs(inp->sctp_lport);
			xstcb.remote_port = ntohs(stcb->rport);
			if (stcb->asoc.primary_destination != NULL)
				xstcb.primary_addr = stcb->asoc.primary_destination->ro._l_addr;
			xstcb.heartbeat_interval = stcb->asoc.heart_beat_delay;
			xstcb.state = SCTP_GET_STATE(&stcb->asoc); /* FIXME */
			xstcb.in_streams = stcb->asoc.streamincnt;
			xstcb.out_streams = stcb->asoc.streamoutcnt;
			xstcb.max_nr_retrans = stcb->asoc.overall_error_count;
			xstcb.primary_process = 0; /* not really supported yet */
			xstcb.T1_expireries = stcb->asoc.timoinit + stcb->asoc.timocookie;
			xstcb.T2_expireries = stcb->asoc.timoshutdown + stcb->asoc.timoshutdownack;
			xstcb.retransmitted_tsns = stcb->asoc.marked_retrans;
			xstcb.start_time.tv_sec = (uint32_t)stcb->asoc.start_time.tv_sec;
			xstcb.start_time.tv_usec = (uint32_t)stcb->asoc.start_time.tv_usec;
			xstcb.discontinuity_time.tv_sec = (uint32_t)stcb->asoc.discontinuity_time.tv_sec;
			xstcb.discontinuity_time.tv_usec = (uint32_t)stcb->asoc.discontinuity_time.tv_usec;
			xstcb.total_sends = stcb->total_sends;
			xstcb.total_recvs = stcb->total_recvs;
			xstcb.local_tag = stcb->asoc.my_vtag;
			xstcb.remote_tag = stcb->asoc.peer_vtag;
			xstcb.initial_tsn = stcb->asoc.init_seq_number;
			xstcb.highest_tsn = stcb->asoc.sending_seq - 1;
			xstcb.cumulative_tsn = stcb->asoc.last_acked_seq;
			xstcb.cumulative_tsn_ack = stcb->asoc.cumulative_tsn;
			xstcb.mtu = stcb->asoc.smallest_mtu;
			xstcb.peers_rwnd = stcb->asoc.peers_rwnd;
			xstcb.refcnt = stcb->asoc.refcnt;
			SCTP_INP_RUNLOCK(inp);
			SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
			KeLowerIrql(oldIrql);
#endif
			error = SYSCTL_OUT(req, &xstcb, sizeof(struct xsctp_tcb));
#if defined(__Windows__)
			KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
			if (error) {
				SCTP_INP_DECR_REF(inp);
#if defined(__Windows__)
				KeLowerIrql(oldIrql);
#endif
				atomic_subtract_int(&stcb->asoc.refcnt, 1);
				return error;
			}
			SCTP_INP_INFO_RLOCK();
			SCTP_INP_RLOCK(inp);
#if !defined(__Windows__)
			error = copy_out_local_addresses(inp, stcb, req);
#else
			error = copy_out_local_addresses(inp, stcb, req, oldIrql);
#endif
			if (error) {
				SCTP_INP_DECR_REF(inp);
#if defined(__Windows__)
				KeLowerIrql(oldIrql);
#endif
				atomic_subtract_int(&stcb->asoc.refcnt, 1);
				return error;
			}
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				xraddr.last = 0;
				xraddr.address = net->ro._l_addr;
				xraddr.active = ((net->dest_state & SCTP_ADDR_REACHABLE) == SCTP_ADDR_REACHABLE);
				xraddr.confirmed = ((net->dest_state & SCTP_ADDR_UNCONFIRMED) == 0);
				xraddr.heartbeat_enabled = ((net->dest_state & SCTP_ADDR_NOHB) == 0);
				xraddr.rto = net->RTO;
				xraddr.max_path_rtx = net->failure_threshold;
				xraddr.rtx = net->marked_retrans;
				xraddr.error_counter = net->error_count;
				xraddr.cwnd = net->cwnd;
				xraddr.flight_size = net->flight_size;
				xraddr.mtu = net->mtu;
				xraddr.start_time.tv_sec = (uint32_t)net->start_time.tv_sec;
				xraddr.start_time.tv_usec = (uint32_t)net->start_time.tv_usec;
				SCTP_INP_RUNLOCK(inp);
				SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
				KeLowerIrql(oldIrql);
#endif
				error = SYSCTL_OUT(req, &xraddr, sizeof(struct xsctp_raddr));
#if defined(__Windows__)
				KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
				if (error) {
					SCTP_INP_DECR_REF(inp);
#if defined(__Windows__)
					KeLowerIrql(oldIrql);
#endif
					atomic_subtract_int(&stcb->asoc.refcnt, 1);
					return error;
				}
				SCTP_INP_INFO_RLOCK();
				SCTP_INP_RLOCK(inp);
			}
			atomic_subtract_int(&stcb->asoc.refcnt, 1);
			memset((void *)&xraddr, 0, sizeof(struct xsctp_raddr));
			xraddr.last = 1;
			SCTP_INP_RUNLOCK(inp);
			SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
			KeLowerIrql(oldIrql);
#endif
			error = SYSCTL_OUT(req, &xraddr, sizeof(struct xsctp_raddr));
#if defined(__Windows__)
			KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
			if (error) {
				SCTP_INP_DECR_REF(inp);
#if defined(__Windows__)
				KeLowerIrql(oldIrql);
#endif
				return error;
			}
			SCTP_INP_INFO_RLOCK();
			SCTP_INP_RLOCK(inp);
		}
		SCTP_INP_DECR_REF(inp);
		SCTP_INP_RUNLOCK(inp);
		SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
		KeLowerIrql(oldIrql);
#endif
		memset((void *)&xstcb, 0, sizeof(struct xsctp_tcb));
		xstcb.last = 1;
		error = SYSCTL_OUT(req, &xstcb, sizeof(struct xsctp_tcb));
		if (error) {
			return error;
		}
#if defined(__Windows__)
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
#endif
		SCTP_INP_INFO_RLOCK();
	}
	SCTP_INP_INFO_RUNLOCK();
#if defined(__Windows__)
	KeLowerIrql(oldIrql);
#endif

	memset((void *)&xinpcb, 0, sizeof(struct xsctp_inpcb));
	xinpcb.last = 1;
	error = SYSCTL_OUT(req, &xinpcb, sizeof(struct xsctp_inpcb));
	return error;
}


#if !defined(__Windows__)
#define RANGECHK(var, min, max) \
	if ((var) < (min)) { (var) = (min); } \
	else if ((var) > (max)) { (var) = (max); }
#else
#define RANGECHK(var, min, max) \
	if ((var) <= (min)) { (var) = (min); } \
	else if ((var) >= (max)) { (var) = (max); }
#endif

static int
#if defined (__APPLE__)
sysctl_sctp_udp_tunneling_check SYSCTL_HANDLER_ARGS
#else
sysctl_sctp_udp_tunneling_check(SYSCTL_HANDLER_ARGS)
#endif
{
	int error;
	uint32_t old_sctp_udp_tunneling_port;

	old_sctp_udp_tunneling_port = SCTP_BASE_SYSCTL(sctp_udp_tunneling_port);
	error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (error == 0) {
		RANGECHK(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port), SCTPCTL_UDP_TUNNELING_PORT_MIN, SCTPCTL_UDP_TUNNELING_PORT_MAX);
#if !defined(__Windows__)
		if (old_sctp_udp_tunneling_port) {
			sctp_over_udp_stop();
		}
		if (SCTP_BASE_SYSCTL(sctp_udp_tunneling_port)) {
			if (sctp_over_udp_start()) {
				SCTP_BASE_SYSCTL(sctp_udp_tunneling_port) = 0;
			}
		}
#else
		sctp_over_udp_restart();
#endif
	}
	return (error);
}

#if defined (__APPLE__)
int sctp_is_vmware_interface(struct ifnet *);

static int
sysctl_sctp_vmware_interfaces_check SYSCTL_HANDLER_ARGS
{
	int error;
	uint32_t old_sctp_ignore_vmware_interfaces;

	old_sctp_ignore_vmware_interfaces = SCTP_BASE_SYSCTL(sctp_ignore_vmware_interfaces);
	error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (error == 0) {
		RANGECHK(SCTP_BASE_SYSCTL(sctp_ignore_vmware_interfaces), SCTPCTL_IGNORE_VMWARE_INTERFACES_MIN, SCTPCTL_IGNORE_VMWARE_INTERFACES_MAX);
		if (old_sctp_ignore_vmware_interfaces  && !SCTP_BASE_SYSCTL(sctp_ignore_vmware_interfaces)) {
			sctp_add_or_del_interfaces(sctp_is_vmware_interface, 1);
		}
		if (!old_sctp_ignore_vmware_interfaces  && SCTP_BASE_SYSCTL(sctp_ignore_vmware_interfaces)) {
			sctp_add_or_del_interfaces(sctp_is_vmware_interface, 0);
		}
	}
	return (error);
}
#endif

static int
#if defined (__APPLE__)
sysctl_sctp_check SYSCTL_HANDLER_ARGS
#else
sysctl_sctp_check(SYSCTL_HANDLER_ARGS)
#endif
{
	int error;

	error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (error == 0) {
		RANGECHK(SCTP_BASE_SYSCTL(sctp_sendspace), SCTPCTL_MAXDGRAM_MIN, SCTPCTL_MAXDGRAM_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_recvspace), SCTPCTL_RECVSPACE_MIN, SCTPCTL_RECVSPACE_MAX);
#if defined(__FreeBSD__) || defined(SCTP_APPLE_AUTO_ASCONF)
		RANGECHK(SCTP_BASE_SYSCTL(sctp_auto_asconf), SCTPCTL_AUTOASCONF_MIN, SCTPCTL_AUTOASCONF_MAX);
#endif
		RANGECHK(SCTP_BASE_SYSCTL(sctp_ecn_enable), SCTPCTL_ECN_ENABLE_MIN, SCTPCTL_ECN_ENABLE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_ecn_nonce), SCTPCTL_ECN_NONCE_MIN, SCTPCTL_ECN_NONCE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_strict_sacks), SCTPCTL_STRICT_SACKS_MIN, SCTPCTL_STRICT_SACKS_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_no_csum_on_loopback), SCTPCTL_LOOPBACK_NOCSUM_MIN, SCTPCTL_LOOPBACK_NOCSUM_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_strict_init), SCTPCTL_STRICT_INIT_MIN, SCTPCTL_STRICT_INIT_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_peer_chunk_oh), SCTPCTL_PEER_CHKOH_MIN, SCTPCTL_PEER_CHKOH_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_max_burst_default), SCTPCTL_MAXBURST_MIN, SCTPCTL_MAXBURST_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_max_chunks_on_queue), SCTPCTL_MAXCHUNKS_MIN, SCTPCTL_MAXCHUNKS_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_hashtblsize), SCTPCTL_TCBHASHSIZE_MIN, SCTPCTL_TCBHASHSIZE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_pcbtblsize), SCTPCTL_PCBHASHSIZE_MIN, SCTPCTL_PCBHASHSIZE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_min_split_point), SCTPCTL_MIN_SPLIT_POINT_MIN, SCTPCTL_MIN_SPLIT_POINT_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_chunkscale), SCTPCTL_CHUNKSCALE_MIN, SCTPCTL_CHUNKSCALE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_delayed_sack_time_default), SCTPCTL_DELAYED_SACK_TIME_MIN, SCTPCTL_DELAYED_SACK_TIME_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_sack_freq_default), SCTPCTL_SACK_FREQ_MIN, SCTPCTL_SACK_FREQ_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_system_free_resc_limit), SCTPCTL_SYS_RESOURCE_MIN, SCTPCTL_SYS_RESOURCE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_asoc_free_resc_limit), SCTPCTL_ASOC_RESOURCE_MIN, SCTPCTL_ASOC_RESOURCE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_heartbeat_interval_default), SCTPCTL_HEARTBEAT_INTERVAL_MIN, SCTPCTL_HEARTBEAT_INTERVAL_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_pmtu_raise_time_default), SCTPCTL_PMTU_RAISE_TIME_MIN, SCTPCTL_PMTU_RAISE_TIME_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_shutdown_guard_time_default), SCTPCTL_SHUTDOWN_GUARD_TIME_MIN, SCTPCTL_SHUTDOWN_GUARD_TIME_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_secret_lifetime_default), SCTPCTL_SECRET_LIFETIME_MIN, SCTPCTL_SECRET_LIFETIME_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_rto_max_default), SCTPCTL_RTO_MAX_MIN, SCTPCTL_RTO_MAX_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_rto_min_default), SCTPCTL_RTO_MIN_MIN, SCTPCTL_RTO_MIN_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_rto_initial_default), SCTPCTL_RTO_INITIAL_MIN, SCTPCTL_RTO_INITIAL_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_init_rto_max_default), SCTPCTL_INIT_RTO_MAX_MIN, SCTPCTL_INIT_RTO_MAX_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_valid_cookie_life_default), SCTPCTL_VALID_COOKIE_LIFE_MIN, SCTPCTL_VALID_COOKIE_LIFE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_init_rtx_max_default), SCTPCTL_INIT_RTX_MAX_MIN, SCTPCTL_INIT_RTX_MAX_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_assoc_rtx_max_default), SCTPCTL_ASSOC_RTX_MAX_MIN, SCTPCTL_ASSOC_RTX_MAX_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_path_rtx_max_default), SCTPCTL_PATH_RTX_MAX_MIN, SCTPCTL_PATH_RTX_MAX_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_add_more_threshold), SCTPCTL_ADD_MORE_ON_OUTPUT_MIN, SCTPCTL_ADD_MORE_ON_OUTPUT_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_nr_outgoing_streams_default), SCTPCTL_OUTGOING_STREAMS_MIN, SCTPCTL_OUTGOING_STREAMS_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_cmt_on_off), SCTPCTL_CMT_ON_OFF_MIN, SCTPCTL_CMT_ON_OFF_MAX);
		/* EY */
		RANGECHK(SCTP_BASE_SYSCTL(sctp_nr_sack_on_off), SCTPCTL_NR_SACK_ON_OFF_MIN, SCTPCTL_NR_SACK_ON_OFF_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_cmt_use_dac), SCTPCTL_CMT_USE_DAC_MIN, SCTPCTL_CMT_USE_DAC_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_cmt_pf), SCTPCTL_CMT_PF_MIN, SCTPCTL_CMT_PF_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_use_cwnd_based_maxburst), SCTPCTL_CWND_MAXBURST_MIN, SCTPCTL_CWND_MAXBURST_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_early_fr), SCTPCTL_EARLY_FAST_RETRAN_MIN, SCTPCTL_EARLY_FAST_RETRAN_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_early_fr_msec), SCTPCTL_EARLY_FAST_RETRAN_MSEC_MIN, SCTPCTL_EARLY_FAST_RETRAN_MSEC_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_asconf_auth_nochk), SCTPCTL_ASCONF_AUTH_NOCHK_MIN, SCTPCTL_ASCONF_AUTH_NOCHK_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_auth_disable), SCTPCTL_AUTH_DISABLE_MIN, SCTPCTL_AUTH_DISABLE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_nat_friendly), SCTPCTL_NAT_FRIENDLY_MIN, SCTPCTL_NAT_FRIENDLY_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_L2_abc_variable), SCTPCTL_ABC_L_VAR_MIN, SCTPCTL_ABC_L_VAR_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_mbuf_threshold_count), SCTPCTL_MAX_CHAINED_MBUFS_MIN, SCTPCTL_MAX_CHAINED_MBUFS_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_do_drain), SCTPCTL_DO_SCTP_DRAIN_MIN, SCTPCTL_DO_SCTP_DRAIN_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_hb_maxburst), SCTPCTL_HB_MAX_BURST_MIN, SCTPCTL_HB_MAX_BURST_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_abort_if_one_2_one_hits_limit), SCTPCTL_ABORT_AT_LIMIT_MIN, SCTPCTL_ABORT_AT_LIMIT_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_strict_data_order), SCTPCTL_STRICT_DATA_ORDER_MIN, SCTPCTL_STRICT_DATA_ORDER_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_min_residual), SCTPCTL_MIN_RESIDUAL_MIN, SCTPCTL_MIN_RESIDUAL_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_max_retran_chunk), SCTPCTL_MAX_RETRAN_CHUNK_MIN, SCTPCTL_MAX_RETRAN_CHUNK_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_logging_level), SCTPCTL_LOGGING_LEVEL_MIN, SCTPCTL_LOGGING_LEVEL_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_default_cc_module), SCTPCTL_DEFAULT_CC_MODULE_MIN, SCTPCTL_DEFAULT_CC_MODULE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_default_frag_interleave), SCTPCTL_DEFAULT_FRAG_INTERLEAVE_MIN, SCTPCTL_DEFAULT_FRAG_INTERLEAVE_MAX);
#if defined(__FreeBSD__) || defined(SCTP_APPLE_MOBILITY_BASE)
		RANGECHK(SCTP_BASE_SYSCTL(sctp_mobility_base), SCTPCTL_MOBILITY_BASE_MIN, SCTPCTL_MOBILITY_BASE_MAX);
#endif
#if defined(__FreeBSD__) || defined(SCTP_APPLE_MOBILITY_FASTHANDOFF)
		RANGECHK(SCTP_BASE_SYSCTL(sctp_mobility_fasthandoff), SCTPCTL_MOBILITY_FASTHANDOFF_MIN, SCTPCTL_MOBILITY_FASTHANDOFF_MAX);
#endif
		RANGECHK(SCTP_BASE_SYSCTL(sctp_udp_tunneling_for_client_enable), SCTPCTL_UDP_TUNNELING_FOR_CLIENT_ENABLE_MIN, SCTPCTL_UDP_TUNNELING_FOR_CLIENT_ENABLE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_enable_sack_immediately), SCTPCTL_SACK_IMMEDIATELY_ENABLE_MIN, SCTPCTL_SACK_IMMEDIATELY_ENABLE_MAX);
		RANGECHK(SCTP_BASE_SYSCTL(sctp_inits_include_nat_friendly), SCTPCTL_NAT_FRIENDLY_MIN, SCTPCTL_NAT_FRIENDLY_MAX);
		
#ifdef SCTP_DEBUG
		RANGECHK(SCTP_BASE_SYSCTL(sctp_debug_on), SCTPCTL_DEBUG_MIN, SCTPCTL_DEBUG_MAX);
#endif
#if defined(__APPLE__)
		RANGECHK(SCTP_BASE_SYSCTL(sctp_main_timer), SCTPCTL_MAIN_TIMER_MIN, SCTPCTL_MAIN_TIMER_MAX);
#endif
#if defined (__APPLE__) || defined(SCTP_SO_LOCK_TESTING)
		RANGECHK(SCTP_BASE_SYSCTL(sctp_output_unlocked), SCTPCTL_OUTPUT_UNLOCKED_MIN, SCTPCTL_OUTPUT_UNLOCKED_MAX);
#endif
	}
	return (error);
}



#if defined(SCTP_LOCAL_TRACE_BUF)
static int
#if defined (__APPLE__)
sysctl_sctp_cleartrace SYSCTL_HANDLER_ARGS
#else
sysctl_sctp_cleartrace(SYSCTL_HANDLER_ARGS)
#endif
{
	int error = 0;
#if defined(__Windows__)
	int value = 0;
	if (req->new_data == NULL) {
		return (error);
	}
	error = SYSCTL_IN(req, &value, sizeof(int));
	if (error == 0 && value != 0 && SCTP_BASE_SYSCTL(sctp_log) != NULL) {
		memset(SCTP_BASE_SYSCTL(sctp_log), 0, sizeof(struct sctp_log));
	}
#else
	memset(&SCTP_BASE_SYSCTL(sctp_log), 0, sizeof(struct sctp_log));
#endif
	return (error);
}
#endif


#if defined(__APPLE__) || defined(__FreeBSD__)
/*
 * sysctl definitions
 */

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, sendspace, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_sendspace), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MAXDGRAM_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, recvspace, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_recvspace), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_RECVSPACE_DESC);

#if defined(__FreeBSD__) || defined(SCTP_APPLE_AUTO_ASCONF)
SYSCTL_PROC(_net_inet_sctp, OID_AUTO, auto_asconf, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_auto_asconf), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_AUTOASCONF_DESC);
#endif

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, ecn_enable, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_ecn_enable), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ECN_ENABLE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, ecn_nonce, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_ecn_nonce), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ECN_NONCE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, strict_sacks, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_strict_sacks), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_STRICT_SACKS_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, loopback_nocsum, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_no_csum_on_loopback), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_LOOPBACK_NOCSUM_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, strict_init, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_strict_init), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_STRICT_INIT_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, peer_chkoh, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_peer_chunk_oh), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_PEER_CHKOH_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, maxburst, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_max_burst_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MAXBURST_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, maxchunks, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_max_chunks_on_queue), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MAXCHUNKS_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, tcbhashsize, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_hashtblsize), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_TCBHASHSIZE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, pcbhashsize, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_pcbtblsize), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_PCBHASHSIZE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, min_split_point, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_min_split_point), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MIN_SPLIT_POINT_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, chunkscale, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_chunkscale), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_CHUNKSCALE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, delayed_sack_time, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_delayed_sack_time_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_DELAYED_SACK_TIME_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, sack_freq, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_sack_freq_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_SACK_FREQ_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, sys_resource, CTLTYPE_INT|CTLFLAG_RW,
             &SCTP_BASE_SYSCTL(sctp_system_free_resc_limit), 0, sysctl_sctp_check, "IU",
	     SCTPCTL_SYS_RESOURCE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, asoc_resource, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_asoc_free_resc_limit), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ASOC_RESOURCE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, heartbeat_interval, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_heartbeat_interval_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_HEARTBEAT_INTERVAL_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, pmtu_raise_time, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_pmtu_raise_time_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_PMTU_RAISE_TIME_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, shutdown_guard_time, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_shutdown_guard_time_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_SHUTDOWN_GUARD_TIME_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, secret_lifetime, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_secret_lifetime_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_SECRET_LIFETIME_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, rto_max, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_rto_max_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_RTO_MAX_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, rto_min, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_rto_min_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_RTO_MIN_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, rto_initial, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_rto_initial_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_RTO_INITIAL_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, init_rto_max, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_init_rto_max_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_INIT_RTO_MAX_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, valid_cookie_life, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_valid_cookie_life_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_VALID_COOKIE_LIFE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, init_rtx_max, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_init_rtx_max_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_INIT_RTX_MAX_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, assoc_rtx_max, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_assoc_rtx_max_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ASSOC_RTX_MAX_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, path_rtx_max, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_path_rtx_max_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_PATH_RTX_MAX_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, add_more_on_output, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_add_more_threshold), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ADD_MORE_ON_OUTPUT_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, outgoing_streams, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_nr_outgoing_streams_default), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_OUTGOING_STREAMS_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, cmt_on_off, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_cmt_on_off), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_CMT_ON_OFF_DESC);

/* EY */	
SYSCTL_PROC(_net_inet_sctp, OID_AUTO, nr_sack_on_off, CTLTYPE_INT | CTLFLAG_RW,
    &SCTP_BASE_SYSCTL(sctp_nr_sack_on_off), 0, sysctl_sctp_check, "IU",
    SCTPCTL_NR_SACK_ON_OFF_DESC);
	
SYSCTL_PROC(_net_inet_sctp, OID_AUTO, cmt_use_dac, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_cmt_use_dac), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_CMT_USE_DAC_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, cmt_pf, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_cmt_pf), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_CMT_PF_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, cwnd_maxburst, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_use_cwnd_based_maxburst), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_CWND_MAXBURST_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, early_fast_retran, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_early_fr), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_EARLY_FAST_RETRAN_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, early_fast_retran_msec, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_early_fr_msec), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_EARLY_FAST_RETRAN_MSEC_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, asconf_auth_nochk, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_asconf_auth_nochk), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ASCONF_AUTH_NOCHK_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, auth_disable, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_auth_disable), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_AUTH_DISABLE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, nat_friendly, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_nat_friendly), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_NAT_FRIENDLY_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, abc_l_var, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_L2_abc_variable), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ABC_L_VAR_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, max_chained_mbufs, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_mbuf_threshold_count), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MAX_CHAINED_MBUFS_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, do_sctp_drain, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_do_drain), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_DO_SCTP_DRAIN_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, hb_max_burst, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_hb_maxburst), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_HB_MAX_BURST_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, abort_at_limit, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_abort_if_one_2_one_hits_limit), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_ABORT_AT_LIMIT_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, strict_data_order, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_strict_data_order), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_STRICT_DATA_ORDER_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, min_residual, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_min_residual), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MIN_RESIDUAL_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, max_retran_chunk, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_max_retran_chunk), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MAX_RETRAN_CHUNK_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, log_level, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_logging_level), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_LOGGING_LEVEL_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, default_cc_module, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_default_cc_module), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_DEFAULT_CC_MODULE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, default_frag_interleave, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_default_frag_interleave), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_DEFAULT_FRAG_INTERLEAVE_DESC);

#if defined(__FreeBSD__) || defined(SCTP_APPLE_MOBILITY_BASE)
SYSCTL_PROC(_net_inet_sctp, OID_AUTO, mobility_base, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_mobility_base), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MOBILITY_BASE_DESC);
#endif

#if defined(__FreeBSD__) || defined(SCTP_APPLE_MOBILITY_FASTHANDOFF)
SYSCTL_PROC(_net_inet_sctp, OID_AUTO, mobility_fasthandoff, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_mobility_fasthandoff), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_MOBILITY_FASTHANDOFF_DESC);
#endif

#if defined(SCTP_LOCAL_TRACE_BUF)
SYSCTL_STRUCT(_net_inet_sctp, OID_AUTO, log, CTLFLAG_RD,
	      &SCTP_BASE_SYSCTL(sctp_log), sctp_log,
			  "SCTP logging (struct sctp_log)");

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, clear_trace, CTLTYPE_OPAQUE|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_log), 0, sysctl_sctp_cleartrace, "IU",
			"Clear SCTP Logging buffer");



#endif

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, udp_tunneling_for_client_enable, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_udp_tunneling_for_client_enable), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_UDP_TUNNELING_FOR_CLIENT_ENABLE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, udp_tunneling_port, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_udp_tunneling_port), 0, sysctl_sctp_udp_tunneling_check, "IU",
	    SCTPCTL_UDP_TUNNELING_PORT_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, enable_sack_immediately, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_enable_sack_immediately), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_SACK_IMMEDIATELY_ENABLE_DESC);

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, nat_friendly_init, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_inits_include_nat_friendly), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_NAT_FRIENDLY_DESC);

#ifdef SCTP_DEBUG
SYSCTL_PROC(_net_inet_sctp, OID_AUTO, debug, CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_debug_on), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_DEBUG_DESC);
#endif				/* SCTP_DEBUG */

#if defined(__APPLE__)
SYSCTL_INT(_net_inet_sctp, OID_AUTO, main_timer, CTLFLAG_RW,
           &SCTP_BASE_SYSCTL(sctp_main_timer), 0, "Main timer interval in ms");

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, ignore_vmware_interfaces, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_ignore_vmware_interfaces), 0, sysctl_sctp_vmware_interfaces_check, "IU",
	    SCTPCTL_IGNORE_VMWARE_INTERFACES_DESC);
#endif

#if defined (__APPLE__) || defined(SCTP_SO_LOCK_TESTING)
SYSCTL_PROC(_net_inet_sctp, OID_AUTO, output_unlocked, CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_output_unlocked), 0, sysctl_sctp_check, "IU",
	    SCTPCTL_OUTPUT_UNLOCKED_DESC);
#endif

SYSCTL_STRUCT(_net_inet_sctp, OID_AUTO, stats, CTLFLAG_RW,
			  &SCTP_BASE_STATS, sctpstat ,
	      "SCTP statistics (struct sctp_stat)");

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, assoclist, CTLFLAG_RD,
            0, 0, sctp_assoclist,
            "S,xassoc", "List of active SCTP associations");

#elif defined(__Windows__)
void sysctl_setup_sctp(void)
{
	sysctl_add_oid(&sysctl_oid_top, "sendspace", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_sendspace), 0, sysctl_sctp_check,
	    SCTPCTL_MAXDGRAM_DESC);

	sysctl_add_oid(&sysctl_oid_top, "recvspace", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_recvspace), 0, sysctl_sctp_check,
	    SCTPCTL_RECVSPACE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "auto_asconf", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_auto_asconf), 0, sysctl_sctp_check,
	    SCTPCTL_AUTOASCONF_DESC);

	sysctl_add_oid(&sysctl_oid_top, "ecn_enable", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_ecn_enable), 0, sysctl_sctp_check,
	    SCTPCTL_ECN_ENABLE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "ecn_nonce", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_ecn_nonce), 0, sysctl_sctp_check,
	    SCTPCTL_ECN_NONCE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "strict_sacks", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_strict_sacks), 0, sysctl_sctp_check,
	    SCTPCTL_STRICT_SACKS_DESC);

	sysctl_add_oid(&sysctl_oid_top, "loopback_nocsum", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_no_csum_on_loopback), 0, sysctl_sctp_check,
	    SCTPCTL_LOOPBACK_NOCSUM_DESC);

	sysctl_add_oid(&sysctl_oid_top, "strict_init", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_strict_init), 0, sysctl_sctp_check,
	    SCTPCTL_STRICT_INIT_DESC);

	sysctl_add_oid(&sysctl_oid_top, "peer_chkoh", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_peer_chunk_oh), 0, sysctl_sctp_check,
	    SCTPCTL_PEER_CHKOH_DESC);

	sysctl_add_oid(&sysctl_oid_top, "maxburst", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_max_burst_default), 0, sysctl_sctp_check,
	    SCTPCTL_MAXBURST_DESC);

	sysctl_add_oid(&sysctl_oid_top, "maxchunks", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_max_chunks_on_queue), 0, sysctl_sctp_check,
	    SCTPCTL_MAXCHUNKS_DESC);

	sysctl_add_oid(&sysctl_oid_top, "tcbhashsize", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_hashtblsize), 0, sysctl_sctp_check,
	    SCTPCTL_TCBHASHSIZE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "pcbhashsize", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_pcbtblsize), 0, sysctl_sctp_check,
	    SCTPCTL_PCBHASHSIZE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "min_split_point", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_min_split_point), 0, sysctl_sctp_check,
	    SCTPCTL_MIN_SPLIT_POINT_DESC);

	sysctl_add_oid(&sysctl_oid_top, "chunkscale", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_chunkscale), 0, sysctl_sctp_check,
	    SCTPCTL_CHUNKSCALE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "delayed_sack_time", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_delayed_sack_time_default), 0, sysctl_sctp_check,
	    SCTPCTL_DELAYED_SACK_TIME_DESC);

	sysctl_add_oid(&sysctl_oid_top, "sack_freq", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_sack_freq_default), 0, sysctl_sctp_check,
	    SCTPCTL_SACK_FREQ_DESC);

	sysctl_add_oid(&sysctl_oid_top, "sys_resource", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_system_free_resc_limit), 0, sysctl_sctp_check,
	    SCTPCTL_SYS_RESOURCE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "asoc_resource", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_asoc_free_resc_limit), 0, sysctl_sctp_check,
	    SCTPCTL_ASOC_RESOURCE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "heartbeat_interval", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_heartbeat_interval_default), 0, sysctl_sctp_check,
	    SCTPCTL_HEARTBEAT_INTERVAL_DESC);

	sysctl_add_oid(&sysctl_oid_top, "pmtu_raise_time", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_pmtu_raise_time_default), 0, sysctl_sctp_check,
	    SCTPCTL_PMTU_RAISE_TIME_DESC);

	sysctl_add_oid(&sysctl_oid_top, "shutdown_guard_time", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_shutdown_guard_time_default), 0, sysctl_sctp_check,
	    SCTPCTL_SHUTDOWN_GUARD_TIME_DESC);

	sysctl_add_oid(&sysctl_oid_top, "secret_lifetime", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_secret_lifetime_default), 0, sysctl_sctp_check,
	    SCTPCTL_SECRET_LIFETIME_DESC);

	sysctl_add_oid(&sysctl_oid_top, "rto_max", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_rto_max_default), 0, sysctl_sctp_check,
	    SCTPCTL_RTO_MAX_DESC);

	sysctl_add_oid(&sysctl_oid_top, "rto_min", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_rto_min_default), 0, sysctl_sctp_check,
	    SCTPCTL_RTO_MIN_DESC);

	sysctl_add_oid(&sysctl_oid_top, "rto_initial", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_rto_initial_default), 0, sysctl_sctp_check,
	    SCTPCTL_RTO_INITIAL_DESC);

	sysctl_add_oid(&sysctl_oid_top, "init_rto_max", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_init_rto_max_default), 0, sysctl_sctp_check,
	    SCTPCTL_INIT_RTO_MAX_DESC);

	sysctl_add_oid(&sysctl_oid_top, "valid_cookie_life", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_valid_cookie_life_default), 0, sysctl_sctp_check,
	    SCTPCTL_VALID_COOKIE_LIFE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "init_rtx_max", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_init_rtx_max_default), 0, sysctl_sctp_check,
	    SCTPCTL_INIT_RTX_MAX_DESC);

	sysctl_add_oid(&sysctl_oid_top, "assoc_rtx_max", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_assoc_rtx_max_default), 0, sysctl_sctp_check,
	    SCTPCTL_ASSOC_RTX_MAX_DESC);

	sysctl_add_oid(&sysctl_oid_top, "path_rtx_max", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_path_rtx_max_default), 0, sysctl_sctp_check,
	    SCTPCTL_PATH_RTX_MAX_DESC);

	sysctl_add_oid(&sysctl_oid_top, "add_more_on_output", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_add_more_threshold), 0, sysctl_sctp_check,
	    SCTPCTL_ADD_MORE_ON_OUTPUT_DESC);

	sysctl_add_oid(&sysctl_oid_top, "outgoing_streams", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_nr_outgoing_streams_default), 0, sysctl_sctp_check,
	    SCTPCTL_OUTGOING_STREAMS_DESC);

	sysctl_add_oid(&sysctl_oid_top, "cmt_on_off", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_cmt_on_off), 0, sysctl_sctp_check,
	    SCTPCTL_CMT_ON_OFF_DESC);

	/* EY */	
	sysctl_add_oid(&sysctl_oid_top, "nr_sack_on_off", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_nr_sack_on_off), 0, sysctl_sctp_check,
	    SCTPCTL_NR_SACK_ON_OFF_DESC);

	sysctl_add_oid(&sysctl_oid_top, "cmt_use_dac", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_cmt_use_dac), 0, sysctl_sctp_check,
	    SCTPCTL_CMT_USE_DAC_DESC);

	sysctl_add_oid(&sysctl_oid_top, "cmt_pf", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_cmt_pf), 0, sysctl_sctp_check,
	    SCTPCTL_CMT_PF_DESC);

	sysctl_add_oid(&sysctl_oid_top, "cwnd_maxburst", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_use_cwnd_based_maxburst), 0, sysctl_sctp_check,
	    SCTPCTL_CWND_MAXBURST_DESC);

	sysctl_add_oid(&sysctl_oid_top, "early_fast_retran", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_early_fr), 0, sysctl_sctp_check,
	    SCTPCTL_EARLY_FAST_RETRAN_DESC);

	sysctl_add_oid(&sysctl_oid_top, "early_fast_retran_msec", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_early_fr_msec), 0, sysctl_sctp_check,
	    SCTPCTL_EARLY_FAST_RETRAN_MSEC_DESC);

	sysctl_add_oid(&sysctl_oid_top, "asconf_auth_nochk", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_asconf_auth_nochk), 0, sysctl_sctp_check,
	    SCTPCTL_ASCONF_AUTH_NOCHK_DESC);

	sysctl_add_oid(&sysctl_oid_top, "auth_disable", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_auth_disable), 0, sysctl_sctp_check,
	    SCTPCTL_AUTH_DISABLE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "nat_friendly", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_nat_friendly), 0, sysctl_sctp_check,
	    SCTPCTL_NAT_FRIENDLY_DESC);

	sysctl_add_oid(&sysctl_oid_top, "abc_l_var", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_L2_abc_variable), 0, sysctl_sctp_check,
	    SCTPCTL_ABC_L_VAR_DESC);

	sysctl_add_oid(&sysctl_oid_top, "max_chained_mbufs", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_mbuf_threshold_count), 0, sysctl_sctp_check,
	    SCTPCTL_MAX_CHAINED_MBUFS_DESC);

	sysctl_add_oid(&sysctl_oid_top, "do_sctp_drain", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_do_drain), 0, sysctl_sctp_check,
	    SCTPCTL_DO_SCTP_DRAIN_DESC);

	sysctl_add_oid(&sysctl_oid_top, "hb_max_burst", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_hb_maxburst), 0, sysctl_sctp_check,
	    SCTPCTL_HB_MAX_BURST_DESC);

	sysctl_add_oid(&sysctl_oid_top, "abort_at_limit", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_abort_if_one_2_one_hits_limit), 0, sysctl_sctp_check,
	    SCTPCTL_ABORT_AT_LIMIT_DESC);

	sysctl_add_oid(&sysctl_oid_top, "strict_data_order", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_strict_data_order), 0, sysctl_sctp_check,
	    SCTPCTL_STRICT_DATA_ORDER_DESC);

	sysctl_add_oid(&sysctl_oid_top, "min_residual", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_min_residual), 0, sysctl_sctp_check,
	    SCTPCTL_MIN_RESIDUAL_DESC);

	sysctl_add_oid(&sysctl_oid_top, "max_retran_chunk", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_max_retran_chunk), 0, sysctl_sctp_check,
	    SCTPCTL_MAX_RETRAN_CHUNK_DESC);

	sysctl_add_oid(&sysctl_oid_top, "log_level", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_logging_level), 0, sysctl_sctp_check,
	    SCTPCTL_LOGGING_LEVEL_DESC);

	sysctl_add_oid(&sysctl_oid_top, "default_cc_module", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_default_cc_module), 0, sysctl_sctp_check,
	    SCTPCTL_DEFAULT_CC_MODULE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "default_frag_interleave", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_default_frag_interleave), 0, sysctl_sctp_check,
	    SCTPCTL_DEFAULT_FRAG_INTERLEAVE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "mobility_base", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_mobility_base), 0, sysctl_sctp_check,
	    SCTPCTL_MOBILITY_BASE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "mobility_fasthandoff", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_mobility_fasthandoff), 0, sysctl_sctp_check,
	    SCTPCTL_MOBILITY_FASTHANDOFF_DESC);

#if defined(SCTP_LOCAL_TRACE_BUF)
	sysctl_add_oid(&sysctl_oid_top, "sctp_log", CTLTYPE_STRUCT|CTLFLAG_RD,
	    SCTP_BASE_SYSCTL(sctp_log), sizeof(struct sctp_log), NULL,
	    "SCTP logging (struct sctp_log)");

	sysctl_add_oid(&sysctl_oid_top, "clear_trace", CTLTYPE_INT|CTLFLAG_WR,
	    NULL, 0, sysctl_sctp_cleartrace,
	    "Clear SCTP Logging buffer");
#endif

	sysctl_add_oid(&sysctl_oid_top, "udp_tunneling_for_client_enable", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_udp_tunneling_for_client_enable), 0, sysctl_sctp_check,
	    SCTPCTL_UDP_TUNNELING_FOR_CLIENT_ENABLE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "udp_tunneling_port", CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_udp_tunneling_port), 0, sysctl_sctp_udp_tunneling_check,
	    SCTPCTL_UDP_TUNNELING_PORT_DESC);

	sysctl_add_oid(&sysctl_oid_top, "enable_sack_immediately", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_enable_sack_immediately), 0, sysctl_sctp_check,
	    SCTPCTL_SACK_IMMEDIATELY_ENABLE_DESC);

	sysctl_add_oid(&sysctl_oid_top, "nat_friendly_init", CTLTYPE_INT|CTLFLAG_RW,
            &SCTP_BASE_SYSCTL(sctp_inits_include_nat_friendly), 0, sysctl_sctp_check,
	    SCTPCTL_NAT_FRIENDLY_DESC);

#ifdef SCTP_DEBUG
	sysctl_add_oid(&sysctl_oid_top, "debug", CTLTYPE_INT|CTLFLAG_RW,
	    &SCTP_BASE_SYSCTL(sctp_debug_on), sizeof(SCTP_BASE_SYSCTL(sctp_debug_on)),
	    SCTPCTL_DEBUG_DESC);
#endif /* SCTP_DEBUG */

	sysctl_add_oid(&sysctl_oid_top, "stats", CTLTYPE_STRUCT|CTLFLAG_RW,
	    &SCTP_BASE_STATS, sizeof(SCTP_BASE_STATS), NULL,
	    "SCTP statistics (struct sctp_stat)");

	sysctl_add_oid(&sysctl_oid_top, "assoclist", CTLTYPE_STRUCT|CTLFLAG_RD,
	    NULL, 0, sctp_assoclist,
	    "List of active SCTP associations");
}
#endif
#endif
