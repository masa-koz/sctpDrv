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

/* $KAME: sctp_timer.c,v 1.29 2005/03/06 16:04:18 itojun Exp $	 */

#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/netinet/sctp_timer.c,v 1.7 2007/02/12 23:24:31 rrs Exp $");
#endif

#define _IP_VHL
#include <netinet/sctp_os.h>
#include <netinet/sctp_pcb.h>
#ifdef INET6
#include <netinet6/sctp6_var.h>
#endif
#include <netinet/sctp_var.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_input.h>
#include <netinet/sctp.h>
#include <netinet/sctp_uio.h>


#ifdef SCTP_DEBUG
extern uint32_t sctp_debug_on;
#endif				/* SCTP_DEBUG */

#if defined(__APPLE__)
#define APPLE_FILE_NO 6
#endif

extern unsigned int sctp_early_fr_msec;

void
sctp_early_fr_timer(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct sctp_tmit_chunk *chk, *tp2;
	struct timeval now, min_wait, tv;
	unsigned int cur_rtt, cnt = 0, cnt_resend = 0;

	/* an early FR is occuring. */
	SCTP_GETTIME_TIMEVAL(&now);
	/* get cur rto in micro-seconds */
	if (net->lastsa == 0) {
		/* Hmm no rtt estimate yet? */
		cur_rtt = stcb->asoc.initial_rto >> 2;
	} else {

		cur_rtt = ((net->lastsa >> 2) + net->lastsv) >> 1;
	}
	if (cur_rtt < sctp_early_fr_msec) {
		cur_rtt = sctp_early_fr_msec;
	}
	cur_rtt *= 1000;
	tv.tv_sec = cur_rtt / 1000000;
	tv.tv_usec = cur_rtt % 1000000;
#ifndef __FreeBSD__
	timersub(&now, &tv, &min_wait);
#else
	min_wait = now;
	timevalsub(&min_wait, &tv);
#endif
	if (min_wait.tv_sec < 0 || min_wait.tv_usec < 0) {
		/*
		 * if we hit here, we don't have enough seconds on the clock
		 * to account for the RTO. We just let the lower seconds be
		 * the bounds and don't worry about it. This may mean we
		 * will mark a lot more than we should.
		 */
		min_wait.tv_sec = min_wait.tv_usec = 0;
	}
	chk = TAILQ_LAST(&stcb->asoc.sent_queue, sctpchunk_listhead);
	for (; chk != NULL; chk = tp2) {
		tp2 = TAILQ_PREV(chk, sctpchunk_listhead, sctp_next);
		if (chk->whoTo != net) {
			continue;
		}
		if (chk->sent == SCTP_DATAGRAM_RESEND)
			cnt_resend++;
		else if ((chk->sent > SCTP_DATAGRAM_UNSENT) &&
		    (chk->sent < SCTP_DATAGRAM_RESEND)) {
			/* pending, may need retran */
			if (chk->sent_rcv_time.tv_sec > min_wait.tv_sec) {
				/*
				 * we have reached a chunk that was sent
				 * some seconds past our min.. forget it we
				 * will find no more to send.
				 */
				continue;
			} else if (chk->sent_rcv_time.tv_sec == min_wait.tv_sec) {
				/*
				 * we must look at the micro seconds to
				 * know.
				 */
				if (chk->sent_rcv_time.tv_usec >= min_wait.tv_usec) {
					/*
					 * ok it was sent after our boundary
					 * time.
					 */
					continue;
				}
			}
#ifdef SCTP_EARLYFR_LOGGING
			sctp_log_fr(chk->rec.data.TSN_seq, chk->snd_count,
			    4, SCTP_FR_MARKED_EARLY);
#endif
			SCTP_STAT_INCR(sctps_earlyfrmrkretrans);
			chk->sent = SCTP_DATAGRAM_RESEND;
			sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
			/* double book size since we are doing an early FR */
			chk->book_size_scale++;
			cnt += chk->send_size;
			if ((cnt + net->flight_size) > net->cwnd) {
				/* Mark all we could possibly resend */
				break;
			}
		}
	}
	if (cnt) {
#ifdef SCTP_CWND_MONITOR
		int old_cwnd;

		old_cwnd = net->cwnd;
#endif
		sctp_chunk_output(inp, stcb, SCTP_OUTPUT_FROM_EARLY_FR_TMR);
		/*
		 * make a small adjustment to cwnd and force to CA.
		 */

		if (net->cwnd > net->mtu)
			/* drop down one MTU after sending */
			net->cwnd -= net->mtu;
		if (net->cwnd < net->ssthresh)
			/* still in SS move to CA */
			net->ssthresh = net->cwnd - 1;
#ifdef SCTP_CWND_MONITOR
		sctp_log_cwnd(stcb, net, (old_cwnd - net->cwnd), SCTP_CWND_LOG_FROM_FR);
#endif
	} else if (cnt_resend) {
		sctp_chunk_output(inp, stcb, SCTP_OUTPUT_FROM_EARLY_FR_TMR);
	}
	/* Restart it? */
	if (net->flight_size < net->cwnd) {
		SCTP_STAT_INCR(sctps_earlyfrstrtmr);
		sctp_timer_start(SCTP_TIMER_TYPE_EARLYFR, stcb->sctp_ep, stcb, net);
	}
}

void
sctp_audit_retranmission_queue(struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *chk;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
		printf("Audit invoked on send queue cnt:%d onqueue:%d\n",
		    asoc->sent_queue_retran_cnt,
		    asoc->sent_queue_cnt);
	}
#endif				/* SCTP_DEBUG */
	asoc->sent_queue_retran_cnt = 0;
	asoc->sent_queue_cnt = 0;
	TAILQ_FOREACH(chk, &asoc->sent_queue, sctp_next) {
		if (chk->sent == SCTP_DATAGRAM_RESEND) {
			sctp_ucount_incr(asoc->sent_queue_retran_cnt);
		}
		asoc->sent_queue_cnt++;
	}
	TAILQ_FOREACH(chk, &asoc->control_send_queue, sctp_next) {
		if (chk->sent == SCTP_DATAGRAM_RESEND) {
			sctp_ucount_incr(asoc->sent_queue_retran_cnt);
		}
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
		printf("Audit completes retran:%d onqueue:%d\n",
		    asoc->sent_queue_retran_cnt,
		    asoc->sent_queue_cnt);
	}
#endif				/* SCTP_DEBUG */
}

int
sctp_threshold_management(struct sctp_inpcb *inp, struct sctp_tcb *stcb,
    struct sctp_nets *net, uint16_t threshold)
{
	if (net) {
		net->error_count++;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
			printf("Error count for %p now %d thresh:%d\n",
			    net, net->error_count,
			    net->failure_threshold);
		}
#endif				/* SCTP_DEBUG */
		if (net->error_count > net->failure_threshold) {
			/* We had a threshold failure */
			if (net->dest_state & SCTP_ADDR_REACHABLE) {
				net->dest_state &= ~SCTP_ADDR_REACHABLE;
				net->dest_state |= SCTP_ADDR_NOT_REACHABLE;
				net->dest_state &= ~SCTP_ADDR_REQ_PRIMARY;
				if (net == stcb->asoc.primary_destination) {
					net->dest_state |= SCTP_ADDR_WAS_PRIMARY;
				}
				sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_DOWN,
				    stcb,
				    SCTP_FAILED_THRESHOLD,
				    (void *)net);
			}
		}
		/*********HOLD THIS COMMENT FOR PATCH OF ALTERNATE
		 *********ROUTING CODE
		 */
		/*********HOLD THIS COMMENT FOR END OF PATCH OF ALTERNATE
		 *********ROUTING CODE
		 */
	}
	if (stcb == NULL)
		return (0);

	if (net) {
		if ((net->dest_state & SCTP_ADDR_UNCONFIRMED) == 0) {
			stcb->asoc.overall_error_count++;
		}
	} else {
		stcb->asoc.overall_error_count++;
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
		printf("Overall error count for %p now %d thresh:%u state:%x\n",
		    &stcb->asoc,
		    stcb->asoc.overall_error_count,
		    (uint32_t) threshold,
		    ((net == NULL) ? (uint32_t) 0 : (uint32_t) net->dest_state));
	}
#endif				/* SCTP_DEBUG */
	/*
	 * We specifically do not do >= to give the assoc one more change
	 * before we fail it.
	 */
	if (stcb->asoc.overall_error_count > threshold) {
		/* Abort notification sends a ULP notify */
		struct mbuf *oper;

		oper = sctp_get_mbuf_for_msg((sizeof(struct sctp_paramhdr) + sizeof(uint32_t)),
					       0, M_DONTWAIT, 1, MT_DATA);
		if (oper) {
			struct sctp_paramhdr *ph;
			uint32_t *ippp;

			SCTP_BUF_LEN(oper) = sizeof(struct sctp_paramhdr) +
			    sizeof(uint32_t);
			ph = mtod(oper, struct sctp_paramhdr *);
			ph->param_type = htons(SCTP_CAUSE_PROTOCOL_VIOLATION);
			ph->param_length = htons(SCTP_BUF_LEN(oper));
			ippp = (uint32_t *) (ph + 1);
			*ippp = htonl(SCTP_FROM_SCTP_TIMER+SCTP_LOC_1);
		}
		inp->last_abort_code = SCTP_FROM_SCTP_TIMER+SCTP_LOC_1;
		sctp_abort_an_association(inp, stcb, SCTP_FAILED_THRESHOLD, oper);
		return (1);
	}
	return (0);
}

struct sctp_nets *
sctp_find_alternate_net(struct sctp_tcb *stcb,
    struct sctp_nets *net,
    int highest_ssthresh)
{
	/* Find and return an alternate network if possible */
	struct sctp_nets *alt, *mnet, *hthresh = NULL;
	int once;
	uint32_t val = 0;

	if (stcb->asoc.numnets == 1) {
		/* No others but net */
		return (TAILQ_FIRST(&stcb->asoc.nets));
	}
	if (highest_ssthresh) {
		TAILQ_FOREACH(mnet, &stcb->asoc.nets, sctp_next) {
			if (((mnet->dest_state & SCTP_ADDR_REACHABLE) != SCTP_ADDR_REACHABLE) ||
			    (mnet->dest_state & SCTP_ADDR_UNCONFIRMED)
			    ) {
				/*
				 * will skip ones that are not-reachable or
				 * unconfirmed
				 */
				continue;
			}
			if (val > mnet->ssthresh) {
				hthresh = mnet;
				val = mnet->ssthresh;
			} else if (val == mnet->ssthresh) {
				uint32_t rndval;
				uint8_t this_random;

				if (stcb->asoc.hb_random_idx > 3) {
					rndval = sctp_select_initial_TSN(&stcb->sctp_ep->sctp_ep);
					memcpy(stcb->asoc.hb_random_values, &rndval,
					    sizeof(stcb->asoc.hb_random_values));
					this_random = stcb->asoc.hb_random_values[0];
					stcb->asoc.hb_random_idx = 0;
					stcb->asoc.hb_ect_randombit = 0;
				} else {
					this_random = stcb->asoc.hb_random_values[stcb->asoc.hb_random_idx];
					stcb->asoc.hb_random_idx++;
					stcb->asoc.hb_ect_randombit = 0;
				}
				if (this_random % 2) {
					hthresh = mnet;
					val = mnet->ssthresh;
				}
			}
		}
		if (hthresh) {
			return (hthresh);
		}
	}
	mnet = net;
	once = 0;

	if (mnet == NULL) {
		mnet = TAILQ_FIRST(&stcb->asoc.nets);
	}
	do {
		alt = TAILQ_NEXT(mnet, sctp_next);
		if (alt == NULL) {
			once++;
			if (once > 1) {
				break;
			}
			alt = TAILQ_FIRST(&stcb->asoc.nets);
		}
		if (alt->ro.ro_rt == NULL) {
#ifndef SCOPEDROUTING
#ifdef SCTP_EMBEDDED_V6_SCOPE
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)&alt->ro._l_addr;
			if (sin6->sin6_family == AF_INET6) {
#if defined(SCTP_BASE_FREEBSD) || defined(__APPLE__)
				(void)in6_embedscope(&sin6->sin6_addr, sin6,
				    NULL, NULL);
#elif defined(SCTP_KAME)
				(void)sa6_embedscope(sin6, ip6_use_defzone);
#else
				(void)in6_embedscope(&sin6->sin6_addr, sin6);
#endif
			}
#endif /* SCTP_EMBEDDED_V6_SCOPE */
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
			rtalloc_ign((struct route *)&alt->ro, 0UL);
#else
			rtalloc((struct route *)&alt->ro);
#endif
#ifndef SCOPEDROUTING
#ifdef SCTP_EMBEDDED_V6_SCOPE
			if (sin6->sin6_family == AF_INET6) {
#ifdef SCTP_KAME
				(void)sa6_recoverscope(sin6);
#else
				(void)in6_recoverscope(sin6, &sin6->sin6_addr,
				    NULL);
#endif /* SCTP_KAME */
			}
#endif /* SCTP_EMBEDDED_V6_SCOPE */
#endif
			if (alt->ro._s_addr) {
				sctp_free_ifa(alt->ro._s_addr);
				alt->ro._s_addr = NULL;
			}
			alt->src_addr_selected = 0;
		}
		if (
		    ((alt->dest_state & SCTP_ADDR_REACHABLE) == SCTP_ADDR_REACHABLE) &&
		    (alt->ro.ro_rt != NULL) &&
		    (!(alt->dest_state & SCTP_ADDR_UNCONFIRMED))
		    ) {
			/* Found a reachable address */
			break;
		}
		mnet = alt;
	} while (alt != NULL);

	if (alt == NULL) {
		/* Case where NO insv network exists (dormant state) */
		/* we rotate destinations */
		once = 0;
		mnet = net;
		do {
			alt = TAILQ_NEXT(mnet, sctp_next);
			if (alt == NULL) {
				once++;
				if (once > 1) {
					break;
				}
				alt = TAILQ_FIRST(&stcb->asoc.nets);
			}
			if ((!(alt->dest_state & SCTP_ADDR_UNCONFIRMED)) &&
			    (alt != net)) {
				/* Found an alternate address */
				break;
			}
			mnet = alt;
		} while (alt != NULL);
	}
	if (alt == NULL) {
		return (net);
	}
	return (alt);
}

static void
sctp_backoff_on_timeout(struct sctp_tcb *stcb,
    struct sctp_nets *net,
    int win_probe,
    int num_marked)
{
	net->RTO <<= 1;
	if (net->RTO > stcb->asoc.maxrto) {
		net->RTO = stcb->asoc.maxrto;
	}
	if ((win_probe == 0) && num_marked) {
		/* We don't apply penalty to window probe scenarios */
#ifdef SCTP_CWND_MONITOR
		int old_cwnd = net->cwnd;

#endif
		net->ssthresh = net->cwnd >> 1;
		if (net->ssthresh < (net->mtu << 1)) {
			net->ssthresh = (net->mtu << 1);
		}
		net->cwnd = net->mtu;
		/* floor of 1 mtu */
		if (net->cwnd < net->mtu)
			net->cwnd = net->mtu;
#ifdef SCTP_CWND_MONITOR
		sctp_log_cwnd(stcb, net, net->cwnd - old_cwnd, SCTP_CWND_LOG_FROM_RTX);
#endif

		net->partial_bytes_acked = 0;
	}
}

extern int sctp_peer_chunk_oh;

static int
sctp_mark_all_for_resend(struct sctp_tcb *stcb,
    struct sctp_nets *net,
    struct sctp_nets *alt,
    int window_probe,
    int *num_marked)
{

	/*
	 * Mark all chunks (well not all) that were sent to *net for
	 * retransmission. Move them to alt for there destination as well...
	 * We only mark chunks that have been outstanding long enough to
	 * have received feed-back.
	 */
	struct sctp_tmit_chunk *chk, *tp2, *could_be_sent = NULL;
	struct sctp_nets *lnets;
	struct timeval now, min_wait, tv;
	int cur_rtt;
	int orig_rwnd, audit_tf, num_mk, fir;
	unsigned int cnt_mk;
	uint32_t orig_flight;
	uint32_t tsnlast, tsnfirst;

#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(SCTP_INP_SO(stcb->sctp_ep));
#endif
	/*
	 * CMT: Using RTX_SSTHRESH policy for CMT. If CMT is being used,
	 * then pick dest with largest ssthresh for any retransmission.
	 * (iyengar@cis.udel.edu, 2005/08/12)
	 */
	if (sctp_cmt_on_off) {
		alt = sctp_find_alternate_net(stcb, net, 1);
		/*
		 * CUCv2: If a different dest is picked for the
		 * retransmission, then new (rtx-)pseudo_cumack needs to be
		 * tracked for orig dest. Let CUCv2 track new (rtx-)
		 * pseudo-cumack always.
		 */
		net->find_pseudo_cumack = 1;
		net->find_rtx_pseudo_cumack = 1;
	}
	/* none in flight now */
	audit_tf = 0;
	fir = 0;
	/*
	 * figure out how long a data chunk must be pending before we can
	 * mark it ..
	 */
	SCTP_GETTIME_TIMEVAL(&now);
	/* get cur rto in micro-seconds */
	cur_rtt = (((net->lastsa >> 2) + net->lastsv) >> 1);
	cur_rtt *= 1000;
#if defined(SCTP_FR_LOGGING) || defined(SCTP_EARLYFR_LOGGING)
	sctp_log_fr(cur_rtt,
	    stcb->asoc.peers_rwnd,
	    window_probe,
	    SCTP_FR_T3_MARK_TIME);
	sctp_log_fr(net->flight_size,
	    SCTP_OS_TIMER_PENDING(&net->fr_timer.timer),
	    SCTP_OS_TIMER_ACTIVE(&net->fr_timer.timer),
	    SCTP_FR_CWND_REPORT);
	sctp_log_fr(net->flight_size, net->cwnd, stcb->asoc.total_flight, SCTP_FR_CWND_REPORT);
#endif
	tv.tv_sec = cur_rtt / 1000000;
	tv.tv_usec = cur_rtt % 1000000;
#ifndef __FreeBSD__
	timersub(&now, &tv, &min_wait);
#else
	min_wait = now;
	timevalsub(&min_wait, &tv);
#endif
	if (min_wait.tv_sec < 0 || min_wait.tv_usec < 0) {
		/*
		 * if we hit here, we don't have enough seconds on the clock
		 * to account for the RTO. We just let the lower seconds be
		 * the bounds and don't worry about it. This may mean we
		 * will mark a lot more than we should.
		 */
		min_wait.tv_sec = min_wait.tv_usec = 0;
	}
#if defined(SCTP_FR_LOGGING) || defined(SCTP_EARLYFR_LOGGING)
	sctp_log_fr(cur_rtt, now.tv_sec, now.tv_usec, SCTP_FR_T3_MARK_TIME);
	sctp_log_fr(0, min_wait.tv_sec, min_wait.tv_usec, SCTP_FR_T3_MARK_TIME);
#endif
	/*
	 * Our rwnd will be incorrect here since we are not adding back the
	 * cnt * mbuf but we will fix that down below.
	 */
	orig_rwnd = stcb->asoc.peers_rwnd;
	orig_flight = net->flight_size;
	net->rto_pending = 0;
	net->fast_retran_ip = 0;
	/* Now on to each chunk */
	num_mk = cnt_mk = 0;
	tsnfirst = tsnlast = 0;
	chk = TAILQ_FIRST(&stcb->asoc.sent_queue);
	for (; chk != NULL; chk = tp2) {
		tp2 = TAILQ_NEXT(chk, sctp_next);
		if ((compare_with_wrap(stcb->asoc.last_acked_seq,
		    chk->rec.data.TSN_seq,
		    MAX_TSN)) ||
		    (stcb->asoc.last_acked_seq == chk->rec.data.TSN_seq)) {
			/* Strange case our list got out of order? */
			printf("Our list is out of order?\n");
			panic("Out of order list");
		}
		if ((chk->whoTo == net) && (chk->sent < SCTP_DATAGRAM_ACKED)) {
			/*
			 * found one to mark: If it is less than
			 * DATAGRAM_ACKED it MUST not be a skipped or marked
			 * TSN but instead one that is either already set
			 * for retransmission OR one that needs
			 * retransmission.
			 */

			/* validate its been outstanding long enough */
#if defined(SCTP_FR_LOGGING) || defined(SCTP_EARLYFR_LOGGING)
			sctp_log_fr(chk->rec.data.TSN_seq,
			    chk->sent_rcv_time.tv_sec,
			    chk->sent_rcv_time.tv_usec,
			    SCTP_FR_T3_MARK_TIME);
#endif
			if ((chk->sent_rcv_time.tv_sec > min_wait.tv_sec) && (window_probe == 0)) {
				/*
				 * we have reached a chunk that was sent
				 * some seconds past our min.. forget it we
				 * will find no more to send.
				 */
#if defined(SCTP_FR_LOGGING) || defined(SCTP_EARLYFR_LOGGING)
				sctp_log_fr(0,
				    chk->sent_rcv_time.tv_sec,
				    chk->sent_rcv_time.tv_usec,
				    SCTP_FR_T3_STOPPED);
#endif
				continue;
			} else if ((chk->sent_rcv_time.tv_sec == min_wait.tv_sec) &&
			    (window_probe == 0)) {
				/*
				 * we must look at the micro seconds to
				 * know.
				 */
				if (chk->sent_rcv_time.tv_usec >= min_wait.tv_usec) {
					/*
					 * ok it was sent after our boundary
					 * time.
					 */
#if defined(SCTP_FR_LOGGING) || defined(SCTP_EARLYFR_LOGGING)
					sctp_log_fr(0,
					    chk->sent_rcv_time.tv_sec,
					    chk->sent_rcv_time.tv_usec,
					    SCTP_FR_T3_STOPPED);
#endif
					continue;
				}
			}
			if (PR_SCTP_TTL_ENABLED(chk->flags)) {
				/* Is it expired? */
				if ((now.tv_sec > chk->rec.data.timetodrop.tv_sec) ||
				    ((chk->rec.data.timetodrop.tv_sec == now.tv_sec) &&
				    (now.tv_usec > chk->rec.data.timetodrop.tv_usec))) {
					/* Yes so drop it */
					if (chk->data) {
						sctp_release_pr_sctp_chunk(stcb,
						    chk,
						    (SCTP_RESPONSE_TO_USER_REQ | SCTP_NOTIFY_DATAGRAM_SENT),
						    &stcb->asoc.sent_queue);
					}
				}
				continue;
			}
			if (PR_SCTP_RTX_ENABLED(chk->flags)) {
				/* Has it been retransmitted tv_sec times? */
				if (chk->snd_count > chk->rec.data.timetodrop.tv_sec) {
					if (chk->data) {
						sctp_release_pr_sctp_chunk(stcb,
						    chk,
						    (SCTP_RESPONSE_TO_USER_REQ | SCTP_NOTIFY_DATAGRAM_SENT),
						    &stcb->asoc.sent_queue);
					}
				}
				continue;
			}
			if (chk->sent != SCTP_DATAGRAM_RESEND) {
				sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
				num_mk++;
				if (fir == 0) {
					fir = 1;
					tsnfirst = chk->rec.data.TSN_seq;
				}
				tsnlast = chk->rec.data.TSN_seq;
#if defined(SCTP_FR_LOGGING) || defined(SCTP_EARLYFR_LOGGING)
				sctp_log_fr(chk->rec.data.TSN_seq, chk->snd_count,
				    0, SCTP_FR_T3_MARKED);

#endif
			}
			if (stcb->asoc.total_flight_count > 0)
				stcb->asoc.total_flight_count--;
			if(chk->rec.data.chunk_was_revoked) {
				/* deflate the cwnd */
				chk->whoTo->cwnd -= chk->book_size;
				chk->rec.data.chunk_was_revoked = 0;
			}
			chk->sent = SCTP_DATAGRAM_RESEND;
			SCTP_STAT_INCR(sctps_markedretrans);
			net->marked_retrans++;
			stcb->asoc.marked_retrans++;
#ifdef SCTP_FLIGHT_LOGGING
			sctp_misc_ints(SCTP_FLIGHT_LOG_DOWN, 
				       chk->whoTo->flight_size,
				       chk->book_size, 
				       (uintptr_t)stcb, 
				       chk->rec.data.TSN_seq);
#endif

			if(net->flight_size >= chk->book_size)
				net->flight_size -= chk->book_size;
			else
				net->flight_size = 0;

			stcb->asoc.peers_rwnd += chk->send_size;
			stcb->asoc.peers_rwnd += sctp_peer_chunk_oh;

			/* reset the TSN for striking and other FR stuff */
			chk->rec.data.doing_fast_retransmit = 0;
			/* Clear any time so NO RTT is being done */
			chk->do_rtt = 0;
			if (alt != net) {
				sctp_free_remote_addr(chk->whoTo);
				chk->no_fr_allowed = 1;
				chk->whoTo = alt;
				atomic_add_int(&alt->ref_count, 1);
			} else {
				chk->no_fr_allowed = 0;
				if (TAILQ_EMPTY(&stcb->asoc.send_queue)) {
					chk->rec.data.fast_retran_tsn = stcb->asoc.sending_seq;
				} else {
					chk->rec.data.fast_retran_tsn = (TAILQ_FIRST(&stcb->asoc.send_queue))->rec.data.TSN_seq;
				}
			}
			if (sctp_cmt_on_off == 1) {
				chk->no_fr_allowed = 1;
			}
		} else if (chk->sent == SCTP_DATAGRAM_ACKED) {
			/* remember highest acked one */
			could_be_sent = chk;
		}
		if (chk->sent == SCTP_DATAGRAM_RESEND) {
			cnt_mk++;
		}
	}
#if defined(SCTP_FR_LOGGING) || defined(SCTP_EARLYFR_LOGGING)
	sctp_log_fr(tsnfirst, tsnlast, num_mk, SCTP_FR_T3_TIMEOUT);
#endif

	if (stcb->asoc.total_flight >= (orig_flight - net->flight_size)) {
		stcb->asoc.total_flight -= (orig_flight - net->flight_size);
	} else {
		stcb->asoc.total_flight = 0;
		stcb->asoc.total_flight_count = 0;
		audit_tf = 1;
	}

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
		if (num_mk) {
			printf("LAST TSN marked was %x\n", tsnlast);
			printf("Num marked for retransmission was %d peer-rwd:%ld\n",
			    num_mk, (u_long)stcb->asoc.peers_rwnd);
			printf("LAST TSN marked was %x\n", tsnlast);
			printf("Num marked for retransmission was %d peer-rwd:%d\n",
			    num_mk,
			    (int)stcb->asoc.peers_rwnd
			    );
		}
	}
#endif
	*num_marked = num_mk;
	if ((stcb->asoc.sent_queue_retran_cnt == 0) && (could_be_sent)) {
		/* fix it so we retransmit the highest acked anyway */
		sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
		cnt_mk++;
		could_be_sent->sent = SCTP_DATAGRAM_RESEND;
	}
	if (stcb->asoc.sent_queue_retran_cnt != cnt_mk) {
#ifdef INVARIANTS
		printf("Local Audit says there are %d for retran asoc cnt:%d\n",
		    cnt_mk, stcb->asoc.sent_queue_retran_cnt);
#endif
#ifndef SCTP_AUDITING_ENABLED
		stcb->asoc.sent_queue_retran_cnt = cnt_mk;
#endif
	}
	/* Now check for a ECN Echo that may be stranded */
	TAILQ_FOREACH(chk, &stcb->asoc.control_send_queue, sctp_next) {
		if ((chk->whoTo == net) &&
		    (chk->rec.chunk_id.id == SCTP_ECN_ECHO)) {
			sctp_free_remote_addr(chk->whoTo);
			chk->whoTo = alt;
			if (chk->sent != SCTP_DATAGRAM_RESEND) {
				chk->sent = SCTP_DATAGRAM_RESEND;
				sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
			}
			atomic_add_int(&alt->ref_count, 1);
		}
	}
	if (audit_tf) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
			printf("Audit total flight due to negative value net:%p\n",
			    net);
		}
#endif				/* SCTP_DEBUG */
		stcb->asoc.total_flight = 0;
		stcb->asoc.total_flight_count = 0;
		/* Clear all networks flight size */
		TAILQ_FOREACH(lnets, &stcb->asoc.nets, sctp_next) {
			lnets->flight_size = 0;
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
				printf("Net:%p c-f cwnd:%d ssthresh:%d\n",
				    lnets, lnets->cwnd, lnets->ssthresh);
			}
#endif				/* SCTP_DEBUG */
		}
		TAILQ_FOREACH(chk, &stcb->asoc.sent_queue, sctp_next) {
			if (chk->sent < SCTP_DATAGRAM_RESEND) {
#ifdef SCTP_FLIGHT_LOGGING
			sctp_misc_ints(SCTP_FLIGHT_LOG_UP, 
				       chk->whoTo->flight_size,
				       chk->book_size, 
				       (uintptr_t)stcb, 
				       chk->rec.data.TSN_seq);
#endif
				stcb->asoc.total_flight += chk->book_size;
				chk->whoTo->flight_size += chk->book_size;
				stcb->asoc.total_flight_count++;
			}
		}
	}
	/*
	 * Setup the ecn nonce re-sync point. We do this since
	 * retranmissions are NOT setup for ECN. This means that do to
	 * Karn's rule, we don't know the total of the peers ecn bits.
	 */
	chk = TAILQ_FIRST(&stcb->asoc.send_queue);
	if (chk == NULL) {
		stcb->asoc.nonce_resync_tsn = stcb->asoc.sending_seq;
	} else {
		stcb->asoc.nonce_resync_tsn = chk->rec.data.TSN_seq;
	}
	stcb->asoc.nonce_wait_for_ecne = 0;
	stcb->asoc.nonce_sum_check = 0;
	/* We return 1 if we only have a window probe outstanding */
	return (0);
}

static void
sctp_move_all_chunks_to_alt(struct sctp_tcb *stcb,
    struct sctp_nets *net,
    struct sctp_nets *alt)
{
	struct sctp_association *asoc;
	struct sctp_stream_out *outs;
	struct sctp_tmit_chunk *chk;
	struct sctp_stream_queue_pending *sp;

#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(SCTP_INP_SO(stcb->sctp_ep));
#endif
	if (net == alt)
		/* nothing to do */
		return;

	asoc = &stcb->asoc;

	/*
	 * now through all the streams checking for chunks sent to our bad
	 * network.
	 */
	TAILQ_FOREACH(outs, &asoc->out_wheel, next_spoke) {
		/* now clean up any chunks here */
		TAILQ_FOREACH(sp, &outs->outqueue, next) {
			if (sp->net == net) {
				sctp_free_remote_addr(sp->net);
				sp->net = alt;
				atomic_add_int(&alt->ref_count, 1);
			}
		}
	}
	/* Now check the pending queue */
	TAILQ_FOREACH(chk, &asoc->send_queue, sctp_next) {
		if (chk->whoTo == net) {
			sctp_free_remote_addr(chk->whoTo);
			chk->whoTo = alt;
			atomic_add_int(&alt->ref_count, 1);
		}
	}

}

int
sctp_t3rxt_timer(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct sctp_nets *alt;
	int win_probe, num_mk;

#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(SCTP_INP_SO(stcb->sctp_ep));
#endif
#ifdef SCTP_FR_LOGGING
	sctp_log_fr(0, 0, 0, SCTP_FR_T3_TIMEOUT);
#ifdef SCTP_CWND_LOGGING
	{
		struct sctp_nets *lnet;

		TAILQ_FOREACH(lnet, &stcb->asoc.nets, sctp_next) {
			if (net == lnet) {
				sctp_log_cwnd(stcb, lnet, 1, SCTP_CWND_LOG_FROM_T3);
			} else {
				sctp_log_cwnd(stcb, lnet, 0, SCTP_CWND_LOG_FROM_T3);
			}
		}
	}
#endif
#endif
	/* Find an alternate and mark those for retransmission */
	if ((stcb->asoc.peers_rwnd == 0) &&
	    (stcb->asoc.total_flight < net->mtu)) {
		SCTP_STAT_INCR(sctps_timowindowprobe);
		win_probe = 1;
	} else {
		win_probe = 0;
	}
	alt = sctp_find_alternate_net(stcb, net, 0);
	sctp_mark_all_for_resend(stcb, net, alt, win_probe, &num_mk);
	/* FR Loss recovery just ended with the T3. */
	stcb->asoc.fast_retran_loss_recovery = 0;

	/* CMT FR loss recovery ended with the T3 */
	net->fast_retran_loss_recovery = 0;

	/*
	 * setup the sat loss recovery that prevents satellite cwnd advance.
	 */
	stcb->asoc.sat_t3_loss_recovery = 1;
	stcb->asoc.sat_t3_recovery_tsn = stcb->asoc.sending_seq;

	/* Backoff the timer and cwnd */
	sctp_backoff_on_timeout(stcb, net, win_probe, num_mk);
	if (win_probe == 0) {
		/* We don't do normal threshold management on window probes */
		if (sctp_threshold_management(inp, stcb, net,
		    stcb->asoc.max_send_times)) {
			/* Association was destroyed */
			return (1);
		} else {
			if (net != stcb->asoc.primary_destination) {
				/* send a immediate HB if our RTO is stale */
				struct timeval now;
				unsigned int ms_goneby;

				SCTP_GETTIME_TIMEVAL(&now);
				if (net->last_sent_time.tv_sec) {
					ms_goneby = (now.tv_sec - net->last_sent_time.tv_sec) * 1000;
				} else {
					ms_goneby = 0;
				}
				if ((ms_goneby > net->RTO) || (net->RTO == 0)) {
					/*
					 * no recent feed back in an RTO or
					 * more, request a RTT update
					 */
					sctp_send_hb(stcb, 1, net);
				}
			}
		}
	} else {
		/*
		 * For a window probe we don't penalize the net's but only
		 * the association. This may fail it if SACKs are not coming
		 * back. If sack's are coming with rwnd locked at 0, we will
		 * continue to hold things waiting for rwnd to raise
		 */
		if (sctp_threshold_management(inp, stcb, NULL,
		    stcb->asoc.max_send_times)) {
			/* Association was destroyed */
			return (1);
		}
	}
	if (net->dest_state & SCTP_ADDR_NOT_REACHABLE) {
		/* Move all pending over too */
		sctp_move_all_chunks_to_alt(stcb, net, alt);
		/* Was it our primary? */
		if ((stcb->asoc.primary_destination == net) && (alt != net)) {
			/*
			 * Yes, note it as such and find an alternate note:
			 * this means HB code must use this to resent the
			 * primary if it goes active AND if someone does a
			 * change-primary then this flag must be cleared
			 * from any net structures.
			 */
			if (sctp_set_primary_addr(stcb,
			    (struct sockaddr *)NULL,
			    alt) == 0) {
				net->dest_state |= SCTP_ADDR_WAS_PRIMARY;
				if (net->ro._s_addr) {
					sctp_free_ifa(net->ro._s_addr);
					net->ro._s_addr = NULL;
				}
				net->src_addr_selected = 0;
			}
		}
	}
	/*
	 * Special case for cookie-echo'ed case, we don't do output but must
	 * await the COOKIE-ACK before retransmission
	 */
	if (SCTP_GET_STATE(&stcb->asoc) == SCTP_STATE_COOKIE_ECHOED) {
		/*
		 * Here we just reset the timer and start again since we
		 * have not established the asoc
		 */
		sctp_timer_start(SCTP_TIMER_TYPE_SEND, inp, stcb, net);
		return (0);
	}
	if (stcb->asoc.peer_supports_prsctp) {
		struct sctp_tmit_chunk *lchk;

		lchk = sctp_try_advance_peer_ack_point(stcb, &stcb->asoc);
		/* C3. See if we need to send a Fwd-TSN */
		if (compare_with_wrap(stcb->asoc.advanced_peer_ack_point,
		    stcb->asoc.last_acked_seq, MAX_TSN)) {
			/*
			 * ISSUE with ECN, see FWD-TSN processing for notes
			 * on issues that will occur when the ECN NONCE
			 * stuff is put into SCTP for cross checking.
			 */
			send_forward_tsn(stcb, &stcb->asoc);
			if (lchk) {
				/* Assure a timer is up */
				sctp_timer_start(SCTP_TIMER_TYPE_SEND, stcb->sctp_ep, stcb, lchk->whoTo);
			}
		}
	}
#ifdef SCTP_CWND_MONITOR
	sctp_log_cwnd(stcb, net, net->cwnd, SCTP_CWND_LOG_FROM_RTX);
#endif
	return (0);
}

int
sctp_t1init_timer(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(SCTP_INP_SO(stcb->sctp_ep));
#endif
	/* bump the thresholds */
	if (stcb->asoc.delayed_connection) {
		/*
		 * special hook for delayed connection. The library did NOT
		 * complete the rest of its sends.
		 */
		stcb->asoc.delayed_connection = 0;
		sctp_send_initiate(inp, stcb);
		return (0);
	}
	if (SCTP_GET_STATE((&stcb->asoc)) != SCTP_STATE_COOKIE_WAIT) {
		return (0);
	}
	if (sctp_threshold_management(inp, stcb, net,
	    stcb->asoc.max_init_times)) {
		/* Association was destroyed */
		return (1);
	}
	stcb->asoc.dropped_special_cnt = 0;
	sctp_backoff_on_timeout(stcb, stcb->asoc.primary_destination, 1, 0);
	if (stcb->asoc.initial_init_rto_max < net->RTO) {
		net->RTO = stcb->asoc.initial_init_rto_max;
	}
	if (stcb->asoc.numnets > 1) {
		/* If we have more than one addr use it */
		struct sctp_nets *alt;

		alt = sctp_find_alternate_net(stcb, stcb->asoc.primary_destination, 0);
		if ((alt != NULL) && (alt != stcb->asoc.primary_destination)) {
			sctp_move_all_chunks_to_alt(stcb, stcb->asoc.primary_destination, alt);
			stcb->asoc.primary_destination = alt;
		}
	}
	/* Send out a new init */
	sctp_send_initiate(inp, stcb);
	return (0);
}

/*
 * For cookie and asconf we actually need to find and mark for resend, then
 * increment the resend counter (after all the threshold management stuff of
 * course).
 */
int
sctp_cookie_timer(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct sctp_nets *alt;
	struct sctp_tmit_chunk *cookie;

#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(SCTP_INP_SO(stcb->sctp_ep));
#endif
	/* first before all else we must find the cookie */
	TAILQ_FOREACH(cookie, &stcb->asoc.control_send_queue, sctp_next) {
		if (cookie->rec.chunk_id.id == SCTP_COOKIE_ECHO) {
			break;
		}
	}
	if (cookie == NULL) {
		if (SCTP_GET_STATE(&stcb->asoc) == SCTP_STATE_COOKIE_ECHOED) {
			/* FOOBAR! */
			struct mbuf *oper;

			oper = sctp_get_mbuf_for_msg((sizeof(struct sctp_paramhdr) + sizeof(uint32_t)),
						       0, M_DONTWAIT, 1, MT_DATA);
			if (oper) {
				struct sctp_paramhdr *ph;
				uint32_t *ippp;

				SCTP_BUF_LEN(oper) = sizeof(struct sctp_paramhdr) +
				    sizeof(uint32_t);
				ph = mtod(oper, struct sctp_paramhdr *);
				ph->param_type = htons(SCTP_CAUSE_PROTOCOL_VIOLATION);
				ph->param_length = htons(SCTP_BUF_LEN(oper));
				ippp = (uint32_t *) (ph + 1);
				*ippp = htonl(SCTP_FROM_SCTP_TIMER+SCTP_LOC_2);
			}
			inp->last_abort_code = SCTP_FROM_SCTP_TIMER+SCTP_LOC_3;
			sctp_abort_an_association(inp, stcb, SCTP_INTERNAL_ERROR,
			    oper);
		} else {
#ifdef INVARIANTS
			panic("Cookie timer expires in wrong state?");
#else
			printf("Strange in state %d not cookie-echoed yet c-e timer expires?\n", SCTP_GET_STATE(&stcb->asoc));
			return (0);
#endif
		}
		return (0);
	}
	/* Ok we found the cookie, threshold management next */
	if (sctp_threshold_management(inp, stcb, cookie->whoTo,
	    stcb->asoc.max_init_times)) {
		/* Assoc is over */
		return (1);
	}
	/*
	 * cleared theshold management now lets backoff the address & select
	 * an alternate
	 */
	stcb->asoc.dropped_special_cnt = 0;
	sctp_backoff_on_timeout(stcb, cookie->whoTo, 1, 0);
	alt = sctp_find_alternate_net(stcb, cookie->whoTo, 0);
	if (alt != cookie->whoTo) {
		sctp_free_remote_addr(cookie->whoTo);
		cookie->whoTo = alt;
		atomic_add_int(&alt->ref_count, 1);
	}
	/* Now mark the retran info */
	if (cookie->sent != SCTP_DATAGRAM_RESEND) {
		sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
	}
	cookie->sent = SCTP_DATAGRAM_RESEND;
	/*
	 * Now call the output routine to kick out the cookie again, Note we
	 * don't mark any chunks for retran so that FR will need to kick in
	 * to move these (or a send timer).
	 */
	return (0);
}

int
sctp_strreset_timer(struct sctp_inpcb *inp, struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct sctp_nets *alt;
	struct sctp_tmit_chunk *strrst = NULL, *chk = NULL;

	if (stcb->asoc.stream_reset_outstanding == 0) {
		return (0);
	}
	/* find the existing STRRESET, we use the seq number we sent out on */
	sctp_find_stream_reset(stcb, stcb->asoc.str_reset_seq_out, &strrst);
	if (strrst == NULL) {
		return (0);
	}
	/* do threshold management */
	if (sctp_threshold_management(inp, stcb, strrst->whoTo,
	    stcb->asoc.max_send_times)) {
		/* Assoc is over */
		return (1);
	}
	/*
	 * cleared theshold management now lets backoff the address & select
	 * an alternate
	 */
	sctp_backoff_on_timeout(stcb, strrst->whoTo, 1, 0);
	alt = sctp_find_alternate_net(stcb, strrst->whoTo, 0);
	sctp_free_remote_addr(strrst->whoTo);
	strrst->whoTo = alt;
	atomic_add_int(&alt->ref_count, 1);

	/* See if a ECN Echo is also stranded */
	TAILQ_FOREACH(chk, &stcb->asoc.control_send_queue, sctp_next) {
		if ((chk->whoTo == net) &&
		    (chk->rec.chunk_id.id == SCTP_ECN_ECHO)) {
			sctp_free_remote_addr(chk->whoTo);
			if (chk->sent != SCTP_DATAGRAM_RESEND) {
				chk->sent = SCTP_DATAGRAM_RESEND;
				sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
			}
			chk->whoTo = alt;
			atomic_add_int(&alt->ref_count, 1);
		}
	}
	if (net->dest_state & SCTP_ADDR_NOT_REACHABLE) {
		/*
		 * If the address went un-reachable, we need to move to
		 * alternates for ALL chk's in queue
		 */
		sctp_move_all_chunks_to_alt(stcb, net, alt);
	}
	/* mark the retran info */
	if (strrst->sent != SCTP_DATAGRAM_RESEND)
		sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
	strrst->sent = SCTP_DATAGRAM_RESEND;

	/* restart the timer */
	sctp_timer_start(SCTP_TIMER_TYPE_STRRESET, inp, stcb, strrst->whoTo);
	return (0);
}

int
sctp_asconf_timer(struct sctp_inpcb *inp, struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct sctp_nets *alt;
	struct sctp_tmit_chunk *asconf, *chk;

	/* is this the first send, or a retransmission? */
	if (stcb->asoc.asconf_sent == 0) {
		/* compose a new ASCONF chunk and send it */
		sctp_send_asconf(stcb, net);
	} else {
		/* Retransmission of the existing ASCONF needed... */

		/* find the existing ASCONF */
		TAILQ_FOREACH(asconf, &stcb->asoc.control_send_queue,
		    sctp_next) {
			if (asconf->rec.chunk_id.id == SCTP_ASCONF) {
				break;
			}
		}
		if (asconf == NULL) {
			return (0);
		}
		/* do threshold management */
		if (sctp_threshold_management(inp, stcb, asconf->whoTo,
		    stcb->asoc.max_send_times)) {
			/* Assoc is over */
			return (1);
		}
		/*
		 * PETER? FIX? How will the following code ever run? If the
		 * max_send_times is hit, threshold managment will blow away
		 * the association?
		 */
		if (asconf->snd_count > stcb->asoc.max_send_times) {
			/*
			 * Something is rotten, peer is not responding to
			 * ASCONFs but maybe is to data etc.  e.g. it is not
			 * properly handling the chunk type upper bits Mark
			 * this peer as ASCONF incapable and cleanup
			 */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
				printf("asconf_timer: Peer has not responded to our repeated ASCONFs\n");
			}
#endif				/* SCTP_DEBUG */
			sctp_asconf_cleanup(stcb, net);
			return (0);
		}
		/*
		 * cleared theshold management now lets backoff the address
		 * & select an alternate
		 */
		sctp_backoff_on_timeout(stcb, asconf->whoTo, 1, 0);
		alt = sctp_find_alternate_net(stcb, asconf->whoTo, 0);
		sctp_free_remote_addr(asconf->whoTo);
		asconf->whoTo = alt;
		atomic_add_int(&alt->ref_count, 1);

		/* See if a ECN Echo is also stranded */
		TAILQ_FOREACH(chk, &stcb->asoc.control_send_queue, sctp_next) {
			if ((chk->whoTo == net) &&
			    (chk->rec.chunk_id.id == SCTP_ECN_ECHO)) {
				sctp_free_remote_addr(chk->whoTo);
				chk->whoTo = alt;
				if (chk->sent != SCTP_DATAGRAM_RESEND) {
					chk->sent = SCTP_DATAGRAM_RESEND;
					sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
				}
				atomic_add_int(&alt->ref_count, 1);
			}
		}
		if (net->dest_state & SCTP_ADDR_NOT_REACHABLE) {
			/*
			 * If the address went un-reachable, we need to move
			 * to alternates for ALL chk's in queue
			 */
			sctp_move_all_chunks_to_alt(stcb, net, alt);
		}
		/* mark the retran info */
		if (asconf->sent != SCTP_DATAGRAM_RESEND)
			sctp_ucount_incr(stcb->asoc.sent_queue_retran_cnt);
		asconf->sent = SCTP_DATAGRAM_RESEND;
	}
	return (0);
}

/*
 * For the shutdown and shutdown-ack, we do not keep one around on the
 * control queue. This means we must generate a new one and call the general
 * chunk output routine, AFTER having done threshold management.
 */
int
sctp_shutdown_timer(struct sctp_inpcb *inp, struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct sctp_nets *alt;

	/* first threshold managment */
	if (sctp_threshold_management(inp, stcb, net, stcb->asoc.max_send_times)) {
		/* Assoc is over */
		return (1);
	}
	/* second select an alternative */
	alt = sctp_find_alternate_net(stcb, net, 0);

	/* third generate a shutdown into the queue for out net */
	if (alt) {
		sctp_send_shutdown(stcb, alt);
	} else {
		/*
		 * if alt is NULL, there is no dest to send to??
		 */
		return (0);
	}
	/* fourth restart timer */
	sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN, inp, stcb, alt);
	return (0);
}

int
sctp_shutdownack_timer(struct sctp_inpcb *inp, struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct sctp_nets *alt;

	/* first threshold managment */
	if (sctp_threshold_management(inp, stcb, net, stcb->asoc.max_send_times)) {
		/* Assoc is over */
		return (1);
	}
	/* second select an alternative */
	alt = sctp_find_alternate_net(stcb, net, 0);

	/* third generate a shutdown into the queue for out net */
	sctp_send_shutdown_ack(stcb, alt);

	/* fourth restart timer */
	sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNACK, inp, stcb, alt);
	return (0);
}

static void
sctp_audit_stream_queues_for_size(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb)
{
	struct sctp_stream_out *outs;
	struct sctp_stream_queue_pending *sp;
	unsigned int chks_in_queue = 0;
	int being_filled=0;
	/*
	 * This function is ONLY called when the send/sent queues are empty.
	 */
	if ((stcb == NULL) || (inp == NULL))
		return;

	if (stcb->asoc.sent_queue_retran_cnt) {
		printf("Hmm, sent_queue_retran_cnt is non-zero %d\n",
		    stcb->asoc.sent_queue_retran_cnt);
		stcb->asoc.sent_queue_retran_cnt = 0;
	}
	SCTP_TCB_SEND_LOCK(stcb);
	if (TAILQ_EMPTY(&stcb->asoc.out_wheel)) {
		int i, cnt = 0;

		/* Check to see if a spoke fell off the wheel */
		for (i = 0; i < stcb->asoc.streamoutcnt; i++) {
			if (!TAILQ_EMPTY(&stcb->asoc.strmout[i].outqueue)) {
				sctp_insert_on_wheel(stcb, &stcb->asoc, &stcb->asoc.strmout[i],1);
				cnt++;
			}
		}
		if (cnt) {
			/* yep, we lost a spoke or two */
			printf("Found an additional %d streams NOT on outwheel, corrected\n", cnt);
		} else {
			/* no spokes lost, */
			stcb->asoc.total_output_queue_size = 0;
		}
		SCTP_TCB_SEND_UNLOCK(stcb);
		return;
	}
	SCTP_TCB_SEND_UNLOCK(stcb);
	/* Check to see if some data queued, if so report it */
	TAILQ_FOREACH(outs, &stcb->asoc.out_wheel, next_spoke) {
		if (!TAILQ_EMPTY(&outs->outqueue)) {
			TAILQ_FOREACH(sp, &outs->outqueue, next) {
				if(sp->msg_is_complete)
					being_filled++;
				chks_in_queue++;
			}
		}
	}
	if (chks_in_queue != stcb->asoc.stream_queue_cnt) {
		printf("Hmm, stream queue cnt at %d I counted %d in stream out wheel\n",
		    stcb->asoc.stream_queue_cnt, chks_in_queue);
	}
	if (chks_in_queue) {
		/* call the output queue function */
		sctp_chunk_output(inp, stcb, SCTP_OUTPUT_FROM_T3);
		if ((TAILQ_EMPTY(&stcb->asoc.send_queue)) &&
		    (TAILQ_EMPTY(&stcb->asoc.sent_queue))) {
			/*
			 * Probably should go in and make it go back through
			 * and add fragments allowed
			 */
			if(being_filled == 0) {
				printf("Still nothing moved %d chunks are stuck\n", 
				       chks_in_queue);
			}
		}
	} else {
		printf("Found no chunks on any queue tot:%lu\n",
		    (u_long)stcb->asoc.total_output_queue_size);
		stcb->asoc.total_output_queue_size = 0;
	}
}

extern int sctp_hb_maxburst;

int
sctp_heartbeat_timer(struct sctp_inpcb *inp, struct sctp_tcb *stcb,
    struct sctp_nets *net, int cnt_of_unconf)
{
#if defined(SCTP_PER_SOCKET_LOCKING)
	sctp_lock_assert(SCTP_INP_SO(stcb->sctp_ep));
#endif
	if (net) {
		if (net->hb_responded == 0) {
			if(net->ro._s_addr) {
				/* Invalidate the src address if we did not get
				 * a response last time.
				 */
				sctp_free_ifa(net->ro._s_addr);
				net->ro._s_addr = NULL;
				net->src_addr_selected = 0;
			}
			sctp_backoff_on_timeout(stcb, net, 1, 0);
		}
		/* Zero PBA, if it needs it */
		if (net->partial_bytes_acked) {
			net->partial_bytes_acked = 0;
		}
	}
	if ((stcb->asoc.total_output_queue_size > 0) &&
	    (TAILQ_EMPTY(&stcb->asoc.send_queue)) &&
	    (TAILQ_EMPTY(&stcb->asoc.sent_queue))) {
		sctp_audit_stream_queues_for_size(inp, stcb);
	}
	/* Send a new HB, this will do threshold managment, pick a new dest */
	if (cnt_of_unconf == 0) {
		if (sctp_send_hb(stcb, 0, NULL) < 0) {
			return (1);
		}
	} else {
		/*
		 * this will send out extra hb's up to maxburst if there are
		 * any unconfirmed addresses.
		 */
		int cnt_sent = 0;

		TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
			if ((net->dest_state & SCTP_ADDR_UNCONFIRMED) &&
			    (net->dest_state & SCTP_ADDR_REACHABLE)) {
				cnt_sent++;
				if (sctp_send_hb(stcb, 1, net) == 0) {
					break;
				}
				if (cnt_sent >= sctp_hb_maxburst)
					break;
			}
		}
	}
	return (0);
}

int
sctp_is_hb_timer_running(struct sctp_tcb *stcb)
{
	if (SCTP_OS_TIMER_PENDING(&stcb->asoc.hb_timer.timer)) {
		/* its running */
		return (1);
	} else {
		/* nope */
		return (0);
	}
}

int
sctp_is_sack_timer_running(struct sctp_tcb *stcb)
{
	if (SCTP_OS_TIMER_PENDING(&stcb->asoc.dack_timer.timer)) {
		/* its running */
		return (1);
	} else {
		/* nope */
		return (0);
	}
}

#define SCTP_NUMBER_OF_MTU_SIZES 18
static uint32_t mtu_sizes[] = {
	68,
	296,
	508,
	512,
	544,
	576,
	1006,
	1492,
	1500,
	1536,
	2002,
	2048,
	4352,
	4464,
	8166,
	17914,
	32000,
	65535
};


static uint32_t
sctp_getnext_mtu(struct sctp_inpcb *inp, uint32_t cur_mtu)
{
	/* select another MTU that is just bigger than this one */
	int i;

	for (i = 0; i < SCTP_NUMBER_OF_MTU_SIZES; i++) {
		if (cur_mtu < mtu_sizes[i]) {
			/* no max_mtu is bigger than this one */
			return (mtu_sizes[i]);
		}
	}
	/* here return the highest allowable */
	return (cur_mtu);
}


void
sctp_pathmtu_timer(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	uint32_t next_mtu;

	/* restart the timer in any case */
	next_mtu = sctp_getnext_mtu(inp, net->mtu);
	if (next_mtu <= net->mtu) {
		/* nothing to do */
		return;
	}
	if (net->ro.ro_rt != NULL) {
		/*
		 * only if we have a route and interface do we set anything.
		 * Note we always restart the timer though just in case it
		 * is updated (i.e. the ifp) or route/ifp is populated.
		 */
		if (net->ro.ro_rt->rt_ifp != NULL) {
			if (net->ro.ro_rt->rt_ifp->if_mtu > next_mtu) {
				/* ok it will fit out the door */
				net->mtu = next_mtu;
			}
		}
	}
	/* restart the timer */
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, net);
}

void
sctp_autoclose_timer(struct sctp_inpcb *inp,
    struct sctp_tcb *stcb,
    struct sctp_nets *net)
{
	struct timeval tn, *tim_touse;
	struct sctp_association *asoc;
	int ticks_gone_by;

	SCTP_GETTIME_TIMEVAL(&tn);
	if (stcb->asoc.sctp_autoclose_ticks &&
	    sctp_is_feature_on(inp, SCTP_PCB_FLAGS_AUTOCLOSE)) {
		/* Auto close is on */
		asoc = &stcb->asoc;
		/* pick the time to use */
		if (asoc->time_last_rcvd.tv_sec >
		    asoc->time_last_sent.tv_sec) {
			tim_touse = &asoc->time_last_rcvd;
		} else {
			tim_touse = &asoc->time_last_sent;
		}
		/* Now has long enough transpired to autoclose? */
		ticks_gone_by = SEC_TO_TICKS(tn.tv_sec - tim_touse->tv_sec);
		if ((ticks_gone_by > 0) &&
		    (ticks_gone_by >= (int)asoc->sctp_autoclose_ticks)) {
			/*
			 * autoclose time has hit, call the output routine,
			 * which should do nothing just to be SURE we don't
			 * have hanging data. We can then safely check the
			 * queues and know that we are clear to send
			 * shutdown
			 */
			sctp_chunk_output(inp, stcb, SCTP_OUTPUT_FROM_AUTOCLOSE_TMR);
			/* Are we clean? */
			if (TAILQ_EMPTY(&asoc->send_queue) &&
			    TAILQ_EMPTY(&asoc->sent_queue)) {
				/*
				 * there is nothing queued to send, so I'm
				 * done...
				 */
				if (SCTP_GET_STATE(asoc) != SCTP_STATE_SHUTDOWN_SENT) {
					/* only send SHUTDOWN 1st time thru */
					sctp_send_shutdown(stcb, stcb->asoc.primary_destination);
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
			}
		} else {
			/*
			 * No auto close at this time, reset t-o to check
			 * later
			 */
			int tmp;

			/* fool the timer startup to use the time left */
			tmp = asoc->sctp_autoclose_ticks;
			asoc->sctp_autoclose_ticks -= ticks_gone_by;
			sctp_timer_start(SCTP_TIMER_TYPE_AUTOCLOSE, inp, stcb,
			    net);
			/* restore the real tick value */
			asoc->sctp_autoclose_ticks = tmp;
		}
	}
}

#if defined(SCTP_PER_SOCKET_LOCKING)
/*
 * This function assumes that no socket lock is locked. The function
 * called per association gets the socket locked.
 */
#endif
void
sctp_iterator_timer(struct sctp_iterator *it)
{
	int iteration_count = 0;
	int inp_skip = 0;
	/*
	 * only one iterator can run at a time. This is the only way we can
	 * cleanly pull ep's from underneath all the running interators when
	 * a ep is freed.
	 */
	SCTP_ITERATOR_LOCK();
	if (it->inp == NULL) {
		/* iterator is complete */
done_with_iterator:
		SCTP_ITERATOR_UNLOCK();
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_LOCK_EXC(sctppcbinfo.ipi_ep_mtx);
#endif
		SCTP_INP_INFO_WLOCK();
		TAILQ_REMOVE(&sctppcbinfo.iteratorhead, it, sctp_nxt_itr);
		/* stopping the callout is not needed, in theory */
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_UNLOCK_EXC(sctppcbinfo.ipi_ep_mtx);
#endif
		SCTP_INP_INFO_WUNLOCK();
		SCTP_OS_TIMER_STOP(&it->tmr.timer);
		if (it->function_atend != NULL) {
			(*it->function_atend) (it->pointer, it->val);
		}
		SCTP_FREE(it);
		return;
	}
select_a_new_ep:
#if defined(SCTP_PER_SOCKET_LOCKING)
	SCTP_SOCKET_LOCK(SCTP_INP_SO(it->inp), 1);
#endif
	SCTP_INP_WLOCK(it->inp);
	while (((it->pcb_flags) &&
		((it->inp->sctp_flags & it->pcb_flags) != it->pcb_flags)) ||
	       ((it->pcb_features) &&
		((it->inp->sctp_features & it->pcb_features) != it->pcb_features))) {
		/* endpoint flags or features don't match, so keep looking */
		if (it->iterator_flags & SCTP_ITERATOR_DO_SINGLE_INP) {
#if defined(SCTP_PER_SOCKET_LOCKING)
			SCTP_SOCKET_UNLOCK(SCTP_INP_SO(it->inp), 1);
#endif
			SCTP_INP_WUNLOCK(it->inp);
			goto done_with_iterator;
		}
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_SOCKET_UNLOCK(SCTP_INP_SO(it->inp), 1);
#endif
		SCTP_INP_WUNLOCK(it->inp);
		it->inp = LIST_NEXT(it->inp, sctp_list);
		if (it->inp == NULL) {
			goto done_with_iterator;
		}
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_SOCKET_LOCK(SCTP_INP_SO(it->inp), 1);
#endif
		SCTP_INP_WLOCK(it->inp);
	}
	if ((it->inp->inp_starting_point_for_iterator != NULL) &&
	    (it->inp->inp_starting_point_for_iterator != it)) {
		printf("Iterator collision, waiting for one at %p\n",
		       it->inp);
#if defined(SCTP_PER_SOCKET_LOCKING)
		/* Unlock done at start_timer_return */
#endif
		SCTP_INP_WUNLOCK(it->inp);
		goto start_timer_return;
	}
	/* mark the current iterator on the endpoint */
	it->inp->inp_starting_point_for_iterator = it;
	SCTP_INP_WUNLOCK(it->inp);
	SCTP_INP_RLOCK(it->inp);
	/* now go through each assoc which is in the desired state */
	if(it->done_current_ep == 0) {
		if (it->function_inp != NULL)
			inp_skip = (*it->function_inp)(it->inp, it->pointer, it->val);
		it->done_current_ep = 1;
	}

	if (it->stcb == NULL) {
		/* run the per instance function */
		it->stcb = LIST_FIRST(&it->inp->sctp_asoc_list);
	}
	SCTP_INP_RUNLOCK(it->inp);
	if((inp_skip) || it->stcb == NULL) {
		if(it->function_inp_end != NULL) {
			inp_skip = (*it->function_inp_end)(it->inp, 
							   it->pointer, 
							   it->val);
		}
		goto no_stcb;
	}
	if ((it->stcb) &&
	    (it->stcb->asoc.stcb_starting_point_for_iterator == it)) {
		it->stcb->asoc.stcb_starting_point_for_iterator = NULL;
	}
	while (it->stcb) {
		SCTP_TCB_LOCK(it->stcb);
		if (it->asoc_state && ((it->stcb->asoc.state & it->asoc_state) != it->asoc_state)) {
			/* not in the right state... keep looking */
			SCTP_TCB_UNLOCK(it->stcb);
			goto next_assoc;
		}
		/* mark the current iterator on the assoc */
		it->stcb->asoc.stcb_starting_point_for_iterator = it;
		/* see if we have limited out the iterator loop */
		iteration_count++;
		if (iteration_count > SCTP_ITERATOR_MAX_AT_ONCE) {
	start_timer_return:
#if defined(SCTP_PER_SOCKET_LOCKING)
			SCTP_SOCKET_UNLOCK(SCTP_INP_SO(it->inp), 1);
#endif
			/* set a timer to continue this later */
			SCTP_TCB_UNLOCK(it->stcb);
			sctp_timer_start(SCTP_TIMER_TYPE_ITERATOR,
			    (struct sctp_inpcb *)it, NULL, NULL);
			SCTP_ITERATOR_UNLOCK();
			return;
		}
		/* run function on this one */
		(*it->function_assoc)(it->inp, it->stcb, it->pointer, it->val);

		/*
		 * we lie here, it really needs to have its own type but
		 * first I must verify that this won't effect things :-0
		 */
		if (it->no_chunk_output == 0)
			sctp_chunk_output(it->inp, it->stcb, SCTP_OUTPUT_FROM_T3);
		
		SCTP_TCB_UNLOCK(it->stcb);
	next_assoc:
		it->stcb = LIST_NEXT(it->stcb, sctp_tcblist);
		if(it->stcb == NULL) {
			if(it->function_inp_end != NULL) {
				inp_skip = (*it->function_inp_end)(it->inp, 
								   it->pointer, 
								   it->val);
			}
		}
	}
 no_stcb:
	/* done with all assocs on this endpoint, move on to next endpoint */
	it->done_current_ep = 0;
	SCTP_INP_WLOCK(it->inp);
	it->inp->inp_starting_point_for_iterator = NULL;
	SCTP_INP_WUNLOCK(it->inp);
#if defined(SCTP_PER_SOCKET_LOCKING)
	SCTP_SOCKET_UNLOCK(SCTP_INP_SO(it->inp), 1);
#endif
	if (it->iterator_flags & SCTP_ITERATOR_DO_SINGLE_INP) {
		it->inp = NULL;
	} else {
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_LOCK_EXC(sctppcbinfo.ipi_ep_mtx);
#endif
		SCTP_INP_INFO_RLOCK();
		it->inp = LIST_NEXT(it->inp, sctp_list);
#if defined(SCTP_PER_SOCKET_LOCKING)
		SCTP_UNLOCK_EXC(sctppcbinfo.ipi_ep_mtx);
#endif
		SCTP_INP_INFO_RUNLOCK();
	}
	if (it->inp == NULL) {
		goto done_with_iterator;
	}
	goto select_a_new_ep;
}
