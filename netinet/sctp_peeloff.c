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


/* $KAME: sctp_peeloff.c,v 1.13 2005/03/06 16:04:18 itojun Exp $	 */

#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/netinet/sctp_peeloff.c,v 1.4 2007/02/12 23:24:31 rrs Exp $");
#endif
#include <netinet/sctp_os.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_peeloff.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_auth.h>


#ifdef SCTP_DEBUG
extern uint32_t sctp_debug_on;
#endif				/* SCTP_DEBUG */

#if defined(__APPLE__)
#define APPLE_FILE_NO 5
#endif

int
sctp_can_peel_off(struct socket *head, sctp_assoc_t assoc_id)
{
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb;

	inp = (struct sctp_inpcb *)head->so_pcb;
	if (inp == NULL) {
		return (EFAULT);
	}
	stcb = sctp_findassociation_ep_asocid(inp, assoc_id, 1);
	if (stcb == NULL) {
		return (ENOTCONN);
	}
	SCTP_TCB_UNLOCK(stcb);
	/* We are clear to peel this one off */
	return (0);
}

int
sctp_do_peeloff(struct socket *head, struct socket *so, sctp_assoc_t assoc_id)
{
	struct sctp_inpcb *inp, *n_inp;
	struct sctp_tcb *stcb;

	inp = (struct sctp_inpcb *)head->so_pcb;
	if (inp == NULL)
		return (EFAULT);
	stcb = sctp_findassociation_ep_asocid(inp, assoc_id, 1);
	if (stcb == NULL)
		return (ENOTCONN);

	n_inp = (struct sctp_inpcb *)so->so_pcb;
	n_inp->sctp_flags = (SCTP_PCB_FLAGS_UDPTYPE |
	    SCTP_PCB_FLAGS_CONNECTED |
	    SCTP_PCB_FLAGS_IN_TCPPOOL |	/* Turn on Blocking IO */
	    (SCTP_PCB_COPY_FLAGS & inp->sctp_flags));
	n_inp->sctp_socket = so;
	n_inp->sctp_features = inp->sctp_features;
	n_inp->sctp_frag_point = inp->sctp_frag_point;
	n_inp->partial_delivery_point = inp->partial_delivery_point;
	n_inp->sctp_context = inp->sctp_context;
	n_inp->inp_starting_point_for_iterator = NULL;

	/*
	 * Now we must move it from one hash table to another and get the
	 * stcb in the right place.
	 */
	sctp_move_pcb_and_assoc(inp, n_inp, stcb);

	sctp_pull_off_control_to_new_inp(inp, n_inp, stcb);

	SCTP_TCB_UNLOCK(stcb);
	return (0);
}

struct socket *
sctp_get_peeloff(struct socket *head, sctp_assoc_t assoc_id, int *error)
{
	struct socket *newso;
	struct sctp_inpcb *inp, *n_inp;
	struct sctp_tcb *stcb;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PEEL1) {
		printf("SCTP peel-off called\n");
	}
#endif				/* SCTP_DEBUG */

	inp = (struct sctp_inpcb *)head->so_pcb;
	if (inp == NULL) {
		*error = EFAULT;
		return (NULL);
	}
	stcb = sctp_findassociation_ep_asocid(inp, assoc_id, 1);
	if (stcb == NULL) {
		*error = ENOTCONN;
		return (NULL);
	}
	newso = sonewconn(head, SS_ISCONNECTED
#if defined(__APPLE__) && !defined(SCTP_APPLE_PANTHER)
	    ,NULL
#endif
	    );
	if (newso == NULL) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PEEL1) {
			printf("sctp_peeloff:sonewconn failed err\n");
		}
#endif				/* SCTP_DEBUG */
		*error = ENOMEM;
		SCTP_TCB_UNLOCK(stcb);
		return (NULL);
#ifndef SCTP_PER_SOCKET_LOCKING
	}
#else
	} else {
		SCTP_SOCKET_LOCK(newso, 1);
	}
#endif
	n_inp = (struct sctp_inpcb *)newso->so_pcb;
	SOCK_LOCK(head);
	SCTP_INP_WLOCK(inp);
	SCTP_INP_WLOCK(n_inp);
	n_inp->sctp_flags = (SCTP_PCB_FLAGS_UDPTYPE |
	    SCTP_PCB_FLAGS_CONNECTED |
	    SCTP_PCB_FLAGS_IN_TCPPOOL |	/* Turn on Blocking IO */
	    (SCTP_PCB_COPY_FLAGS & inp->sctp_flags));
	n_inp->sctp_features = inp->sctp_features;
	n_inp->sctp_frag_point = inp->sctp_frag_point;
	n_inp->partial_delivery_point = inp->partial_delivery_point;
	n_inp->sctp_context = inp->sctp_context;
	n_inp->inp_starting_point_for_iterator = NULL;

	/* copy in the authentication parameters from the original endpoint */
	if (n_inp->sctp_ep.local_hmacs)
		sctp_free_hmaclist(n_inp->sctp_ep.local_hmacs);
	n_inp->sctp_ep.local_hmacs =
	    sctp_copy_hmaclist(inp->sctp_ep.local_hmacs);
	if (n_inp->sctp_ep.local_auth_chunks)
		sctp_free_chunklist(n_inp->sctp_ep.local_auth_chunks);
	n_inp->sctp_ep.local_auth_chunks =
	    sctp_copy_chunklist(inp->sctp_ep.local_auth_chunks);
	(void)sctp_copy_skeylist(&inp->sctp_ep.shared_keys,
	    &n_inp->sctp_ep.shared_keys);

	n_inp->sctp_socket = newso;
	if (sctp_is_feature_on(inp, SCTP_PCB_FLAGS_AUTOCLOSE)) {
		sctp_feature_off(n_inp, SCTP_PCB_FLAGS_AUTOCLOSE);
		n_inp->sctp_ep.auto_close_time = 0;
		sctp_timer_stop(SCTP_TIMER_TYPE_AUTOCLOSE, n_inp, stcb, NULL,
				SCTP_FROM_SCTP_PEELOFF+SCTP_LOC_1);
	}
	/* Turn off any non-blocking semantic. */
	SCTP_CLEAR_SO_NBIO(newso);
	newso->so_state |= SS_ISCONNECTED;
	/* We remove it right away */
#if defined(__FreeBSD__) || defined(__APPLE__)
#ifdef SCTP_LOCK_LOGGING
	sctp_log_lock(inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_SOCK);
#endif
	TAILQ_REMOVE(&head->so_comp, newso, so_list);
	head->so_qlen--;
	SOCK_UNLOCK(head);
#else

#if defined(__NetBSD__) || defined(__OpenBSD__)
	newso = TAILQ_FIRST(&head->so_q);
#else
	newso = head->so_q;
#endif
	if (soqremque(newso, 1) == 0) {
#ifdef INVARIANTS
		panic("sctp_peeloff");
#else
		printf("soremque failed, peeloff-fails (invarients would panic)\n");
		SCTP_INP_WUNLOCK(inp);
		SCTP_INP_WUNLOCK(n_inp);
		SCTP_TCB_UNLOCK(stcb);
		*error = ENOTCONN;
		return (NULL);

#endif
	}
#endif				/* __FreeBSD__ */
	/*
	 * Now we must move it from one hash table to another and get the
	 * stcb in the right place.
	 */
	SCTP_INP_WUNLOCK(n_inp);
	SCTP_INP_WUNLOCK(inp);
	sctp_move_pcb_and_assoc(inp, n_inp, stcb);
	/*
	 * And now the final hack. We move data in the pending side i.e.
	 * head to the new socket buffer. Let the GRUBBING begin :-0
	 */
	sctp_pull_off_control_to_new_inp(inp, n_inp, stcb);

	SCTP_TCB_UNLOCK(stcb);
	return (newso);
}
