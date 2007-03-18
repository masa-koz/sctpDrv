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
 * $Id: sctp_windows_addr.c,v 1.1 2007/03/18 19:24:44 kozuka Exp $
 */

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

#include <netinet/sctp_os.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_header.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_addr.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_indata.h>
#include <sys/unistd.h>

#ifdef SCTP_DEBUG
extern uint32_t sctp_debug_on;
#endif


void
sctp_gather_internal_ifa_flags(struct sctp_ifa *ifa)
{
	return;
}

static void
sctp_init_ifns_for_vrf(int vrfid)
{
	/* Here we must apply ANY locks needed by the
	 * IFN we access and also make sure we lock
	 * any IFA that exists as we float through the
	 * list of IFA's
	 */
	struct ifnet *ifn;
	struct ifaddr *ifa;
	struct in6_ifaddr *ifa6;
	struct sctp_ifa *sctp_ifa;
	uint32_t ifa_flags;

	TAILQ_FOREACH(ifn, &ifnet, if_list) {
		TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
			if(ifa->ifa_addr == NULL) {
				continue;
			}
			if ((ifa->ifa_addr->sa_family != AF_INET) &&
			    (ifa->ifa_addr->sa_family != AF_INET6)
				) {
				/* non inet/inet6 skip */
				continue;
			}
			if(ifa->ifa_addr->sa_family == AF_INET6) {
				ifa6 = (struct in6_ifaddr *)ifa;
				ifa_flags = ifa6->ia6_flags;
				if (IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr)) {
					/* skip unspecifed addresses */
					continue;
				}

			} else if (ifa->ifa_addr->sa_family == AF_INET) {
				if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == 0) {
					continue;
				}
			}

			if (sctp_is_desired_interface_type(ifa) == 0) {
				/* non desired type */
				continue;
			}

			if((ifa->ifa_addr->sa_family == AF_INET6) ||
			   (ifa->ifa_addr->sa_family == AF_INET)) {
				if (ifa->ifa_addr->sa_family == AF_INET6) {
					ifa6 = (struct in6_ifaddr *)ifa;
					ifa_flags = ifa6->ia6_flags;
				} else {
					ifa_flags = 0;
				}
				sctp_ifa = sctp_add_addr_to_vrf(vrfid, 
								(void *)ifn,
								ifn->if_index, 
								ifn->if_type,
#ifdef __APPLE__
								ifn->if_name,
#else
								ifn->if_xname,
#endif
								(void *)ifa,
								ifa->ifa_addr,
								ifa_flags
					);
				if(sctp_ifa) {
					sctp_ifa->localifa_flags &= ~SCTP_ADDR_DEFER_USE;
				} 
			}
		}
	}
}


void 
sctp_init_vrf_list(int vrfid)
{
	if(vrfid > SCTP_MAX_VRF_ID)
		/* can't do that */
		return;

	/* Don't care about return here */
	(void)sctp_allocate_vrf(vrfid);

	/* Now we need to build all the ifn's 
	 * for this vrf and there addresses
	 */
	sctp_init_ifns_for_vrf(vrfid); 
}

static uint8_t first_time=0;


void
sctp_addr_change(struct ifaddr *ifa, int cmd)
{
	struct sctp_laddr *wi;
	struct sctp_ifa *ifap=NULL;
	uint32_t ifa_flags=0;
	struct in6_ifaddr *ifa6;
	/* BSD only has one VRF, if this changes
	 * we will need to hook in the right 
	 * things here to get the id to pass to
	 * the address managment routine.
	 */
	if (first_time == 0) {
		/* Special test to see if my ::1 will showup with this */
		first_time = 1;
		sctp_init_ifns_for_vrf(SCTP_DEFAULT_VRFID);
	}
	if ((cmd != RTM_ADD) && (cmd != RTM_DELETE)) {
		/* don't know what to do with this */
		return;
	}

	if(ifa->ifa_addr == NULL) {
		return;
	}
	if ((ifa->ifa_addr->sa_family != AF_INET) &&
	    (ifa->ifa_addr->sa_family != AF_INET6)
		) {
		/* non inet/inet6 skip */
		return;
	}
	if(ifa->ifa_addr->sa_family == AF_INET6) {
		ifa6 = (struct in6_ifaddr *)ifa;
		ifa_flags = ifa6->ia6_flags;
		if (IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr)) {
			/* skip unspecifed addresses */
			return;
		}

	} else if (ifa->ifa_addr->sa_family == AF_INET) {
		if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == 0) {
			return;
		}
	}

	if (sctp_is_desired_interface_type(ifa) == 0) {
		/* non desired type */
		return;
	}
	if(cmd == RTM_ADD) {
		ifap = sctp_add_addr_to_vrf(SCTP_DEFAULT_VRFID, (void *)ifa->ifa_ifp,
					    ifa->ifa_ifp->if_index, ifa->ifa_ifp->if_type,
#ifdef __APPLE__
		                            ifa->ifa_ifp->if_name,
#else
		                            ifa->ifa_ifp->if_xname,
#endif
					    (void *)ifa, ifa->ifa_addr, ifa_flags);
		/* Bump up the refcount so that when the timer
		 * completes it will drop back down.
		 */
 		if(ifap)
			atomic_add_int(&ifap->refcount, 1);
		
	} else if (cmd == RTM_DELETE) {

		ifap = sctp_del_addr_from_vrf(SCTP_DEFAULT_VRFID, ifa->ifa_addr, ifa->ifa_ifp->if_index);
		/* We don't bump refcount here so when it completes
		 * the final delete will happen.
		 */
 	}
	if (ifap == NULL) 
		return;

	wi = SCTP_ZONE_GET(sctppcbinfo.ipi_zone_laddr, struct sctp_laddr);
	if (wi == NULL) {
		/*
		 * Gak, what can we do? We have lost an address change can
		 * you say HOSED?
		 */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB1) {
			printf("Lost and address change ???\n");
		}
#endif				/* SCTP_DEBUG */

		/* Opps, must decrement the count */
		sctp_free_ifa(ifap);
		return;
	}
	SCTP_INCR_LADDR_COUNT();
	bzero(wi, sizeof(*wi));
	wi->ifa = ifap;
	if(cmd == RTM_ADD) {
		wi->action = SCTP_ADD_IP_ADDRESS;
	} else if (cmd == RTM_DELETE) {
		wi->action = SCTP_DEL_IP_ADDRESS;
	}
	SCTP_IPI_ITERATOR_WQ_LOCK();
	/*
	 * Should this really be a tailq? As it is we will process the
	 * newest first :-0
	 */
	LIST_INSERT_HEAD(&sctppcbinfo.addr_wq, wi, sctp_nxt_addr);
	sctp_timer_start(SCTP_TIMER_TYPE_ADDR_WQ,
			 (struct sctp_inpcb *)NULL,
			 (struct sctp_tcb *)NULL,
			 (struct sctp_nets *)NULL);
	SCTP_IPI_ITERATOR_WQ_UNLOCK();
}
