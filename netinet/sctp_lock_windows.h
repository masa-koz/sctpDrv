#ifndef __sctp_lock_windows_h__
#define __sctp_lock_windows_h__
/*-
 * Copyright (c) 2001-2006, Cisco Systems, Inc. All rights reserved.
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

/*
 * General locking concepts: The goal of our locking is to of course provide
 * consistency and yet minimize overhead. We will attempt to use
 * non-recursive locks which are supposed to be quite inexpensive. Now in
 * order to do this the goal is that most functions are not aware of locking.
 * Once we have a TCB we lock it and unlock when we are through. This means
 * that the TCB lock is kind-of a "global" lock when working on an
 * association. Caution must be used when asserting a TCB_LOCK since if we
 * recurse we deadlock.
 *
 * Most other locks (INP and INFO) attempt to localize the locking i.e. we try
 * to contain the lock and unlock within the function that needs to lock it.
 * This sometimes mean we do extra locks and unlocks and lose a bit of
 * efficency, but if the performance statements about non-recursive locks are
 * true this should not be a problem.  One issue that arises with this only
 * lock when needed is that if an implicit association setup is done we have
 * a problem. If at the time I lookup an association I have NULL in the tcb
 * return, by the time I call to create the association some other processor
 * could have created it. This is what the CREATE lock on the endpoint.
 * Places where we will be implicitly creating the association OR just
 * creating an association (the connect call) will assert the CREATE_INP
 * lock. This will assure us that during all the lookup of INP and INFO if
 * another creator is also locking/looking up we can gate the two to
 * synchronize. So the CREATE_INP lock is also another one we must use
 * extreme caution in locking to make sure we don't hit a re-entrancy issue.
 *
 * For non FreeBSD 5.x we provide a bunch of EMPTY lock macros so we can
 * blatantly put locks everywhere and they reduce to nothing on
 * NetBSD/OpenBSD and FreeBSD 4.x
 *
 */

/*
 * When working with the global SCTP lists we lock and unlock the INP_INFO
 * lock. So when we go to lookup an association we will want to do a
 * SCTP_INP_INFO_RLOCK() and then when we want to add a new association to
 * the sctppcbinfo list's we will do a SCTP_INP_INFO_WLOCK().
 */
#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/netinet/sctp_lock_bsd.h,v 1.3 2006/12/14 17:02:54 rrs Exp $");
#endif


extern struct sctp_foo_stuff sctp_logoff[];
extern int sctp_logoff_stuff;

#define SCTP_IPI_COUNT_INIT()

#define SCTP_STATLOG_INIT_LOCK() do { \
	sctppcbinfo.logging_mtx = ExAllocatePool(NonPagedPool, sizeof(*sctppcbinfo.logging_mtx)); \
	KeInitializeMutex(sctppcbinfo.logging_mtx, 0); \
} while (0)
#define SCTP_STATLOG_LOCK() \
	KeWaitForMutexObject(sctppcbinfo.logging_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#define SCTP_STATLOG_UNLOCK() \
	KeReleaseMutex(sctppcbinfo.logging_mtx, 0)
#define SCTP_STATLOG_DESTROY()
#define SCTP_STATLOG_GETREF(x) do { \
	KeWaitForMutexObject(sctppcbinfo.logging_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	x = global_sctp_cwnd_log_at; \
	global_sctp_cwnd_log_at++; \
	if (global_sctp_cwnd_log_at == SCTP_STAT_LOG_SIZE) { \
		global_sctp_cwnd_log_at = 0; \
		global_sctp_cwnd_log_rolled = 1; \
	} \
	KeReleaseMutex(sctppcbinfo.logging_mtx, 0); \
} while (0)

#define SCTP_INP_INFO_LOCK_INIT() do { \
	sctppcbinfo.ipi_ep_mtx = ExAllocatePool(NonPagedPool, sizeof(*(sctppcbinfo.ipi_ep_mtx))); \
	KeInitializeMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_INP_INFO_RLOCK() \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#define SCTP_INP_INFO_WLOCK() \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#define SCTP_INP_INFO_RUNLOCK() \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0)
#define SCTP_INP_INFO_WUNLOCK() \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0)

#define SCTP_IPI_ADDR_INIT() do { \
	sctppcbinfo.ipi_addr_mtx = ExAllocatePool(NonPagedPool, sizeof(*(sctppcbinfo.ipi_addr_mtx))); \
	KeInitializeMutex(sctppcbinfo.ipi_addr_mtx, 0); \
} while (0)
#define SCTP_IPI_ADDR_DESTROY()
#define SCTP_IPI_ADDR_LOCK() \
	KeWaitForMutexObject(sctppcbinfo.ipi_addr_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#define SCTP_IPI_ADDR_UNLOCK() \
	KeReleaseMutex(sctppcbinfo.ipi_addr_mtx, 0)


#define SCTP_IPI_ITERATOR_WQ_INIT() do { \
	sctppcbinfo.ipi_iterator_wq_mtx = ExAllocatePool(NonPagedPool, sizeof(*sctppcbinfo.ipi_iterator_wq_mtx)); \
	KeInitializeMutex(sctppcbinfo.ipi_iterator_wq_mtx, 0); \
} while (0)
#define SCTP_IPI_ITERATOR_WQ_DESTROY()
#define SCTP_IPI_ITERATOR_WQ_LOCK() \
	KeWaitForMutexObject(sctppcbinfo.ipi_iterator_wq_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#define SCTP_IPI_ITERATOR_WQ_UNLOCK() \
	KeReleaseMutex(sctppcbinfo.ipi_iterator_wq_mtx, 0)

/*
 * The INP locks we will use for locking an SCTP endpoint, so for example if
 * we want to change something at the endpoint level for example random_store
 * or cookie secrets we lock the INP level.
 */

#define SCTP_INP_READ_INIT(_inp) do { \
	KeInitializeMutex(&(_inp)->inp_rdata_mtx, 0)
#define SCTP_INP_READ_DESTROY(_inp)
#define SCTP_INP_READ_LOCK(_inp) \
	KeWaitForMutexObject(&(_inp)->inp_rdata_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#define SCTP_INP_READ_UNLOCK(_inp) \
	KeReleaseMutex(&(_inp)->inp_rdata_mtx, 0)

#define SCTP_INP_LOCK_INIT(_inp) \
	KeInitializeMutex(&(_inp)->inp_mtx, 0)
#define SCTP_INP_LOCK_DESTROY(_inp)
#define SCTP_ASOC_CREATE_LOCK_INIT(_inp) \
	KeInitializeMutex(&(_inp)->inp_create_mtx, 0)
#define SCTP_ASOC_CREATE_LOCK_DESTROY(_inp)

#ifdef SCTP_LOCK_LOGGING
#define SCTP_INP_RLOCK(_inp) do { \
	sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_INP); \
	KeWaitForMutexObject(&(_inp)->inp_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
} while (0)
#define SCTP_INP_WLOCK(_inp) do { \
	sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_INP); \
	KeWaitForMutexObject(&(_inp)->inp_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
} while (0)

#else
#define SCTP_INP_RLOCK(_inp) \
	KeWaitForMutexObject(&(_inp)->inp_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#define SCTP_INP_WLOCK(_inp) \
	KeWaitForMutexObject(&(_inp)->inp_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#endif


#define SCTP_TCB_SEND_LOCK_INIT(_tcb) \
	KeInitializeMutex(&(&(_tcb)->tcb_send_mtx, 0)
#define SCTP_TCB_SEND_LOCK_DESTROY(_tcb)
#define SCTP_TCB_SEND_LOCK(_tcb) \
	KeWaitForMutexObject(&(_tcb)->tcb_send_mtx, Executive, KernelMode, \
	    FALSE, NULL) 
#define SCTP_TCB_SEND_UNLOCK(_tcb) \
	KeReleaseMutex(&(_tcb)->tcb_send_mtx, 0)

#define SCTP_INP_INCR_REF(_inp) do { \
	KeWaitForMutexObject(&(_inp)->inp_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_inp)->refcount++; \
	KeReleaseMutex(&(_inp)->inp_mtx, 0); \
} while (0)
#define SCTP_INP_DECR_REF(_inp) do { \
	KeWaitForMutexObject(&(_inp)->inp_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_inp)->refcount--; \
	KeReleaseMutex(&(_inp)->inp_mtx, 0); \
} while (0)

#define SCTP_TCB_INCR_REF(_tcb) do { \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_tcb)->asoc.refcnt++; \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0); \
} while (0)
#define SCTP_TCB_DECR_REF(_tcb) do { \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_tcb)->asoc.refcnt--; \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0); \
} while (0)

#ifdef SCTP_LOCK_LOGGING
#define SCTP_ASOC_CREATE_LOCK(_inp) do { \
	sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_CREATE); \
	KeWaitForMutexObject(&(_inp)->inp_create_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
} while (0)
#else
#define SCTP_ASOC_CREATE_LOCK(_inp) do { \
	KeWaitForMutexObject(&(_inp)->inp_create_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
} while (0)
#endif

#define SCTP_INP_RUNLOCK(_inp) \
	KeReleaseMutex(&(_inp)->inp_mtx, 0)
#define SCTP_INP_WUNLOCK(_inp) \
	KeReleaseMutex(&(_inp)->inp_mtx, 0)
#define SCTP_ASOC_CREATE_UNLOCK(_inp) \
	KeReleaseMutex(&(_inp)->inp_create_mtx, 0)

/*
 * For the majority of things (once we have found the association) we will
 * lock the actual association mutex. This will protect all the assoiciation
 * level queues and streams and such. We will need to lock the socket layer
 * when we stuff data up into the receiving sb_mb. I.e. we will need to do an
 * extra SOCKBUF_LOCK(&so->so_rcv) even though the association is locked.
 */

#define SCTP_TCB_LOCK_INIT(_tcb) \
	KeInitializeMutex(&(_tcb)->tcb_mtx, 0)
#define SCTP_TCB_LOCK_DESTROY(_tcb)

#ifdef SCTP_LOCK_LOGGING
#define SCTP_TCB_LOCK(_tcb) do { \
        sctp_log_lock(_tcb->sctp_ep, _tcb, SCTP_LOG_LOCK_TCB); \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
} while (0)
#else
#define SCTP_TCB_LOCK(_tcb) \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL);
#endif


#define SCTP_TCB_TRYLOCK(_tcb) do { \
	LARGE_INTEGER _timeout = 0; \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, &_timeout); \
} while (0)
#define SCTP_TCB_UNLOCK(_tcb) \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0)

#define SCTP_TCB_UNLOCK_IFOWNED(_tcb) \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0) 


#define SCTP_RADDR_INIT_REF(_net) do { \
	KeInitializeMutex(&(&(_net)->mtx, 0)); \
	(_net)->ref_count = 0; \
} while (0)
#define SCTP_RADDR_INCR_REF(_net) do { \
	KeWaitForMutexObject(&(_net)->mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_net)->ref_count++; \
	KeReleaseMutex(&(_net)->mtx, 0); \
} while (0)
#define SCTP_RADDR_DECR_REF(_net) do { \
	KeWaitForMutexObject(&(_net)->mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_net)->ref_count--; \
	KeReleaseMutex(&(_net)->mtx, 0); \
} while (0)

#define SCTP_LADDR_INIT_REF(_ifa) do { \
	KeInitializeMutex(&(&(_ifa)->mtx, 0)); \
	(_ifa)->refcount = 0; \
} while (0)
#define SCTP_LADDR_INCR_REF(_ifa) do { \
	KeWaitForMutexObject(&(_ifa)->mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_ifa)->refcount++; \
	KeReleaseMutex(&(_ifa)->mtx, 0); \
} while (0)
#define SCTP_LADDR_DECR_REF(_ifa) do { \
	KeWaitForMutexObject(&(_ifa)->mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_ifa)->refcount--; \
	KeReleaseMutex(&(_ifa)->mtx, 0); \
} while (0)

#define SCTP_INCR_TCB_FREE_STRMOQ_COUNT(_tcb) do { \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_tcb)->asoc.free_strmoq_cnt++; \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0); \
} while (0)
#define SCTP_DECR_TCB_FREE_STRMOQ_COUNT(_tcb) do { \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_tcb)->asoc.free_strmoq_cnt--; \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0); \
} while (0)

#define SCTP_INCR_TCB_FREE_CHK_COUNT(_tcb) do { \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_tcb)->asoc.free_chunk_cnt++; \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0); \
} while (0)
#define SCTP_DECR_TCB_FREE_CHK_COUNT(_tcb) do { \
	KeWaitForMutexObject(&(_tcb)->tcb_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	(_tcb)->asoc.free_chunk_cnt--; \
	KeReleaseMutex(&(_tcb)->tcb_mtx, 0); \
} while (0)

#ifdef INVARIANTS
#define SCTP_TCB_LOCK_ASSERT(_tcb) \
	_ASSERT(KeReadStateMutex(&(_tcb)->tcb_mtx) == 0)
#else
#define SCTP_TCB_LOCK_ASSERT(_tcb)
#endif

#define SCTP_ITERATOR_LOCK_INIT() do { \
	sctppcbinfo.it_mtx = ExAllocatePool(NonPagedPool, sizeof(*(sctppcbinfo.it_mtx))); \
	KeInitializeMutex(sctppcbinfo.it_mtx, 0); \
} while (0)

#ifdef INVARIANTS
#define SCTP_ITERATOR_LOCK() do { \
	_ASSERT(KeReadStateMutex(sctppcbinfo.it_mtx) == 0); \
	KeWaitForMutexObject(sctppcbinfo.it_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
} while (0)
#else
#define SCTP_ITERATOR_LOCK() \
	KeWaitForMutexObject(sctppcbinfo.it_mtx, Executive, KernelMode, \
	    FALSE, NULL)
#endif
#define SCTP_ITERATOR_UNLOCK() \
	KeReleaseMutex(sctppcbinfo.it_mtx, 0)
#define SCTP_ITERATOR_LOCK_DESTROY()


#define SCTP_INCR_EP_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_ep++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_EP_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_ep--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_INCR_ASOC_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_asoc++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_ASOC_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_asoc--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_INCR_LADDR_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_laddr++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_LADDR_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_laddr--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_INCR_RADDR_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_raddr++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_RADDR_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_raddr--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_INCR_CHK_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_chunk++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_CHK_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_chunk--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_INCR_READQ_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_readq++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_READQ_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_readq--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)

#define SCTP_INCR_STRMOQ_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_strmoq++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_STRMOQ_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_count_strmoq--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)

#define SCTP_INCR_FREE_STRMOQ_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_free_strmoq++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_FREE_STRMOQ_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_free_strmoq--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)

#define SCTP_INCR_FREE_CHK_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_free_chunks++; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#define SCTP_DECR_FREE_CHK_COUNT() do { \
	KeWaitForMutexObject(sctppcbinfo.ipi_ep_mtx, Executive, KernelMode, \
	    FALSE, NULL); \
	sctppcbinfo.ipi_free_chunks--; \
	KeReleaseMutex(sctppcbinfo.ipi_ep_mtx, 0); \
} while (0)
#endif
