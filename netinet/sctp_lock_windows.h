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
extern struct sctp_foo_stuff sctp_logoff[];
extern int sctp_logoff_stuff;
extern LARGE_INTEGER zero_timeout;

#define SCTP_IPI_COUNT_INIT()
#define SCTP_IPI_COUNT_DESTROY()

#define SCTP_STATLOG_INIT_LOCK()
#define SCTP_STATLOG_DESTROY()
#define SCTP_STATLOG_LOCK()
#define SCTP_STATLOG_UNLOCK()
#define SCTP_STATLOG_GETREF(x) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_STATLOG_GETREF: %s[%d]\n", __FILE__, __LINE__); \
	} \
	(x) = atomic_fetchadd_int(&global_sctp_cwnd_log_at, 1); \
	if ((x) == SCTP_STAT_LOG_SIZE) { \
		global_sctp_cwnd_log_at = 1; \
		(x) = 0; \
		global_sctp_cwnd_log_rolled = 1; \
	} \
} while (0)

#define SCTP_INP_INFO_LOCK_INIT() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_INFO_LOCK_INIT: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&sctppcbinfo.ipi_ep_lock); \
} while (0)

#define SCTP_INP_INFO_LOCK_DESTROY() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_INFO_LOCK_DESTROY: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.ipi_ep_lock); \
} while (0)

#define SCTP_INP_INFO_RLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_INFO_RLOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&sctppcbinfo.ipi_ep_lock); \
} while (0)

#define SCTP_INP_INFO_WLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_INFO_WLOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&sctppcbinfo.ipi_ep_lock); \
} while (0)

#define SCTP_INP_INFO_RUNLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_INFO_RUNLOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.ipi_ep_lock); \
} while (0)

#define SCTP_INP_INFO_WUNLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_INFO_WUNLOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.ipi_ep_lock); \
} while (0)


#define SCTP_IPI_ADDR_INIT() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ADDR_INIT: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&sctppcbinfo.ipi_addr_lock); \
} while (0)

#define SCTP_IPI_ADDR_DESTROY() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ADDR_DESTROY: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.ipi_addr_lock); \
} while (0)

#define SCTP_IPI_ADDR_LOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ADDR_LOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&sctppcbinfo.ipi_addr_lock); \
} while (0)

#define SCTP_IPI_ADDR_UNLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ADDR_UNLOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.ipi_addr_lock); \
} while (0)


#define SCTP_IPI_ITERATOR_WQ_INIT() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ITERATOR_WQ_INIT: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&sctppcbinfo.ipi_iterator_wq_lock); \
} while (0)

#define SCTP_IPI_ITERATOR_WQ_DESTROY() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ITERATOR_WQ_DESTROY: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.ipi_iterator_wq_lock); \
} while (0)

#define SCTP_IPI_ITERATOR_WQ_LOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ITERATOR_WQ_LOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&sctppcbinfo.ipi_iterator_wq_lock); \
} while (0)

#define SCTP_IPI_ITERATOR_WQ_UNLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_IPI_ITERATOR_WQ_UNLOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.ipi_iterator_wq_lock); \
} while (0)


/*
 * The INP locks we will use for locking an SCTP endpoint, so for example if
 * we want to change something at the endpoint level for example random_store
 * or cookie secrets we lock the INP level.
 */

#define SCTP_INP_READ_INIT(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_READ_INIT: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&(_inp)->inp_rdata_lock); \
} while (0)

#define SCTP_INP_READ_DESTROY(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_READ_DESTROY: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_inp)->inp_rdata_lock); \
} while (0)

#define SCTP_INP_READ_LOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_READ_LOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_inp)->inp_rdata_lock); \
} while (0)

#define SCTP_INP_READ_UNLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_READ_UNLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_inp)->inp_rdata_lock); \
} while (0)


#define SCTP_INP_LOCK_INIT(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_LOCK_INIT: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&(_inp)->inp_lock); \
} while (0)

#define SCTP_INP_LOCK_DESTROY(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_LOCK_DESTROY: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_inp)->inp_lock); \
} while (0)

#ifdef SCTP_LOCK_LOGGING
#define SCTP_INP_RLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_RLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_INP); \
	KeAcquireSpinLockAtDpcLevel(&(_inp)->inp_lock); \
} while (0)
#else
#define SCTP_INP_RLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_RLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_inp)->inp_lock); \
} while (0)
#endif

#ifdef SCTP_LOCK_LOGGING
#define SCTP_INP_WLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_WLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_INP); \
	KeAcquireSpinLockAtDpcLevel(&(_inp)->inp_lock); \
} while (0)
#else
#define SCTP_INP_WLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_WLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_inp)->inp_lock); \
} while (0)
#endif

#define SCTP_INP_RUNLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_RUNLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_inp)->inp_lock); \
} while (0)

#define SCTP_INP_WUNLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_WUNLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_inp)->inp_lock); \
} while (0)

#define SCTP_INP_INCR_REF(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_INCR_REF: inp=%p, refcount=%d %s[%d]\n", (_inp), (_inp)->refcount, __FILE__, __LINE__); \
	} \
	atomic_add_int(&(_inp)->refcount, 1); \
} while (0)

#define SCTP_INP_DECR_REF(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_INP_DECR_REF: inp=%p, refcount=%d %s[%d]\n", (_inp), (_inp)->refcount, __FILE__, __LINE__); \
	} \
	atomic_subtract_int(&(_inp)->refcount, 1); \
} while (0)


#define SCTP_ASOC_CREATE_LOCK_INIT(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ASOC_CREATE_LOCK_INIT: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&(_inp)->inp_create_lock); \
} while (0)

#define SCTP_ASOC_CREATE_LOCK_DESTROY(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ASOC_CREATE_LOCK_DESTROY: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_inp)->inp_create_lock); \
} while (0)

#ifdef SCTP_LOCK_LOGGING
#define SCTP_ASOC_CREATE_LOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ASOC_CREATE_LOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_CREATE); \
	KeAcquireSpinLockAtDpcLevel(&(_inp)->inp_create_lock); \
} while (0)
#else
#define SCTP_ASOC_CREATE_LOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ASOC_CREATE_LOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_inp)->inp_create_lock); \
} while (0)
#endif

#define SCTP_ASOC_CREATE_UNLOCK(_inp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ASOC_CREATE_UNLOCK: inp=%p %s[%d]\n", (_inp), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_inp)->inp_create_lock); \
} while (0)


/*
 * For the majority of things (once we have found the association) we will
 * lock the actual association mutex. This will protect all the assoiciation
 * level queues and streams and such. We will need to lock the socket layer
 * when we stuff data up into the receiving sb_mb. I.e. we will need to do an
 * extra SOCKBUF_LOCK(&so->so_rcv) even though the association is locked.
 */
#define SCTP_TCB_LOCK_INIT(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_LOCK_INIT: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&(_tcb)->tcb_lock); \
} while (0)

#define SCTP_TCB_LOCK_DESTROY(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_LOCK_DESTROY: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_tcb)->tcb_lock); \
} while (0)

#ifdef SCTP_LOCK_LOGGING
#define SCTP_TCB_LOCK(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_LOCK: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
       	sctp_log_lock((_tcb)->sctp_ep, _tcb, SCTP_LOG_LOCK_TCB); \
	KeAcquireSpinLockAtDpcLevel(&(_tcb)->tcb_lock); \
} while (0)
#else
#define SCTP_TCB_LOCK(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_LOCK: tcb=%p,thread=%p %s[%d]\n", (_tcb), KeGetCurrentThread(), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_tcb)->tcb_lock); \
} while (0)
#endif

__inline int _SCTP_TCB_TRYLOCK(struct sctp_tcb *tcb, char *filename, int lineno) {
	if (LOCKDEBUG) {
		DbgPrint("SCTP_TCB_TRYLOCK: tcb=%p,thread=%p %s[%d]\n", tcb, KeGetCurrentThread(), filename, lineno);
	}
	KeAcquireSpinLockAtDpcLevel(&tcb->tcb_lock);
	return 1;
}
#define SCTP_TCB_TRYLOCK(_tcb) _SCTP_TCB_TRYLOCK((_tcb), __FILE__, __LINE__)

#define SCTP_TCB_UNLOCK(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_UNLOCK: tcb=%p,thread=%p %s[%d]\n", (_tcb), KeGetCurrentThread(), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_tcb)->tcb_lock); \
} while (0)

#define SCTP_TCB_UNLOCK_IFOWNED(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_UNLOCK_IFOWNED: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_tcb)->tcb_lock); \
} while (0)

#define SCTP_TCB_INCR_REF(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_INCR_REF: tcb=%p, refcount=%d %s[%d]\n", (_tcb), (_tcb)->asoc.refcnt, __FILE__, __LINE__); \
	} \
	atomic_add_int(&(_tcb)->asoc.refcnt, 1); \
} while (0)

#define SCTP_TCB_DECR_REF(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_DECR_REF: tcb=%p, refcount=%d %s[%d]\n", (_tcb), (_tcb)->asoc.refcnt, __FILE__, __LINE__); \
	} \
	atomic_subtract_int(&(_tcb)->asoc.refcnt, 1); \
} while (0)


#define SCTP_TCB_SEND_LOCK_INIT(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_SEND_LOCK_INIT: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&(_tcb)->tcb_send_lock); \
} while (0)

#define SCTP_TCB_SEND_LOCK_DESTROY(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_SEND_LOCK_DESTROY: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_tcb)->tcb_send_lock); \
} while (0) 

#define SCTP_TCB_SEND_LOCK(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_SEND_LOCK: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&(_tcb)->tcb_send_lock); \
} while (0)

#define SCTP_TCB_SEND_UNLOCK(_tcb) do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_TCB_SEND_UNLOCK: tcb=%p %s[%d]\n", (_tcb), __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&(_tcb)->tcb_send_lock); \
} while (0)


#define SCTP_RADDR_INCR_REF(_net) do { \
	atomic_add_int(&(_net)->ref_count, 1); \
} while (0)
#define SCTP_RADDR_DECR_REF(_net) do { \
	atomic_subtract_int(&(_net)->ref_count, 1); \
} while (0)

#define SCTP_LADDR_INCR_REF(_ifa) do { \
	atomic_add_int(&(_ifa)->refcount, 1); \
} while (0)
#define SCTP_LADDR_DECR_REF(_ifa) do { \
	atomic_subtract_int(&(_ifa)->refcount, 1); \
} while (0)

#define SCTP_INCR_TCB_FREE_STRMOQ_COUNT(_tcb) do { \
	atomic_add_int(&(_tcb)->asoc.free_strmoq_cnt, 1); \
} while (0)
#define SCTP_DECR_TCB_FREE_STRMOQ_COUNT(_tcb) do { \
	atomic_subtract_int(&(_tcb)->asoc.free_strmoq_cnt, 1); \
} while (0)

#define SCTP_INCR_TCB_FREE_CHK_COUNT(_tcb) do { \
	atomic_add_int(&(_tcb)->asoc.free_chunk_cnt, 1); \
} while (0)
#define SCTP_DECR_TCB_FREE_CHK_COUNT(_tcb) do { \
	atomic_subtract_int(&(_tcb)->asoc.free_chunk_cnt, 1); \
} while (0)

#ifdef INVARIANTS
#define SCTP_TCB_LOCK_ASSERT(_tcb) \
	_ASSERT(KeReadStateMutex(&(_tcb)->tcb_mtx) == 0)
#else
#define SCTP_TCB_LOCK_ASSERT(_tcb)
#endif

#define SCTP_ITERATOR_LOCK_INIT() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ITERATOR_LOCK_INIT: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeInitializeSpinLock(&sctppcbinfo.it_lock); \
} while (0)

#define SCTP_ITERATOR_LOCK_DESTROY() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ITERATOR_LOCK_DESTROY: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.it_lock); \
} while (0)


#ifdef INVARIANTS
#define SCTP_ITERATOR_LOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ITERATOR_LOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&sctppcbinfo.it_lock); \
} while (0)
#else
#define SCTP_ITERATOR_LOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ITERATOR_LOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireSpinLockAtDpcLevel(&sctppcbinfo.it_lock); \
} while (0)
#endif

#define SCTP_ITERATOR_UNLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("SCTP_ITERATOR_UNLOCK: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseSpinLockFromDpcLevel(&sctppcbinfo.it_lock); \
} while (0)

#define SCTP_INCR_EP_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_count_ep, 1); \
} while (0)
#define SCTP_DECR_EP_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_count_ep, 1); \
} while (0)
#define SCTP_INCR_ASOC_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_count_asoc, 1); \
} while (0)
#define SCTP_DECR_ASOC_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_count_asoc, 1); \
} while (0)
#define SCTP_INCR_LADDR_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_count_laddr, 1); \
} while (0)
#define SCTP_DECR_LADDR_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_count_laddr, 1); \
} while (0)
#define SCTP_INCR_RADDR_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_count_raddr, 1); \
} while (0)
#define SCTP_DECR_RADDR_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_count_raddr, 1); \
} while (0)
#define SCTP_INCR_CHK_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_count_chunk, 1); \
} while (0)
#define SCTP_DECR_CHK_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_count_chunk, 1); \
} while (0)
#define SCTP_INCR_READQ_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_count_readq, 1); \
} while (0)
#define SCTP_DECR_READQ_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_count_readq, 1); \
} while (0)

#define SCTP_INCR_STRMOQ_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_count_strmoq, 1); \
} while (0)
#define SCTP_DECR_STRMOQ_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_count_strmoq, 1); \
} while (0)

#define SCTP_INCR_FREE_STRMOQ_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_free_strmoq, 1); \
} while (0)
#define SCTP_DECR_FREE_STRMOQ_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_free_strmoq, 1); \
} while (0)

#define SCTP_INCR_FREE_CHK_COUNT() do { \
	atomic_add_int(&sctppcbinfo.ipi_free_chunks, 1); \
} while (0)
#define SCTP_DECR_FREE_CHK_COUNT() do { \
	atomic_subtract_int(&sctppcbinfo.ipi_free_chunks, 1); \
} while (0)
#endif
