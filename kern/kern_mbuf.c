/*-
 * Copyright (c) 2004, 2005,
 * 	Bosko Milekic <bmilekic@FreeBSD.org>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ntifs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include <net/if.h>

NPAGED_LOOKASIDE_LIST zone_mbuf;
NPAGED_LOOKASIDE_LIST zone_clust;
NPAGED_LOOKASIDE_LIST zone_jumbop;
NPAGED_LOOKASIDE_LIST zone_jumbo9;
NPAGED_LOOKASIDE_LIST zone_jumbo16;
NPAGED_LOOKASIDE_LIST zone_refcnt;

int nmbclusters;
struct mbstat mbstat;


void
mbuf_init(void)
{
	ExInitializeNPagedLookasideList(&zone_mbuf, NULL, NULL, 0, MSIZE, 0x64657246, 0);
	ExInitializeNPagedLookasideList(&zone_clust, NULL, NULL, 0, MCLBYTES, 0x64657246, 0);
	ExInitializeNPagedLookasideList(&zone_jumbop, NULL, NULL, 0, MJUMPAGESIZE, 0x64657246, 0);
	ExInitializeNPagedLookasideList(&zone_jumbo9, NULL, NULL, 0, MJUM9BYTES, 0x64657246, 0);
	ExInitializeNPagedLookasideList(&zone_jumbo16, NULL, NULL, 0, MJUM16BYTES, 0x64657246, 0);
	ExInitializeNPagedLookasideList(&zone_refcnt, NULL, NULL, 0, sizeof(u_int), 0x64657246, 0);

	nmbclusters = 1024 + 256 * 64;
}

void
mbuf_destroy(void)
{
	DebugPrint(DEBUG_KERN_INFO, "zone_mbuf: L.Depth=%d, Depth=%d,TotalAllocates=%d,TotalFrees=%d,AllocateMisses=%d,FreeMisses=%d\n",
	    zone_mbuf.L.Depth, ExQueryDepthSList(&zone_mbuf.L.ListHead), zone_mbuf.L.TotalAllocates,
	    zone_mbuf.L.TotalFrees, zone_mbuf.L.AllocateMisses, zone_mbuf.L.FreeMisses);
	DebugPrint(DEBUG_KERN_INFO, "zone_clust: L.Depth=%d, Depth=%d,TotalAllocates=%d,TotalFrees=%d,AllocateMisses=%d,FreeMisses=%d\n",
	    zone_clust.L.Depth, ExQueryDepthSList(&zone_clust.L.ListHead), zone_clust.L.TotalAllocates,
	    zone_clust.L.TotalFrees, zone_clust.L.AllocateMisses, zone_clust.L.FreeMisses);
	DebugPrint(DEBUG_KERN_INFO, "zone_refcnt: L.Depth=%d, Depth=%d,TotalAllocates=%d,TotalFrees=%d,AllocateMisses=%d,FreeMisses=%d\n",
	    zone_refcnt.L.Depth, ExQueryDepthSList(&zone_refcnt.L.ListHead), zone_refcnt.L.TotalAllocates,
	    zone_refcnt.L.TotalFrees, zone_refcnt.L.AllocateMisses, zone_refcnt.L.FreeMisses);
	ExDeleteNPagedLookasideList(&zone_mbuf);
	ExDeleteNPagedLookasideList(&zone_clust);
	ExDeleteNPagedLookasideList(&zone_jumbop);
	ExDeleteNPagedLookasideList(&zone_jumbo9);
	ExDeleteNPagedLookasideList(&zone_jumbo16);
	ExDeleteNPagedLookasideList(&zone_refcnt);
	nmbclusters = 0;
}

/*
 * Constructor for Mbuf master zone.
 *
 * The 'arg' pointer points to a mb_args structure which
 * contains call-specific information required to support the
 * mbuf allocation API.  See mbuf.h.
 */
int
mb_ctor_mbuf(void *mem, int size, void *arg)
{
	struct mbuf *m;
	struct mb_args *args;
	int flags;
	short type;

	m = (struct mbuf *)mem;
	args = (struct mb_args *)arg;
	flags = args->flags;
	type = args->type;

	/*
	 * The mbuf is initialized later.  The caller has the
	 * responsibility to set up any MAC labels too.
	 */
	if (type == MT_NOINIT)
		return (0);

	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_len = 0;
	m->m_flags = flags;
	m->m_type = type;
	if (flags & M_PKTHDR) {
		m->m_data = m->m_pktdat;
		m->m_pkthdr.rcvif = NULL;
		m->m_pkthdr.len = 0;
		m->m_pkthdr.header = NULL;
		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;
	} else
		m->m_data = m->m_dat;
	mbstat.m_mbufs += 1;	/* XXX */
	return (0);
}

/*
 * The Mbuf master zone destructor.
 */
void
mb_dtor_mbuf(void *mem)
{
	struct mbuf *m;

	mbstat.m_mbufs -= 1;	/* XXX */
}

/*
 * The Cluster and Jumbo[PAGESIZE|9|16] zone constructor.
 *
 * Here the 'arg' pointer points to the Mbuf which we
 * are configuring cluster storage for.  If 'arg' is
 * empty we allocate just the cluster without setting
 * the mbuf to it.  See mbuf.h.
 */
int
mb_ctor_clust(void *mem, int size, void *arg)
{
	struct mbuf *m;
	u_int *ref_cnt;
	int type = 0;

 	m = (struct mbuf *)arg;
	ref_cnt = (u_int *)ExAllocateFromNPagedLookasideList(&zone_refcnt);
	if (ref_cnt != NULL) {
		*ref_cnt = 1;
	}
	if (m != NULL && ref_cnt != NULL) {
		switch (size) {
		case MCLBYTES:
			type = EXT_CLUSTER;
			break;
#if MJUMPAGESIZE != MCLBYTES
		case MJUMPAGESIZE:
			type = EXT_JUMBOP;
			break;
#endif
		case MJUM9BYTES:
			type = EXT_JUMBO9;
			break;
		case MJUM16BYTES:
			type = EXT_JUMBO16;
			break;
		default:
			panic("unknown cluster size");
			break;
		}
		m->m_ext.ext_buf = (caddr_t)mem;
		m->m_ext.ref_cnt = ref_cnt;
		m->m_data = m->m_ext.ext_buf;
		m->m_flags |= M_EXT;
		m->m_ext.ext_free = NULL;
		m->m_ext.ext_arg1 = NULL;
		m->m_ext.ext_arg2 = NULL;
		m->m_ext.ext_size = size;
		m->m_ext.ext_type = type;
	}
	mbstat.m_mclusts += 1;	/* XXX */
	return (0);
}

/*
 * The Mbuf Cluster zone destructor.
 */
void
mb_dtor_clust(void *mem)
{
	mbstat.m_mclusts -= 1;	/* XXX */
}

/*
 * The "packet" keg constructor.
 */
int
mb_ctor_pack(void *mem, int size, void *arg)
{
	struct mbuf *m;
	void *_mem;
	struct mb_args *args;
	int flags;
	short type;

	m = (struct mbuf *)mem;
	args = (struct mb_args *)arg;
	flags = args->flags;
	type = args->type;
	_mem = (void *)((caddr_t)m + MSIZE);
	mb_ctor_clust(_mem, size, m);

	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_data = m->m_ext.ext_buf;
	m->m_len = 0;
	m->m_flags = (flags | M_EXT);
	m->m_type = type;

	if (flags & M_PKTHDR) {
		m->m_pkthdr.rcvif = NULL;
		m->m_pkthdr.len = 0;
		m->m_pkthdr.header = NULL;
		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;
	}
	/* m_ext is already initialized. */

	mbstat.m_mpacks += 1;	/* XXX */
	return (0);
}

/*
 * The Mbuf Packet zone destructor.
 */
void
mb_dtor_pack(void *mem)
{
	struct mbuf *m;

	m = (struct mbuf *)mem;

	/* Make sure we've got a clean cluster back. */
	KASSERT((m->m_flags & M_EXT) == M_EXT, ("%s: M_EXT not set", __func__));
	KASSERT(m->m_ext.ext_buf != NULL, ("%s: ext_buf == NULL", __func__));
	KASSERT(m->m_ext.ext_free == NULL, ("%s: ext_free != NULL", __func__));
	KASSERT(m->m_ext.ext_arg1 == NULL, ("%s: ext_arg1 != NULL", __func__));
	KASSERT(m->m_ext.ext_arg2 == NULL, ("%s: ext_arg2 != NULL", __func__));
	KASSERT(m->m_ext.ext_size == MCLBYTES, ("%s: ext_size != MCLBYTES", __func__));
	KASSERT(m->m_ext.ext_type == EXT_PACKET, ("%s: ext_type != EXT_PACKET", __func__));
	mbstat.m_mpacks -= 1;	/* XXX */
}
