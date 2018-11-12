/*
 * Copyright (c) 2008 CO-CONV, Corp. All rights reserved.
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
 */

#ifndef _SYS_CALLOUT_H_
#define _SYS_CALLOUT_H_

#include <ntifs.h>

#include <sys/atomic.h>

struct callout {
	KTIMER c_tmr;
	KDPC c_dpc;
	KSPIN_LOCK c_lock;
	void (*c_func)(void *);
	void *c_arg;
	KSPIN_LOCK *c_mtx;
	int c_pending;
	int c_flags;
};

#define	CALLOUT_ACTIVE		0x0001
#define	CALLOUT_MPSAFE		0x0002
#define	CALLOUT_RETURNUNLOCKED	0x0004

#define	callout_pending(c)	((c)->c_pending > 0)
#define	callout_active(c)	((c)->c_flags & CALLOUT_ACTIVE)
#define	callout_deactivate(c)	((c)->c_flags &= ~CALLOUT_ACTIVE)

void	callout_init(struct callout *, int);
void	callout_init_mtx(struct callout *, KSPIN_LOCK *mtx, int);
int	callout_reset(struct callout *, int, void (*)(void *), void *);
int	callout_stop(struct callout *);
int	callout_drain(struct callout *);

#endif /* _SYS_CALLOUT_H_ */
