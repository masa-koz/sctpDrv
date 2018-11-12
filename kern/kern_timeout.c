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

#include <sys/callout.h>


VOID
CustomTimerDpc(
    IN struct _KDPC *dpc,
    IN PVOID  deferredContext,
    IN PVOID  systemArgument1,
    IN PVOID  systemArgument2)
{
	struct callout *c = deferredContext;
	void (*c_func)(void *);
	void *c_arg;
	KSPIN_LOCK *c_mtx;
	int c_flags, c_flags1;

	c_func = c->c_func;
	c_arg = c->c_arg;
	c_mtx = c->c_mtx;
	c_flags = c->c_flags;

	atomic_add_int(&c->c_pending, -1);

	KeAcquireSpinLockAtDpcLevel(&c->c_lock);
	if (c_mtx != NULL) {
		KeAcquireSpinLockAtDpcLevel(c_mtx);
	}

	(*c_func)(c_arg);

	if (c_mtx != NULL && (c_flags & CALLOUT_RETURNUNLOCKED) == 0) {
		KeReleaseSpinLockFromDpcLevel(c_mtx);
	}
	KeReleaseSpinLockFromDpcLevel(&c->c_lock);
}

void
callout_init(
    struct callout *c,
    int mpsafe)
{
	RtlZeroMemory(c, sizeof(struct callout));
	KeInitializeTimer(&c->c_tmr);
	KeInitializeDpc(&c->c_dpc, CustomTimerDpc, c);
	KeInitializeSpinLock(&c->c_lock);

	if (mpsafe) {
		c->c_mtx = NULL;
		c->c_flags |= CALLOUT_RETURNUNLOCKED;
	} else {
		/* XXX Currently, no giant lock exists.*/
	}
}

void
callout_init_mtx(
    struct callout *c,
    KSPIN_LOCK *mtx,
    int flags)
{
	RtlZeroMemory(c, sizeof(struct callout));
	KeInitializeTimer(&c->c_tmr);
	KeInitializeDpc(&c->c_dpc, CustomTimerDpc, c);
	KeInitializeSpinLock(&c->c_lock);

	c->c_mtx = mtx;
	c->c_flags = flags & CALLOUT_RETURNUNLOCKED;
}

int
callout_reset(
    struct callout *c,
    int to_ticks,
    void (*func)(void *),
    void *arg)
{
	int ret = 0;
	LARGE_INTEGER ExpireTime;

	if (KeCancelTimer(&c->c_tmr)) {
		atomic_add_int(&c->c_pending, -1);
		ret++;
	}

	c->c_func = func;
	c->c_arg = arg;
	atomic_add_int(&c->c_pending, 1);
	c->c_flags |= CALLOUT_ACTIVE;
	/* convertion from millisecond (ticks) to 100-nanosecond */
	ExpireTime.QuadPart = -(LONGLONG)(10000)*to_ticks; 

	KeSetTimer(&c->c_tmr, ExpireTime, &c->c_dpc);

	return ret;
}

int
callout_stop(
    struct callout *c)
{
	int ret = 0;

	if (KeCancelTimer(&c->c_tmr)) {
		atomic_add_int(&c->c_pending, -1);
		ret++;
	}
	c->c_flags &= ~CALLOUT_ACTIVE;

	return ret;
}

int
callout_drain(
    struct callout *c)
{
	int ret = 0;

	if (KeCancelTimer(&c->c_tmr)) {
		atomic_add_int(&c->c_pending, -1);
		ret++;
	} else {
		KeAcquireSpinLockAtDpcLevel(&c->c_lock);
		KeReleaseSpinLockFromDpcLevel(&c->c_lock);
	}
	c->c_flags &= ~CALLOUT_ACTIVE;

	return ret;
}
