/*-
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 *      @(#)time.h      8.5 (Berkeley) 5/4/95
 * $FreeBSD: src/sys/sys/time.h,v 1.69 2005/04/02 12:33:27 das Exp $
 */
#ifndef _SYS_TIME_H_
#define _SYS_TIME_H_

#include <ntifs.h>

struct timeval {
	long	tv_sec;		/* seconds since Jan. 1, 1970 */
	long	tv_usec;	/* and microseconds */
};

void __inline
timevalfix(struct timeval *t1)
{
	if (t1->tv_usec < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
	if (t1->tv_usec >= 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

void __inline
timevaladd(struct timeval *t1, const struct timeval *t2)
{
	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}
#define timeradd(tvp, uvp, vvp) do { \
	(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec; \
	(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec; \
	if ((vvp)->tv_usec >= 1000000) { \
		(vvp)->tv_sec++; \
		(vvp)->tv_usec -= 1000000; \
	} \
} while (0)

void __inline
timevalsub(struct timeval *t1, const struct timeval *t2)
{
	t1->tv_sec -= t2->tv_sec;
	t1->tv_usec -= t2->tv_usec;
	timevalfix(t1);
}
#define timersub(tvp, uvp, vvp) do { \
	(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec; \
	(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec; \
	if ((vvp)->tv_usec < 0) { \
		(vvp)->tv_sec--; \
		(vvp)->tv_usec += 1000000; \
	} \
} while (0)

#define timevalcmp(tvp, uvp, cmp) \
	(((tvp)->tv_sec == (uvp)->tv_sec) ? \
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) : \
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define timercmp timevalcmp

__inline void
microuptime(struct timeval *x)
{
	LARGE_INTEGER tickCount, upTime;
	KeQueryTickCount(&tickCount);
	upTime.QuadPart = tickCount.QuadPart * KeQueryTimeIncrement();
	x->tv_sec = (LONG)(upTime.QuadPart/10000000);
	x->tv_usec = (LONG)((upTime.QuadPart%10000000)/10);
}
#define getmicrouptime microuptime

__inline void
microtime(struct timeval *x)
{
	LARGE_INTEGER systemTime;
	KeQuerySystemTime(&systemTime);
	x->tv_sec = (LONG)(systemTime.QuadPart/10000000);
	x->tv_usec = (LONG)((systemTime.QuadPart%10000000)/10);
}
#define getmicrotime microtime

#endif /* _SYS_TIME_H_ */
