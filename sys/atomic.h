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
#ifndef __SYS_ATOMIC_H__
#define __SYS_ATOMIC_H__

#if defined(_KERNEL)
#include <ntifs.h>
#else
#include <winbase.h>
#endif

#define	atomic_set_long(p, v)	InterlockedExchange((PLONG)(p), (LONG)(v))
#define	atomic_set_int		atomic_set_long
#define	atomic_set_short	atomic_set_long
#define	atomic_set_char		atomic_set_long

#define	atomic_clear_long(p, v)	InterlockedXor((PLONG)(p), (LONG)(v))
#define	atomic_clear_int	atomic_clear_long
#define	atomic_clear_short	atomic_clear_long
#define	atomic_clear_char	atomic_clear_long

#define	atomic_add_long(p, v)	InterlockedExchangeAdd((PLONG)(p), (LONG)(v))
#define	atomic_add_int		atomic_add_long
#define	atomic_add_short	atomic_add_long
#define	atomic_add_char		atomic_add_long

#define	atomic_fetchadd_long	atomic_add_long
#define	atomic_fetchadd_int	atomic_add_int
#define	atomic_fetchadd_short	atomic_add_short
#define	atomic_fetchadd_char	atomic_add_char

#define	atomic_subtract_long(p, v)	InterlockedExchangeAdd((PLONG)(p), -(LONG)(v))
#define	atomic_subtract_int		atomic_subtract_long
#define	atomic_subtract_short		atomic_subtract_long
#define	atomic_subtract_char		atomic_subtract_long

#define	atomic_cmpset_long(p, c, v)	InterlockedCompareExchange((PLONG)(p), (LONG)v, (LONG)c)
#define	atomic_cmpset_int		atomic_cmpset_long
#define	atomic_cmpset_short		atomic_cmpset_long
#define	atomic_cmpset_char		atomic_cmpset_long

#endif	/* __SYS_ATOMIC_H__ */
