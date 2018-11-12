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
#ifndef _SYS_TYPES_H_
#define _SYS_TYPES_H_

#include <stddef.h>

#include <sys/cdefs.h>
#include <sys/endian.h>

typedef char			int8_t;
typedef short			int16_t;
typedef long			int32_t;
typedef long long		int64_t;
typedef unsigned char		u_int8_t, uint8_t, u_char;
typedef unsigned short		u_int16_t, uint16_t, u_short, n_short, sa_family_t, in_port_t;
typedef unsigned long		u_int32_t, uint32_t, u_long, n_long, n_time, DWORD, in_addr_t;
typedef unsigned long long 	uint64_t, u_quad_t;
#if defined(_KERNEL)
typedef unsigned long		u_int, socklen_t;
typedef unsigned long long 	off_t;
#else
typedef long			ssize_t;
#endif

typedef char 			*caddr_t;
typedef unsigned char 		*c_caddr_t;

#endif	/* _SYS_TYPES_H_ */
