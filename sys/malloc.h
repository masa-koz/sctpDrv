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
#ifndef _SYS_MALLOC_H_
#define _SYS_MALLOC_H_

#define M_NOWAIT	0x0001
#define M_WAITOK	0x0002
#define M_ZERO		0x0100
#define M_NOVM		0x0200
#define M_USE_RESERVE	0x0400


struct malloc_type {
	u_long tag;
	char *shortdesc;
	char *longdesc;
};


#ifdef _KERNEL
#define MALLOC_DEFINE(type, tag, shortdesc, longdesc)	\
	struct malloc_type type[1] = {			\
		{ tag, shortdesc, longdesc }	\
	};						\

#define MALLOC_DECLARE(type) \
	extern struct malloc_type type[1]

#define MALLOC(var, type, size, name, flags) do { \
	(var) = (type)ExAllocatePoolWithTag(NonPagedPool, (size), (name)->tag); \
	if ((var) != NULL && ((flags) & M_ZERO) != 0) { \
		RtlZeroMemory(var, size); \
	} \
} while (0)
#define FREE(var, type) ExFreePool((var))

static __inline void *
malloc(unsigned long size, struct malloc_type *type, int flags)
{
	void *var = NULL;
	var = ExAllocatePoolWithTag(NonPagedPool, size, type->tag);
	if (var != NULL && (flags & M_ZERO) != 0) {
		RtlZeroMemory(var, size);
	}
	return var;
}
#define free(buf, type) ExFreePool((buf))
#endif

#endif /* _SYS_MALLOC_H_ */
