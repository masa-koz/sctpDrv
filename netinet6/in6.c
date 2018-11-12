/*-
 * Copyright (C) 2000 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ntifs.h>

#include <ndis.h>

#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include <netinet6/in6.h>

/*
 * Convert sockaddr_in6 to sockaddr_in.  Original sockaddr_in6 must be
 * v4 mapped addr or v4 compat addr
 */
void
in6_sin6_2_sin(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
	memcpy(&sin->sin_addr, &sin6->sin6_addr.s6_addr[12], sizeof(struct in_addr));
}

/* Convert sockaddr_in to sockaddr_in6 in v4 mapped addr format. */
void
in6_sin_2_v4mapsin6(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sin->sin_port;
	*(uint32_t *)&sin6->sin6_addr.s6_addr[0] = 0;
	*(uint32_t *)&sin6->sin6_addr.s6_addr[4] = 0;
	*(uint32_t *)&sin6->sin6_addr.s6_addr[8] = IPV6_ADDR_INT32_SMP;
	*(uint32_t *)&sin6->sin6_addr.s6_addr[12] = sin->sin_addr.s_addr;
}

int
ip6_ctloutput(
    struct socket *so,
    struct sockopt *sopt)
{
	struct in6pcb *in6p;
	int error, optval;

	in6p = (struct in6pcb *)so->so_pcb;

	if (sopt->sopt_level != IPPROTO_IPV6) {
		error = EINVAL;
		return error;
	}
	if (in6p == NULL) {
		error = EINVAL;
		return error;
	}

	if (sopt->sopt_dir == SOPT_SET) {
		switch (sopt->sopt_name) {
		case IPV6_V6ONLY:
			error = sooptcopyin(sopt, &optval, sizeof(optval), sizeof(optval));
			if (error != 0) {
				break;
			}
			if (optval) {
				in6p->in6p_vflag &= ~INP_IPV4;
				in6p->in6p_flags |= IN6P_IPV6_V6ONLY;
			} else {
				in6p->in6p_vflag |= INP_IPV4;
				in6p->in6p_flags &= ~IN6P_IPV6_V6ONLY;
			}
			break;
		default:
			error = ENOPROTOOPT;
			break;
		}
	} else if (
	    sopt->sopt_dir == SOPT_GET) {
		switch (sopt->sopt_name) {
		case IPV6_V6ONLY:
			if ((in6p->in6p_vflag & IN6P_IPV6_V6ONLY) != 0) {
				optval = 1;
			} else {
				optval = 0;
			}
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			if (error != 0) {
				break;
			}
			break;
		default:
			error = ENOPROTOOPT;
			break;
		}
	} else {
		error = EINVAL;
	}
	return error;
}

int
in6_embedscope(
    struct in6_addr *in6,
    const struct sockaddr_in6 *sin6)
{
	u_int32_t scope_id;
	struct ifnet *ifp = NULL;

	scope_id = sin6->sin6_scope_id;

	if (scope_id != 0 &&
	    (IN6_IS_SCOPE_LINKLOCAL(in6) ||
	     IN6_IS_ADDR_MC_NODELOCAL(in6))) {
		IFNET_WLOCK();
		TAILQ_FOREACH(ifp, &ifnet, if_link) {
			if (ifp->if_family != AF_INET6) {
				continue;
			}
			if (ifp->if_ifIndex == scope_id) {
				break;
			}
		}
		IFNET_WUNLOCK();
		if (ifp != NULL) {
			in6->s6_words[1] = htons(scope_id & 0xffff);
		}
	}
	return 0;
}

int
in6_recoverscope(
    struct sockaddr_in6 *sin6,
    const struct in6_addr *in6,
    struct ifnet *ifp)
{
	u_int32_t scope_id;

	sin6->sin6_addr = *in6;

	if ((IN6_IS_SCOPE_LINKLOCAL(in6) ||
	     IN6_IS_ADDR_MC_NODELOCAL(in6))) {
		scope_id = ntohs(sin6->sin6_addr.s6_words[1]);
		if (ifp != NULL && ifp->if_family == AF_INET6 &&
		    ifp->if_ifIndex != scope_id) {
			return ENXIO;
		}

		sin6->sin6_addr.s6_words[1] = 0;
		sin6->sin6_scope_id = scope_id;
	}
	return 0;
}

int
in6_clearscope(
    struct in6_addr *in6)
{
	if ((IN6_IS_SCOPE_LINKLOCAL(in6) ||
	     IN6_IS_ADDR_MC_NODELOCAL(in6)) &&
	    in6->s6_words[1] != 0) {
		in6->s6_words[1] = 0;
		return 1;
	} else {
		return 0;
	}
}

static char digits[] = "0123456789abcdef";
static int ip6round = 0;
char *
ip6_sprintf(addr)
	const struct in6_addr *addr;
{
	static char ip6buf[8][48];
	int i;
	char *cp;
	const u_int16_t *a = (const u_int16_t *)addr;
	const u_int8_t *d;
	int dcolon = 0;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (const u_char *)a;
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d++ & 0xf];
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = 0;
	return (ip6buf[ip6round]);
}
