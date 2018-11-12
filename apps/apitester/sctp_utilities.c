/*-
 * Copyright (c) 2001-2007 by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2001-2007, by Michael Tuexen, tuexen@fh-muenster.de. All rights reserved.
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

#if !defined(__Windows__)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <mswsock.h>
#include <WS2tcpip.h>
#endif
#include <string.h>
#include <stdio.h>
#if !defined(__Windows__)
#include <unistd.h>
#else
#include <malloc.h>
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#if !defined(__Windows__)
#include <netinet/sctp.h>
#else
#include <ws2sctp.h>
#endif

#include "sctp_utilities.h"

void
sctp_delay(int ms)
{
#if !defined(__Windows__)
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = (ms * 1000 * 1000);
    (void)nanosleep(&ts, NULL);
#else
    Sleep(ms);
#endif
}

unsigned short
sctp_get_local_port(int fd)
{
	struct sockaddr_in addr;
	socklen_t addr_len;

	addr_len = (socklen_t)sizeof(struct sockaddr_in);
	(void)getsockname(fd, (struct sockaddr *) &addr, &addr_len);
	return ntohs(addr.sin_port);
}

int
sctp_bind(int fd, in_addr_t address, in_port_t port)
{
	struct sockaddr_in addr;
	
	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
#ifdef HAVE_SIN_LEN
	addr.sin_len         = sizeof(struct sockaddr_in);
#endif
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = htonl(address);
	
	return (bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(struct sockaddr_in)));
}

int
sctp_connect(int fd, in_addr_t address, in_port_t port)
{
	struct sockaddr_in addr;

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return -1;

	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
#ifdef HAVE_SIN_LEN
	addr.sin_len         = sizeof(struct sockaddr_in);
#endif
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = htonl(address);
	return (connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(struct sockaddr_in)));
}
	
int 
sctp_one2one(unsigned short port, int should_listen, int bindall)
{
	int fd;

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0) 
		return -1;

	if (sctp_bind(fd, bindall?INADDR_ANY:INADDR_LOOPBACK, 0) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return -1;
	}
	if (should_listen) {
		if (listen(fd, 1) < 0) {
#if !defined(__Windows__)
			close(fd);
#else
			closesocket(fd);
#endif
			return -1;
		}
	}
	return fd;
}



int sctp_socketpair(int *fds, int bindall)
{
	int fd;
	struct sockaddr_in addr;
	socklen_t addr_len;
	

	/* Get any old port, but listen */
	fd = sctp_one2one(0, 1, bindall);
	if (fd < 0) {
		return -1;
	}

	/* Get any old port, but no listen */
	fds[0] = sctp_one2one(0, 0, bindall);
	if (fds[0] < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return -1;
	}
	addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if (getsockname(fd, (struct sockaddr *) &addr, &addr_len) < 0) {
#if !defined(__Windows__)
		close(fd);
		close(fds[0]);
#else
		closesocket(fd);
		closesocket(fds[0]);
#endif
		return -1;
	}
	if (bindall) {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	if (connect(fds[0], (struct sockaddr *)&addr, addr_len) < 0) {
#if !defined(__Windows__)
		close(fd);
		close(fds[0]);
#else
		closesocket(fd);
		closesocket(fds[0]);
#endif
		return -1;
	}

	if ((fds[1] = accept(fd, NULL, 0)) < 0) {
#if !defined(__Windows__)
		close(fd);
		close(fds[0]);
#else
		closesocket(fd);
		closesocket(fds[0]);
#endif
		return -1;
	}

#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
	return 0;
}

int sctp_socketpair_reuse(int fd, int *fds, int bindall)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	

	/* Get any old port, but no listen */
	fds[0] = sctp_one2one(0, 0, bindall);
	if (fds[0] < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return -1;
	}
	addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if (getsockname (fd, (struct sockaddr *) &addr, &addr_len) < 0) {
#if !defined(__Windows__)
		close(fd);
		close(fds[0]);
#else
		closesocket(fd);
		closesocket(fds[0]);
#endif
		return -1;
	}
	if (bindall) {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	if (connect(fds[0], (struct sockaddr *) &addr, addr_len) < 0) {
#if !defined(__Windows__)
		close(fd);
		close(fds[0]);
#else
		closesocket(fd);
		closesocket(fds[0]);
#endif
		return -1;
	}

	if ((fds[1] = accept(fd, NULL, 0)) < 0) {
#if !defined(__Windows__)
		close(fd);
		close(fds[0]);
#else
		closesocket(fd);
		closesocket(fds[0]);
#endif
		return -1;
	}
	return 0;
}


int sctp_socketstar(int *fd, int *fds, unsigned int n)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	unsigned int i, j;
	
	if ((*fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
    	return -1;

	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
#ifdef HAVE_SIN_LEN
	addr.sin_len         = sizeof(struct sockaddr_in);
#endif
	addr.sin_port        = htons(0);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(*fd, (struct sockaddr *)&addr, (socklen_t)sizeof(struct sockaddr_in)) < 0) {
#if !defined(__Windows__)
		close(*fd);
#else
		closesocket(*fd);
#endif
		return -1;
	}
	
	addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if (getsockname (*fd, (struct sockaddr *) &addr, &addr_len) < 0) {
#if !defined(__Windows__)
		close(*fd);
#else
		closesocket(*fd);
#endif
		return -1;
	}

	if (listen(*fd, 1) < 0) {
#if !defined(__Windows__)
		close(*fd);
#else
		closesocket(*fd);
#endif
		return -1;
	}

	for (i = 0; i < n; i++){
		if ((fds[i] = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0) {
#if !defined(__Windows__)
			close(*fd);
#else
			closesocket(*fd);
#endif
			for (j = 0; j < i; j++ )
#if !defined(__Windows__)
				close(*fd);
#else
				closesocket(*fd);
#endif
			return -1;
		}

		if (connect(fds[i], (struct sockaddr *) &addr, addr_len) < 0) {
#if !defined(__Windows__)
			close(*fd);
#else
			closesocket(*fd);
#endif
			for (j = 0; j <= i; j++ )
#if !defined(__Windows__)
				close(*fd);
#else
				closesocket(*fd);
#endif
			return -1;
		}
	}

	return 0;
}

int sctp_shutdown(int fd) {
#if !defined(__Windows__)
	return shutdown(fd, SHUT_WR);
#else
	return shutdown(fd, SD_SEND);
#endif
}

int sctp_abort(int fd) {
    struct linger l;
    
    l.l_onoff  = 1;
    l.l_linger = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof (struct linger)) < 0)
    	return -1;
#if !defined(__Windows__)
    return close(fd);
#else
    return closesocket(fd);
#endif
 }

int sctp_enable_reuse_port(int fd)
{
	const int on = 1;

	return setsockopt(fd, IPPROTO_SCTP, SCTP_REUSE_PORT, (const void *)&on, sizeof(int));
}

int sctp_disable_reuse_port(int fd)
{
	const int off = 0;

	return setsockopt(fd, IPPROTO_SCTP, SCTP_REUSE_PORT, (const void *)&off, sizeof(int));
}

int sctp_enable_non_blocking(int fd)
{
	int flags;
	
#if !defined(__Windows__)
	flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags  | O_NONBLOCK);
#else
	flags = 1;
	return ioctlsocket(fd, FIONBIO, &flags);
#endif
}

int sctp_disable_non_blocking_blocking(int fd)
{
	int flags;
	
#if !defined(__Windows__)
	flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags  & ~O_NONBLOCK);
#else
	flags = 0;
	return ioctlsocket(fd, FIONBIO, &flags);
#endif
}

int sctp_set_rto_info(int fd, sctp_assoc_t assoc_id, uint32_t init, uint32_t max, uint32_t min)
{
	struct sctp_rtoinfo rtoinfo;
	socklen_t len;
	
	len = (socklen_t)sizeof(struct sctp_rtoinfo);
	memset((void *)&rtoinfo, 0, sizeof(struct sctp_rtoinfo));
	
	rtoinfo.srto_assoc_id = assoc_id;
	rtoinfo.srto_initial  = init;
	rtoinfo.srto_max      = max;
	rtoinfo.srto_min      = min;

	return setsockopt(fd, IPPROTO_SCTP, SCTP_RTOINFO, (const void *)&rtoinfo, len);
}

int sctp_set_initial_rto(int fd, sctp_assoc_t assoc_id, uint32_t init)
{
	return sctp_set_rto_info(fd, assoc_id, init, 0, 0);
}

int sctp_set_maximum_rto(int fd, sctp_assoc_t assoc_id, uint32_t max)
{
	return sctp_set_rto_info(fd, assoc_id, 0, max, 0);
}

int sctp_set_minimum_rto(int fd, sctp_assoc_t assoc_id, uint32_t min)
{
	return sctp_set_rto_info(fd, assoc_id, 0, 0, min);
}

int sctp_get_rto_info(int fd, sctp_assoc_t assoc_id, uint32_t *init, uint32_t *max, uint32_t *min)
{
	struct sctp_rtoinfo rtoinfo;
	socklen_t len;
	int result;
	
	len = (socklen_t)sizeof(struct sctp_rtoinfo);
	memset((void *)&rtoinfo, 0, sizeof(struct sctp_rtoinfo));
	rtoinfo.srto_assoc_id = assoc_id;
	
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_RTOINFO, (void *)&rtoinfo, &len);	

	if (init)
		*init = rtoinfo.srto_initial;
	if (max)
		*max = rtoinfo.srto_max;
	if (min)
		*min = rtoinfo.srto_min;

	return result;
}

int sctp_get_initial_rto(int fd, sctp_assoc_t assoc_id, uint32_t *init)
{
	return sctp_get_rto_info(fd, assoc_id, init, NULL, NULL);
}

int sctp_get_minimum_rto(int fd, sctp_assoc_t assoc_id, uint32_t *min)
{
	return sctp_get_rto_info(fd, assoc_id, NULL, NULL, min);
}

int sctp_get_maximum_rto(int fd, sctp_assoc_t assoc_id, uint32_t *max)
{
	return sctp_get_rto_info(fd, assoc_id, NULL, max, NULL);
}





static sctp_assoc_t 
__get_assoc_id (int fd, struct sockaddr *addr)
{
	struct sctp_paddrinfo sp;
	socklen_t siz;
	socklen_t sa_len;
	int cnt = 0;

	/* First get the assoc id */
 try_again:
	siz = sizeof(sp);
	memset(&sp,0,sizeof(sp));
	if(addr->sa_family == AF_INET) {
		sa_len = sizeof(struct sockaddr_in);
	} else if (addr->sa_family == AF_INET6) {
		sa_len = sizeof(struct sockaddr_in6);
	} else {
		return ((sctp_assoc_t)0);
	}
	memcpy((caddr_t)&sp.spinfo_address, addr, sa_len);
	if(getsockopt(fd, IPPROTO_SCTP, SCTP_GET_PEER_ADDR_INFO,
		      (void *)&sp, &siz) != 0) {
		if (cnt < 1) {
			cnt++;
			sctp_delay(SCTP_SLEEP_MS);
			goto try_again;
		}
		return ((sctp_assoc_t)0);
	}
	/* BSD: We depend on the fact that 0 can never be returned */
	return (sp.spinfo_assoc_id);
}



int 
sctp_one2many(unsigned short port, int bindall)
{
	int fd;
	struct sockaddr_in addr;

	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return -1;

	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
#ifdef HAVE_SIN_LEN
	addr.sin_len         = sizeof(struct sockaddr_in);
#endif
	addr.sin_port        = htons(port);
	if (bindall) {
		addr.sin_addr.s_addr = 0;
	} else {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	if (bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(struct sockaddr_in)) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return -1;
	}

	if (listen(fd, 1) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return -1;
	}
	return(fd);
}



/* If fds[0] != -1 its a valid 1-2-M socket already open
 * that is to be used with the new association 
 */
int 
sctp_socketpair_1tom(int *fds, sctp_assoc_t *ids, int bindall)
{
	int fd;
	struct sockaddr_in addr;
	socklen_t addr_len;
	int set=0;
	sctp_assoc_t aid;

	fd = sctp_one2many(0, bindall);
	if (fd == -1) {
		printf("Can't get socket\n");
		return -1;
	}

	if(fds[0] == -1) {
		fds[0] = sctp_one2many(0, bindall);
		if (fds[0]  < 0) {
#if !defined(__Windows__)
			close(fd);
#else
			closesocket(fd);
#endif
			return -1;
		}
	}
	set = 1;
	addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if (getsockname (fd, (struct sockaddr *) &addr, &addr_len) < 0) {
		if(set)
#if !defined(__Windows__)
			close(fds[0]);
		close(fd);
#else
			closesocket(fds[0]);
		closesocket(fd);
#endif
		return -1;
	}
	if (bindall) {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	if (sctp_connectx(fds[0], (struct sockaddr *) &addr, 1, &aid) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		if(set)
#if !defined(__Windows__)
			close(fds[0]);
		close(fd);
#else
			closesocket(fds[0]);
		closesocket(fd);
#endif
		return -1;
	}
	fds[1] = fd;
	/* Now get the assoc-id's if the caller wants them */
	if(ids == NULL)
		return 0;

	ids[0] = aid;

	if (getsockname (fds[0], (struct sockaddr *) &addr, &addr_len) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		printf("Can't get socket name2\n");
		if (set) 
#if !defined(__Windows__)
			close(fds[0]);
#else
			closesocket(fds[0]);
#endif
		return -1;
	}
	if (bindall) {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	ids[1] = __get_assoc_id (fds[1], (struct sockaddr *)&addr);
	return 0;
}



int 
sctp_get_assoc_info(int fd, sctp_assoc_t assoc_id, 
		    uint16_t *asoc_maxrxt,
		    uint16_t *peer_dest_cnt, 
		    uint32_t *peer_rwnd,
		    uint32_t *local_rwnd,
		    uint32_t *cookie_life)
{
	struct sctp_assocparams asocinfo;
	socklen_t len;
	int result;
	
	len = (socklen_t)sizeof(asocinfo);
	memset((void *)&asocinfo, 0, sizeof(asocinfo));
	asocinfo.sasoc_assoc_id = assoc_id;
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_ASSOCINFO, (void *)&asocinfo, &len);

	if(asoc_maxrxt) 
		*asoc_maxrxt = asocinfo.sasoc_asocmaxrxt;
	if (peer_dest_cnt) 
		*peer_dest_cnt = asocinfo.sasoc_number_peer_destinations;
	if (peer_rwnd) 
		*peer_rwnd = asocinfo.sasoc_peer_rwnd;
	if (local_rwnd)
		*local_rwnd = asocinfo.sasoc_local_rwnd;
	if (cookie_life)
		*cookie_life = asocinfo.sasoc_cookie_life;
	return result;
}

int
sctp_set_assoc_info(int fd, sctp_assoc_t assoc_id, 
		    uint16_t asoc_maxrxt,
		    uint16_t peer_dest_cnt, 
		    uint32_t peer_rwnd,
		    uint32_t local_rwnd,
		    uint32_t cookie_life)
{
	struct sctp_assocparams asocinfo;
	socklen_t len;
	int result;
	
	len = (socklen_t)sizeof(asocinfo);
	memset((void *)&asocinfo, 0, sizeof(asocinfo));
	asocinfo.sasoc_assoc_id = assoc_id;
	asocinfo.sasoc_asocmaxrxt = asoc_maxrxt;
	asocinfo.sasoc_number_peer_destinations = peer_dest_cnt;
	asocinfo.sasoc_peer_rwnd = peer_rwnd;
	asocinfo.sasoc_local_rwnd = local_rwnd;
	asocinfo.sasoc_cookie_life = cookie_life;
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_ASSOCINFO, (void *)&asocinfo, len);
	return result;
}

int 
sctp_set_asoc_maxrxt(int fd, sctp_assoc_t asoc, uint16_t max)
{
	return(sctp_set_assoc_info(fd, asoc, max, 0, 0, 0, 0));
}

int 
sctp_get_asoc_maxrxt(int fd, sctp_assoc_t asoc, uint16_t *max)
{
	return(sctp_get_assoc_info(fd, asoc, max, NULL, NULL, NULL, NULL));
}

int 
sctp_set_asoc_peerdest_cnt(int fd, sctp_assoc_t asoc, uint16_t dstcnt)
{
	return(sctp_set_assoc_info(fd, asoc, 0, dstcnt, 0, 0, 0));
}

int 
sctp_get_asoc_peerdest_cnt(int fd, sctp_assoc_t asoc, uint16_t *dst)
{
	return(sctp_get_assoc_info(fd, asoc, NULL, dst, NULL, NULL, NULL));
}

int 
sctp_set_asoc_peer_rwnd(int fd, sctp_assoc_t asoc, uint32_t rwnd)
{
	return(sctp_set_assoc_info(fd, asoc, 0, 0, rwnd, 0, 0));
}

int 
sctp_get_asoc_peer_rwnd(int fd, sctp_assoc_t asoc, uint32_t *rwnd)
{
	return(sctp_get_assoc_info(fd, asoc, NULL, NULL, rwnd, NULL, NULL));
}


int 
sctp_set_asoc_local_rwnd(int fd, sctp_assoc_t asoc, uint32_t lrwnd)
{
	return(sctp_set_assoc_info(fd, asoc, 0, 0, 0, lrwnd, 0));
}

int 
sctp_get_asoc_local_rwnd(int fd, sctp_assoc_t asoc, uint32_t *lrwnd)
{

	return(sctp_get_assoc_info(fd, asoc, NULL, NULL, NULL, lrwnd, NULL));
}

int 
sctp_set_asoc_cookie_life(int fd, sctp_assoc_t asoc, uint32_t life)
{
	return(sctp_set_assoc_info(fd, asoc, 0, 0, 0, 0, life));
}

int 
sctp_get_asoc_cookie_life(int fd, sctp_assoc_t asoc, uint32_t *life)
{
	return(sctp_get_assoc_info(fd, asoc, NULL, NULL, NULL, NULL, life));
}


uint32_t
sctp_get_number_of_associations(int fd)
{
	uint32_t number;
	socklen_t len;
	
	len = (socklen_t) sizeof(uint32_t);
	if (getsockopt(fd, IPPROTO_SCTP, SCTP_GET_ASSOC_NUMBER, (void *)&number, &len) < 0)
		return -1;
	else
		return number;
}

uint32_t
sctp_get_association_identifiers(int fd, sctp_assoc_t ids[], unsigned int n)
{
	socklen_t len;
	
	len = (socklen_t) (n * sizeof(sctp_assoc_t));
	if (getsockopt(fd, IPPROTO_SCTP, SCTP_GET_ASSOC_ID_LIST, (void *)ids, &len) < 0)
		return -1;
	else
		return (len / sizeof(sctp_assoc_t));
}


int 
sctp_get_initmsg(int fd, 
		 uint32_t *ostreams,
		 uint32_t *istreams,
		 uint16_t *maxattempt,
		 uint16_t *max_init_timeo)

{
	struct sctp_initmsg initmsg;
	socklen_t len;
	int result;
	
	len = (socklen_t)sizeof(initmsg);
	memset((void *)&initmsg, 0, sizeof(initmsg));
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, 
			    (void *)&initmsg, &len);

	if(ostreams) 
		*ostreams = initmsg.sinit_num_ostreams;
	if (istreams)
		*istreams = initmsg.sinit_max_instreams;
	if (maxattempt) 
		*maxattempt = initmsg.sinit_max_attempts;
	if (max_init_timeo)
		*max_init_timeo = initmsg.sinit_max_init_timeo;
	return result;
}

int 
sctp_set_initmsg(int fd, 
		 uint32_t ostreams,
		 uint32_t istreams,
		 uint16_t maxattempt,
		 uint16_t max_init_timeo)

{
	struct sctp_initmsg initmsg;
	socklen_t len;
	int result;
	
	len = (socklen_t)sizeof(initmsg);
	memset((void *)&initmsg, 0, sizeof(initmsg));
	initmsg.sinit_num_ostreams = ostreams;
	initmsg.sinit_max_instreams = istreams;
	initmsg.sinit_max_attempts = maxattempt;
	initmsg.sinit_max_init_timeo = max_init_timeo;
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, 
			    (void *)&initmsg, len);

	return result;
}
int sctp_set_im_ostream(int fd, uint32_t ostream)
{
	return (sctp_set_initmsg(fd, ostream, 0, 0, 0));
}
int sctp_set_im_istream(int fd, uint32_t istream)
{
	return (sctp_set_initmsg(fd, 0, istream, 0, 0));
}
int sctp_set_im_maxattempt(int fd, uint16_t max)
{
	return (sctp_set_initmsg(fd, 0, 0, max, 0));
}
int sctp_set_im_maxtimeo(int fd, uint16_t timeo)
{
	return (sctp_set_initmsg(fd, 0, 0, 0, timeo));
}

int sctp_get_ndelay(int fd, uint32_t *val)
{
	int result;
	socklen_t len;
	len = sizeof(*val);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, 
			    (void *)val, &len);
	return (result);
}

int sctp_set_ndelay(int fd, uint32_t val)
{
	int result;
	socklen_t len;
	len = sizeof(val);

	result = setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, 
			    (void *)&val, len);
	return(result);
}

int sctp_set_autoclose(int fd, uint32_t val)
{
	int result;
	socklen_t len;
	len = sizeof(val);

	result = setsockopt(fd, IPPROTO_SCTP, SCTP_AUTOCLOSE, 
			    (void *)&val, len);
	return(result);

}

int sctp_get_autoclose(int fd, uint32_t *val)
{
	int result;
	socklen_t len;
	len = sizeof(*val);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_AUTOCLOSE, 
			    (void *)val, &len);
	return (result);
}

int sctp_set_peer_prim(int fd, sctp_assoc_t id,  struct sockaddr *sa)
{

	struct sctp_setpeerprim prim;	
	int result;
	socklen_t len;
	if(sa == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if(sa->sa_family == AF_INET) {
		memcpy(&prim.sspp_addr, sa, sizeof(struct sockaddr_in));
	}else if (sa->sa_family == AF_INET6) {
		memcpy(&prim.sspp_addr, sa, sizeof(struct sockaddr_in6));
	} else {
		errno = EINVAL;
		return (-1);
	}
	prim.sspp_assoc_id = id;
	len = sizeof(prim);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_SET_PEER_PRIMARY_ADDR,
			    (void *)&prim, len);
	return (result);
}


int 
sctp_set_primary(int fd, sctp_assoc_t id, struct sockaddr *sa)
{
	struct sctp_setprim prim;
	socklen_t len;
	int result;

	len = sizeof(prim);
	prim.ssp_assoc_id = id;
	if(sa->sa_family == AF_INET) {
		memcpy(&prim.ssp_addr, sa, sizeof(struct sockaddr_in));
	} else if (sa->sa_family == AF_INET6) {
		memcpy(&prim.ssp_addr, sa, sizeof(struct sockaddr_in6));
	} else {
		errno = EINVAL;
		return -1;
	}
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, 
			    (void *)&prim, len);
	return(result);
}

int 
sctp_get_primary(int fd, sctp_assoc_t id, struct sockaddr *sa, socklen_t *alen)
{
	struct sctp_setprim prim;
	socklen_t len, clen;
	int result;
	struct sockaddr *lsa;

	len = sizeof(prim);
	memset(&prim, 0, sizeof(prim));
	prim.ssp_assoc_id = id;
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, 
			    (void *)&prim, &len);
	lsa = (struct sockaddr *)&prim.ssp_addr;
	if(lsa->sa_family == AF_INET)
		clen = sizeof(struct sockaddr_in);
	else if (lsa->sa_family == AF_INET6)
		clen = sizeof(struct sockaddr_in6);
	else {
		errno = EFAULT;
		return -1;
	}
	if(*alen > clen) 
		len = clen;
	else
		len = *alen;

	memcpy(sa, lsa, len);
	*alen = clen;
	return(result);
}


int
sctp_set_adaptation( int fd, uint32_t val)
{
	struct sctp_setadaptation adapt;
	socklen_t len;
	int result;

	len = sizeof(adapt);
	memset(&adapt, 0, sizeof(adapt));
	adapt.ssb_adaptation_ind = val;

	result = setsockopt(fd, IPPROTO_SCTP, SCTP_ADAPTATION_LAYER,
			    (void *)&adapt, len);
	return(result);

}

int 
sctp_get_adaptation( int fd, uint32_t *val)
{
	struct sctp_setadaptation adapt;
	socklen_t len;
	int result;

	len = sizeof(adapt);
	memset(&adapt, 0, sizeof(adapt));

	result = getsockopt(fd, IPPROTO_SCTP, SCTP_ADAPTATION_LAYER,
			    (void *)&adapt, &len);
	*val = adapt.ssb_adaptation_ind;
	return(result);
}

int sctp_set_disfrag( int fd, int val)
{
	socklen_t len;
	int result;

	len = sizeof(val);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_DISABLE_FRAGMENTS,
			    (void *)&val, len);
	return(result);

}

int sctp_get_disfrag( int fd, int *val)
{
	socklen_t len;
	int result;

	len = sizeof(*val);

	result = getsockopt(fd, IPPROTO_SCTP, SCTP_DISABLE_FRAGMENTS,
			    (void *)val, &len);
	return(result);
}

int sctp_get_paddr_param(int fd, sctp_assoc_t id, 
			 struct sockaddr *sa,
			 uint32_t *hbinterval,
			 uint16_t *maxrxt,
			 uint32_t *pathmtu,
			 uint32_t *flags,
			 uint32_t *ipv6_flowlabel,
			 uint8_t *ipv4_tos)
{
	struct sctp_paddrparams param;
	socklen_t len;
	int result;
	memset(&param, 0, sizeof(param));
	param.spp_assoc_id = id;
	if(sa) {
		if (sa->sa_family == AF_INET) {
			memcpy(&param.spp_address, sa, sizeof(struct sockaddr_in));
		} else if (sa->sa_family == AF_INET6) {
			memcpy(&param.spp_address, sa, sizeof(struct sockaddr_in6));
		} else {
			errno = EINVAL;
			return -1;
		}
	} else {
		struct sockaddr *sa;
		sa = (struct sockaddr *)&param.spp_address;
		sa->sa_family = AF_INET;
	}
	len = sizeof(param);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
			    (void *)&param, &len);
	if (result < 0) {
		return (result);
	}
	if (hbinterval) {
		*hbinterval = param.spp_hbinterval;
	}
	if (maxrxt) {
		*maxrxt = param.spp_pathmaxrxt;
	}
	if (pathmtu) {
		*pathmtu  = param.spp_pathmtu;
	}
	if (flags) {
		*flags = param.spp_flags;
	}
	if (ipv6_flowlabel) {
		*ipv6_flowlabel = param.spp_ipv6_flowlabel;
	}
	if (ipv4_tos) {
		*ipv4_tos = param.spp_ipv4_tos;
	}
	return (result);
}


int sctp_set_paddr_param(int fd, sctp_assoc_t id, 
			 struct sockaddr *sa,
			 uint32_t hbinterval,
			 uint16_t maxrxt,
			 uint32_t pathmtu,
			 uint32_t flags,
			 uint32_t ipv6_flowlabel,
			 uint8_t ipv4_tos)
{
	struct sctp_paddrparams param;
	socklen_t len;
	int result;

	memset(&param, 0, sizeof(param));
	param.spp_assoc_id = id;
	if(sa) {
		if (sa->sa_family == AF_INET) {
			memcpy(&param.spp_address, sa, sizeof(struct sockaddr_in));
		} else if (sa->sa_family == AF_INET6) {
			memcpy(&param.spp_address, sa, sizeof(struct sockaddr_in6));
		} else {
			errno = EINVAL;
			return -1;
		}
	} else {
		struct sockaddr *sa;
		sa = (struct sockaddr *)&param.spp_address;
		sa->sa_family = AF_INET;
	}
	param.spp_hbinterval = hbinterval;
	param.spp_pathmaxrxt = maxrxt;
	param.spp_pathmtu = pathmtu;
	param.spp_flags = flags;
	param.spp_ipv6_flowlabel = ipv6_flowlabel;
	param.spp_ipv4_tos = ipv4_tos;
	len = sizeof(param);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
			    (void *)&param, len);
	return(result);
	
}

int
sctp_set_hbint(int fd, sctp_assoc_t id, 
	       struct sockaddr *sa,
	       uint32_t hbinterval)
{
	int result;
	uint32_t flags;
	flags = SPP_HB_ENABLE;
	result  = sctp_set_paddr_param(fd, id, sa,
				       hbinterval,
				       0,
				       0,
				       flags,
				       0,
				       0);
	return result;	
}

int
sctp_set_hbdisable(int fd, sctp_assoc_t id, 
		   struct sockaddr *sa)
{
	int result;
	uint32_t flags;
	flags = SPP_HB_DISABLE;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       0,
				       0,
				       flags,
				       0,
				       0);
	return result;
}

int
sctp_set_hbenable(int fd, sctp_assoc_t id, 
		   struct sockaddr *sa)
{
	int result;
	uint32_t flags;
	flags = SPP_HB_ENABLE;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       0,
				       0,
				       flags,
				       0,
				       0);
	return result;
}


int
sctp_set_hbzero(int fd, sctp_assoc_t id, 
		struct sockaddr *sa)
{
	int result;
	uint32_t flags;
	flags = SPP_HB_ENABLE | SPP_HB_TIME_IS_ZERO;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       0,
				       0,
				       flags,
				       0,
				       0);
	return result;

}


int
sctp_set_maxrxt(int fd, sctp_assoc_t id, 
	       struct sockaddr *sa,
	       uint16_t maxrxt)
{
	int result;
	uint32_t flags;
	flags = 0;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       maxrxt,
				       0,
				       flags,
				       0,
				       0);
	return (result);

}

int
sctp_set_pmtu(int fd, sctp_assoc_t id, 
	      struct sockaddr *sa,
	      uint32_t pathmtu)
{
	int result;
	uint32_t flags;
	flags = SPP_PMTUD_DISABLE;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       0,
				       pathmtu,
				       flags,
				       0,
				       0);
	return (result);

}

int
sctp_set_pmtu_enable(int fd, sctp_assoc_t id, 
		     struct sockaddr *sa)
{
	int result;
	uint32_t flags;
	flags = SPP_PMTUD_ENABLE;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       0,
				       0,
				       flags,
				       0,
				       0);
	return (result);
}



int
sctp_set_flow(int fd, sctp_assoc_t id, 
	      struct sockaddr *sa,
	      uint32_t ipv6_flowlabel)
{
	int result;
	uint32_t flags;

	flags = SPP_IPV6_FLOWLABEL;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       0,
				       0,
				       flags,
				       ipv6_flowlabel,
				       0);
	return (result);
}

int
sctp_set_tos(int fd, sctp_assoc_t id, 
	     struct sockaddr *sa,
	     uint8_t ipv4_tos)
{
	int result;
	uint32_t flags;
	flags = SPP_IPV4_TOS;
	result  = sctp_set_paddr_param(fd, id, sa,
				       0,
				       0,
				       0,
				       flags,
				       0,
				       ipv4_tos);
	return (result);
}


int sctp_get_maxseg(int fd, sctp_assoc_t id, int *val)
{
	socklen_t len;
	struct sctp_assoc_value av;
	int result;

	av.assoc_id = id;
	av.assoc_value = 0;

	len = sizeof(av);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_MAXSEG,
			    (void *)&av, &len);
	*val = av.assoc_value;
	return(result);

}

int sctp_set_maxseg(int fd, sctp_assoc_t id, int val)
{
	socklen_t len;
	int result;
	struct sctp_assoc_value av;
	len = sizeof(av);
	av.assoc_id = id;
	av.assoc_value = val;

	result = setsockopt(fd, IPPROTO_SCTP, SCTP_MAXSEG,
			    (void *)&av, len);
	return(result);
}

int sctp_get_defsend(int fd, sctp_assoc_t id, struct sctp_sndrcvinfo *s)
{
	socklen_t len;
	int result;
	s->sinfo_assoc_id = id;

	len = sizeof(*s);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_DEFAULT_SEND_PARAM,
			    (void *)s, &len);
	return (result);
	
}

int sctp_set_defsend(int fd, sctp_assoc_t id, struct sctp_sndrcvinfo *s)
{
	socklen_t len;
	int result;
	s->sinfo_assoc_id = id;

	len = sizeof(*s);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_DEFAULT_SEND_PARAM,
			    (void *)s, len);
	return (result);
}


int sctp_set_events(int fd, struct sctp_event_subscribe *ev)
{
	socklen_t len;
	int result;
	len = sizeof(*ev);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
			    (void *)ev, len);
	return (result);
}

int sctp_get_events(int fd, struct sctp_event_subscribe *ev)
{
	socklen_t len;
	int result;
	len = sizeof(*ev);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
			    (void *)ev, &len);
	return (result);
}

int
sctp_enable_v4_address_mapping(int fd)
{
	const int on = 1;
	socklen_t length;
	
	length = (socklen_t)sizeof(int);
	return (setsockopt(fd, IPPROTO_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, (void *)&on, length));
}

int
sctp_disable_v4_address_mapping(int fd)
{
	const int off = 0;
	socklen_t length;
	
	length = (socklen_t)sizeof(int);
	return (setsockopt(fd, IPPROTO_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, (void *)&off, length));
}

int
sctp_v4_address_mapping_enabled(int fd)
{
	int onoff;
	socklen_t length;
	
	length = (socklen_t)sizeof(int);
	(void)getsockopt(fd, IPPROTO_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, (void *)&onoff, &length);
	return (onoff);
}

int
sctp_enable_v6_only(int fd)
{
	const int on = 1;
	socklen_t length;
	
	length = (socklen_t)sizeof(int);
#if !defined(__Windows__)
	return (setsockopt(fd, IPPROTO_IPV6, IPV6_BINDV6ONLY, (void *)&on, length));
#else
	return (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, length));
#endif
}

int
sctp_v6_only_enabled(int fd)
{
	int onoff = 1;
	socklen_t length;
	
	length = (socklen_t)sizeof(int);
#if !defined(__Windows__)
	(void)getsockopt(fd, IPPROTO_IPV6, IPV6_BINDV6ONLY, (void *)&onoff, &length);
#else
	(void)getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&onoff, &length);
#endif
	return (onoff);
}

int sctp_get_auth_chunk_id(int fd, uint8_t *fill)
{
	int result;
	socklen_t len;
	struct sctp_authchunk ch;

	len = sizeof(ch);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_CHUNK,
			    (void *)&ch, &len);
	if(result >= 0) {
		/* We really expect this to ALWAYS fail */
		*fill = ch.sauth_chunk;
	}
	return(result);
}

int sctp_set_auth_chunk_id(int fd, uint8_t chk)
{
	int result;
	socklen_t len;
	struct sctp_authchunk ch;

	len = sizeof(ch);
	ch.sauth_chunk = chk;
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_CHUNK,
			    (void *)&ch, len);
	return(result);

}


/********************************************************
 *
 * SCTP_KEY tests
 *
 ********************************************************/
int sctp_get_auth_key(int fd, sctp_assoc_t assoc_id, uint16_t *keyid,
		      uint16_t *keylen, uint8_t *keytext) {
	socklen_t len;
	struct sctp_authkey *akey;
	int result;

	len = sizeof(*akey) + *keylen;
	akey = (struct sctp_authkey *)alloca(len);
	if (akey == NULL) {
		printf("could not get memory for akey\n");
		return (-1);
	}
	akey->sca_assoc_id = assoc_id;
	akey->sca_keynumber = *keyid;
	memcpy(akey->sca_key, keytext, *keylen);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_KEY, (void *)akey, &len);
	if (result >= 0) {
	    /* This should always fail */
	    *keyid = akey->sca_keynumber;
	    *keylen = len - sizeof(*akey);
	    memcpy(keytext, akey->sca_key, *keylen);
	}
	return (result);
}

int sctp_set_auth_key(int fd, sctp_assoc_t assoc_id, uint16_t keyid,
		      uint16_t keylen, uint8_t *keytext) {
	socklen_t len;
	struct sctp_authkey *akey;
	int result;

	len = sizeof(*akey) + keylen;
	akey = (struct sctp_authkey *)alloca(len);
	if (akey == NULL) {
		printf("could not get memory for akey\n");
		return (-1);
	}
	akey->sca_assoc_id = assoc_id;
	akey->sca_keynumber = keyid;
	memcpy(akey->sca_key, keytext, keylen);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_KEY, (void *)akey, len);
	return (result);
}

int sctp_get_active_key(int fd, sctp_assoc_t assoc_id, uint16_t *keyid) {
	socklen_t len;
	struct sctp_authkeyid akey;
	int result;

	len = sizeof(akey);
	akey.scact_assoc_id = assoc_id;
	akey.scact_keynumber = *keyid;
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY,
			    (void *)&akey, &len);
	if (result >= 0) {
		*keyid = akey.scact_keynumber;
	}
	return (result);
}


int sctp_set_active_key(int fd, sctp_assoc_t assoc_id, uint16_t keyid) {
	socklen_t len;
	struct sctp_authkeyid akey;
	int result;

	len = sizeof(akey);
	akey.scact_assoc_id = assoc_id;
	akey.scact_keynumber = keyid;
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY,
			    (void *)&akey, len);
	return (result);
}


int sctp_get_delete_key(int fd, sctp_assoc_t assoc_id, uint16_t *keyid) {
	socklen_t len;
	struct sctp_authkeyid akey;
	int result;

	len = sizeof(akey);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_DELETE_KEY,
			    (void *)&akey, &len);
	if (result >= 0) {
	    /* This should always fail */
	    *keyid = akey.scact_keynumber;
	}
	return (result);
}

int sctp_set_delete_key(int fd, sctp_assoc_t assoc_id, uint16_t keyid) {
	socklen_t len;
	struct sctp_authkeyid akey;
	int result;

	len = sizeof(akey);
	akey.scact_assoc_id = assoc_id;
	akey.scact_keynumber = keyid;
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_DELETE_KEY,
			    (void *)&akey, len);
	return (result);
}




/********************************************************
 *
 * SCTP_OTHER tests
 *
 ********************************************************/


/********************************************************
 *
 * SCTP_DELAYED_SACK tests
 *
 ********************************************************/

int sctp_set_dsack(int fd, sctp_assoc_t id, uint32_t delay, uint32_t freq)
{
	int result;
	socklen_t len;
	struct sctp_sack_info sack;

	len = sizeof(sack);
	sack.sack_assoc_id = id;
	sack.sack_delay = delay;
	sack.sack_freq = freq;
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_DELAYED_SACK,
			    (void *)&sack, len);
	return(result);

}

int sctp_set_ddelay(int fd, sctp_assoc_t id, uint32_t delay)
{
	return (sctp_set_dsack(fd, id, delay, 0));
}

int sctp_set_dfreq(int fd, sctp_assoc_t id, uint32_t freq)
{
	return (sctp_set_dsack(fd, id, 0, freq));
}

int sctp_get_dsack(int fd, sctp_assoc_t id,uint32_t *delay, uint32_t *freq)
{
	int result;
	socklen_t len;
	struct sctp_sack_info sack;
	memset(&sack, 0, sizeof(sack));
	sack.sack_assoc_id = id;
	len = sizeof(sack);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_DELAYED_SACK,
			    (void *)&sack, &len);
	if (delay) {
		*delay = sack.sack_delay;
	}
	if (freq) {
		*freq = sack.sack_freq;
	}
	return(result);
}


int sctp_get_interleave(int fd, int *inter)
{
	int result;
	socklen_t len;

	len = sizeof(*inter);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE,
			    (void *)inter, &len);
	return(result);

}

int sctp_set_interleave(int fd, int inter)
{
	int result;
	socklen_t len;

	len = sizeof(inter);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE,
			    (void *)&inter, len);
	return(result);
}

int sctp_get_pdapi_point(int fd, int *point)
{
	int result;
	socklen_t len;

	len = sizeof(*point);
	result = getsockopt(fd, IPPROTO_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
			    (void *)point, &len);
	return(result);

}


int sctp_set_pdapi_point(int fd, int point)
{
	int result;
	socklen_t len;

	len = sizeof(point);
	result = setsockopt(fd, IPPROTO_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
			    (void *)&point, len);
	return(result);

}

int sctp_set_context(int fd, sctp_assoc_t id, uint32_t context)
{
	int result;
	socklen_t len;
	struct sctp_assoc_value av;

	len = sizeof(av);
	av.assoc_id = id;
	av.assoc_value = context;

	result = setsockopt(fd, IPPROTO_SCTP, SCTP_CONTEXT,
			    (void *)&av, len);
	return(result);

}

int sctp_get_context(int fd, sctp_assoc_t id, uint32_t *context)
{
	int result;
	socklen_t len;
	struct sctp_assoc_value av;

	len = sizeof(av);
	av.assoc_id = id;
	av.assoc_value = 0;

	result = getsockopt(fd, IPPROTO_SCTP, SCTP_CONTEXT,
			    (void *)&av, &len);
	*context = av.assoc_value;
	return(result);
}

