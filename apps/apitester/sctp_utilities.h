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

#ifdef __Panda__
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK (uint32_t)0x01010101
#endif
#endif

#if defined(__Windows__)
typedef char                    int8_t;
typedef short                   int16_t;
typedef long                    int32_t;
typedef long long               int64_t;
typedef unsigned char           u_int8_t, uint8_t, u_char;
typedef unsigned short          u_int16_t, uint16_t, u_short, n_short, sa_family_t;
typedef unsigned long           u_int32_t, uint32_t, u_long, n_long, n_time, DWORD;
typedef unsigned long long      uint64_t, u_quad_t;
typedef long                    ssize_t;
typedef	unsigned long		in_addr_t;
typedef unsigned short		in_port_t;

typedef char                    *caddr_t;
typedef unsigned char           *c_caddr_t;
#endif
#define SCTP_SLEEP_MS	100
void sctp_delay(int ms);

int sctp_one2one(unsigned short port, int should_listen, int bindall);
unsigned short sctp_get_local_port(int);
int sctp_bind(int, in_addr_t, in_port_t);
int sctp_connect(int, in_addr_t, in_port_t);
int sctp_socketpair(int *, int bindall);
int sctp_socketpair_reuse(int fd, int *fds, int bindall);
int sctp_socketstar(int *, int *, unsigned int);
int sctp_shutdown(int);
int sctp_abort(int);
int sctp_enable_non_blocking(int);
int sctp_disable_non_blocking_blocking(int);
int sctp_enable_reuse_port(int);
int sctp_disable_reuse_port(int);
int sctp_set_rto_info(int, sctp_assoc_t, uint32_t, uint32_t, uint32_t);
int sctp_set_initial_rto(int , sctp_assoc_t, uint32_t);
int sctp_set_maximum_rto(int , sctp_assoc_t, uint32_t);
int sctp_set_minimum_rto(int , sctp_assoc_t, uint32_t);
int sctp_get_rto_info(int, sctp_assoc_t, uint32_t *, uint32_t *, uint32_t *);
int sctp_get_initial_rto(int fd, sctp_assoc_t, uint32_t *);
int sctp_get_maximum_rto(int fd, sctp_assoc_t, uint32_t *);
int sctp_get_minimum_rto(int fd, sctp_assoc_t, uint32_t *);

int sctp_one2many(unsigned short port, int bindall);
int sctp_socketpair_1tom(int *fds, sctp_assoc_t *asocids, int bindall);
int sctp_get_assoc_info(int fd, sctp_assoc_t assoc_id, 
			uint16_t *asoc_maxrxt,
			uint16_t *peer_dest_cnt, 
			uint32_t *peer_rwnd,
			uint32_t *local_rwnd,
			uint32_t *cookie_life);
int sctp_set_assoc_info(int fd, sctp_assoc_t assoc_id, 
			uint16_t asoc_maxrxt,
			uint16_t peer_dest_cnt, 
			uint32_t peer_rwnd,
			uint32_t local_rwnd,
			uint32_t cookie_life);
int sctp_set_asoc_maxrxt(int fd, sctp_assoc_t asoc, uint16_t max);
int sctp_get_asoc_maxrxt(int fd, sctp_assoc_t asoc, uint16_t *max);

int sctp_set_asoc_peerdest_cnt(int fd, sctp_assoc_t asoc, uint16_t dstcnt);
int sctp_get_asoc_peerdest_cnt(int fd, sctp_assoc_t asoc, uint16_t *dst);

int sctp_set_asoc_peer_rwnd(int fd, sctp_assoc_t asoc, uint32_t rwnd);
int sctp_get_asoc_peer_rwnd(int fd, sctp_assoc_t asoc, uint32_t *rwnd);

int sctp_set_asoc_local_rwnd(int fd, sctp_assoc_t asoc, uint32_t lrwnd);
int sctp_get_asoc_local_rwnd(int fd, sctp_assoc_t asoc, uint32_t *lrwnd);

int sctp_set_asoc_cookie_life(int fd, sctp_assoc_t asoc, uint32_t life);
int sctp_get_asoc_cookie_life(int fd, sctp_assoc_t asoc, uint32_t *life);

uint32_t sctp_get_number_of_associations(int);
uint32_t sctp_get_association_identifiers(int, sctp_assoc_t [], unsigned int);

int 
sctp_get_initmsg(int fd, 
		 uint32_t *ostreams,
		 uint32_t *istreams,
		 uint16_t *maxattempt,
		 uint16_t *max_init_timeo);

int 
sctp_set_initmsg(int fd, 
		 uint32_t ostreams,
		 uint32_t istreams,
		 uint16_t maxattempt,
		 uint16_t max_init_timeo);

int sctp_set_im_ostream(int fd, uint32_t ostream);
int sctp_set_im_istream(int fd, uint32_t istream);
int sctp_set_im_maxattempt(int fd, uint16_t max);
int sctp_set_im_maxtimeo(int fd, uint16_t timeo);
int sctp_get_ndelay(int fd, uint32_t *val);
int sctp_set_ndelay(int fd, uint32_t val);
int sctp_get_autoclose(int fd, uint32_t *val);
int sctp_set_autoclose(int fd, uint32_t val);

int sctp_set_peer_prim(int, sctp_assoc_t,  struct sockaddr *);


int sctp_set_primary(int, sctp_assoc_t, struct sockaddr *);
int sctp_get_primary(int, sctp_assoc_t, struct sockaddr *, socklen_t *len);

int sctp_set_adaptation( int fd, uint32_t val);
int sctp_get_adaptation( int fd, uint32_t *val);

int sctp_set_disfrag( int fd, int val);
int sctp_get_disfrag( int fd, int *val);

int sctp_get_paddr_param(int fd, sctp_assoc_t id, 
			 struct sockaddr *sa,
			 uint32_t *hbinterval,
			 uint16_t *maxrxt,
			 uint32_t *pathmtu,
			 uint32_t *flags,
			 uint32_t *ipv6_flowlabel,
			 uint8_t *ipv4_tos);

int sctp_set_paddr_param(int fd, sctp_assoc_t id, 
			 struct sockaddr *sa,
			 uint32_t hbinterval,
			 uint16_t maxrxt,
			 uint32_t pathmtu,
			 uint32_t flags,
			 uint32_t ipv6_flowlabel,
			 uint8_t ipv4_tos);



int
sctp_set_hbint(int fd, sctp_assoc_t id, 
	       struct sockaddr *sa,
	       uint32_t hbinterval);
int
sctp_set_hbdisable(int fd, sctp_assoc_t id, 
		   struct sockaddr *sa);

int
sctp_set_hbenable(int fd, sctp_assoc_t id, 
		   struct sockaddr *sa);

int
sctp_set_hbzero(int fd, sctp_assoc_t id, 
		struct sockaddr *sa);


int
sctp_set_maxrxt(int fd, sctp_assoc_t id, 
		struct sockaddr *sa,
		uint16_t maxrxt);

int
sctp_set_pmtu(int fd, sctp_assoc_t id, 
	      struct sockaddr *sa,
	      uint32_t pathmtu);
int
sctp_set_pmtu_enable(int fd, sctp_assoc_t id, 
		     struct sockaddr *sa);

int
sctp_set_flow(int fd, sctp_assoc_t id, 
	      struct sockaddr *sa,
	      uint32_t ipv6_flowlabel);

int
sctp_set_tos(int fd, sctp_assoc_t id, 
	     struct sockaddr *sa,
	     uint8_t ipv4_tos);

int sctp_get_defsend(int fd, sctp_assoc_t id, struct sctp_sndrcvinfo *s);
int sctp_set_defsend(int fd, sctp_assoc_t id, struct sctp_sndrcvinfo *s);


int sctp_set_maxseg(int fd, sctp_assoc_t id, int val);
int sctp_get_maxseg(int fd, sctp_assoc_t id, int *val);

int sctp_set_events(int fd, struct sctp_event_subscribe *ev);
int sctp_get_events(int fd, struct sctp_event_subscribe *ev);

int sctp_enable_v4_address_mapping(int);
int sctp_disable_v4_address_mapping(int);
int sctp_v4_address_mapping_enabled(int);

int sctp_enable_v6_only(int);
int sctp_v6_only_enabled(int);

int sctp_get_auth_chunk_id(int fd, uint8_t *fill);
int sctp_set_auth_chunk_id(int fd, uint8_t chk);

/********************************************************
 *
 * SCTP_KEY tests
 *
 ********************************************************/
int sctp_get_auth_key(int fd, sctp_assoc_t assoc_id, uint16_t *keyid,
		      uint16_t *keylen, uint8_t *keytext);
int sctp_set_auth_key(int fd, sctp_assoc_t assoc_id, uint16_t keyid,
		      uint16_t keylen, uint8_t *keytext);

int sctp_get_active_key(int fd, sctp_assoc_t assoc_id, uint16_t *keyid);
int sctp_set_active_key(int fd, sctp_assoc_t assoc_id, uint16_t keyid);

int sctp_get_delete_key(int fd, sctp_assoc_t assoc_id, uint16_t *keyid);
int sctp_set_delete_key(int fd, sctp_assoc_t assoc_id, uint16_t keyid);

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
int sctp_set_dsack(int fd, sctp_assoc_t id, uint32_t delay, uint32_t freq);
int sctp_get_dsack(int fd, sctp_assoc_t id,uint32_t *delay, uint32_t *freq);
int sctp_set_ddelay(int fd, sctp_assoc_t id, uint32_t delay);
int sctp_set_dfreq(int fd, sctp_assoc_t id, uint32_t freq);

/********************************************************
 *
 * SCTP_FRAGMENT_INTERLEAVE tests
 *
 ********************************************************/
int sctp_get_interleave(int fd, int *inter);
int sctp_set_interleave(int fd, int inter);

/********************************************************
 *
 * SCTP_PARTIAL_DELIVERY_POINT tests
 *
 ********************************************************/
int sctp_get_pdapi_point(int fd, int *point);
int sctp_set_pdapi_point(int fd, int point);


/********************************************************
 *
 * SCTP_CONTEXT tests
 *
 ********************************************************/
int sctp_set_context(int fd, sctp_assoc_t id, uint32_t context);
int sctp_get_context(int fd, sctp_assoc_t id, uint32_t *context);
