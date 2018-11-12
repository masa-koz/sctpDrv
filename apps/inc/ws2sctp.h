/*-
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
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
#ifndef WS2SCTP_INCLUDED
#define WS2SCTP_INCLUDED 1

#define IPPROTO_SCTP	132

#define MSG_EOR				0x0100	/* data completes record */
#define	MSG_NOTIFICATION		0x1000	/* SCTP notification */

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY			27
#endif

/* ==> The below definitions are based on netinet/sctp.h (Revision 1.115) */
/*
 * SCTP protocol - RFC2960.
 */
struct sctphdr {
	unsigned short src_port;	/* source port */
	unsigned short dest_port;	/* destination port */
	unsigned long v_tag;		/* verification tag of packet */
	unsigned long checksum;	/* Adler32 C-Sum */
	/* chunks follow... */
};

/*
 * SCTP Chunks
 */
struct sctp_chunkhdr {
	unsigned char chunk_type;	/* chunk type */
	unsigned char chunk_flags;	/* chunk flags */
	unsigned short chunk_length;	/* chunk length */
	/* optional params follow */
};

/*
 * SCTP chunk parameters
 */
struct sctp_paramhdr {
	unsigned short param_type;	/* parameter type */
	unsigned short param_length;	/* parameter length */
};

/*
 * user socket options: socket API defined
 */
/*
 * read-write options
 */
#define SCTP_RTOINFO			0x00000001
#define SCTP_ASSOCINFO			0x00000002
#define SCTP_INITMSG			0x00000003
#define SCTP_NODELAY			0x00000004
#define SCTP_AUTOCLOSE			0x00000005
#define SCTP_SET_PEER_PRIMARY_ADDR	0x00000006
#define SCTP_PRIMARY_ADDR		0x00000007
#define SCTP_ADAPTATION_LAYER		0x00000008
/* same as above */
#define SCTP_ADAPTION_LAYER		0x00000008
#define SCTP_DISABLE_FRAGMENTS		0x00000009
#define SCTP_PEER_ADDR_PARAMS 		0x0000000a
#define SCTP_DEFAULT_SEND_PARAM		0x0000000b
/* ancillary data/notification interest options */
#define SCTP_EVENTS			0x0000000c
/* Without this applied we will give V4 and V6 addresses on a V6 socket */
#define SCTP_I_WANT_MAPPED_V4_ADDR	0x0000000d
#define SCTP_MAXSEG 			0x0000000e
#define SCTP_DELAYED_SACK		0x0000000f
#define SCTP_FRAGMENT_INTERLEAVE	0x00000010
#define SCTP_PARTIAL_DELIVERY_POINT	0x00000011
/* authentication support */
#define SCTP_AUTH_CHUNK 		0x00000012
#define SCTP_AUTH_KEY 			0x00000013
#define SCTP_HMAC_IDENT 		0x00000014
#define SCTP_AUTH_ACTIVE_KEY 		0x00000015
#define SCTP_AUTH_DELETE_KEY 		0x00000016
#define SCTP_USE_EXT_RCVINFO		0x00000017
#define SCTP_AUTO_ASCONF		0x00000018 /* rw */
#define SCTP_MAXBURST			0x00000019 /* rw */
#define SCTP_MAX_BURST			0x00000019 /* rw */
/* assoc level context */
#define SCTP_CONTEXT			0x0000001a /* rw */
/* explict EOR signalling */
#define SCTP_EXPLICIT_EOR		0x0000001b
#define SCTP_REUSE_PORT			0x0000001c /* rw */
#define SCTP_AUTH_DEACTIVATE_KEY	0x0000001d

/*
 * read-only options
 */
#define SCTP_STATUS			0x00000100
#define SCTP_GET_PEER_ADDR_INFO		0x00000101
/* authentication support */
#define SCTP_PEER_AUTH_CHUNKS		0x00000102
#define SCTP_LOCAL_AUTH_CHUNKS		0x00000103
#define SCTP_GET_ASSOC_NUMBER		0x00000104 /* ro */
#define SCTP_GET_ASSOC_ID_LIST		0x00000105 /* ro */

/*
 * user socket options: BSD implementation specific
 */
/*
 * Blocking I/O is enabled on any TCP type socket by default. For the UDP
 * model if this is turned on then the socket buffer is shared for send
 * resources amongst all associations.  The default for the UDP model is that
 * is SS_NBIO is set.  Which means all associations have a seperate send
 * limit BUT they will NOT ever BLOCK instead you will get an error back
 * EAGAIN if you try to send to much. If you want the blocking symantics you
 * set this option at the cost of sharing one socket send buffer size amongst
 * all associations. Peeled off sockets turn this option off and block. But
 * since both TCP and peeled off sockets have only one assoc per socket this
 * is fine. It probably does NOT make sense to set this on SS_NBIO on a TCP
 * model OR peeled off UDP model, but we do allow you to do so. You just use
 * the normal syscall to toggle SS_NBIO the way you want.
 *
 * Blocking I/O is controled by the SS_NBIO flag on the socket state so_state
 * field.
 */

/* these should probably go into sockets API */
#define SCTP_RESET_STREAMS		0x00001004 /* wo */


/* here on down are more implementation specific */
#define SCTP_SET_DEBUG_LEVEL		0x00001005
#define SCTP_CLR_STAT_LOG		0x00001007
/* CMT ON/OFF socket option */
#define SCTP_CMT_ON_OFF			0x00001200
#define SCTP_CMT_USE_DAC		0x00001201
/* EY - NR_SACK on/off socket option */
#define SCTP_NR_SACK_ON_OFF		0x00001300
/* JRS - Pluggable Congestion Control Socket option */
#define SCTP_PLUGGABLE_CC		0x00001202

/* read only */
#define SCTP_GET_SNDBUF_USE		0x00001101
#define SCTP_GET_STAT_LOG		0x00001103
#define SCTP_PCB_STATUS			0x00001104
#define SCTP_GET_NONCE_VALUES		0x00001105


/* Special hook for dynamically setting primary for all assoc's,
 * this is a write only option that requires root privledge.
 */
#define SCTP_SET_DYNAMIC_PRIMARY	0x00002001

/* VRF (virtual router feature) and multi-VRF support 
 * options. VRF's provide splits within a router
 * that give the views of multiple routers. A
 * standard host, without VRF support, is just
 * a single VRF. If VRF's are supported then 
 * the transport must be VRF aware. This means
 * that every socket call coming in must be directed
 * within the endpoint to one of the VRF's it belongs
 * to. The endpoint, before binding, may select
 * the "default" VRF it is in by using a set socket 
 * option with SCTP_VRF_ID. This will also
 * get propegated to the default VRF. Once the
 * endpoint binds an address then it CANNOT add
 * additional VRF's to become a Multi-VRF endpoint.
 *
 * Before BINDING additional VRF's can be added with
 * the SCTP_ADD_VRF_ID call or deleted with
 * SCTP_DEL_VRF_ID.
 *
 * Associations are ALWAYS contained inside a single
 * VRF. They cannot reside in two (or more) VRF's. Incoming
 * packets, assuming the router is VRF aware, can always
 * tell us what VRF they arrived on. A host not supporting
 * any VRF's will find that the packets always arrived on the
 * single VRF that the host has. 
 *
 */

#define SCTP_VRF_ID			0x00003001
#define SCTP_ADD_VRF_ID			0x00003002
#define SCTP_GET_VRF_IDS		0x00003003
#define SCTP_GET_ASOC_VRF		0x00003004
#define SCTP_DEL_VRF_ID			0x00003005

/* 
 * If you enable packet logging you can get
 * a poor mans ethereal output in binary
 * form. Note this is a compile option to
 * the kernel,  SCTP_PACKET_LOGGING, and
 * without it in your kernel you
 * will get a EOPNOTSUPP
 */
#define SCTP_GET_PACKET_LOG		0x00004001

/* sctp_bindx() flags as hidden socket options */
#define SCTP_BINDX_ADD_ADDR		0x00008001
#define SCTP_BINDX_REM_ADDR		0x00008002

/* JRS - Supported congestion control modules for pluggable
 * congestion control
 */
/* Standard TCP Congestion Control */
#define SCTP_CC_RFC2581			0x00000000
/* High Speed TCP Congestion Control (Floyd) */
#define SCTP_CC_HSTCP			0x00000001
/* HTCP Congestion Control */
#define SCTP_CC_HTCP			0x00000002


/* fragment interleave constants 
 * setting must be one of these or
 * EINVAL returned.
 */
#define SCTP_FRAG_LEVEL_0		0x00000000
#define SCTP_FRAG_LEVEL_1		0x00000001
#define SCTP_FRAG_LEVEL_2		0x00000002

/*
 * user state values
 */
#define SCTP_CLOSED			0x0000
#define SCTP_BOUND			0x1000
#define SCTP_LISTEN			0x2000
#define SCTP_COOKIE_WAIT		0x0002
#define SCTP_COOKIE_ECHOED		0x0004
#define SCTP_ESTABLISHED		0x0008
#define SCTP_SHUTDOWN_SENT		0x0010
#define SCTP_SHUTDOWN_RECEIVED		0x0020
#define SCTP_SHUTDOWN_ACK_SENT		0x0040
#define SCTP_SHUTDOWN_PENDING		0x0080

/*
 * SCTP operational error codes (user visible)
 */
#define SCTP_CAUSE_NO_ERROR		0x0000
#define SCTP_CAUSE_INVALID_STREAM	0x0001
#define SCTP_CAUSE_MISSING_PARAM	0x0002
#define SCTP_CAUSE_STALE_COOKIE		0x0003
#define SCTP_CAUSE_OUT_OF_RESC		0x0004
#define SCTP_CAUSE_UNRESOLVABLE_ADDR	0x0005
#define SCTP_CAUSE_UNRECOG_CHUNK	0x0006
#define SCTP_CAUSE_INVALID_PARAM	0x0007
#define SCTP_CAUSE_UNRECOG_PARAM	0x0008
#define SCTP_CAUSE_NO_USER_DATA		0x0009
#define SCTP_CAUSE_COOKIE_IN_SHUTDOWN	0x000a
#define SCTP_CAUSE_RESTART_W_NEWADDR	0x000b
#define SCTP_CAUSE_USER_INITIATED_ABT	0x000c
#define SCTP_CAUSE_PROTOCOL_VIOLATION	0x000d

/* Error causes from RFC5061 */
#define SCTP_CAUSE_DELETING_LAST_ADDR	0x00a0
#define SCTP_CAUSE_RESOURCE_SHORTAGE	0x00a1
#define SCTP_CAUSE_DELETING_SRC_ADDR	0x00a2
#define SCTP_CAUSE_ILLEGAL_ASCONF_ACK	0x00a3
#define SCTP_CAUSE_REQUEST_REFUSED	0x00a4

/* Error causes from nat-draft */
#define SCTP_CAUSE_NAT_COLLIDING_STATE  0x00b0
#define SCTP_CAUSE_NAT_MISSING_STATE    0x00b1

/* Error causes from RFC4895 */
#define SCTP_CAUSE_UNSUPPORTED_HMACID	0x0105

/*
 * error cause parameters (user visisble)
 */
struct sctp_error_cause {
	unsigned short code;
	unsigned short length;
	/* optional cause-specific info may follow */
};

struct sctp_error_invalid_stream {
	struct sctp_error_cause cause;	/* code=SCTP_ERROR_INVALID_STREAM */
	unsigned short stream_id;	/* stream id of the DATA in error */
	unsigned short reserved;
};

struct sctp_error_missing_param {
	struct sctp_error_cause cause;	/* code=SCTP_ERROR_MISSING_PARAM */
	unsigned long num_missing_params;	/* number of missing parameters */
	/* unsigned short param_type's follow */
};

struct sctp_error_stale_cookie {
	struct sctp_error_cause cause;	/* code=SCTP_ERROR_STALE_COOKIE */
	unsigned long stale_time;	/* time in usec of staleness */
};

struct sctp_error_out_of_resource {
	struct sctp_error_cause cause;	/* code=SCTP_ERROR_OUT_OF_RESOURCES */
};

struct sctp_error_unresolv_addr {
	struct sctp_error_cause cause;	/* code=SCTP_ERROR_UNRESOLVABLE_ADDR */

};

struct sctp_error_unrecognized_chunk {
	struct sctp_error_cause cause;	/* code=SCTP_ERROR_UNRECOG_CHUNK */
	struct sctp_chunkhdr ch;/* header from chunk in error */
};

/*
 * Main SCTP chunk types we place these here so natd and f/w's in user land
 * can find them.
 */
/************0x00 series ***********/
#define SCTP_DATA			0x00
#define SCTP_INITIATION			0x01
#define SCTP_INITIATION_ACK		0x02
#define SCTP_SELECTIVE_ACK		0x03
#define SCTP_HEARTBEAT_REQUEST		0x04
#define SCTP_HEARTBEAT_ACK		0x05
#define SCTP_ABORT_ASSOCIATION		0x06
#define SCTP_SHUTDOWN			0x07
#define SCTP_SHUTDOWN_ACK		0x08
#define SCTP_OPERATION_ERROR		0x09
#define SCTP_COOKIE_ECHO		0x0a
#define SCTP_COOKIE_ACK			0x0b
#define SCTP_ECN_ECHO			0x0c
#define SCTP_ECN_CWR			0x0d
#define SCTP_SHUTDOWN_COMPLETE		0x0e
/* RFC4895 */
#define SCTP_AUTHENTICATION     	0x0f
/* EY nr_sack chunk id*/
#define SCTP_NR_SELECTIVE_ACK		0x10
/************0x40 series ***********/
/************0x80 series ***********/
/* RFC5061 */
#define	SCTP_ASCONF_ACK			0x80
/* draft-ietf-stewart-pktdrpsctp */
#define SCTP_PACKET_DROPPED		0x81
/* draft-ietf-stewart-strreset-xxx */
#define SCTP_STREAM_RESET       	0x82

/* RFC4820                         */
#define SCTP_PAD_CHUNK          	0x84
/************0xc0 series ***********/
/* RFC3758 */
#define SCTP_FORWARD_CUM_TSN		0xc0
/* RFC5061 */
#define SCTP_ASCONF			0xc1
/* <== The above definitions are based on netinet/sctp.h (Revision 1.115) */

/* ==> The below definitions are based on netinet/sctp_uio.h (Revision 1.209) */
typedef unsigned long sctp_assoc_t;

/* On/Off setup for subscription to events */
struct sctp_event_subscribe {
	unsigned char sctp_data_io_event;
	unsigned char sctp_association_event;
	unsigned char sctp_address_event;
	unsigned char sctp_send_failure_event;
	unsigned char sctp_peer_error_event;
	unsigned char sctp_shutdown_event;
	unsigned char sctp_partial_delivery_event;
	unsigned char sctp_adaptation_layer_event;
	unsigned char sctp_authentication_event;
	unsigned char sctp_sender_dry_event;
	unsigned char sctp_stream_reset_events;
};

/* ancillary data types */
#define SCTP_INIT	0x0001
#define SCTP_SNDRCV	0x0002
#define SCTP_EXTRCV	0x0003
/*
 * ancillary data structures
 */
struct sctp_initmsg {
	unsigned long sinit_num_ostreams;
	unsigned long sinit_max_instreams;
	unsigned short sinit_max_attempts;
	unsigned short sinit_max_init_timeo;
};

/* We add 96 bytes to the size of sctp_sndrcvinfo.
 * This makes the current structure 128 bytes long
 * which is nicely 64 bit aligned but also has room
 * for us to add more and keep ABI compatability.
 * For example, already we have the sctp_extrcvinfo
 * when enabled which is 48 bytes.
 */

/*
 * The assoc up needs a verfid
 * all sendrcvinfo's need a verfid for SENDING only.
 */


#define SCTP_ALIGN_RESV_PAD 96
#define SCTP_ALIGN_RESV_PAD_SHORT 80

struct sctp_sndrcvinfo {
	unsigned short sinfo_stream;
	unsigned short sinfo_ssn;
	unsigned short sinfo_flags;
	unsigned short sinfo_pr_policy;
	unsigned long sinfo_ppid;
	unsigned long sinfo_context;
	unsigned long sinfo_timetolive;
	unsigned long sinfo_tsn;
	unsigned long sinfo_cumtsn;
	sctp_assoc_t sinfo_assoc_id;
	unsigned char  __reserve_pad[SCTP_ALIGN_RESV_PAD];
};

struct sctp_extrcvinfo {
	unsigned short sinfo_stream;
	unsigned short sinfo_ssn;
	unsigned short sinfo_flags;
	unsigned short sinfo_pr_policy;
	unsigned long sinfo_ppid;
	unsigned long sinfo_context;
	unsigned long sinfo_timetolive;
	unsigned long sinfo_tsn;
	unsigned long sinfo_cumtsn;
	sctp_assoc_t sinfo_assoc_id;
	unsigned short sreinfo_next_flags;
	unsigned short sreinfo_next_stream; 
	unsigned long sreinfo_next_aid;
	unsigned long sreinfo_next_length;
	unsigned long sreinfo_next_ppid;
	unsigned char  __reserve_pad[SCTP_ALIGN_RESV_PAD_SHORT];
};

#define SCTP_NO_NEXT_MSG           0x0000
#define SCTP_NEXT_MSG_AVAIL        0x0001
#define SCTP_NEXT_MSG_ISCOMPLETE   0x0002
#define SCTP_NEXT_MSG_IS_UNORDERED 0x0004
#define SCTP_NEXT_MSG_IS_NOTIFICATION 0x0008

struct sctp_snd_all_completes {
	unsigned short sall_stream;
	unsigned short sall_flags;
	unsigned long sall_ppid;
	unsigned long sall_context;
	unsigned long sall_num_sent;
	unsigned long sall_num_failed;
};

/* Flags that go into the sinfo->sinfo_flags field */
#define SCTP_EOF			0x0100 /* Start shutdown procedures */
#define SCTP_ABORT			0x0200 /* Send an ABORT to peer */
#define SCTP_UNORDERED			0x0400 /* Message is un-ordered */
#define SCTP_ADDR_OVER			0x0800 /* Override the primary-address */
#define SCTP_SENDALL			0x1000 /* Send this on all associations */
#define SCTP_EOR			0x2000 /* end of message signal */
#define SCTP_SACK_IMMEDIATELY	0x4000 /* Set I-Bit */

#define INVALID_SINFO_FLAG(x) (((x) & 0xffffff00 \
                                    & ~(SCTP_EOF | SCTP_ABORT | SCTP_UNORDERED |\
				       SCTP_ADDR_OVER | SCTP_SENDALL | SCTP_EOR |\
				       SCTP_SACK_IMMEDIATELY)) != 0)
/* for the endpoint */

/* The lower byte is an enumeration of PR-SCTP policies */
#define SCTP_PR_SCTP_TTL  0x0001/* Time based PR-SCTP */
#define SCTP_PR_SCTP_BUF  0x0002/* Buffer based PR-SCTP */
#define SCTP_PR_SCTP_RTX  0x0003/* Number of retransmissions based PR-SCTP */

#define PR_SCTP_POLICY(x)         ((x) & 0xff)
#define PR_SCTP_ENABLED(x)        (PR_SCTP_POLICY(x) != 0)
#define PR_SCTP_TTL_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_TTL)
#define PR_SCTP_BUF_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_BUF)
#define PR_SCTP_RTX_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_RTX)
#define PR_SCTP_INVALID_POLICY(x) (PR_SCTP_POLICY(x) > SCTP_PR_SCTP_RTX)
/* Stat's */
struct sctp_pcbinfo {
	unsigned long ep_count;
	unsigned long asoc_count;
	unsigned long laddr_count;
	unsigned long raddr_count;
	unsigned long chk_count;
	unsigned long readq_count;
	unsigned long free_chunks;
	unsigned long stream_oque;
};

struct sctp_sockstat {
	sctp_assoc_t ss_assoc_id;
	unsigned long ss_total_sndbuf;
	unsigned long ss_total_recv_buf;
};

/*
 * notification event structures
 */

/*
 * association change event
 */
struct sctp_assoc_change {
	unsigned short sac_type;
	unsigned short sac_flags;
	unsigned long sac_length;
	unsigned short sac_state;
	unsigned short sac_error;
	unsigned short sac_outbound_streams;
	unsigned short sac_inbound_streams;
	sctp_assoc_t sac_assoc_id;
};

/* sac_state values */
#define SCTP_COMM_UP		0x0001
#define SCTP_COMM_LOST		0x0002
#define SCTP_RESTART		0x0003
#define SCTP_SHUTDOWN_COMP	0x0004
#define SCTP_CANT_STR_ASSOC	0x0005


/*
 * Address event
 */
struct sctp_paddr_change {
	unsigned short spc_type;
	unsigned short spc_flags;
	unsigned long spc_length;
	struct sockaddr_storage spc_aaddr;
	unsigned long spc_state;
	unsigned long spc_error;
	sctp_assoc_t spc_assoc_id;
	unsigned char spc_padding[4];
};

/* paddr state values */
#define SCTP_ADDR_AVAILABLE	0x0001
#define SCTP_ADDR_UNREACHABLE	0x0002
#define SCTP_ADDR_REMOVED	0x0003
#define SCTP_ADDR_ADDED		0x0004
#define SCTP_ADDR_MADE_PRIM	0x0005
#define SCTP_ADDR_CONFIRMED	0x0006

/*
 * CAUTION: these are user exposed SCTP addr reachability states must be
 * compatible with SCTP_ADDR states in sctp_constants.h
 */
#ifdef SCTP_ACTIVE
#undef SCTP_ACTIVE
#endif
#define SCTP_ACTIVE		0x0001	/* SCTP_ADDR_REACHABLE */

#ifdef SCTP_INACTIVE
#undef SCTP_INACTIVE
#endif
#define SCTP_INACTIVE		0x0002	/* SCTP_ADDR_NOT_REACHABLE */

#ifdef SCTP_UNCONFIRMED
#undef SCTP_UNCONFIRMED
#endif
#define SCTP_UNCONFIRMED	0x0200	/* SCTP_ADDR_UNCONFIRMED */

#ifdef SCTP_NOHEARTBEAT
#undef SCTP_NOHEARTBEAT
#endif
#define SCTP_NOHEARTBEAT	0x0040	/* SCTP_ADDR_NOHB */


/* remote error events */
struct sctp_remote_error {
	unsigned short sre_type;
	unsigned short sre_flags;
	unsigned long sre_length;
	unsigned short sre_error;
	sctp_assoc_t sre_assoc_id;
	unsigned char sre_data[4];
};

/* data send failure event */
struct sctp_send_failed {
	unsigned short ssf_type;
	unsigned short ssf_flags;
	unsigned long ssf_length;
	unsigned long ssf_error;
	struct sctp_sndrcvinfo ssf_info;
	sctp_assoc_t ssf_assoc_id;
	unsigned char ssf_data[0];
};

/* flag that indicates state of data */
#define SCTP_DATA_UNSENT	0x0001	/* inqueue never on wire */
#define SCTP_DATA_SENT		0x0002	/* on wire at failure */

/* shutdown event */
struct sctp_shutdown_event {
	unsigned short sse_type;
	unsigned short sse_flags;
	unsigned long sse_length;
	sctp_assoc_t sse_assoc_id;
};

/* Adaptation layer indication stuff */
struct sctp_adaptation_event {
	unsigned short sai_type;
	unsigned short sai_flags;
	unsigned long sai_length;
	unsigned long sai_adaptation_ind;
	sctp_assoc_t sai_assoc_id;
};

struct sctp_setadaptation {
	unsigned long ssb_adaptation_ind;
};

/* compatable old spelling */
struct sctp_adaption_event {
	unsigned short sai_type;
	unsigned short sai_flags;
	unsigned long sai_length;
	unsigned long sai_adaption_ind;
	sctp_assoc_t sai_assoc_id;
};

struct sctp_setadaption {
	unsigned long ssb_adaption_ind;
};


/*
 * Partial Delivery API event
 */
struct sctp_pdapi_event {
	unsigned short pdapi_type;
	unsigned short pdapi_flags;
	unsigned long pdapi_length;
	unsigned long pdapi_indication;
	unsigned short pdapi_stream;
	unsigned short pdapi_seq;
	sctp_assoc_t pdapi_assoc_id;
};

/* indication values */
#define SCTP_PARTIAL_DELIVERY_ABORTED	0x0001


/*
 * authentication key event
 */
struct sctp_authkey_event {
	unsigned short auth_type;
	unsigned short auth_flags;
	unsigned long auth_length;
	unsigned short auth_keynumber;
	unsigned short auth_altkeynumber;
	unsigned long auth_indication;
	sctp_assoc_t auth_assoc_id;
};

/* indication values */
#define SCTP_AUTH_NEWKEY	0x0001
#define SCTP_AUTH_NO_AUTH	0x0002
#define SCTP_AUTH_FREE_KEY	0x0003


struct sctp_sender_dry_event {
	unsigned short sender_dry_type;
	unsigned short sender_dry_flags;
	unsigned long sender_dry_length;
	sctp_assoc_t sender_dry_assoc_id;
};


/*
 * stream reset event
 */
struct sctp_stream_reset_event {
	unsigned short strreset_type;
	unsigned short strreset_flags;
	unsigned long strreset_length;
	sctp_assoc_t strreset_assoc_id;
	unsigned short strreset_list[0];
};

/* flags in strreset_flags field */
#define SCTP_STRRESET_INBOUND_STR  0x0001
#define SCTP_STRRESET_OUTBOUND_STR 0x0002
#define SCTP_STRRESET_ALL_STREAMS  0x0004
#define SCTP_STRRESET_STREAM_LIST  0x0008
#define SCTP_STRRESET_FAILED       0x0010


/* SCTP notification event */
struct sctp_tlv {
	unsigned short sn_type;
	unsigned short sn_flags;
	unsigned long sn_length;
};

union sctp_notification {
	struct sctp_tlv sn_header;
	struct sctp_assoc_change sn_assoc_change;
	struct sctp_paddr_change sn_paddr_change;
	struct sctp_remote_error sn_remote_error;
	struct sctp_send_failed sn_send_failed;
	struct sctp_shutdown_event sn_shutdown_event;
	struct sctp_adaptation_event sn_adaptation_event;
	/* compatability same as above */
	struct sctp_adaption_event sn_adaption_event;
	struct sctp_pdapi_event sn_pdapi_event;
	struct sctp_authkey_event sn_auth_event;
	struct sctp_sender_dry_event sn_sender_dry_event;
	struct sctp_stream_reset_event sn_strreset_event;
};

/* notification types */
#define SCTP_ASSOC_CHANGE		0x0001
#define SCTP_PEER_ADDR_CHANGE		0x0002
#define SCTP_REMOTE_ERROR		0x0003
#define SCTP_SEND_FAILED		0x0004
#define SCTP_SHUTDOWN_EVENT		0x0005
#define SCTP_ADAPTATION_INDICATION	0x0006
/* same as above */
#define SCTP_ADAPTION_INDICATION	0x0006
#define SCTP_PARTIAL_DELIVERY_EVENT	0x0007
#define SCTP_AUTHENTICATION_EVENT	0x0008
#define SCTP_STREAM_RESET_EVENT		0x0009
#define SCTP_SENDER_DRY_EVENT		0x000a


/*
 * socket option structs
 */

struct sctp_paddrparams {
	struct sockaddr_storage spp_address;
	sctp_assoc_t spp_assoc_id;
	unsigned long spp_hbinterval;
	unsigned long spp_pathmtu;
	unsigned long spp_flags;
	unsigned long spp_ipv6_flowlabel;
	unsigned short spp_pathmaxrxt;
	unsigned char spp_ipv4_tos;
};

#define SPP_HB_ENABLE		0x00000001
#define SPP_HB_DISABLE		0x00000002
#define SPP_HB_DEMAND		0x00000004
#define SPP_PMTUD_ENABLE	0x00000008
#define SPP_PMTUD_DISABLE	0x00000010
#define SPP_HB_TIME_IS_ZERO     0x00000080
#define SPP_IPV6_FLOWLABEL      0x00000100
#define SPP_IPV4_TOS            0x00000200

struct sctp_paddrinfo {
	struct sockaddr_storage spinfo_address;
	sctp_assoc_t spinfo_assoc_id;
	long spinfo_state;
	unsigned long spinfo_cwnd;
	unsigned long spinfo_srtt;
	unsigned long spinfo_rto;
	unsigned long spinfo_mtu;
};

struct sctp_rtoinfo {
	sctp_assoc_t srto_assoc_id;
	unsigned long srto_initial;
	unsigned long srto_max;
	unsigned long srto_min;
};

struct sctp_assocparams {
	sctp_assoc_t sasoc_assoc_id;
	unsigned long sasoc_peer_rwnd;
	unsigned long sasoc_local_rwnd;
	unsigned long sasoc_cookie_life;
	unsigned short sasoc_asocmaxrxt;
	unsigned short sasoc_number_peer_destinations;
};

struct sctp_setprim {
	struct sockaddr_storage ssp_addr;
	sctp_assoc_t ssp_assoc_id;
	unsigned char ssp_padding[4];
};

struct sctp_setpeerprim {
	struct sockaddr_storage sspp_addr;
	sctp_assoc_t sspp_assoc_id;
	unsigned char sspp_padding[4];
};

struct sctp_getaddresses {
	sctp_assoc_t sget_assoc_id;
	/* addr is filled in for N * sockaddr_storage */
	struct sockaddr addr[1];
};

struct sctp_setstrm_timeout {
	sctp_assoc_t ssto_assoc_id;
	unsigned long ssto_timeout;
	unsigned long ssto_streamid_start;
	unsigned long ssto_streamid_end;
};

struct sctp_status {
	sctp_assoc_t sstat_assoc_id;
	long sstat_state;
	unsigned long sstat_rwnd;
	unsigned short sstat_unackdata;
	unsigned short sstat_penddata;
	unsigned short sstat_instrms;
	unsigned short sstat_outstrms;
	unsigned long sstat_fragmentation_point;
	struct sctp_paddrinfo sstat_primary;
};

/*
 * AUTHENTICATION support
 */
/* SCTP_AUTH_CHUNK */
struct sctp_authchunk {
	unsigned char sauth_chunk;
};

/* SCTP_AUTH_KEY */
struct sctp_authkey {
	sctp_assoc_t sca_assoc_id;
	unsigned short sca_keynumber;
	unsigned char sca_key[0];
};

/* SCTP_HMAC_IDENT */
struct sctp_hmacalgo {
	unsigned long shmac_number_of_idents;
	unsigned short shmac_idents[0];
};

/* AUTH hmac_id */
#define SCTP_AUTH_HMAC_ID_RSVD		0x0000
#define SCTP_AUTH_HMAC_ID_SHA1		0x0001	/* default, mandatory */
#define SCTP_AUTH_HMAC_ID_MD5		0x0002	/* deprecated */
#define SCTP_AUTH_HMAC_ID_SHA256	0x0003
#define SCTP_AUTH_HMAC_ID_SHA224	0x0004
#define SCTP_AUTH_HMAC_ID_SHA384	0x0005
#define SCTP_AUTH_HMAC_ID_SHA512	0x0006


/* SCTP_AUTH_ACTIVE_KEY / SCTP_AUTH_DELETE_KEY */
struct sctp_authkeyid {
	sctp_assoc_t scact_assoc_id;
	unsigned short scact_keynumber;
};

/* SCTP_PEER_AUTH_CHUNKS / SCTP_LOCAL_AUTH_CHUNKS */
struct sctp_authchunks {
	sctp_assoc_t gauth_assoc_id;
	unsigned char gauth_chunks[0];
};

struct sctp_assoc_value {
	sctp_assoc_t assoc_id;
	unsigned long assoc_value;
};

struct sctp_assoc_ids {
	unsigned long gaids_number_of_ids;
	sctp_assoc_t gaids_assoc_id[0];
};

struct sctp_sack_info {
	sctp_assoc_t sack_assoc_id;
	unsigned long sack_delay;
	unsigned long sack_freq;
};

struct sctp_cwnd_args {
	struct sctp_nets *net;	/* network to */ /* FIXME: LP64 issue */
	unsigned long cwnd_new_value;/* cwnd in k */
	unsigned long inflight;	/* flightsize in k */
	unsigned long pseudo_cumack;
	unsigned long cwnd_augment;	/* increment to it */
	unsigned char meets_pseudo_cumack;
	unsigned char need_new_pseudo_cumack;
	unsigned char cnt_in_send;
	unsigned char cnt_in_str;
};

struct sctp_blk_args {
	unsigned long onsb;		/* in 1k bytes */
	unsigned long sndlen;	/* len of send being attempted */
	unsigned long peer_rwnd;	/* rwnd of peer */
	unsigned short send_sent_qcnt;/* chnk cnt */
	unsigned short stream_qcnt;	/* chnk cnt */
	unsigned short chunks_on_oque;/* chunks out */
	unsigned short flight_size;   /* flight size in k */
};

/*
 * Max we can reset in one setting, note this is dictated not by the define
 * but the size of a mbuf cluster so don't change this define and think you
 * can specify more. You must do multiple resets if you want to reset more
 * than SCTP_MAX_EXPLICIT_STR_RESET.
 */
#define SCTP_MAX_EXPLICT_STR_RESET   1000

#define SCTP_RESET_LOCAL_RECV  0x0001
#define SCTP_RESET_LOCAL_SEND  0x0002
#define SCTP_RESET_BOTH        0x0003
#define SCTP_RESET_TSN         0x0004

struct sctp_stream_reset {
	sctp_assoc_t strrst_assoc_id;
	unsigned short strrst_flags;
	unsigned short strrst_num_streams;	/* 0 == ALL */
	unsigned short strrst_list[0];/* list if strrst_num_streams is not 0 */
};


struct sctp_get_nonce_values {
	sctp_assoc_t gn_assoc_id;
	unsigned long gn_peers_tag;
	unsigned long gn_local_tag;
};

/* Debugging logs */
struct sctp_str_log {
	void *stcb; /* FIXME: LP64 issue */
	unsigned long n_tsn;
	unsigned long e_tsn;
	unsigned short n_sseq;
	unsigned short e_sseq;
	unsigned short strm;
};

struct sctp_sb_log {
	void  *stcb; /* FIXME: LP64 issue */
	unsigned long so_sbcc;
	unsigned long stcb_sbcc;
	unsigned long incr;
};

struct sctp_fr_log {
	unsigned long largest_tsn;
	unsigned long largest_new_tsn;
	unsigned long tsn;
};

struct sctp_fr_map {
	unsigned long base;
	unsigned long cum;
	unsigned long high;
};

struct sctp_rwnd_log {
	unsigned long rwnd;
	unsigned long send_size;
	unsigned long overhead;
	unsigned long new_rwnd;
};

struct sctp_mbcnt_log {
	unsigned long total_queue_size;
	unsigned long size_change;
	unsigned long total_queue_mb_size;
	unsigned long mbcnt_change;
};

struct sctp_sack_log {
	unsigned long cumack;
	unsigned long oldcumack;
	unsigned long tsn;
	unsigned short numGaps;
	unsigned short numDups;
};

struct sctp_lock_log {
	void *sock;  /* FIXME: LP64 issue */
	void *inp; /* FIXME: LP64 issue */
	unsigned char tcb_lock;
	unsigned char inp_lock;
	unsigned char info_lock;
	unsigned char sock_lock;
	unsigned char sockrcvbuf_lock;
	unsigned char socksndbuf_lock;
	unsigned char create_lock;
	unsigned char resv;
};

struct sctp_rto_log {
	void * net; /* FIXME: LP64 issue */
	unsigned long rtt;
};

struct sctp_nagle_log {
	void  *stcb; /* FIXME: LP64 issue */
	unsigned long total_flight;
	unsigned long total_in_queue;
	unsigned short count_in_queue;
	unsigned short count_in_flight;
};

struct sctp_sbwake_log {
	void *stcb; /* FIXME: LP64 issue */
	unsigned short send_q;
	unsigned short sent_q;
	unsigned short flight;
	unsigned short wake_cnt;
	unsigned char stream_qcnt;	/* chnk cnt */
	unsigned char chunks_on_oque;/* chunks out */
	unsigned char sbflags;
	unsigned char sctpflags;
};

struct sctp_misc_info {
	unsigned long log1;
	unsigned long log2;
	unsigned long log3;
	unsigned long log4;
};

struct sctp_log_closing {
	void *inp; /* FIXME: LP64 issue */
	void *stcb;  /* FIXME: LP64 issue */
	unsigned long sctp_flags;
	unsigned short  state;
	short  loc;
};

struct sctp_mbuf_log {
	void *mp; /* FIXME: LP64 issue */
	unsigned char *ext;
	unsigned char *data;
	unsigned short size;
	unsigned char  refcnt;
	unsigned char  mbuf_flags;
};

struct sctp_cwnd_log {
	unsigned long long time_event;
	unsigned char  from;
	unsigned char  event_type;
	unsigned char  resv[2];
	union {
		struct sctp_log_closing close;
		struct sctp_blk_args blk;
		struct sctp_cwnd_args cwnd;
		struct sctp_str_log strlog;
		struct sctp_fr_log fr;
		struct sctp_fr_map map;
		struct sctp_rwnd_log rwnd;
		struct sctp_mbcnt_log mbcnt;
		struct sctp_sack_log sack;
		struct sctp_lock_log lock;
		struct sctp_rto_log rto;
		struct sctp_sb_log sb;
		struct sctp_nagle_log nagle;
		struct sctp_sbwake_log wake;
		struct sctp_mbuf_log mb;
		struct sctp_misc_info misc;
	}     x;
};

struct sctp_cwnd_log_req {
	long num_in_log;		/* Number in log */
	long num_ret;		/* Number returned */
	long start_at;		/* start at this one */
	long end_at;		        /* end at this one */
	struct sctp_cwnd_log log[0];
};

struct sctp_timeval {
	unsigned long tv_sec;
	unsigned long tv_usec;
};

struct sctpstat {
	/* MIB according to RFC 3873 */
	unsigned long  sctps_currestab;           /* sctpStats  1   (Gauge32) */
	unsigned long  sctps_activeestab;         /* sctpStats  2 (Counter32) */
	unsigned long  sctps_restartestab;
	unsigned long  sctps_collisionestab;
	unsigned long  sctps_passiveestab;        /* sctpStats  3 (Counter32) */
	unsigned long  sctps_aborted;             /* sctpStats  4 (Counter32) */
	unsigned long  sctps_shutdown;            /* sctpStats  5 (Counter32) */
	unsigned long  sctps_outoftheblue;        /* sctpStats  6 (Counter32) */
	unsigned long  sctps_checksumerrors;      /* sctpStats  7 (Counter32) */
	unsigned long  sctps_outcontrolchunks;    /* sctpStats  8 (Counter64) */
	unsigned long  sctps_outorderchunks;      /* sctpStats  9 (Counter64) */
	unsigned long  sctps_outunorderchunks;    /* sctpStats 10 (Counter64) */
	unsigned long  sctps_incontrolchunks;     /* sctpStats 11 (Counter64) */
	unsigned long  sctps_inorderchunks;       /* sctpStats 12 (Counter64) */
	unsigned long  sctps_inunorderchunks;     /* sctpStats 13 (Counter64) */
	unsigned long  sctps_fragusrmsgs;         /* sctpStats 14 (Counter64) */
	unsigned long  sctps_reasmusrmsgs;        /* sctpStats 15 (Counter64) */
	unsigned long  sctps_outpackets;          /* sctpStats 16 (Counter64) */
	unsigned long  sctps_inpackets;           /* sctpStats 17 (Counter64) */

	/* input statistics: */
	unsigned long  sctps_recvpackets;         /* total input packets        */
	unsigned long  sctps_recvdatagrams;       /* total input datagrams      */
	unsigned long  sctps_recvpktwithdata;     /* total packets that had data */
	unsigned long  sctps_recvsacks;           /* total input SACK chunks    */
	unsigned long  sctps_recvdata;            /* total input DATA chunks    */
	unsigned long  sctps_recvdupdata;         /* total input duplicate DATA chunks */
	unsigned long  sctps_recvheartbeat;       /* total input HB chunks      */
	unsigned long  sctps_recvheartbeatack;    /* total input HB-ACK chunks  */
	unsigned long  sctps_recvecne;            /* total input ECNE chunks    */
	unsigned long  sctps_recvauth;            /* total input AUTH chunks    */
	unsigned long  sctps_recvauthmissing;     /* total input chunks missing AUTH */
	unsigned long  sctps_recvivalhmacid;      /* total number of invalid HMAC ids received */
	unsigned long  sctps_recvivalkeyid;       /* total number of invalid secret ids received */
	unsigned long  sctps_recvauthfailed;      /* total number of auth failed */
	unsigned long  sctps_recvexpress;         /* total fast path receives all one chunk */
	unsigned long  sctps_recvexpressm;        /* total fast path multi-part data */
	/* output statistics: */
	unsigned long  sctps_sendpackets;         /* total output packets       */
	unsigned long  sctps_sendsacks;           /* total output SACKs         */
	unsigned long  sctps_senddata;            /* total output DATA chunks   */
	unsigned long  sctps_sendretransdata;     /* total output retransmitted DATA chunks */
	unsigned long  sctps_sendfastretrans;     /* total output fast retransmitted DATA chunks */
	unsigned long  sctps_sendmultfastretrans; /* total FR's that happened more than once
                                              * to same chunk (u-del multi-fr algo).
					      */
	unsigned long  sctps_sendheartbeat;       /* total output HB chunks     */
	unsigned long  sctps_sendecne;            /* total output ECNE chunks    */
	unsigned long  sctps_sendauth;            /* total output AUTH chunks FIXME   */
	unsigned long  sctps_senderrors;	   /* ip_output error counter */
	/* PCKDROPREP statistics: */
	unsigned long  sctps_pdrpfmbox;           /* Packet drop from middle box */
	unsigned long  sctps_pdrpfehos;           /* P-drop from end host */
	unsigned long  sctps_pdrpmbda;            /* P-drops with data */
	unsigned long  sctps_pdrpmbct;            /* P-drops, non-data, non-endhost */
	unsigned long  sctps_pdrpbwrpt;           /* P-drop, non-endhost, bandwidth rep only */
	unsigned long  sctps_pdrpcrupt;           /* P-drop, not enough for chunk header */
	unsigned long  sctps_pdrpnedat;           /* P-drop, not enough data to confirm */
	unsigned long  sctps_pdrppdbrk;           /* P-drop, where process_chunk_drop said break */
	unsigned long  sctps_pdrptsnnf;           /* P-drop, could not find TSN */
	unsigned long  sctps_pdrpdnfnd;           /* P-drop, attempt reverse TSN lookup */
	unsigned long  sctps_pdrpdiwnp;           /* P-drop, e-host confirms zero-rwnd */
	unsigned long  sctps_pdrpdizrw;           /* P-drop, midbox confirms no space */
	unsigned long  sctps_pdrpbadd;            /* P-drop, data did not match TSN */
	unsigned long  sctps_pdrpmark;            /* P-drop, TSN's marked for Fast Retran */
	/* timeouts */
	unsigned long  sctps_timoiterator;        /* Number of iterator timers that fired */
	unsigned long  sctps_timodata;            /* Number of T3 data time outs */
	unsigned long  sctps_timowindowprobe;     /* Number of window probe (T3) timers that fired */
	unsigned long  sctps_timoinit;            /* Number of INIT timers that fired */
	unsigned long  sctps_timosack;            /* Number of sack timers that fired */
	unsigned long  sctps_timoshutdown;        /* Number of shutdown timers that fired */
	unsigned long  sctps_timoheartbeat;       /* Number of heartbeat timers that fired */
	unsigned long  sctps_timocookie;          /* Number of times a cookie timeout fired */
	unsigned long  sctps_timosecret;          /* Number of times an endpoint changed its cookie secret*/
	unsigned long  sctps_timopathmtu;         /* Number of PMTU timers that fired */
	unsigned long  sctps_timoshutdownack;     /* Number of shutdown ack timers that fired */
	unsigned long  sctps_timoshutdownguard;   /* Number of shutdown guard timers that fired */
	unsigned long  sctps_timostrmrst;         /* Number of stream reset timers that fired */
	unsigned long  sctps_timoearlyfr;         /* Number of early FR timers that fired */
	unsigned long  sctps_timoasconf;          /* Number of times an asconf timer fired */
	unsigned long  sctps_timodelprim;	     /* Number of times a prim_deleted timer fired */
	unsigned long  sctps_timoautoclose;       /* Number of times auto close timer fired */
	unsigned long  sctps_timoassockill;       /* Number of asoc free timers expired */
	unsigned long  sctps_timoinpkill;         /* Number of inp free timers expired */
	/* Early fast retransmission counters */
	unsigned long  sctps_earlyfrstart;        
	unsigned long  sctps_earlyfrstop;
	unsigned long  sctps_earlyfrmrkretrans;
	unsigned long  sctps_earlyfrstpout;
	unsigned long  sctps_earlyfrstpidsck1;
	unsigned long  sctps_earlyfrstpidsck2;
	unsigned long  sctps_earlyfrstpidsck3;
	unsigned long  sctps_earlyfrstpidsck4;
	unsigned long  sctps_earlyfrstrid;
	unsigned long  sctps_earlyfrstrout;
	unsigned long  sctps_earlyfrstrtmr;
	/* otheres */
	unsigned long  sctps_hdrops;	          /* packet shorter than header */
	unsigned long  sctps_badsum;	          /* checksum error             */
	unsigned long  sctps_noport;           /* no endpoint for port       */
	unsigned long  sctps_badvtag;          /* bad v-tag                  */
	unsigned long  sctps_badsid;           /* bad SID                    */
	unsigned long  sctps_nomem;            /* no memory                  */
	unsigned long  sctps_fastretransinrtt; /* number of multiple FR in a RTT window */
	unsigned long  sctps_markedretrans;
	unsigned long  sctps_naglesent;        /* nagle allowed sending      */
	unsigned long  sctps_naglequeued;      /* nagle does't allow sending */
	unsigned long  sctps_maxburstqueued;   /* max burst dosn't allow sending */
	unsigned long  sctps_ifnomemqueued;    /* look ahead tells us no memory in 
                                         * interface ring buffer OR we had a
					 * send error and are queuing one send.
                                         */
	unsigned long  sctps_windowprobed;     /* total number of window probes sent */
	unsigned long  sctps_lowlevelerr;	/* total times an output error causes us
					 * to clamp down on next user send.
					 */
	unsigned long  sctps_lowlevelerrusr;	/* total times sctp_senderrors were caused from
					 * a user send from a user invoked send not
					 * a sack response
					 */
	unsigned long  sctps_datadropchklmt;	/* Number of in data drops due to chunk limit reached */
	unsigned long  sctps_datadroprwnd;	/* Number of in data drops due to rwnd limit reached */
	unsigned long  sctps_ecnereducedcwnd;  /* Number of times a ECN reduced the cwnd */
	unsigned long  sctps_vtagexpress;	/* Used express lookup via vtag */
	unsigned long  sctps_vtagbogus;	/* Collision in express lookup. */
	unsigned long  sctps_primary_randry;	/* Number of times the sender ran dry of user data on primary */
	unsigned long  sctps_cmt_randry;       /* Same for above */
	unsigned long  sctps_slowpath_sack;    /* Sacks the slow way */
	unsigned long  sctps_wu_sacks_sent;	/* Window Update only sacks sent */
	unsigned long  sctps_sends_with_flags; /* number of sends with sinfo_flags !=0 */
	unsigned long  sctps_sends_with_unord	/* number of undordered sends */; 
	unsigned long  sctps_sends_with_eof; 	/* number of sends with EOF flag set */
	unsigned long  sctps_sends_with_abort; /* number of sends with ABORT flag set */
	unsigned long  sctps_protocol_drain_calls;	/* number of times protocol drain called */
	unsigned long  sctps_protocol_drains_done; 	/* number of times we did a protocol drain */
	unsigned long  sctps_read_peeks;	/* Number of times recv was called with peek */
	unsigned long  sctps_cached_chk;       /* Number of cached chunks used */
	unsigned long  sctps_cached_strmoq;    /* Number of cached stream oq's used */
	unsigned long  sctps_left_abandon;     /* Number of unread message abandonded by close */
	unsigned long  sctps_send_burst_avoid; /* Send burst avoidance, already max burst inflight to net */
	unsigned long  sctps_send_cwnd_avoid;  /* Send cwnd full  avoidance, already max burst inflight to net */
	unsigned long  sctps_fwdtsn_map_over;  /* number of map array over-runs via fwd-tsn's */

	struct sctp_timeval sctps_discontinuitytime; /* sctpStats 18 (TimeStamp) */
};

#define SCTP_STAT_INCR(_x) SCTP_STAT_INCR_BY(_x,1)
#define SCTP_STAT_DECR(_x) SCTP_STAT_DECR_BY(_x,1)
#define SCTP_STAT_INCR_BY(_x,_d) atomic_add_int(&sctpstat._x, _d)
#define SCTP_STAT_DECR_BY(_x,_d) atomic_subtract_int(&sctpstat._x, _d)

/* The following macros are for handling MIB values, */
#define SCTP_STAT_INCR_COUNTER32(_x) SCTP_STAT_INCR(_x)
#define SCTP_STAT_INCR_COUNTER64(_x) SCTP_STAT_INCR(_x)
#define SCTP_STAT_INCR_GAUGE32(_x) SCTP_STAT_INCR(_x)
#define SCTP_STAT_DECR_COUNTER32(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_DECR_COUNTER64(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_DECR_GAUGE32(_x) SCTP_STAT_DECR(_x)

union sctp_sockstore {
#if defined(INET) || !defined(_KERNEL)
	struct sockaddr_in sin;
#endif
#if defined(INET6) || !defined(_KERNEL)
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr sa;
};

struct xsctp_inpcb {
	unsigned long last;
	unsigned long flags;
	unsigned long features;
	unsigned long total_sends;
	unsigned long total_recvs;
	unsigned long total_nospaces;
	unsigned long fragmentation_point;
	unsigned short local_port;
	unsigned short qlen;
	unsigned short maxqlen;
};

struct xsctp_tcb {
	union sctp_sockstore primary_addr;      /* sctpAssocEntry 5/6 */
	unsigned long last;
	unsigned long heartbeat_interval;            /* sctpAssocEntry 7   */
	unsigned long state;                         /* sctpAssocEntry 8   */
	unsigned long in_streams;                    /* sctpAssocEntry 9   */
	unsigned long out_streams;                   /* sctpAssocEntry 10  */
	unsigned long max_nr_retrans;                /* sctpAssocEntry 11  */
	unsigned long primary_process;               /* sctpAssocEntry 12  */
	unsigned long T1_expireries;                 /* sctpAssocEntry 13  */
	unsigned long T2_expireries;                 /* sctpAssocEntry 14  */
	unsigned long retransmitted_tsns;            /* sctpAssocEntry 15  */
	unsigned long total_sends;
	unsigned long total_recvs;
	unsigned long local_tag;
	unsigned long remote_tag;
	unsigned long initial_tsn;
	unsigned long highest_tsn;
	unsigned long cumulative_tsn;
	unsigned long cumulative_tsn_ack;
	unsigned long mtu;
	unsigned long peers_rwnd;
	unsigned long refcnt;
	unsigned short local_port;                    /* sctpAssocEntry 3   */
	unsigned short remote_port;                   /* sctpAssocEntry 4   */
	struct sctp_timeval start_time;         /* sctpAssocEntry 16  */
	struct sctp_timeval discontinuity_time; /* sctpAssocEntry 17  */
};

struct xsctp_laddr {
	union sctp_sockstore address;    /* sctpAssocLocalAddrEntry 1/2 */
	unsigned long last;
	struct sctp_timeval start_time;  /* sctpAssocLocalAddrEntry 3   */
};

struct xsctp_raddr {
	union sctp_sockstore address;      /* sctpAssocLocalRemEntry 1/2 */
	unsigned long last;
	unsigned long rto;                      /* sctpAssocLocalRemEntry 5   */
	unsigned long max_path_rtx;             /* sctpAssocLocalRemEntry 6   */
	unsigned long rtx;                      /* sctpAssocLocalRemEntry 7   */
	unsigned long error_counter;            /*                            */
	unsigned long cwnd;                     /*                            */
	unsigned long flight_size;              /*                            */
	unsigned long mtu;                      /*                            */
	unsigned char active;                    /* sctpAssocLocalRemEntry 3   */
	unsigned char confirmed;                 /*                            */
	unsigned char heartbeat_enabled;         /* sctpAssocLocalRemEntry 4   */
	struct sctp_timeval start_time;    /* sctpAssocLocalRemEntry 8   */
};

#define SCTP_MAX_LOGGING_SIZE 30000
#define SCTP_TRACE_PARAMS 6                /* This number MUST be even   */

struct sctp_log_entry {
	unsigned long long timestamp;
	unsigned long subsys;
	unsigned long padding;
	unsigned long params[SCTP_TRACE_PARAMS];
};

struct sctp_log {
	struct sctp_log_entry entry[SCTP_MAX_LOGGING_SIZE];
	unsigned long index;
	unsigned long padding;
};

/*
 * API system calls
 */
#if _WIN32_WINNT < 0x0600
typedef
INT
(PASCAL FAR * LPFN_WSASENDMSG) (
    IN SOCKET s,
    IN LPWSAMSG lpMsg,
    IN DWORD dwFlags,
    __out_opt LPDWORD lpNumberOfBytesSent,
    IN LPWSAOVERLAPPED lpOverlapped OPTIONAL,
    IN LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine OPTIONAL);

#define WSAID_WSASENDMSG /* a441e712-754f-43ca-84a7-0dee44cf606d */ \
    {0xa441e712,0x754f,0x43ca,{0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}}
#endif


int WSAAPI sctp_peeloff(int, sctp_assoc_t);
int WSAAPI sctp_bindx(int, struct sockaddr *, int, int);
int WSAAPI sctp_connectx(int, const struct sockaddr *, int, sctp_assoc_t *);
int WSAAPI sctp_getaddrlen(int);
int WSAAPI sctp_getpaddrs(int, sctp_assoc_t, struct sockaddr **);
void WSAAPI sctp_freepaddrs(struct sockaddr *);
int WSAAPI sctp_getladdrs(int, sctp_assoc_t, struct sockaddr **);
void WSAAPI sctp_freeladdrs(struct sockaddr *);
int WSAAPI sctp_opt_info(int, sctp_assoc_t, int, void *, socklen_t *);

int WSAAPI sctp_sendmsg(SOCKET, const void *, size_t,
    const struct sockaddr *, socklen_t,
    unsigned long, unsigned long, unsigned short, unsigned long, unsigned long);

int WSAAPI sctp_send(SOCKET, const void *, size_t,
    const struct sctp_sndrcvinfo *, int);

int WSAAPI sctp_sendx(SOCKET, const void *, size_t,
    struct sockaddr *, int,
    struct sctp_sndrcvinfo *, int);

int WSAAPI sctp_sendmsgx(SOCKET, const void *, size_t,
    struct sockaddr *, int,
    unsigned long, unsigned long, unsigned short, unsigned long, unsigned long);

sctp_assoc_t WSAAPI sctp_getassocid(SOCKET, struct sockaddr *);

int WSAAPI sctp_recvmsg(SOCKET, void *, size_t, struct sockaddr *,
    socklen_t *, struct sctp_sndrcvinfo *, int *);
/* <== The above definitions are based on netinet/sctp_uio.h (Revision 1.209) */

#endif /* WS2SCTP_INCLUDED */
