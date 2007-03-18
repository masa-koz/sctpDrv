#ifndef __sctp_addr_h__
#define __sctp_addr_h__

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <netinet/sctp_bsd_addr.h>
#endif

#if defined(__Windows__)
#include <netinet/sctp_windows_addr.h>
#endif

#endif
