#ifndef __sctp_windows_addr_h__
#define __sctp_windows_addr_h__

#include <netinet/sctp_header.h>

void
sctp_gather_internal_ifa_flags(struct sctp_ifa *ifa);

extern void
sctp_addr_change(struct ifaddr *ifa, int cmd);

#endif
