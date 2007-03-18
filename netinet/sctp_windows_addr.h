#ifndef __sctp_windows_addr_h__
#define __sctp_windows_addr_h__

#include <netinet/sctp_header.h>

TAILQ_HEAD(ifnethead, ifnet);
TAILQ_HEAD(ifaddrhead, ifaddr);


struct ifnet {
	TAILQ_ENTRY(ifnet)	if_link;
	KMUTEX			if_mtx;
	int			refcount;
	UNICODE_STRING		if_xname;
	struct ifaddrhead	if_addrhead;
};

struct ifaddr {
	TAILQ_ENTRY(ifaddr)	ifa_link;
	KMUTEX			ifa_mtx;
	int			refcount;
	struct sockaddr_storage	ifa_addr;
};

#define IFNET_LOCK_INIT() do { \
	ifnet_mtx = ExAllocatePool(NonPagedPool, sizeof(*(ifnet_mtx))); \
	KeInitializeMutex(ifnet_mtx, 0); \
} while (0)

#define IFNET_LOCK_DESTROY()

#define IFNET_WLOCK() do { \
	DbgPrint("IFNET_WLOCK @ %d\n", __LINE__); \
	KeWaitForMutexObject(ifnet_mtx, Executive, KernelMode,  FALSE, NULL); \
} while (0)
#define IFNET_RLOCK IFNET_WLOCK

#define IFNET_WUNLOCK() do { \
	DbgPrint("IFNET_WUNLOCK @ %d\n", __LINE__); \
	KeReleaseMutex(ifnet_mtx, 0); \
} while (0)
#define IFNET_RUNLOCK IFNET_WUNLOCK

#define IF_LOCK_INIT(_ifp) \
	KeInitializeMutex(&(_ifp)->if_mtx, 0)

#define IF_LOCK_DESTROY(_ifp)

#define IF_LOCK(_ifp) do { \
	DbgPrint("IF_LOCK @ %d\n", __LINE__); \
	KeWaitForMutexObject(&(_ifp)->if_mtx, Executive, KernelMode,  FALSE, NULL); \
} while (0)

#define IF_UNLOCK(_ifp) do { \
	DbgPrint("IF_UNLOCK @ %d\n", __LINE__); \
	KeReleaseMutex(&(_ifp)->if_mtx, 0); \
} while (0)

#define IF_INCR_REF(_ifp) do { \
	IF_LOCK((_ifp)); \
	(_ifp)->refcount++; \
	IF_UNLOCK((_ifp)); \
} while (0)

#define IF_DECR_REF(_ifp) do { \
	IF_LOCK((_ifp)); \
	(_ifp)->refcount--; \
	IF_UNLOCK((_ifp)); \
} while (0)

#define IFA_LOCK_INIT(_ifa) \
	KeInitializeMutex(&(_ifa)->ifa_mtx, 0)

#define IFA_LOCK_DESTROY(_ifa)

#define IFA_LOCK(_ifa) do { \
	DbgPrint("IFA_LOCK @ %d\n", __LINE__); \
	KeWaitForMutexObject(&(_ifa)->ifa_mtx, Executive, KernelMode,  FALSE, NULL); \
} while (0)

#define IFA_UNLOCK(_ifa) do { \
	DbgPrint("IFA_UNLOCK @ %d\n", __LINE__); \
	KeReleaseMutex(&(_ifa)->ifa_mtx, 0); \
} while (0)

#define IFA_INCR_REF(_ifa) do { \
	IFA_LOCK((_ifa)); \
	(_ifa)->refcount++; \
	IFA_UNLOCK((_ifa)); \
} while (0)

#define IFA_DECR_REF(_ifa) do { \
	IFA_LOCK((_ifa)); \
	(_ifa)->refcount--; \
	IFA_UNLOCK((_ifa)); \
} while (0)

#define IFAFREE(_ifa) do { \
	IFA_LOCK((_ifa)); \
	(_ifa)->refcount--; \
	if ((_ifa)->refcount == 0) { \
		IFA_LOCK_DESTROY((_ifa)); \
	} \
	IFA_UNLOCK((_ifa)); \
} while (0)

void
sctp_gather_internal_ifa_flags(struct sctp_ifa *ifa);

extern void
sctp_addr_change(struct ifaddr *ifa, int cmd);

#endif
