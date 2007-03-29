#ifndef __sctp_windows_addr_h__
#define __sctp_windows_addr_h__

#include <netinet/sctp_header.h>

TAILQ_HEAD(ifnethead, ifnet);
TAILQ_HEAD(ifaddrhead, ifaddr);


struct ifnet {
	TAILQ_ENTRY(ifnet)	if_link;
	KSPIN_LOCK		if_spinlock;
	KLOCK_QUEUE_HANDLE	if_lockqueue;
	int			refcount;
	UNICODE_STRING		if_xname;
	int			if_index;
	struct ifaddrhead	if_addrhead;
};

struct ifaddr {
	TAILQ_ENTRY(ifaddr)	ifa_link;
	KSPIN_LOCK		ifa_spinlock;
	KLOCK_QUEUE_HANDLE	ifa_lockqueue;
	struct ifnet		*ifa_ifp;
	int			refcount;
	struct sockaddr_storage	ifa_addr;
};

#if 0
extern struct ifnethead ifnet;
extern KSPIN_LOCK *ifnet_spinlock;
extern KLOCK_QUEUE_HANDLE *ifnet_lockqueue;

#define	LOCKDEBUG	1

#define IFNET_LOCK_INIT() do { \
	ifnet_spinlock = ExAllocatePool(NonPagedPool, sizeof(KSPIN_LOCK)); \
	ifnet_lockqueue = ExAllocatePool(NonPagedPool, sizeof(KLOCK_QUEUE_HANDLE)); \
	KeInitializeSpinLock(ifnet_spinlock); \
} while (0)

#define IFNET_LOCK_DESTROY() do { \
	ExFreePool(ifnet_spinlock); \
	ExFreePool(ifnet_lockqueue); \
} while (0)

#define IFNET_WLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("IFNET_WLOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireInStackQueuedSpinLock(ifnet_spinlock, ifnet_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
} while (0)
#define IFNET_RLOCK IFNET_WLOCK

#define IFNET_WUNLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("IFNET_WUNLOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseInStackQueuedSpinLock(ifnet_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
} while (0)
#define IFNET_RUNLOCK IFNET_WUNLOCK

#else
extern struct ifnethead ifnet;
extern KSPIN_LOCK ifnet_spinlock;
extern KLOCK_QUEUE_HANDLE ifnet_lockqueue;

#define	LOCKDEBUG	1

#define IFNET_LOCK_INIT() do { \
	KeInitializeSpinLock(&ifnet_spinlock); \
} while (0)

#define IFNET_LOCK_DESTROY() do { \
} while (0)

#define IFNET_WLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("IFNET_WLOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireInStackQueuedSpinLock(&ifnet_spinlock, &ifnet_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
} while (0)
#define IFNET_RLOCK IFNET_WLOCK

#define IFNET_WUNLOCK() do { \
	if (LOCKDEBUG) { \
		DbgPrint("IFNET_WUNLOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseInStackQueuedSpinLock(&ifnet_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
} while (0)
#define IFNET_RUNLOCK IFNET_WUNLOCK
#endif

#define IF_LOCK_INIT(_ifp) \
	KeInitializeSpinLock(&(_ifp)->if_spinlock)

#define IF_LOCK_DESTROY(_ifp)

#define IF_LOCK(_ifp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("IF_LOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireInStackQueuedSpinLock(&(_ifp)->if_spinlock, &(_ifp)->if_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
} while (0)

#define IF_UNLOCK(_ifp) do { \
	if (LOCKDEBUG) { \
		DbgPrint("IF_UNLOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseInStackQueuedSpinLock(&(_ifp)->if_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
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

#define IFFREE(_ifp) do { \
	IF_LOCK((_ifp)); \
	(_ifp)->refcount--; \
	if ((_ifp)->refcount == 0) { \
		IF_LOCK_DESTROY((_ifp)); \
		ExFreePool((_ifp)); \
	} else {\
		IF_UNLOCK((_ifp)); \
	} \
} while (0)

#define IFA_LOCK_INIT(_ifa) \
	KeInitializeSpinLock(&(_ifa)->ifa_spinlock)

#define IFA_LOCK_DESTROY(_ifa)

#define IFA_LOCK(_ifa) do { \
	if (LOCKDEBUG) { \
		DbgPrint("IFA_LOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeAcquireInStackQueuedSpinLock(&(_ifa)->ifa_spinlock, &(_ifa)->ifa_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
} while (0)

#define IFA_UNLOCK(_ifa) do { \
	if (LOCKDEBUG) { \
		DbgPrint("IFA_UNLOCK @ %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeReleaseInStackQueuedSpinLock(&(_ifa)->ifa_lockqueue); \
	if (LOCKDEBUG) { \
		KIRQL _irql; \
		_irql = KeGetCurrentIrql(); \
		DbgPrint("_irql => %d\n", _irql); \
	} \
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
		ExFreePool((_ifa)); \
	} else {\
		IFA_UNLOCK((_ifa)); \
	} \
} while (0)

void
sctp_gather_internal_ifa_flags(struct sctp_ifa *ifa);

extern void
sctp_addr_change(struct ifaddr *ifa, int cmd);

#endif
