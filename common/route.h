#include <net/radix.h>

struct rtentry {
	struct radix_node rt_nodes[2];
#define rt_key(r)	(*((struct sockaddr **)(&(r)->rt_nodes->rn_key)))
#define rt_mask(r)	(*((struct sockaddr **)(&(r)->rt_nodes->rn_mask)))
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} rt_dst;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} rt_netmask;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} rt_gateway;
	struct ifnet *rt_ifp;
	struct ifaddr *rt_ifa;
	uint16_t rt_flags;
	uint32_t rt_refcnt;
	KMUTEX rt_mtx;
};
#define	RT_FLAG_UP	0x0001

#define	RT_LOCK_INIT(rt) do { \
	if (LOCKDEBUG) { \
		DbgPrint("RT_LOCK_INIT: %s[%d]\n", __FILE__, __LINE__); \
	} \
	KeInitializeMutex(&(rt)->rt_mtx, 0); \
} while (0)
#define	RT_LOCK(rt) do { \
	if (LOCKDEBUG) { \
		DbgPrint("RT_LOCK: rt=%p %s[%d]\n", (rt), __FILE__, __LINE__); \
	} \
	KeWaitForMutexObject(&(rt)->rt_mtx, Executive, KernelMode, FALSE, NULL); \
} while (0)
#define	RT_UNLOCK(rt) do { \
	if (LOCKDEBUG) { \
		DbgPrint("RT_UNLOCK: rt=%p %s[%d]\n", (rt), __FILE__, __LINE__); \
	} \
	KeReleaseMutex(&(rt)->rt_mtx, 0); \
} while(0)
#define	RT_LOCK_DESTROY(rt) do { \
	if (LOCKDEBUG) { \
		DbgPrint("RT_LOCK_DESTROY: rt=%p %s[%d]\n", (rt), __FILE__, __LINE__); \
	} \
	if (KeReadStateMutex(&(rt)->rt_mtx) == 0) { \
		KeReleaseMutex(&(rt)->rt_mtx, 0); \
	} \
} while (0)
#define	RT_ADDREF(rt) do { \
	(rt)->rt_refcnt++; \
} while (0)
#define	RT_REMREF(rt) do { \
	(rt)->rt_refcnt--; \
} while (0)
#define RTFREE_LOCKED(rt) do { \
	if ((rt)->rt_refcnt <= 1) { \
		rtfree((rt)); \
	} else { \
		RT_REMREF((rt)); \
		RT_UNLOCK((rt)); \
	} \
	(rt) = NULL; \
} while (0)
#define RTFREE(rt) do { \
	RT_LOCK((rt)); \
	RTFREE_LOCKED((rt)); \
} while (0)

struct route {
	struct rtentry *ro_rt;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} ro_dst;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} ro_src;
};

void rtalloc(struct route *);
void rtfree(struct rtentry *);
void route_init(void);

#define	RTM_ADD		0x01
#define	RTM_DELETE	0x02

typedef struct {
	unsigned long ipsi_forwarding;
	unsigned long ipsi_defaultttl;
	unsigned long ipsi_inreceives;
	unsigned long ipsi_inhdrerrors;
	unsigned long ipsi_inaddrerrors;
	unsigned long ipsi_forwdatagrams;
	unsigned long ipsi_inunknownprotos;
	unsigned long ipsi_indiscards;
	unsigned long ipsi_indelivers;
	unsigned long ipsi_outrequests;
	unsigned long ipsi_routingdiscards;
	unsigned long ipsi_outdiscards;
	unsigned long ipsi_outnoroutes;
	unsigned long ipsi_reasmtimeout;
	unsigned long ipsi_reasmreqds;
	unsigned long ipsi_reasmoks;
	unsigned long ipsi_reasmfails;
	unsigned long ipsi_fragoks;
	unsigned long ipsi_fragfails;
	unsigned long ipsi_fragcreates;
	unsigned long ipsi_numif;
	unsigned long ipsi_numaddr;
	unsigned long ipsi_numroutes;
} IPSNMPInfo;

typedef struct {
	unsigned long iae_addr;
	unsigned long iae_index;
	unsigned long iae_mask;
	unsigned long iae_bcastaddr;
	unsigned long iae_reasmsize;
	unsigned short iae_context;
	unsigned short iae_pad;
} IPAddrEntry;

typedef struct IPRouteEntry {
	ulong ire_addr;
	ulong ire_index;
	ulong ire_metric;
	ulong ire_metric2;
	ulong ire_metric3;
	ulong ire_metric4;
	ulong ire_gw;
	ulong ire_type;
	ulong ire_proto;
	ulong ire_age;
	ulong ire_mask;
	ulong ire_metric5;
	ulong ire_unk8; /* AS? */
} IPRouteEntry;

typedef struct IPRouteQuery {
	ulong		irq_unk1;	/* 0x00000301 */
	ulong		irq_unk2;	/* 0x00000000 */
	ulong		irq_unk3;	/* 0x00000200 */
	ulong		irq_unk4;	/* 0x00000101 */
	ulong		irq_unk5;	/* 0x00000101 */
	ulong		irq_unk6;	/* 0x00000034 */
	IPRouteEntry	irq_entry;
	u_char		irq_unk7[3];	/* 0x000000 */
} IPRouteQuery;

typedef struct IPv6QueryRouteEntry {
	struct in6_addr	i6qre_addr;
	ulong		i6qre_prefix;
	ulong		i6qre_index;
	ulong		i6qre_unk1;	/* 0x00000000 */
	ulong		i6qre_unk2;	/* 0x0006FD08 */
	ulong		i6qre_unk3;	/* 0x00000004 */
	ulong		i6qre_unk4;	/* 0x00000000 */
	struct in6_addr	i6qre_gw;
} IPv6QueryRouteEntry;

typedef struct IPv6RouteEntry {
	IPv6QueryRouteEntry i6re_query;
	ulong		i6re_siteprefix;
	ulong		i6re_expire;
	ulong		i6re_expire2;
	ulong		i6re_metric;
	ulong		i6re_type;	/* 0: System, 2: Autoconf, 3: Manual */
	ulong		i6re_publish;	/* 0: no, 1: yes or age */
	ulong		i6re_publish2;	/* 0: age, 1: yes */
} IPv6RouteEntry;
