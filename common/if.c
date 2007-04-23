/*
 * Copyright (c) 2007 KOZUKA Masahiro  All rights reserved.
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
 * $Id: if.c,v 1.1 2007/04/23 15:49:41 kozuka Exp $
 */

#include "globals.h"
#include "if.h"

int if_index = 0;
struct ifnethead ifnet;
KSPIN_LOCK ifnet_spinlock;
KLOCK_QUEUE_HANDLE ifnet_lockqueue;

#define IN4_ISLOOPBACK_ADDRESS(a) \
	(((uint8_t *)&(a)->s_addr)[0] == 127)

VOID
ClientPnPAddNetAddress(
    IN PTA_ADDRESS Address,
    IN PUNICODE_STRING DeviceName,
    IN PTDI_PNP_CONTEXT Context)
{
	NTSTATUS status;
	ANSI_STRING ansiStr;
	int i, len;
	unsigned char if_xname[48], *start = NULL, *end = NULL;
	unsigned char *p;
	struct ifnet *ifp, *ifp1;
	struct ifaddr *ifa;


	DbgPrint("ClientPnPAddNetAddress: DeviceName=%ws\n", DeviceName->Buffer);

	if (Address->AddressType != TDI_ADDRESS_TYPE_IP &&
	    Address->AddressType != TDI_ADDRESS_TYPE_IP6) {
		return;
	}

	status = RtlUnicodeStringToAnsiString(&ansiStr, DeviceName, TRUE);
	if (status != STATUS_SUCCESS) {
		DbgPrint("RtlUnicodeStringToAnsiString failed, code=%x\n", status);
		return;
	}
	/* Get GUID */
	for (i = 0; i < ansiStr.Length; i++) {
		if (ansiStr.Buffer[i] == '{' && i + 1 < ansiStr.Length) {
			start = &ansiStr.Buffer[i] + 1;
		}
		if (ansiStr.Buffer[i] == '}') {
			end = &ansiStr.Buffer[i] - 1;
		}
	}

	if (start == NULL || end == NULL) {
		DbgPrint("Invalid I/F name?, %s\n", ansiStr.Buffer);
		return;
	}
	len = min(end - start + 1, sizeof(if_xname));
	RtlZeroMemory(&if_xname, sizeof(if_xname));
	RtlCopyMemory(&if_xname, start, len);

	RtlFreeAnsiString(&ansiStr);

	DbgPrint("if_xname => %s\n", if_xname);

	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		p = (unsigned char *)&((PTDI_ADDRESS_IP)Address->Address)->in_addr;
		DbgPrint("IPv4 address: %u.%u.%u.%u\n",
		    p[0], p[1], p[2], p[3]);
		break;
	case TDI_ADDRESS_TYPE_IP6:
		DbgPrint("IPv6 address: %s%%%d\n",
		    ip6_sprintf((struct in6_addr *)&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr),
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id);
		break;
	}

	IFNET_WLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (RtlCompareMemory(&if_xname, &ifp->if_xname, sizeof(if_xname)) == sizeof(if_xname)) {
			break;
		}
	}
	if (ifp == NULL) {
		/* New interface */
		ifp = ExAllocatePool(NonPagedPool, sizeof(*ifp));
		if (ifp == NULL) {
			DbgPrint("ClientPnPAddNetAddress: Resource unavailable\n");
			IFNET_WUNLOCK();
			return;
		}
		RtlZeroMemory(ifp, sizeof(*ifp));

		TAILQ_INIT(&ifp->if_addrhead);
		IF_LOCK_INIT(ifp);
		ifp->refcount = 2;
		RtlCopyMemory(&ifp->if_xname, &if_xname, sizeof(if_xname));

		for (ifp->if_index = 0; ifp->if_index <= if_index; ifp->if_index++) {
			TAILQ_FOREACH(ifp1, &ifnet, if_link) {
				if (ifp1->if_index == ifp->if_index) {
					break;
				}
			}
			if (ifp1 == NULL) {
				break;
			}
		}
		if (ifp->if_index > if_index) {
			if_index = ifp->if_index;
		}
		TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	}
	IFNET_WUNLOCK();
	IF_LOCK(ifp);
	ifp->refcount--;

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ifa->ifa_addr.ss_family == AF_INET &&
		    ((PTDI_ADDRESS_IP)Address->Address)->in_addr == ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr) ||
		    (Address->AddressType == TDI_ADDRESS_TYPE_IP6 &&
		    ifa->ifa_addr.ss_family == AF_INET6 &&
		    RtlCompareMemory(&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
			&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == sizeof(struct in6_addr) &&
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id ==
		    ((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id)) {
			break;
		}
	}
	if (ifa != NULL) {
		DbgPrint("Already exists....\n");
		IF_UNLOCK(ifp);
		return;
	}

	ifa = ExAllocatePool(NonPagedPool, sizeof(*ifa));
	if (ifa == NULL) {
		DbgPrint("ClientPnPAddNetAddress: Resource unavailable#2\n");
		IF_UNLOCK(ifp);
		return;
	}
	RtlZeroMemory(ifa, sizeof(*ifa));
	IFA_LOCK_INIT(ifa);
	ifa->ifa_ifp = ifp;
	ifa->refcount = 1;

	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		ifa->ifa_addr.ss_family = AF_INET;
		ifa->ifa_addr.ss_len = sizeof(struct sockaddr_in);
		RtlCopyMemory(&((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr,
		    &((PTDI_ADDRESS_IP)Address->Address)->in_addr,
		    sizeof(struct in_addr));
		break;
	case TDI_ADDRESS_TYPE_IP6:
		ifa->ifa_addr.ss_family = AF_INET6;
		ifa->ifa_addr.ss_len = sizeof(struct sockaddr_in6);
		RtlCopyMemory(&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr,
		    &((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
		    sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id = 
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id;
		break;
	}
	TAILQ_INSERT_TAIL(&ifp->if_addrhead, ifa, ifa_link);
	IF_UNLOCK(ifp);
}

VOID
ClientPnPDelNetAddress(
    IN PTA_ADDRESS Address,
    IN PUNICODE_STRING DeviceName,
    IN PTDI_PNP_CONTEXT Context)
{
	NTSTATUS status;
	ANSI_STRING ansiStr;
	int i, len;
	unsigned char if_xname[48], *start = NULL, *end = NULL;
	unsigned char *p;
	struct ifnet *ifp;
	struct ifaddr *ifa;

	DbgPrint("ClientPnPDelNetAddress: DeviceName=%ws\n", DeviceName->Buffer);

	if (Address->AddressType != TDI_ADDRESS_TYPE_IP &&
	    Address->AddressType != TDI_ADDRESS_TYPE_IP6) {
		return;
	}

	status = RtlUnicodeStringToAnsiString(&ansiStr, DeviceName, TRUE);
	if (status != STATUS_SUCCESS) {
		DbgPrint("RtlUnicodeStringToAnsiString failed, code=%x\n", status);
		return;
	}
	/* Get GUID */
	for (i = 0; i < ansiStr.Length; i++) {
		if (ansiStr.Buffer[i] == '{' && i + 1 < ansiStr.Length) {
			start = &ansiStr.Buffer[i] + 1;
		}
		if (ansiStr.Buffer[i] == '}') {
			end = &ansiStr.Buffer[i] - 1;
		}
	}

	if (start == NULL || end == NULL) {
		DbgPrint("Invalid I/F name?, %s\n", ansiStr.Buffer);
		return;
	}
	len = min(end - start + 1, sizeof(if_xname));
	RtlZeroMemory(&if_xname, sizeof(if_xname));
	RtlCopyMemory(&if_xname, start, len);

	RtlFreeAnsiString(&ansiStr);

	DbgPrint("if_xname => %s\n", if_xname);

	switch (Address->AddressType) {
	case TDI_ADDRESS_TYPE_IP:
		p = (unsigned char *)&((PTDI_ADDRESS_IP)Address->Address)->in_addr;
		DbgPrint("IPv4 address: %u.%u.%u.%u\n",
		    p[0], p[1], p[2], p[3]);
		break;
	case TDI_ADDRESS_TYPE_IP6:
		DbgPrint("IPv6 address: %s%%%d\n",
		    ip6_sprintf((struct in6_addr *)&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr),
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id);
		break;
	}

	IFNET_RLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (RtlCompareMemory(&if_xname, &ifp->if_xname, sizeof(if_xname)) == sizeof(if_xname)) {
			break;
		}
	}
	if (ifp != NULL) {
		IF_INCR_REF(ifp);
	}
	if (ifp == NULL) {
		DbgPrint("No such device....\n");
		IFNET_RUNLOCK();
		return;
	}
	IFNET_RUNLOCK();
	IF_LOCK(ifp);
	ifp->refcount--;

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if ((Address->AddressType == TDI_ADDRESS_TYPE_IP &&
		    ifa->ifa_addr.ss_family == AF_INET &&
		    ((PTDI_ADDRESS_IP)Address->Address)->in_addr == ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr) ||
		    (Address->AddressType == TDI_ADDRESS_TYPE_IP6 &&
		    ifa->ifa_addr.ss_family == AF_INET6 &&
		    RtlCompareMemory(&((PTDI_ADDRESS_IP6)Address->Address)->sin6_addr,
			&((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == sizeof(struct in6_addr) &&
		    ((PTDI_ADDRESS_IP6)Address->Address)->sin6_scope_id ==
		    ((struct sockaddr_in6 *)&ifa->ifa_addr)->sin6_scope_id)) {
			break;
		}
	}
	if (ifa == NULL) {
		IF_UNLOCK(ifp);
		DbgPrint("No such address....\n");
		return;
	}

	TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);
	IFAFREE(ifa);
	IF_UNLOCK(ifp);
#if 0
	if (TAILQ_EMPTY(&ifp->if_addrhead)) {
		TAILQ_REMOVE(&ifnet, ifp, if_link);
	}
#endif
}
