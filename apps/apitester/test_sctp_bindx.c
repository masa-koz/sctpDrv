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
#include "api_tests.h"

/*
 * TEST-TITLE bind/port_w_a_w_p
 * TEST-DESCR: (port without adress without port )
 * TEST-DESCR: On a 1-1 socket, bindx to a single
 * TEST-DESCR: address (INADDR_ANY) and 0 port.
 * TEST-DESCR: We expect success.
 */
DEFINE_APITEST(bindx, port_w_a_w_p)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(0);
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return strerror(errno);
	else
		return NULL;
}

/*
 * TEST-TITLE bind/port_s_a_w_p
 * TEST-DESCR: (port specified adress without port )
 * TEST-DESCR: On a 1-1 socket, bindx to a single
 * TEST-DESCR: address (LOOPBACK) and 0 port.
 * TEST-DESCR: We expect success.
 */
DEFINE_APITEST(bindx, port_s_a_w_p)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(0);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return strerror(errno);
	else
		return NULL;
}

/*
 * TEST-TITLE bind/port_w_a_s_p
 * TEST-DESCR: (port without address specifed port )
 * TEST-DESCR: On a 1-1 socket, bindx to a single
 * TEST-DESCR: address (ANY) and a specified port.
 * TEST-DESCR: We expect success and we got that port.
 */
DEFINE_APITEST(bindx, port_w_a_s_p)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return strerror(errno);
	else
		return NULL;
}

/*
 * TEST-TITLE bind/port_s_a_s_p
 * TEST-DESCR: (port specified address specifed port )
 * TEST-DESCR: On a 1-1 socket, bindx to a single
 * TEST-DESCR: address (LOOPBACK) and a specified port.
 * TEST-DESCR: We expect success and we got that port.
 */
DEFINE_APITEST(bindx, port_s_a_s_p)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return strerror(errno);
	else
		return NULL;
}

/*
 * TEST-TITLE bind/zero_flag
 * TEST-DESCR: On a 1-1 socket, bindx to a single
 * TEST-DESCR: address (LOOPBACK) and a specified port with
 * TEST-DESCR: no flags, we expect failure.
 */
DEFINE_APITEST(bindx, zero_flag)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, 0);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return NULL;
	else
		return "sctp_bindx() was successful";
}

/*
 * TEST-TITLE bind/add_zero_addresses
 * TEST-DESCR: On a 1-1 socket, bindx add to a single
 * TEST-DESCR: address (LOOPBACK) and a specified port with
 * TEST-DESCR: but address count is 0, we expect failure.
 */
DEFINE_APITEST(bindx, add_zero_addresses)
{
	int fd, result;
	struct sockaddr_in address;
#if defined(__Windows__)
	int error;
#endif
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 0, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	error = WSAGetLastError();
	closesocket(fd);
#endif
		
	if (result)
#if !defined(__Windows__)
		if (errno == EINVAL)
#else
		if (error == WSAEINVAL)
#endif
			return NULL;
		else
			return strerror(errno);
	else
		return "sctp_bindx() succeeded";
}

/*
 * TEST-TITLE bind/rem_zero_addresses
 * TEST-DESCR: On a 1-1 socket, bindx remove to a single
 * TEST-DESCR: address (LOOPBACK) and a specified port with
 * TEST-DESCR: but address count is 0, we expect failure.
 */
DEFINE_APITEST(bindx, rem_zero_addresses)
{
	int fd, result;
	struct sockaddr_in address;
#if defined(__Windows__)
	int error;
#endif
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 0, SCTP_BINDX_REM_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	error = WSAGetLastError();
	closesocket(fd);
#endif
		
	if (result)
#if !defined(__Windows__)
		if (errno == EINVAL)
#else
		if (error == WSAEINVAL)
#endif
			return NULL;
		else
			return strerror(errno);
	else
		return "sctp_bindx() succeeded";
}

/*
 * TEST-TITLE bind/add_zero_addresses_NULL
 * TEST-DESCR: On a 1-1 socket, bindx add no addresses
 * TEST-DESCR: and NULL pointer, we expect a error.
 */
DEFINE_APITEST(bindx, add_zero_addresses_NULL)
{
	int fd, result;
#if defined(__Windows__)
	int error;
#endif
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	result = sctp_bindx(fd, NULL, 0, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	error = WSAGetLastError();
	closesocket(fd);
#endif
		
	if (result)
#if !defined(__Windows__)
		if (errno == EINVAL)
#else
		if (error == WSAEINVAL)
#endif
			return NULL;
		else
			return strerror(errno);
	else
		return "sctp_bindx() succeeded";
}

/*
 * TEST-TITLE bind/rem_zero_addresses_NULL
 * TEST-DESCR: On a 1-1 socket, bindx remove no addresses
 * TEST-DESCR: and NULL pointer, we expect a error.
 */
DEFINE_APITEST(bindx, rem_zero_addresses_NULL)
{
	int fd, result;
#if defined(__Windows__)
	int error;
#endif
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	result = sctp_bindx(fd, NULL, 0, SCTP_BINDX_REM_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	error = WSAGetLastError();
	closesocket(fd);
#endif
		
	if (result)
#if !defined(__Windows__)
		if (errno == EINVAL)
#else
		if (error == WSAEINVAL)
#endif
			return NULL;
		else
			return strerror(errno);
	else
		return "sctp_bindx() succeeded";
}

/*
 * TEST-TITLE bind/add_null_addresses
 * TEST-DESCR: On a 1-1 socket, bindx add addresses
 * TEST-DESCR: with a NULL pointer, we expect a error.
 */
DEFINE_APITEST(bindx, add_null_addresses)
{
	int fd, result;
#if defined(__Windows__)
	int error;
#endif
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	result = sctp_bindx(fd, NULL, 1, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	error = WSAGetLastError();
	closesocket(fd);
#endif
		
	if (result)
#if !defined(__Windows__)
		if (errno == EINVAL)
#else
		if (error == WSAEINVAL)
#endif
			return NULL;
		else
			return strerror(errno);
	else
		return "sctp_bindx() succeeded";
}

/*
 * TEST-TITLE bind/rem_null_addresses
 * TEST-DESCR: On a 1-1 socket, bindx remove addresses
 * TEST-DESCR: with NULL pointer, we expect a error.
 */
DEFINE_APITEST(bindx, rem_null_addresses)
{
	int fd, result;
#if defined(__Windows__)
	int error;
#endif
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	result = sctp_bindx(fd, NULL, 1, SCTP_BINDX_REM_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	error = WSAGetLastError();
	closesocket(fd);
#endif
		
	if (result)
#if !defined(__Windows__)
		if (errno == EINVAL)
#else
		if (error == WSAEINVAL)
#endif
			return NULL;
		else
			return strerror(errno);
	else
		return "sctp_bindx() succeeded";
}

/*
 * TEST-TITLE bind/dup_add_s_a_s_p
 * TEST-DESCR: (duplicate add specified addres specified port)
 * TEST-DESCR: On a 1-1 socket, bindx add an address (loopback/1234)
 * TEST-DESCR: and then do it a second time and look for failure
 * TEST-DESCR: of the second attempt.
 */
DEFINE_APITEST(bindx, dup_add_s_a_s_p)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	if (sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return strerror(errno);
	else
		return NULL;
}

/*
 * TEST-TITLE bind/rem_last_s_a_s_p
 * TEST-DESCR: (remove last specified address specified port)
 * TEST-DESCR: On a 1-1 socket, bindx add an address (loopback/1234)
 * TEST-DESCR: and then do it a second time with a remove.
 * TEST-DESCR: This should fail, since you can't remove your last address.
 */
DEFINE_APITEST(bindx, rem_last_s_a_s_p)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	if (sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_REM_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return NULL;
	else
		return "Can remove last address";
}

/*
 * TEST-TITLE bind/rem_s_a_s_p
 * TEST-DESCR: (remove specified address specified port)
 * TEST-DESCR: On a 1-1 socket, bindx add an address (inaddr_any/1234)
 * TEST-DESCR: and then do it a second time with a remove of the loopback.
 * TEST-DESCR: This should fail, since you can't downgrade a bound-all
 * TEST-DESCR: socket to bound specific.
 */
DEFINE_APITEST(bindx, rem_s_a_s_p)
{
	int fd, result;
	struct sockaddr_in address;
	
	if ((fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if (sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_ADD_ADDR) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}

	memset((void *)&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	address.sin_len = sizeof(struct sockaddr_in);
#endif
	address.sin_port = htons(1234);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	result = sctp_bindx(fd, (struct sockaddr *)&address, 1, SCTP_BINDX_REM_ADDR);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return NULL;
	else
		return "Allowed to remove a boundall address";

}

/*
 * packed/unpacked.
 * v6only
 * multiple values.
 */
