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
 * TEST-TITLE sctp_sendmsg/c_p_c_a
 * TEST-DESCR: (correct port correct address).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Validate that no error
 * TEST-DESCR: occurs when sending with an address and
 * TEST-DESCR: proper size (tolen).
 */
DEFINE_APITEST(sctp_sendmsg, c_p_c_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);

#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/c_p_c_a_over
 * TEST-DESCR: (correct port correct address override).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Validate that no error
 * TEST-DESCR: occurs when sending with an address and
 * TEST-DESCR: proper size (tolen), add the override flag.
 */
DEFINE_APITEST(sctp_sendmsg, c_p_c_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);

#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/w_p_c_a
 * TEST-DESCR: (without port correct address).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Validate that no error
 * TEST-DESCR: occurs when sending with an port
 * TEST-DESCR: that is set to zero, but sized correctly.
 */

DEFINE_APITEST(sctp_sendmsg, w_p_c_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);

	addr.sin_port        = htons(0);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/w_p_c_a_over
 * TEST-DESCR: (without port correct address override).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Validate that no error
 * TEST-DESCR: occurs when sending with an address 
 * TEST-DESCR: that is set with a port of zero, but sized correctly and
 * TEST-DESCR: with the override address flag set.
 */
DEFINE_APITEST(sctp_sendmsg, w_p_c_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);

	addr.sin_port        = htons(0);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/c_p_w_a
 * TEST-DESCR: (correct port without address).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. And send to INADDR_ANY
 * TEST-DESCR: with no port set. Validate it succeeds.
 */
DEFINE_APITEST(sctp_sendmsg, c_p_w_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/c_p_w_a_over
 * TEST-DESCR: (correct port without address override).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. And send to INADDR_ANY
 * TEST-DESCR: with port set and address override
 * TEST-DESCR: Validate it succeeds.
 */

DEFINE_APITEST(sctp_sendmsg, c_p_w_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/w_p_w_a
 * TEST-DESCR: (with port without address).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. And send to INADDR_ANY
 * TEST-DESCR: with no port set and no address override
 * TEST-DESCR: Validate it succeeds.
 */
DEFINE_APITEST(sctp_sendmsg, w_p_w_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_port        = htons(0);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/w_p_w_a_over
 * TEST-DESCR: (with port without address and override).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. And send to INADDR_ANY
 * TEST-DESCR: with no port set and address override
 * TEST-DESCR: Validate it succeeds.
 */
DEFINE_APITEST(sctp_sendmsg, w_p_w_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_port        = htons(0);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/b_p_c_a
 * TEST-DESCR: (bad port correct address).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port
 * TEST-DESCR: with correct address.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, b_p_c_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_port        = htons(1);

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/b_p_c_a_over
 * TEST-DESCR: (bad port correct address override).
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port
 * TEST-DESCR: with correct address.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, b_p_c_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_port        = htons(1);

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/c_p_b_a
 * TEST-DESCR: (correct port bad address)
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a correct port
 * TEST-DESCR: with bad address.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, c_p_b_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/c_p_b_a_over
 * TEST-DESCR: (correct port bad address override) 
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a correct port
 * TEST-DESCR: with bad address and override.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, c_p_b_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");

	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/b_p_b_a
 * TEST-DESCR: (bad port bad address) 
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port
 * TEST-DESCR: with bad address and override.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, b_p_b_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/b_p_b_a_over
 * TEST-DESCR: (bad port bad address override) 
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port
 * TEST-DESCR: with bad address and override.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, b_p_b_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/w_p_b_a
 * TEST-DESCR: (without port bad address) 
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a no port (0)
 * TEST-DESCR: with bad address.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, w_p_b_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(0);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/w_p_b_a_over
 * TEST-DESCR: (without port bad address override) 
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a no port (0)
 * TEST-DESCR: with bad address and override.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, w_p_b_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(0);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/b_p_w_a
 * TEST-DESCR: (bad port without address) 
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port
 * TEST-DESCR: without an  address.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, b_p_w_a)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(0);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}
/*
 * TEST-TITLE sctp_sendmsg/b_p_w_a
 * TEST-DESCR: (bad port without address override) 
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port
 * TEST-DESCR: without an address with override.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, b_p_w_a_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(0);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/non_null_zero
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port/bad address
 * TEST-DESCR: with no override.
 * TEST-DESCR: Validate it succeeds.
 */
DEFINE_APITEST(sctp_sendmsg, non_null_zero)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, 0, 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/non_null_zero_over
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a bad port/bad address
 * TEST-DESCR: with override.
 * TEST-DESCR: Validate it succeeds.
 */
DEFINE_APITEST(sctp_sendmsg, non_null_zero_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)&addr, 0, 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/null_zero
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a null address with 0 length
 * TEST-DESCR: without override.
 * TEST-DESCR: Validate it succeeds.
 */
DEFINE_APITEST(sctp_sendmsg, null_zero)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)NULL, 0, 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/null_zero_over
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a null address with 0 length
 * TEST-DESCR: with override.
 * TEST-DESCR: Validate it succeeds.
 */
DEFINE_APITEST(sctp_sendmsg, null_zero_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)NULL, 0, 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else {
		return NULL;
	}
}

/*
 * TEST-TITLE sctp_sendmsg/null_non_zero
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a null address with non-zero length
 * TEST-DESCR: without override.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, null_non_zero)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)NULL, sizeof(struct sockaddr_in), 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/null_non_zero_over
 * TEST-DESCR: On a 1-1 socket, create an
 * TEST-DESCR: association. Send to a null address with non-zero length
 * TEST-DESCR: with override.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, null_non_zero_over)
{
	int fd[2], n;
	struct sockaddr_in addr;
	socklen_t size;
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(struct sockaddr_in);
	memset((void *)&addr, 0, size);
	(void)getsockname(fd[1], (struct sockaddr *)&addr, &size);
	
	addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	addr.sin_port        = htons(1);
	
	n = sctp_sendmsg(fd[0], "Hello", 5, (struct sockaddr *)NULL, sizeof(struct sockaddr_in), 0, SCTP_ADDR_OVER, 0, 0, 0);
#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}


/*
 * TEST-TITLE sctp_sendmsg/large_addrlen
 * TEST-DESCR: On a 1-M socket, create an association.
 * TEST-DESCR: Send to an address with a large address length argument.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, large_addrlen)
{
	int fds[2], result, n;
	sctp_assoc_t ids[2];
	struct sockaddr_storage addrstore;
	struct sockaddr_in *addr;
	socklen_t size;

	fds[0] = fds[1] = -1;
	result = sctp_socketpair_1tom(fds, ids, 1);
	if (result < 0)
		return strerror(errno);

	size = (socklen_t)sizeof(addrstore);
	addr = (struct sockaddr_in *)&addrstore;
	memset((void *)addr, 0, size);
	(void)getsockname(fds[0], (struct sockaddr *)addr, &size);

	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* reset size */
	size = (socklen_t)sizeof(addrstore);
	n = sctp_sendmsg(fds[0], "Hello", 5, (struct sockaddr *)addr,
			 size, 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fds[0]);
	close(fds[1]);
#else
	closesocket(fds[0]);
	closesocket(fds[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}

/*
 * TEST-TITLE sctp_sendmsg/short_addrlen
 * TEST-DESCR: On a 1-M socket, create an association.
 * TEST-DESCR: Send to an address with a short addr length argument.
 * TEST-DESCR: Validate it fails.
 */
DEFINE_APITEST(sctp_sendmsg, short_addrlen)
{
	int fds[2], result, n;
	sctp_assoc_t ids[2];
	struct sockaddr_in addr;
	socklen_t size;

	fds[0] = fds[1] = -1;
	result = sctp_socketpair_1tom(fds, ids, 1);
	if (result < 0)
		return strerror(errno);
	
	size = (socklen_t)sizeof(addr);
	memset((void *)&addr, 0, size);
	(void)getsockname(fds[0], (struct sockaddr *)&addr, &size);

	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	n = sctp_sendmsg(fds[0], "Hello", 5, (struct sockaddr *)&addr,
			 size - 1, 0, 0, 0, 0, 0);
#if !defined(__Windows__)
	close(fds[0]);
	close(fds[1]);
#else
	closesocket(fds[0]);
	closesocket(fds[1]);
#endif
	
	if (n < 0) {
		return NULL;
	} else {
		return "sctp_sendmsg was successful";
	}
}
