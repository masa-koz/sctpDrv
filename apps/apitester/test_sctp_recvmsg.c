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

DEFINE_APITEST(sctp_recvmsg, rd_compl)
{
	int fd[2], n;
	int flags;
	char buffer[10];
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	if (send(fd[0], "Hello", 5, 0) != 5) {
#if !defined(__Windows__)
		close(fd[0]);
		close(fd[1]);
#else
		closesocket(fd[0]);
		closesocket(fd[1]);
#endif
		return "sending failed";
	}
	flags = 0;
	n = sctp_recvmsg(fd[1], buffer, 10, NULL, 0, NULL, &flags);

#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else if (n != 5) {
		return "Wrong length";
	} else if (flags != MSG_EOR) {
		return "Wrong flags";
	} else {
		return NULL;
	}
}

DEFINE_APITEST(sctp_recvmsg, rd_incompl)
{
	int fd[2], n;
	int flags;
	char buffer[10];
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	if (send(fd[0], "Hello", 5, 0) != 5) {
#if !defined(__Windows__)
		close(fd[0]);
		close(fd[1]);
#else
		closesocket(fd[0]);
		closesocket(fd[1]);
#endif
		return "sending failed";
	}
	flags = 0;
	n = sctp_recvmsg(fd[1], buffer, 1, NULL, 0, NULL, &flags);

#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else if (n != 1) {
		return "Wrong length";
	} else if (flags != 0) {
		return "Wrong flags";
	} else {
		return NULL;
	}
}

DEFINE_APITEST(sctp_recvmsg, msg_peek_in)
{
	int fd[2], n;
	int flags;
	char buffer[10];
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	if (send(fd[0], "Hello", 5, 0) != 5) {
#if !defined(__Windows__)
		close(fd[0]);
		close(fd[1]);
#else
		closesocket(fd[0]);
		closesocket(fd[1]);
#endif
		return "sending failed";
	}
	flags = MSG_PEEK;
	n = sctp_recvmsg(fd[1], buffer, 1, NULL, 0, NULL, &flags);

#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else if (n != 1) {
		return "Wrong length";
	} else if (flags != 0) {
		printf("flags = %x", flags);
		return "Wrong flags";
	} else {
		return NULL;
	}
}

DEFINE_APITEST(sctp_recvmsg, msg_eor_in)
{
	int fd[2], n;
	int flags;
	char buffer[10];
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	if (send(fd[0], "Hello", 5, 0) != 5) {
#if !defined(__Windows__)
		close(fd[0]);
		close(fd[1]);
#else
		closesocket(fd[0]);
		closesocket(fd[1]);
#endif
		return "sending failed";
	}
	flags = MSG_EOR;
	n = sctp_recvmsg(fd[1], buffer, 1, NULL, 0, NULL, &flags);

#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else if (n != 1) {
		return "Wrong length";
	} else if (flags != 0) {
		printf("flags = %x", flags);
		return "Wrong flags";
	} else {
		return NULL;
	}
}

DEFINE_APITEST(sctp_recvmsg, msg_notification_in)
{
	int fd[2], n;
	int flags;
	char buffer[10];
	
	if (sctp_socketpair(fd, 0) < 0)
		return strerror(errno);
	
	if (send(fd[0], "Hello", 5, 0) != 5) {
#if !defined(__Windows__)
		close(fd[0]);
		close(fd[1]);
#else
		closesocket(fd[0]);
		closesocket(fd[1]);
#endif
		return "sending failed";
	}
	flags = MSG_NOTIFICATION;
	n = sctp_recvmsg(fd[1], buffer, 1, NULL, 0, NULL, &flags);

#if !defined(__Windows__)
	close(fd[0]);
	close(fd[1]);
#else
	closesocket(fd[0]);
	closesocket(fd[1]);
#endif
	
	if (n < 0) {
		return strerror(errno);
	} else if (n != 1) {
		return "Wrong length";
	} else if (flags != 0) {
		printf("flags = %x", flags);
		return "Wrong flags";
	} else {
		return NULL;
	}
}
