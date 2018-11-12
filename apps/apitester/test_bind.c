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
 * TEST-TITLE bind/port_s_a_s_p
 * TEST-DESCR: (port specifed adress specfied port )
 * TEST-DESCR: On a 1-1 socket, bind to
 * TEST-DESCR: a specified port and address and
 * TEST-DESCR: validate we get the port.
 */
DEFINE_APITEST(bind, port_s_a_s_p)
{
	int fd;
	unsigned short port;
	
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	if (sctp_bind(fd, INADDR_LOOPBACK, 12345) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	port = sctp_get_local_port(fd);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
	
	if (port != 12345)
		return "Wrong port";
	else
		return NULL;
}

/*
 * TEST-TITLE bind/v4tov6_s_a_s_p
 * TEST-DESCR: (specifed adress specfied port )
 * TEST-DESCR: On a 1-1 socket v6, bind to
 * TEST-DESCR: a specified port and address (v4) and
 * TEST-DESCR: validate we get the port.
 */
DEFINE_APITEST(bind, v4tov6_s_a_s_p)
{
	int fd;
	unsigned short port;
	
	if ((fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	if (sctp_bind(fd, INADDR_LOOPBACK, 12345) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	port = sctp_get_local_port(fd);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
	
	if (port != 12345)
		return "Wrong port";
	else
		return NULL;
}

/*
 * TEST-TITLE bind/v4tov6_w_a_s_p
 * TEST-DESCR: (without adress specfied port )
 * TEST-DESCR: On a 1-1 socket v6, bind to
 * TEST-DESCR: a specified port and address set to v4 INADDR_ANY
 * TEST-DESCR: validate we get the port.
 */
DEFINE_APITEST(bind, v4tov6_w_a_s_p)
{
	int fd;
	unsigned short port;
	
	if ((fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	if (sctp_bind(fd, INADDR_ANY, 12345) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	port = sctp_get_local_port(fd);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
	
	if (port != 12345)
		return "Wrong port";
	else
		return NULL;
}

/*
 * TEST-TITLE bind/v4tov6only_w_a
 * TEST-DESCR: (without adress)
 * TEST-DESCR: On a 1-1 socket v6 set for v6 only.
 * TEST-DESCR: Bind a specified port and address set to v4 INADDR_ANY
 * TEST-DESCR: validate we fail.
 */
DEFINE_APITEST(bind, v4tov6only_w_a)
{
	int fd, result;
	
	if ((fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);
	
	if (sctp_enable_v6_only(fd)	< 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	result = sctp_bind(fd, INADDR_ANY, 12345);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return NULL;
	else
		return "bind() was successful";
}

/*
 * TEST-TITLE bind/v4tov6only_s_a
 * TEST-DESCR: (specified adress)
 * TEST-DESCR: On a 1-1 socket v6 set for v6 only.
 * TEST-DESCR: Bind a specified port and address set to v4 LOOPBACK
 * TEST-DESCR: validate we fail.
 */
DEFINE_APITEST(bind, v4tov6only_s_a)
{
	int fd, result;
	
	if ((fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);
	
	if (sctp_enable_v6_only(fd)	< 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	result = sctp_bind(fd, INADDR_LOOPBACK, 12345);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
		
	if (result)
		return NULL;
	else
		return "bind() was successful";
}

/*
 * TEST-TITLE bind/same_port_s_a_s_p
 * TEST-DESCR: (specified adress specified port)
 * TEST-DESCR: On a 1-1 socket.
 * TEST-DESCR: Bind a specified port and address. Then
 * TEST-DESCR: attempt to bind the same address on another
 * TEST-DESCR: socket, validate we fail.
 */
DEFINE_APITEST(bind, same_port_s_a_s_p)
{
	int fd1, fd2, result;
	
	if ((fd1 = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);
		
	if (sctp_bind(fd1, INADDR_LOOPBACK, 12345) < 0) {
#if !defined(__Windows__)
		close(fd1);
#else
		closesocket(fd1);
#endif
		return strerror(errno);
	}
	
	if ((fd2 = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);

	result = sctp_bind(fd2, INADDR_LOOPBACK, 12345);
	
#if !defined(__Windows__)
	close(fd1);
	close(fd2);
#else
	closesocket(fd1);
	closesocket(fd2);
#endif
	
	if (result < 0)
		return NULL;
	else
		return "bind was successful";
}

/*
 * TEST-TITLE bind/duplicate_s_a_s_p
 * TEST-DESCR: (specified adress specified port)
 * TEST-DESCR: On a 1-1 socket.
 * TEST-DESCR: Bind a specified port and address. Then
 * TEST-DESCR: attempt to bind the same address/port
 * TEST-DESCR: on the same socket, validate we fail.
 */
DEFINE_APITEST(bind, duplicate_s_a_s_p)
{
	int fd, result;
	
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);

	if (sctp_bind(fd, INADDR_LOOPBACK, 1234) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}
	
	result = sctp_bind(fd, INADDR_LOOPBACK, 1234);
	
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
	
	if (result < 0)
		return NULL;
	else
		return "bind was successful";
}

/*
 * TEST-TITLE bind/refinement
 * TEST-DESCR: On a 1-1 socket.
 * TEST-DESCR: Bind a specified port and with address INADDR_ANY. 
 * TEST-DESCR: validate that binding the same socket to
 * TEST-DESCR: a more specific address (the loopback) fails.
 */
DEFINE_APITEST(bind, refinement)
{
	int fd, result;
	
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
		return strerror(errno);

	if (sctp_bind(fd, INADDR_ANY, 1234) < 0) {
#if !defined(__Windows__)
		close(fd);
#else
		closesocket(fd);
#endif
		return strerror(errno);
	}

	result = sctp_bind(fd, INADDR_LOOPBACK, 1234);
#if !defined(__Windows__)
	close(fd);
#else
	closesocket(fd);
#endif
	
	if (result == 0)
		return "bind was successful";
	else
		return NULL;
}
