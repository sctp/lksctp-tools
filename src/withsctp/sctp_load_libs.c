/* Load the real underlying functions for withsctp and related scripts.
 *
 * Copyright 2003 La Monte HP Yarroll <piggy@acm.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. 
 *    2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with
 * the distribution.
 *    3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */
#include <stdio.h>
#include <stdlib.h>
#include "sctp_socket.h"

int (*real_bind)(int  sockfd, const struct sockaddr *my_addr, socklen_t addrlen);
int (*real_socket)(int domain, int type, int protocol);
int (*real_setsockopt)(int s, int level, int optname, const void *optval,
		       socklen_t optlen);	
static void *lib_handle = NULL;

void
_sctp_load_libs(void)
{
    if (NULL != lib_handle) return; /* Only init once.  */

    if (!(lib_handle = dlopen("libc.so", RTLD_LAZY))) {
	if (!(lib_handle = dlopen("libc.so.6", RTLD_LAZY))) {
	    fprintf(stderr, "error loading libc!\n");
	    exit (1);
	}
    }
    
    if (!(real_socket = dlsym(lib_handle, "socket"))) {
	fprintf(stderr, "socket() not found in libc!\n");
	exit (1);
    }

    if (!(real_bind = dlsym(lib_handle, "bind"))) {
	fprintf(stderr, "bind() not found in libc!\n");
	exit (1);
    }

    if (!(real_setsockopt = dlsym(lib_handle, "setsockopt"))) {
	fprintf(stderr, "setsockopt() not found in libc!\n");
	exit (1);
    }
}
