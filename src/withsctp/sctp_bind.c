/* Wrap bind() to force the protocol for STREAM connections to SCTP.
 * 
 * Thanks to Midgard Security Services for
 * http://www.securiteam.com/tools/3D5PTR5QAE.html
 * from whence I cribbed the code to find the old bind().
 * 
 * gcc sctp_socket.c sctp_bind.c -o sctp_socket.so -ldl -shared -O2 -s
 * export LD_PRELOAD=./sctp_socket.so
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
#include <string.h> /* for strncmp() */
#include <stdio.h>
#include "sctp_socket.h"

/* IPPROTO_SCTP SHOULD be defined in
 * /usr/include/linux/in.h but probably isn't.
 * It is an enum element, not a #define, so we can't easily check.
 */
#define SHOULD_IPPROTO_SCTP 132

int
bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
{
    _sctp_load_libs();

    /* STUB.  The intent is to allow us to substitute an elaborate call to
     * bindx() for the initial call to bind().  TBD.
     */

    return (real_bind)(sockfd, my_addr, addrlen);
}
