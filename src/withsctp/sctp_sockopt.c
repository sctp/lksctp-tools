/* Wrap socket() to force the protocol to SCTP for STREAM connections.
 * 
 * Thanks to Midgard Security Services for
 * http://www.securiteam.com/tools/3D5PTR5QAE.html
 * from whence I cribbed the code to find the old socket().
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
setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
    _sctp_load_libs();

    if ((IPPROTO_TCP == level) && (TCP_NODELAY == optname)) {
	level = SHOULD_IPPROTO_SCTP;
	optname = SCTP_NODELAY;
    }

    return (real_setsockopt)(s, level, optname, optval, optlen);
}
