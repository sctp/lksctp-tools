/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 *
 * ft_frame_nobind.c
 * This is a functional test for the SCTP kernel implementation.
 *
 * This test will test the SCTP auto-bind capability defined as a 
 * UDP-style API support:
 * <draft-ietf-tsvwg-sctpsocket-01.txt>
 * 3.1.2 bind() - UDP Style Syntax
 * If a bind() or sctp_bindx() is not called prior to a sendmsg() call that 
 * initiates a new association,, the system picks an ephemeral port and 
 * will choose an address set equivalent to binding with a wildcard address. 
 *
 * The SCTP implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * the SCTP implementation  is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.  
 * 
 * Please send any bug reports or fixes you make to one of the
 * following email addresses:
 *
 * Daisy Chang <daisyc@us.ibm.com>
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */                                                                        

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <funtest.h>

extern struct net_device *dev_base;
extern struct net_device eth2_dev;
 

int
main(int argc, char *argv[])
{
	int pf_class;
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr3;
	char *messages = "Don't worry, be happy!";
#if TEST_V6
	struct in6_addr ipv6_loopback = SCTP_IN6ADDR_LOOPBACK_INIT;
#endif /* TEST_V6 */

	/* Do all that random stuff needed to make a sensible
	 * universe.
	 */
	init_Internet();
	sctp_init();

#if TEST_V6
	pf_class = PF_INET6;
	addr1.v6.sin6_family = AF_INET6;
	addr1.v6.sin6_addr= ipv6_loopback;
	addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	pf_class = PF_INET;
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = INADDR_ANY;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind sk1 with INADDR_ANY  */

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}
        
	/* sk2 is not bound at all */

	/* Send a message from sk2 to sk1.  This will create the association 
	 * from sk2 to sk1.
	 */
#if TEST_V6
	addr3.v6.sin6_family = AF_INET6;
	addr3.v6.sin6_addr= ipv6_loopback;
	addr3.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif

	test_frame_send_message(sk2, (struct sockaddr *)&addr3, messages);

	if ( test_run_network() ) DUMP_CORE;

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, messages);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

	exit(0);

} /* main() */
