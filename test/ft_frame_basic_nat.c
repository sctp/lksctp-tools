/*
 * (C) Copyright IBM Corp. 2002, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
 * 
 * The SCTP  implementation is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * The SCTP implementation is distributed in the hope that it 
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
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 * 
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by: 
 *    Sridhar Samudrala <sri@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* This is a functional test that verifies the fix for BUG#611927. This bug
 * exposes a problem where tsn_missing_report is not incremented for all
 * eligible chunks due to the incorect calculation of highest new tsn in 
 * the incoming SACK when the chunks are sent across multiple transports.
 * This test can be extended in future to include other multihoming tests.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

#define BINDX_ADDR_COUNT 1

int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
	void *msg_buf;

	/* Jump start the Internet. */
	init_Internet();

	/* Do all that random stuff needed to make a sensible universe. */
	sctp_init();

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind sk1 with SCTP_ADDR_ETH0, port 1  */
        addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_GLOBAL_ETH0;
        addr1.v4.sin_port = htons(SCTP_TESTPORT_1);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	/* Bind sk2 with SCTP_ADDR_ETH0, port 2 */
        addr2.v4.sin_family = AF_INET;
        addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr2.v4.sin_port = htons(SCTP_TESTPORT_2);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	/* Send a message from sk2 to sk1 by using a sk1 address that was
	 * added by bindx().  
	 * This will create the association from sk2 to sk1's ETH1.  
	 */
	addr3.v4.sin_family = AF_INET;
        addr3.v4.sin_addr.s_addr = SCTP_GLOBAL_ETH0;
        addr3.v4.sin_port = htons(SCTP_TESTPORT_1);

	msg_buf = test_build_msg(20);
	test_frame_send_message(sk2, (struct sockaddr *)&addr3, msg_buf);

	if (test_run_network())
		DUMP_CORE;

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, msg_buf);


	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

	exit(0);
}
