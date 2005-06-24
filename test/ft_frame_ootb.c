/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * The SCTP reference implementation is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * The SCTP reference implementation is distributed in the hope that it 
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
 *    lksctp developers <sctp-developers-list@cig.mot.com>
 * 
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by: 
 *    La Monte H.P. Yarroll <piggy@acm.org>
 *    Daisy Chang <daisyc@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* 
 * This is a functional test for the SCTP kernel reference implementation.
 *
 * RFC 8.4, a SCTP packet is called an "out of the blue" packet if it is
 * correctly formed, i.e., passed the receiver's checksum verification, but 
 * the receiver is not able to identify the association to which this 
 * packet belongs.
 * We test the SCTP out-of-the-blue(OOTB) handling with the following 
 * scenarios :
 *
 * 1. Open sk1 and try to send a message to a non-existent endpoint. 
 * An ABORT should be returned, and an event should be generated.
 *
 * 2. Open sk2, however, send a message from sk1 to sk2 by using broadcast
 * address. This should result into a packet discard case, no association 
 * should be created. 
 * 
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h> 
#include <funtest.h>


int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
	char *messages = "Don't worry, be happy!";
	struct sk_buff *skb;


	/* Do all that random stuff needed to make a sensible
	 * universe.
	 */
	init_Internet();
	sctp_init();

	/* Create an endpoint which will talk to a non-existent endpoint.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1  */
        addr1.v4.sin_family = AF_INET;
        addr1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        addr1.v4.sin_port = htons(SCTP_TESTPORT_1);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	/**** Case 1 ****/

	/* Send out a message through sk1 to a non-existent endpoint.
	 * The receiver side would treat any of these packets as OOTB
	 * packets. In this case, an INIT would arrive without any 
	 * endpoint to be associated with. An ABORT should be returned.
	 */

	addr2.v4.sin_family = AF_INET;
        addr2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        addr2.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_frame_send_message(sk1, (struct sockaddr *)&addr2, messages);

	if ( test_run_network() ) DUMP_CORE;

	/* sk1 should get an event for no association can be established.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);

	printk("\n\n%s case 1 passed\n\n\n", argv[0]);

	/**** Case 2 ****/

	/* Setup sk2 to be an listening endpoint. However, try to send a 
	 * message from sk1 to sk2 by using the broadcast address as the 
	 * destination address.  For the receiving side, the INIT packet 
	 * should be handled as an OOTB packet. The packet
	 * would be discarded. No association should be established. 
	 */

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		skb->nh.iph->daddr = SCTP_IP_BCAST;
	} else {
		DUMP_CORE;
	}

	if ( test_run_network() ) DUMP_CORE;

	/* There should be no association between sk1 and sk2. 
	 * Make sure that sk2 has not received any messages from sk1. 
	 */
	test_frame_get_message(sk2, NULL); 

	printk("\n\n%s case 2 passed\n\n\n", argv[0]);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);


	exit(0);

} /* main() */
