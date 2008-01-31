/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2000, 2003
 * Copyright (C) 1999 Cisco and Motorola
 *
 * This file is part of the SCTP kernel Implementation
 *
 * ft_frame_lost_cwr
 *
 * This is Functional Test for the SCTP kernel reference
 * implementation state machine.
 *
 * Regression test a bug we had were we would not quiet the sender in
 * the case of a lost CWR.
 *
 * Set up a link, send message from sk1 to sk2.  Drop a data packet and then
 * congest the next packet.  This tests a hole in our current logic where
 * we won't handle a lost CWR because we think we already handled it.
 * This additionally lets us get through the bakeoff kamikazee test as
 * we will now try to always quiet the sender even if we have no
 * cwnd variable work to do.
 *
 * The SCTP implementation is free software;
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
 *    Jon Grimm         <jgrimm@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */


#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <errno.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in loop1, loop2;
	uint8_t *message01 = "First message from A!\n";
        int error;

        /* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);
	loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.sin_port = htons(SCTP_TESTPORT_2);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message01);

	/* Now, let ep2 send message to ep1 to cause INIT collision. */

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	test_run_network();
	if (error != 0) { DUMP_CORE; }

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	test_frame_get_message(sk2, message01);

	/* Now drop a packet, then send a congested packet. This
	 * should send a ECNE with the outgoing SACK.
	 */
	test_congest_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message01);
	test_run_network();

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message01);
	test_run_network();

	/* Drop the CWR, so that sk1 thinks it has already sent
	 * a CWR, for the next ECNE "lowest tsn". 
	 */
	test_kill_next_packet(SCTP_CID_ECN_CWR);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message01);
	test_run_network();

	/* Now step through the packet exchange.  The bug would not
	 * send a CWR to "quiet" the ECNE sender.  We've already
	 * performed the cwnd reduction, so we just resend a CWR
	 * to ack that we've done so. 
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message01);
	if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	if (test_step(SCTP_CID_ECN_ECNE, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Make sure that the CWR gets resent. */
	if (test_step(SCTP_CID_ECN_CWR, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* We are really done with this test at this point. */

	error = test_run_network();
	if (!error) 
		printf("\n\n%s passed\n\n\n", argv[0]);

	/* If we've made it this far the test has passed. */
	exit(0);

}

