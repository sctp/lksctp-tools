/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * These functions frob the sctp nagle structure.
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
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 * 
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by: 
 *    Daisy Chang <tcdc@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* 
 * This is a functional test for the SCTP kernel reference implementation.
 * This test is focused on testing a bug regarding the fast retransmit and
 * the cwnd limit.
 *
 * RFC 7.2.4 & the Implementers Guide 2.8.
 *
 * 3) Determine how many of the earliest (i.e., lowest TSN) DATA chunks
 *    marked for retransmission will fit into a single packet, subject
 *    to constraint of the path MTU of the destination transport address
 *    to which the packet is being sent. Call this value K. Retransmit
 *    those K DATA chunks in a single packet. When a Fast Retransmit is
 *    being performed the sender SHOULD ignore the value of cwnd and
 *    SHOULD NOT delay retransmission.
 *
 * There is a bug in our code which always perform the cwnd check against
 * the flightsize, regardless if we are sending for fast retransmit or not.
 * This testcase is supposed to expose the bug and verify the code fix for
 * it. 
 *
 * The test scenario is 
 * - To create a situation where the flight size would equal or
 * be greater than the possible cwnd value.
 * - Drop packets, create a big gap (big flight size), and force a fast
 *   retransmit.
 * - Make sure that all of the dropped packets are sent as fast retransmit.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sctp_transport *t1, *t2;
	struct sock *sk1, *sk2;
	struct sockaddr_in loop1, loop2;
	struct list_head *lchunk1;
	struct sctp_chunk *chunk1;
	void *msg_buf;
	int error;
	struct bare_sctp_packet *packet;
	struct sk_buff *skb;
	int count;

	/* Do all that random stuff needed to make a sensible universe.  */
	sctp_init();

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind this sockets to the test ports.  */
	loop1.sin_family = AF_INET;
	loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.sin_port = htons(SCTP_TESTPORT_1);

	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }

	loop2.sin_family = AF_INET;
	loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.sin_port = htons(SCTP_TESTPORT_2);

	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }

	/* We now do Cookie-Echo bundling as much as possible, so
	 * get this out of the way for the rest of the tests.
	 */
	msg_buf = test_build_msg(100);
	/* Send the first messages.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	/* Get the primary transport. */	
	t1 = asoc1->peer.primary_path;

	if (0 != test_run_network()) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	t2 = asoc2->peer.primary_path;

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, msg_buf);

	/* Verify the initial Congestion Parameters. */
	test_verify_congestion_parameters(t1, 3000, 32768, 0, 0);

	free(msg_buf);
	msg_buf = test_build_msg(1352);
	
	/* To create the situation where the flight size would equal or
	 * be greater than the possible cwnd value - the max of cwnd/2 or
	 * 2*mtu - when we force a fast retransmit later.
	 */

	/* Send 2 messages. */
	/* The SACK received for these messages will increase the cwnd by
	 * 1 mtu. 
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	test_verify_congestion_parameters(t1, 4500, 32768, 0, 1352);

	if (0 != test_run_network()) { DUMP_CORE; }

	test_verify_congestion_parameters(t1, 4500, 32768, 0, 0);

	/* Send another 4 messages. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* At this point, the receiver has acked all the sent data and
	 * the cwnd is increased again. */
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 0);

	/* Send 6 more messages. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 7500, 32768, 0, 0);

	/* Send 4 messages and drop all of them.
	 * This would make the flight size grow up to 5408.
	 */
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }

	/* No SACK is received, so the flight_size stays as 5408.
	 * And the cwnd have been adjusted by the max burst value - 
	 * by default, 4 * 1500 (MTU).
	 */
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 5408);

	/* Get a reference to the chunk from the transmitted list. */
	lchunk1 = t1->transmitted.next;	
	chunk1 = list_entry(lchunk1, struct sctp_chunk, transmitted_list);

	/* Send another message so that the receiver sends back a SACK. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 5408);
	if (1 != chunk1->tsn_missing_report) { DUMP_CORE; }

	/* Send another message so that the receiver sends back a SACK. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	if (2 != chunk1->tsn_missing_report) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 5408);

	/* Send another message so that the receiver sends back a SACK. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	if (3 != chunk1->tsn_missing_report) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 5408);

	/* Send another message so that the receiver sends back a SACK. */
	/* This time, the tsn_missing_report will reach 4, which will 
	 * trigger the fast retransmit right away.  
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	/* Run network twice to get the 4th SACK processed. */
	if (test_run_network_once(TEST_NETWORK0) < 0) 
		{ DUMP_CORE; }
	if (test_run_network_once(TEST_NETWORK0) < 0) 
		{ DUMP_CORE; }


	/* Let the fast retransmit do its work.  
	 * chunk->fast_retransmit cannot be verified as it is reset afte the
	 * chunk is sent. 
	 *
	 * At this point, the cwnd would have been reset to 3000 as 
	 * max(cwnd/2, 2*MTU).  As we try to generate packets for fast 
	 * retransmit, if the cwnd rule is still applied, the flight size
	 * can only grow up to 1352*3 = 4056, therefore, not all 4 chunks
	 * can be sent as what the implementors guide says. 
	 */

	/* Verify that 1 of the packets dropped should have been sent as
	 * fast retranmit and 2 other packets dropped are sent because of
	 * the avaialble window.
	 */
	count = 0;
	SK_FOR(struct sk_buff *, skb, *(get_Internet(TEST_NETWORK0)), {
		packet = test_get_sctp(skb->data);
		if (SCTP_CID_DATA == packet->ch.type) {
			count++;
		}
	});

	if (count != 3) {
		printk("Fast retransmit sent %d chunks out of 4\n", count);
		DUMP_CORE;
	}
	if (0 != test_run_network()) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	exit(0);

} /* main() */
