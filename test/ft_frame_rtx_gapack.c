/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
 * 
 * This file is part of the SCTP kernel Implementation
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
 *    Jon Grimm  <jgrimm@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* 
 * This is a regression test for a bug reported in the field to both 
 * duplicate the condition logged, as well as, excercise the fix.
 *
 * The bug manifests itself as a deadlock condition, but the ultimate cause 
 * is that we retransmit gap acked TSNs that are sitting on the retransmit 
 * queue.
 *
 * In and of itself this is not a horrendous problem (as the peer should
 * be able to handle duplicated TSNs), however this causes later issues
 * with 'flight_size' calculations, where we "leak" bytes and eventually
 * get to a deadlock condition, thinking there is more than enough 
 * data already out on the network.
 *
 * The fix is to not retransmit gap-acked TSNs sitting on the retransmit
 * queue. 
 * 
 * This test case forces a scenario where a retransmission pending TSN
 * gets Gap-ACKed (by delaying a Gap-ACK SACK) and then a transmission
 * condition allows a TSN to be sent (where this is the next TSN on
 * the retransmission list.   Yes, quite contrived, but excercises the 
 * BUG sufficiently to show the condition, as well as, that such a 
 * condition no longer exists after the fix.
 *
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sctp_transport *t1, *t2;
	struct sock *sk1, *sk2;
	struct sockaddr_in loop1, loop2;
	void *msg_buf;
	int error;
	struct bare_sctp_packet *packet;
	sctp_data_chunk_t *data_chunk;
	struct sk_buff *skb, *skb_sack;
	int i, count;
	uint32_t tsn1, tsn_acked;

	/* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();
	
	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk1->sk_rcvbuf = 65536;
	sk2->sk_rcvbuf = 65536;

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

	free(msg_buf);
	msg_buf = test_build_msg(1352);

	/* Verify the initial Congestion Parameters. */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 0);

	/* Send 3 messages. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	test_verify_congestion_parameters(t1, 4380, 32768, 0, 1352);

	/* Process the rwnd update SACK sent after the third message is 
	 * read. 
	 */
	if (0 != test_run_network()) { DUMP_CORE; }

	/* At this point, the receiver has acked all the sent data. */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 0);

	/* Send 3 messages and drop all of them.
	 * Save their TSN's for subsequent verifications in retransmission.
	 */
	tsn1 = asoc1->next_tsn;
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }

	/* No SACK is received, so the flight_size stays as 4056. */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 4056);

	/* Force the retransmission for several times.
	 * Make sure that the chunks are transmitted in the same order
	 * every time the retransmission occurs.
	 */ 
	for (i = 0; i < 3; i++) {
		/* Force the retransmission timer to timeout. */
		jiffies = asoc1->peer.primary_path->T3_rtx_timer.expires + 1;
		test_run_timeout();

		count = 0;
		/* Look for the data chunk with the expected tsn. */
		SK_FOR(struct sk_buff *, skb, *(get_Internet(TEST_NETWORK0)), {
			packet = test_get_sctp(skb->data);
			data_chunk = (sctp_data_chunk_t *)&packet->ch;
			if (SCTP_CID_DATA == data_chunk->chunk_hdr.type) {
				if (tsn1 + count != 
					ntohl(data_chunk->data_hdr.tsn)) {
					printf("\nTSN is %x, should be %x\n",
					       ntohl(data_chunk->data_hdr.tsn),
					       tsn1 + count);
					printk("\n\n%s testcase 1 failed"
					       "\n\n\n", argv[0]);
					
					DUMP_CORE;
				}
			} else {
				DUMP_CORE;
			}
			count++;
		});

		/* Drop all the packets on network. */
		while ((skb = test_peek_packet(TEST_NETWORK0))) {
			test_kill_next_packet(SCTP_CID_DATA);
			if (test_run_network_once(TEST_NETWORK0) < 0) {
				DUMP_CORE; 
			}
		}

	}


	/* 
	 * Send out a new packet. This should trigger retransmission
	 * as well, according to RFC 2960 6.1 (C), but this retransmission
	 * is supposed to send out chunks which were not retransmitted last
	 * time around due to the MTU limit.
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	count = 0;
	/* Look for the data chunk with the expected tsn. */
	skb = test_peek_packet(TEST_NETWORK0);
	if (skb) {
		packet = test_get_sctp(skb->data);
		data_chunk = (sctp_data_chunk_t *)&packet->ch;
		if (SCTP_CID_DATA == data_chunk->chunk_hdr.type) {
			if (tsn1 + 1 != ntohl(data_chunk->data_hdr.tsn)) {
				printf("\nTSN is %x, should be %x\n",
					ntohl(data_chunk->data_hdr.tsn), 
					tsn1 + 1);
				printk("\n\n%s testcase 2 failed\n\n\n", 
					argv[0]); 
				DUMP_CORE;
			}
		} else {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	/* What TSN are we retransmitting. */
	skb = test_peek_packet(TEST_NETWORK0);
	packet = test_get_sctp(skb->data);
	data_chunk = (sctp_data_chunk_t *)&packet->ch;
	if (SCTP_CID_DATA == data_chunk->chunk_hdr.type) 
		tsn_acked =  ntohl(data_chunk->data_hdr.tsn);
	else 
		DUMP_CORE;

	/* Deliver first TSN */
	if (test_run_network_once(TEST_NETWORK0) < 0) {
		DUMP_CORE; 
	}

	skb = test_peek_packet(TEST_NETWORK0);
	packet = test_get_sctp(skb->data);
	data_chunk = (sctp_data_chunk_t *)&packet->ch;

	if (SCTP_CID_SACK != data_chunk->chunk_hdr.type) {
		DUMP_CORE;
	} else {
		skb_sack = skb_clone(skb, GFP_ATOMIC);
		skb_sack->sk = skb->sk;
	}

	/* Let's delay the SACK.  Copy it so we can put it back
	 * on the network again.
	 */
	test_kill_next_packet(SCTP_CID_SACK);
	if (test_run_network_once(TEST_NETWORK0) < 0) {
		DUMP_CORE; 
	}       
       

	/* Force the retransmission timer to timeout. */
	jiffies = asoc1->peer.primary_path->T3_rtx_timer.expires + 1;
	test_run_timeout();

	/* Drop all the packets on network. */
	while ((skb = test_peek_packet(TEST_NETWORK0))) {
		test_kill_next_packet(SCTP_CID_DATA);
		if (test_run_network_once(TEST_NETWORK0) < 0) {
			DUMP_CORE; 
		}
	}

	/* Reinsert the SACK that gap_acks the packet.  */
	skb_queue_tail(get_Internet(TEST_NETWORK0), skb_sack);
	if (test_run_network_once(TEST_NETWORK0) < 0) {
		DUMP_CORE; 
	}

	/* Check what we are not sending the Gap Acked TSN! */

	/* What TSN are we retransmitting?  Is it the 
	 * TSN that was Gap-ACKed? 
	 */
	skb = test_peek_packet(TEST_NETWORK0);
	packet = test_get_sctp(skb->data);
	data_chunk = (sctp_data_chunk_t *)&packet->ch;
	if (SCTP_CID_DATA == data_chunk->chunk_hdr.type) {
		if (tsn_acked ==  ntohl(data_chunk->data_hdr.tsn)) {

			/* This is a bug. */
			printk("Aaaaargh! TSN %x was retransmitted, but "
			       "it was already Gap Acked \n", tsn_acked);
			printk("BUG\n");
			DUMP_CORE;
		}
	} else 
		DUMP_CORE;

	/* Force the retransmission timer to timeout, so we'll retransmit
	 * everything we have left in the retransmit queue.
	 */
	jiffies = asoc1->peer.primary_path->T3_rtx_timer.expires + 1;
	test_run_timeout();

	if (0 != test_run_network()) { DUMP_CORE; }

	/* Everything should have been retransmitted and done. Read all
	 * 4 messages sent during network drops.
	 */

	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);


	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s testcase passed\n\n\n", argv[0]);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	exit(0);

} /* main() */
