/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2002, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
 * 
 * This file is part of the SCTP kernel Implementation
 * 
 * These functions frob the sctp nagle structure.
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

int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
	union sctp_addr bindx_addr;
	void *msg_buf;
	struct sctp_association *asoc1, *asoc2;
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_transport *asoc2_t1, *asoc2_t2;
	struct sctp_chunk *chunk, *chunk1, *chunk2, *chunk3;

	/* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
	sctp_init();

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind sk1 with SCTP_ADDR_ETH0, port 1  */
        addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
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

	/* Add one more address eth1 to be bound to sk1.  */
        bindx_addr.v4.sin_family = AF_INET;
        bindx_addr.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
        bindx_addr.v4.sin_port = htons(SCTP_TESTPORT_1);

	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr,
		       sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR)) {
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
        addr3.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
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

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	asoc2_t1 = asoc2->peer.primary_path;

	/* Make sure that heartbeats are sent and all the paths are 
	 * confirmed.
	 */
	jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

	/*** Real test starts from here. ***/

	/* Send and drop the first message. */
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk2, (struct sockaddr *)&addr1, msg_buf); 
	if (test_run_network()) DUMP_CORE;

	/* The chunk should be on the primary path transmitted list. */ 
	chunk1 = test_get_chunk(&asoc2_t1->transmitted, 1);

	/* Force the retransmission timer. */
	jiffies += asoc2_t1->rto + 1;
	/* As it is a multi-homed association, the retransmitted message
	 * is sent on the second transport. Drop the retransmitted message.
	 */ 
	test_kill_next_packet(SCTP_CID_DATA);
	if (0 != test_run_timeout()) { DUMP_CORE; }
	if (test_run_network()) DUMP_CORE;

	asoc2_t2 = asoc2->peer.retran_path;

	/* The chunk should now have moved to the retransmit path transmitted
	   list.
	*/ 
	chunk = test_get_chunk(&asoc2_t2->transmitted, 1);
	if (chunk != chunk1)
		DUMP_CORE;

	/* Send and drop the second message. */
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk2, (struct sockaddr *)&addr1, msg_buf); 
	if (test_run_network()) DUMP_CORE;

	/* Get the second chunk from the primary path transmitted list. */
	chunk2 = test_get_chunk(&asoc2_t1->transmitted, 1);

	/* Send a third message. */ 
	test_frame_send_message(sk2, (struct sockaddr *)&addr1, msg_buf); 
	if (test_run_network())
		DUMP_CORE;

	/* Get the third chunk which should be added to the primary path
	 * transmitted list.
	 */
	chunk3 = test_get_chunk(&asoc2_t1->transmitted, 2);

	/* The SACK for the third message should have incremented the 
	 * missing report counter for chunk1 and chunk2 which are on 2
	 * different transport's transmitted lists.
	 */
	if (chunk1->tsn_missing_report != 1)
		DUMP_CORE;
	if (chunk2->tsn_missing_report != 1)
		DUMP_CORE;
	
	/* Force the retransmission timer. */
	jiffies += asoc2_t2->rto + 1;
	if (test_run_network()) DUMP_CORE;

	test_frame_get_message(sk1, msg_buf);
	test_frame_get_message(sk1, msg_buf);
	test_frame_get_message(sk1, msg_buf);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

	exit(0);
}
