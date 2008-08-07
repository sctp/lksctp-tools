/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
 * Copyright 2008 Hewlett-Packard Development Company, L.P.
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
 *    Daisy Chang <tcdc@us.ibm.com>
 *
 * Re-written by
 *    Vlad Yasevich <vladislav.yasevich@hp.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* 
 * This is a functional test for the SCTP kernel implementation.
 * It test different fast retransmit scenarios:
 *
 * Test 1:  The first data packet of the association is reported missing 3
 *   times.  This is there to test a bug that used to exist in our CACC
 *   algorithm.
 *
 * Test 2:  Fast-retransmission is lost and causes a T3-RTX timeout.  This
 *   is to test a bug that we had wrt timing out chunks correctly.
 *
 * Test 3:  Multiple chunks are reported missing at the same time.  We must
 *   only fast-rtx 1 MTU worth of data.  We can not fast retransmit multiple
 *   packets wort of data.  Subsequent retransmissions will occure once
 *   fast-rtx is acknowledged.
 *
 * Test 4:  Two gaps are reported.  This test should make sure that cwnd
 *   is not affected multiple times and that fast recorvery is correctly
 *   implemented and exited.
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
	void *msg_buf;
	int error;

	/* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();

	sctp_rto_initial = 20;
	sctp_rto_min = 20;

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
	/* Send the first messages.  This will create the association.  */
	error = sctp_connect(sk1, (struct sockaddr *)&loop2, sizeof(loop2));
	if (0 != test_run_network()) { DUMP_CORE; }

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	t1 = asoc1->peer.primary_path;

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

	msg_buf = test_build_msg(1024);
	
	/* TEST 1:
	 * Test fast retransmission of the very first data chunk
	 * Force the following scenario (we send in pairs so as to not
	 * wait for SACK timeouts)
	 *
	 * DATA1 (kill) ----->
	 * DATA2        ----->
	 * DATA3        ----->
	 * DATA4        ----->
	 * 
	 * DATA1 should be fast-retransmitted after we got SACK #3.
	 */
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_run_network_once(TEST_NETWORK0);

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	/* Expecting the SACK for the last message, this will #3 */
	if (test_step(SCTP_CID_SACK, TEST_NETWORK0) <= 0)
		DUMP_CORE;

	/* DATA will be fast-rtx'ed */
	if (test_step(SCTP_CID_DATA, TEST_NETWORK0) <= 0)
		DUMP_CORE;

	/* process DATA */
	if (test_run_network_once(TEST_NETWORK0) < 0)
		DUMP_CORE;

	/* Send one more message, to ellicit a SACK */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (test_step(SCTP_CID_SACK, TEST_NETWORK0) <= 0)
		DUMP_CORE;

	if (0 != test_run_network()) { DUMP_CORE; }
	
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }


	/* TEST 2:
	 * Test fast retransmission and subsequent timeouts
	 * Force the following scenario (we send in pairs so as to not
	 * wait for SACK timeouts)
	 *
	 * DATA1        ----->
	 * DATA2 (kill) ----->
	 * DATA3        ----->
	 * DATA4        ----->
	 * DATA5        ----->
	 * 	        <---- SACK (CTSN=1)
	 *              <---- SACK (CTSN=1, GAP = 3)
	 *              <---- SACK (CTSN=1, GAP = 3-4)
	 *              <---- SACK (CTSN=1, GAP = 3-5)
	 * DATA2 (FAST) ----->
	 *              <---- SACK (Kill)
	 * 
	 * DATA2 should be retransmitted again afater timeout.
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_run_network_once(TEST_NETWORK0);

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	/* Eat the first SACK */
	test_run_network_once(TEST_NETWORK0);

	jiffies += t1->rto - 1;

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network())
		{ DUMP_CORE; }

	if (0 != test_run_network())
		{ DUMP_CORE; }

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	test_kill_next_packet(SCTP_CID_SACK);
	if (0 != test_run_network()) { DUMP_CORE; }

	jiffies += 2;
	if (0 != test_run_network()) { DUMP_CORE; }

	jiffies += t1->rto + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* Because of t3-timeout above, the cwnd got dropped to 1 MTU.
	 * Restore it back to something we can work with
	 */
	t1->cwnd = 6000;
	t1->ssthresh = 6000;

	/* TEST 3:
	 * Test fast retransmission followed by retrnasmission on
	 * SACK which moves the cumulative tsn.
	 * Force the following scenario (we send in pairs so as to not
	 * wait for SACK timeouts)
	 *
	 * DATA1        ----->
	 * DATA2 (kill) ----->
	 * DATA3 (kill) ----->
	 * DATA4        ----->
	 * DATA5        ----->
	 * DATA6        ----->
	 * 	        <---- SACK (CTSN=1)
	 *              <---- SACK (CTSN=1, GAP = 4)
	 *              <---- SACK (CTSN=1, GAP = 4-5)
	 *              <---- SACK (CTSN=1, GAP = 4-6)
	 * DATA2 (FAST) ----->
	 *              <---- SACK (CTSN=2, GAP = 4-6)
	 * DATA3 (rtx flush) --->
	 *              <---- SACK (CTSN=6)
	 * 
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_run_network_once(TEST_NETWORK0);

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_run_network_once(TEST_NETWORK0);

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_run_network_once(TEST_NETWORK0);

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	/* miss counter will be 1 */
	if (0 != test_run_network()) 
		{ DUMP_CORE; }
	
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	/* miss counter will be 2 */
	if (0 != test_run_network())
		{ DUMP_CORE; }

	jiffies += t1->rto - 2;

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network())
		{ DUMP_CORE; }

	if (0 != test_run_network())
		{ DUMP_CORE; }

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }


	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* Because of t3-timeout above, the cwnd got dropped to 1 MTU.
	 * Restore it back to values we need for the next test.
	 */
	t1->cwnd = 14000;
	t1->ssthresh = 16000;
	asoc1->max_burst = 10;

	/*
	 * Test 4:
	 *
	 * Test when multiple chunks need to be fast retransmitted at
	 * different times
	 *
	 * DATA - (lost) ->
	 * DATA ---------->
	 * DATA - (lost) ->
	 * DATA ---------->
	 * DATA ---------->
	 * DATA ---------->
	 * DATA ---------->
	 */

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	jiffies++;
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	jiffies++;
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* At this point we enter fast recovery */
	if (!t1->fast_recovery || t1->cwnd < 7000)
		DUMP_CORE;

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	if (test_step(SCTP_CID_SACK, TEST_NETWORK0) <= 0)
		DUMP_CORE;

	if (test_step(SCTP_CID_DATA, TEST_NETWORK0) <= 0)
		DUMP_CORE;

	/* Make sure we dont' touch cwnd again */
	if (t1->cwnd < 7000)
		DUMP_CORE;

	if (0 != test_run_network()) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (0 != test_run_network()) { DUMP_CORE; }
	
	printk("\n\n%s tests passed\n\n\n", argv[0]);
	return 0;
}
