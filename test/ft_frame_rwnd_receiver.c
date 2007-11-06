/* SCTP kernel reference Implementation 
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (C) 1999 Cisco And Motorola
 *
 * This is the Functional Test for testing the rwnd behavior of the SCTP
 * receiver.  
 *
 * This file is part of the SCTP kernel reference Implementation
 * 
 * The SCTP reference implementation is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation; either
 * version 2, or (at your option) any later version.
 * 
 * the SCTP reference implementation  is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ^^^^^^^^^^^^^^^^^^^^^^^^
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 * 
 * 
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Jon Grimm <jgrimm@us.ibm.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 */

#include <net/sctp/sctp.h>
#include <funtest.h>
#include <errno.h>

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1, *ep2;
        struct sctp_association *asoc1, *asoc2;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
        uint8_t *messages[] = {
                "associate",
                "This test loop will run fewer times the longer I make this string.  If you want to hit the TSN Map Limit I suggest using the string \"st\".",
                "The test frame has a bug!", /* We should NEVER see this... */
        };
        int error = 0;
	int rwnd;
	int msglen;
	int i, ngets;
	void *msg_buf;
	void *msgp;

        /* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk1->sk_rcvbuf = 65536;
	sk2->sk_rcvbuf = 65536;

        /* Bind these sockets to the test ports.  */
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
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        /* Send the first message.  This will create the association.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[0]);
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
        ep2 = sctp_sk(sk2)->ep;
        asoc2 = test_ep_first_asoc(ep2);

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent.  */
        test_frame_get_message(sk2, messages[0]);

	msglen = strlen(messages[1]) + 1;

        /* Now the real testing begins... */

	rwnd = asoc2->rwnd;

	/* 
	 *   Test #1
	 *   Compare rwnd before and after receiving a message.
	 */

	/* Send a message.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[1]);
	error = test_run_network();
	if (rwnd != asoc2->rwnd + msglen) {
                DUMP_CORE;
	}

        /* 
	 *   Test #2 
	 *   Read the received msg--rwnd should go back to its
         *   original value.
	 */

	test_frame_get_message(sk2, messages[1]); 
	if (rwnd != asoc2->rwnd) {
                DUMP_CORE;
        }

	/* 
	 *   Test #3 
	 *      Send fixed-length messages until there is no more room.
	 *      Send one more... rwnd should not change.
	 */
	sk2->sk_rcvbuf = 500000;
	while (msglen <= (rwnd = asoc1->peer.rwnd) ) {
		
		/* Send a message.  */
		test_frame_send_message(sk1, (struct sockaddr *)&loop2, 
					messages[1]);
		error = test_run_network();
		
		/* The TSN Map limits the number of TSNs that we can
		 * accept... otherwise we drop the chunks.
		 * We kick out if we don't see the rwnd progressing.
                 * [Even for tiny messages this SHOULD NEVER HAPPEN.
                 *  We probably have a bug somewhere in the TSN map
                 *  code. --piggy]
		 */

		if (rwnd == asoc1->peer.rwnd) {
			printk("Testcase error:\t"); 
			printk("msg is too small to exercise this test.\n");
			DUMP_CORE;
		}
		   
	} /* while (we have more rwnd than msglen) */

	/* Give peer the time to SACK.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Send a message.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[1]);

	/* The rwnd is allowed to slop over a maximumm of the association's
	 * frag_point.
	 */
	error = test_run_network();

#if 0
	/* Verify that the rwnd and rwnd_over are updated as expected. */
	if ((0 != asoc2->rwnd) && (asoc2->rwnd_over != (msglen - rwnd))) {
	        DUMP_CORE;
        }
#endif

        /* 
	 *   Test #4
	 *      Test Gratuitous SACK behavior.
	 *      Read out just under 1 PMTU worth of messages.  We should 
	 *      conservatively only generate the gratuitous SACK when
	 *      going over this limit.
	 */
	
	/* Make sure there is no SACK in the network. */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	ngets = asoc2->pathmtu/msglen + (asoc2->pathmtu%msglen?1:-1);
	/* Read out just enough data to not force a gratuitous SACK. */
	for (i = 0; i < ngets; i++) {
		test_frame_get_message(sk2, messages[1]); 
	}
	
	/* Test against excessive gratuitous SACK. */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Read one more message out of the receive buffer. */
	test_frame_get_message(sk2, messages[1]); 
        
	/* Test that gratuitous SACK has been submitted to the network. */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Read all the pending messages */
	while (asoc2->rwnd != 32768) {
		test_frame_get_message(sk2, messages[1]);
	}

	/* Test #5
	 *    Verify that rwnd is updated correctly even when the message is
	 *    fragmented. 
	 */
	rwnd = asoc2->rwnd;
	msg_buf = test_build_msg(2*asoc1->pathmtu);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Verify that rwnd is decreased correctly after receiving the
	 * fragmented message.
	 */
	if (asoc2->rwnd  != (rwnd - 2*asoc1->pathmtu))
		DUMP_CORE;

	test_frame_get_message(sk2, msg_buf); 

	/* Verify that rwnd is increased back to the original value after the
	 * message is read.
	 */
	if (asoc2->rwnd != rwnd)
		DUMP_CORE;

	/* Test #6
	 *    Verify that rwnd is updated correctly even when the message is
	 *    read partially. 
	 */
	rwnd = asoc2->rwnd;
	msg_buf = test_build_msg(30000);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Verify that rwnd is decreased correctly after receiving the
	 * fragmented message.
	 */
	rwnd = rwnd - 30000;
	if (asoc2->rwnd  != rwnd)
		DUMP_CORE;

	/* Read the big 30000 byte message using multiple recvmsg() calls in
	 * a loop with 2000 bytes per read.
	 */ 
	for (i = 0; i <= 14; i++) {
		msgp = msg_buf + i*2000;
        	test_frame_get_message2(sk2, msgp, 2000, 0,
					(i == 14)?MSG_EOR:0);
		/* Verify that rwnd is updated correctly after each partial
		 * read.
	 	 */
		rwnd = rwnd + 2000;
		if (asoc2->rwnd != rwnd)
			DUMP_CORE;
	}

        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);
        
	/* Give peer the time to SACK.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(0);

} /* main() */
