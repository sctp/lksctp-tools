/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco And Motorola
 *
 * This is the Functional Test for testing the rwnd behavior of the SCTP
 * sender.  
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
 * Jon Grimm <jgrimm@us.ibm.com>
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/cache.h> /* For SMP_CACHE_BYTES */
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;
        struct sctp_endpoint *ep2;
        struct sctp_association *asoc2;

        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in loop1;
        struct sockaddr_in loop2;
	int inflight;
        uint8_t *messages[] = {
                "first",
		"second",
		"third",		
                "The rwnd test loop will run fewer times the longer I make "
		"this string, since it will fill the receive window at a "
		"faster pace.",
		"Leftover message after rwnd filled. This sould be as long "
		"or longer than the prevous message.  Otherwise, you'll "
		"squeak another message into rwnd and the test doesn't work "
		"right.",
                "The test frame has a bug!", /* We should NEVER see this... */
        };

        int error = 0;
	int rwnd, sent;
	int msglen;

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk1->sk_sndbuf = 200000;

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

        /* We should have seen a SACK in there... */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */

	msglen = strlen(messages[0]) + 1;

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the message that was received */
	test_frame_get_message(sk2, messages[0]);
	
        /* Now the real testing begins... */

	/* 
	 *   Test #1
	 *   Compare peer's rwnd before send, after send, and after SACK.
	 *   
	 */


	/* Save away RWND. */
	rwnd = asoc1->peer.rwnd;

	/* Check that the SACK a_rwnd we (sk1) got back from the
         * reciever (sk2) reflects the DATA that sk2 is acknowledging.
         * This test catches a bug where sk2 sends the SACK before it
         * updates its rwnd accounting.
         */
	printf("Testing that initial rwnd that we hold matches peer's.\n");
	if (rwnd != asoc2->rwnd - msglen) {
		DUMP_CORE;
	}

        /* Give peer the time to SACK, if it has not done so already.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();

	/* Save away rwnd. */
	rwnd = asoc1->peer.rwnd;
	
        /* Send a second message.  */
	msglen = strlen(messages[1]) + 1;
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[1]);
	
	/* We've submitted to the network but the peer has not been
	 * given a chance to SACK. 
	 */
	printf("Testing that we updated our local view of peer's rwnd.\n");
	if (rwnd - msglen  != asoc1->peer.rwnd) {
		DUMP_CORE;
	}

	error = test_run_network();

	/* Give peer the time to SACK, if it has not done so already. */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();

	/* Update saved rwnd to hold rwnd before we send our 3rd message. */
	rwnd = asoc1->peer.rwnd;
	

	/* Send a 3rd message.  Test that the SACK actually updates our
	 * view of the peer's rwnd.
	 */
	printf("Testing that rwnd gets updated by SACK.\n");
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[2]);
	msglen = strlen(messages[2]) + 1;
	
	/* We've submitted to the network but the peer has not 
	 * been given a chance to SACK.
	 */
	if (rwnd - msglen != asoc1->peer.rwnd) {
		DUMP_CORE;
	}

	/* Let the internet deliver DATA to the receiver so that the 
	 * SACK timer will be started. 
	 */
	error = test_run_network_once(TEST_NETWORK0);

        /* First, let's modify our copy of the peer's rwnd, so we can make 
	 * sure it really changes when we get a SACK.
	 */
	asoc1->peer.rwnd = 0;

        /* Give peer the time to SACK, if it has not done so already. */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();

	/* Check that the peer rwnd got updated. */
	if (0 == asoc1->peer.rwnd) {
		DUMP_CORE;
	}
	
	/* Peer rwnd should match what we thought it should be - before
	 * we sent the third message. 
	 */
	if (rwnd - msglen != asoc1->peer.rwnd) {
                DUMP_CORE;
	}

	/* Clear out the receiver, by reading the messages we sent */
	test_frame_get_message(sk2, messages[1]);
	test_frame_get_message(sk2, messages[2]);
	
	/* Set cwnd equal to rwnd and max_burst to a high value so that data 
	 * packets are not blocked by the low inital value of cwnd and to 
	 * simplify the test.
	 */ 
	asoc1->peer.primary_path->cwnd = asoc1->peer.rwnd;
	asoc1->max_burst = 50;

        /* 
	 *   Test #2 
	 *   Let's fill up the peer's rwnd, before getting a chance to
	 *   receive any SACKs.  Make sure we stop sending out data.
	 */

	printf("Testing fill of peer rwnd, but dropping all SACKs.\n");
	msglen = strlen(messages[3]) + 1;	
	while (asoc1->peer.rwnd >= msglen) {
		test_frame_send_message(sk1, (struct sockaddr *)&loop2, 
					messages[3]);

		/* Drop SACK that may get sent due to DATA reception. */
		test_kill_next_packet(SCTP_CID_SACK);
		test_run_network();
		
		/* Drop any gratuitous SACK that may get sent due
		 * to DATA consumption.
		 */
		test_kill_next_packet(SCTP_CID_SACK);
		test_frame_get_message(sk2, messages[3]);
	} /* while (We still have room at the peer) */


	/* So, we now believe that there is no room in rwnd and that all
	 * of our data is still inflight (or at least un-SACKed).
	 * There is plenty of room in our peer's rwnd, however we do 
	 * not know it.
	 */

	inflight = asoc1->outqueue.outstanding_bytes;
	rwnd = asoc1->peer.rwnd;

        /* Reset slaughter to something harmless. */
	test_kill_next_packet(SCTP_CID_INIT);
        
	/* Send another message and make sure we don't put any more
	 * data bytes on to the wire.
	 */
	printf("Testing that calculated rwnd limit prevents transmission.\n");
	msglen = strlen(messages[4]) + 1;
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[4]);
	if (inflight != asoc1->outqueue.outstanding_bytes) {
		DUMP_CORE;
	}
	test_run_network();
	
	/* Force the retransmit timeout and see that it goes through. 
	 * Since timeouts reduce our outstanding bytes, we should get back
	 * down to a level where we can send _a_ retransmit packet.
	 * This should catch us up to our peer's real state, as this should
	 * force a SACK from our peer telling us that it has really accepted
	 * all the previously transmitted DATA.
	 */
        jiffies += asoc1->peer.primary_path->rto + 1;
	test_run_network();

	/* Give peer the time to SACK.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();

	/* We should be all caught up on our SACKs. */
	inflight = asoc1->outqueue.outstanding_bytes;	
	rwnd = asoc1->peer.rwnd;	


	/* Test that we have no bytes in flight after all data has been
	 * resent.  We should have no data in flight since all DATA has
	 * been acknowledged, but rwnd prevents us from sending.
	 */
	printf("Testing that we have no data in flight after SACK.\n");
	if (0 != inflight){
		DUMP_CORE;
	}
	
	/* Test that our calculation matches peer's calculation. */
	printf("Test that our calculations match our peer's view of rwnd.\n");
	if (asoc2->rwnd != asoc1->peer.rwnd) {
		DUMP_CORE;
	}

	/* There should be one left over message.. the one that we submitted
	 * to transmit but could not send because of rwnd limitations.  It
	 * should get resent once rwnd opens up.  
	 */

        /* Get the message that was received */
	test_frame_get_message(sk2, messages[4]);

	/* Reset cwnd and max_burst back to the expected values for the 
	 * remaining tests. 
	 */
	asoc1->peer.primary_path->cwnd = 2*asoc1->pathmtu;
	asoc1->max_burst = 4;

	/* Test #3
	 *   Fill our peer's rwnd due to not reading data out.
	 *   We should be able to probe for an opening in rwnd.
	 */
	sk2->sk_rcvbuf = 500000;
	msglen = strlen(messages[3]) + 1;
	sent = 0;
	while (asoc1->peer.rwnd >= msglen) {
		test_frame_send_message(sk1, (struct sockaddr *)&loop2, 
					messages[3]);
		test_run_network();
		sent++;
	} /* while still room at the peer */

        /* Force a final SACK to catch us up.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();


	inflight = asoc1->outqueue.outstanding_bytes;
	rwnd = asoc1->peer.rwnd;

        if (0 != inflight) { DUMP_CORE; }
        if (rwnd >= msglen) { DUMP_CORE; }

        /* Send another message.  We should be able to put a packet out on
	 * the wire to probe for rwnd changes.  This is different than the
	 * above test #2 where we were not able to send any DATA since
	 * we already had DATA sent which should do the probing.
	 */
	msglen = strlen(messages[4]) + 1;
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, 
				messages[4]);
        /* We do not need to increment 'sent' because that variable
         * only tracks the number of messages[3] data chunks
         * outstanding.  We extract this probe by hand later.
         */
	
	/* The amount of in-flight data should change, since we expect
         * to probe rwnd.
         */ 
	if (inflight != (asoc1->outqueue.outstanding_bytes - msglen)) {
		DUMP_CORE;
	}

        /* The peer may choose to accept our bytes anyway even though
	 * it does not have enough rwnd.  Let's force the issue by
	 * dropping any SACK.
	 */

        /* Deliver the probe chunk.  */
	error = test_run_network();

        /* Destroy the SACK.  */
	test_kill_next_packet(SCTP_CID_SACK);
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();


	/* Make some room for the message. */

        /* Get the messages that sk2 received, but don't let any SACKs
         * through.
         */
	test_frame_get_message(sk2, messages[3]);
	sent--;

	test_kill_next_packet(SCTP_CID_SACK);
        error = test_run_network();

	test_frame_get_message(sk2, messages[3]);
	sent--;

	test_kill_next_packet(SCTP_CID_SACK);
        error = test_run_network();

	/* Set to 'kill' to a harmless chunk type. */
	test_kill_next_packet(SCTP_CID_INIT);

	inflight = asoc1->outqueue.outstanding_bytes;

	/* We should have one packet 'inflight', since we lost our SACK. */
	if (inflight != msglen) {
		DUMP_CORE;
	}

	/* Force a retransmit timeout.  Since we lost all the SACKs,
	 * we should generate another probe.
	 */
        jiffies += asoc1->peer.primary_path->rto + 1;
	test_run_network();

        /* Finally let a SACK through.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();

	/* This time we should get our data accepted and SACKed.  */
	printf("Test that there is no more data to send after retransmit.\n");
	inflight = asoc1->outqueue.outstanding_bytes;
	if (inflight != 0) {
		DUMP_CORE;
	}

	/* Let's make sure all the messages showed up at the other end. */
	printf("Testing that all messages were received by our peer.\n");
	while (sent--) {
		test_frame_get_message(sk2, messages[3]);
	}
	test_frame_get_message(sk2, messages[4]);
		
        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);
        
	/* Give peer the time to SACK.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		printf("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(0);

} /* main() */


