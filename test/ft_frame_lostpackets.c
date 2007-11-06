/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco And Motorola
 *
 * This is the Functional Test for the ability to handle several lost
 * packets during data transmission for the SCTP kernel reference
 * implementation state machine.
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
 * Karl Knutson          <karl@athena.chicago.il.us>
 * Sridhar Samudrala     <samudrala@us.ibm.com>
 * Jon Grimm             <jgrimm@us.ibm.com>
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

test_chunk_fn_t test_cmp_tsn;

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;
	struct sctp_transport *tran1;
        struct sctp_endpoint *ep2;
        struct sctp_association *asoc2;
	struct sctp_transport *tran2;
	sctp_chunkhdr_t *chunk;
	uint32_t tsn;

        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in loop1;
        struct sockaddr_in loop2;
	int i;
	int sent;
	int msglen;
        uint8_t *messages[] = {
                "associate",
                "strike1",
                "strike2",
                "strike3",
                "strikeout",
                "steal",
                "home run",
                "The test frame has a bug!", /* We should NEVER see this... */
        };
        int error = 0;

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

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
	tran1 = (struct sctp_transport *)asoc1->peer.transport_addr_list.next;
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	tran2 = (struct sctp_transport *)asoc1->peer.transport_addr_list.next;

        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */



        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent.  */
        test_frame_get_message(sk2, messages[0]);

        /* Now the real testing begins... */

	test_kill_next_packet(SCTP_CID_DATA);

        /* Send a message.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[1]);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* The message should not get through at this point.  */
        test_frame_get_message(sk2, NULL);

        /* Force the retransmit timeout and see that it goes through. */
        jiffies += asoc1->peer.primary_path->rto + 1;
        test_run_timeout();

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_message(sk2, messages[1]);

        printk("\n%s single loss passed\n", argv[0]);

        /* Cause two sequential lost packets.  */
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[2]);
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_message(sk2, NULL);

	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[3]);
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_message(sk2, NULL);

        /* Now that we've lost two packets, let's move forward in time
         * causing them to retransmit.  But first, let's make the SACK
	 * happen.
         */
        jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
        if (error != 0) { DUMP_CORE; }

	/* We could insert a test here which checked to see that we
	 * DID restart the rtx timer when we got the SACK.
	 */

	/* OK, NOW we can move forward to the RTX timeout... */
        jiffies += asoc1->peer.primary_path->rto + 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Collect the retransmitted messages in order.  */
        test_frame_get_message(sk2, messages[2]);
        test_frame_get_message(sk2, messages[3]);

	/* Cause the SACK to happen so that we have a clean slate.  */
        jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        printk("\n%s double loss passed\n", argv[0]);

        /* Cause two non-sequential lost packets.  */
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[4]);
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Get one message through.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[5]);
	if (test_run_network_once(TEST_NETWORK0) <= 0) { DUMP_CORE; }

	/* Figure out what the TSN of that DATA chunk should have.  */
	tsn = asoc1->next_tsn - 1;

	/* We should have generated a SACK because we have a gap.  If
	 * we did not notice the gap, we would still be waiting for
	 * the next DATA chunk before SACKing.
	 */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	if (test_run_network_once(TEST_NETWORK0) != 0) { DUMP_CORE; }

	/* Now we can lose that next chunk.  */
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[6]);
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* We should not deliver the DATA chunk which got through
	 * because we are waiting for its predecessor.
	 */
        test_frame_get_message(sk2, NULL);

        /* Now that we've lost two packets, let's move forward in time
         * causing them to retransmit.
         */
        jiffies += asoc1->peer.primary_path->rto + 1;
        test_run_timeout();

	/* Look so see if messages[5] got retransmitted.  */
	if (NULL !=
	    (chunk = test_find_chunk(TEST_NETWORK0, SCTP_CID_DATA,
				     test_cmp_tsn, (void *)tsn))) {
		DUMP_CORE;
	}

        test_run_timeout();
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Collect the retransmitted messages in order.  */
        test_frame_get_message(sk2, messages[4]);
        test_frame_get_message(sk2, messages[5]);
        test_frame_get_message(sk2, messages[6]);

	/* Make sure we SACK to clean up state. */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();

        printk("\n%s split double loss passed\n", argv[0]);

	/* Test losing >PMTU worth of data.
	 */

	/* Really, this is regression testing a couple bugs in this path,
	 * where the implementation mishandles retransmitting if there
	 * is >PMTU worth of retransmit data available.   Additionally,
	 * this highlights that any such leftover retransmit data
	 * seems to get stranded down on the retransmit queue unless some
	 * other data were to get transmitted.
	 */
	/* Set rcvbuf to a large value so that we don't run into drops
	 * due to out of receive buffer space.
	 */
	sk2->sk_rcvbuf = 500000;
	msglen = strlen(messages[6]) + 1;
	for (i=0, sent=0; i <= tran1->pathmtu;
			 i += (msglen + sizeof(struct sk_buff)), sent++) {
		test_kill_next_packet(SCTP_CID_DATA);
		test_frame_send_message(sk1, (struct sockaddr *)&loop2,
					messages[6]);
		test_run_network();
	}

        /* Force the retransmit timeout and let the network
	 * run to completion.
	 */
        jiffies += asoc1->peer.primary_path->rto + 1;
        error = test_run_timeout();

	/* Give the peer time to SACK. */
	test_run_network();

        jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
	test_run_network();

	/* Retrieve all the messages that should have been retransmitted. */
	for (; sent; sent--) {
		test_frame_get_message(sk2, messages[6]);
	}

	printk("\n%s multi (>PMTU) loss passed\n", argv[0]);

        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	/* Give peer the time to SACK and do the SHUTDOWN sequence.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

        sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(0);
} /* main() */

/* Returns true if the given chunk (which is known to be a DATA chunk)
 * has the given TSN.
 */
int
test_cmp_tsn(void *arg, sctp_chunkhdr_t *hdr)
{
	uint32_t tsn = (uint32_t)arg;
	sctp_data_chunk_t *chunk
		= (sctp_data_chunk_t *)hdr;

	return (tsn == ntohl(chunk->data_hdr.tsn));

} /* test_cmp_tsn() */
