/* SCTP kernel reference Implementation 
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco And Motorola
 *
 * This "functional test" is really a regression test to see if
 * our implementation mistakenly sends an extra SACK.  When the
 * implementation sees a packet containing DATA, it starts the SACK
 * timer.  If it sees a second DATA packet before the timer expires,
 * it should send a SACK and stop the timer.  If the implementation
 * fails to stop the timer, it sends a redundant SACK.  This
 * regression test looks for that redundant SACK.
 *
 * This file is part of the SCTP kernel reference Implementation
 * 
 * The SCTP reference implementation is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation; either
 * version 2, or (at your option) any later version.
 * 
 * The SCTP reference implementation  is distributed in the hope that it 
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

#define SACK_DELAY_2 300
#define SACK_DELAY_2b 400
#define SACK_DELAY_3 100

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;
        struct sctp_endpoint *ep2;
        struct sctp_association *asoc2;

        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in loop1a;
        struct sockaddr_in loop1b;
        struct sockaddr_in loop2a;
        struct sockaddr_in loop2b;
        union sctp_addr *peer2a = (union sctp_addr *)&loop1a;
        union sctp_addr *peer2b = (union sctp_addr *)&loop1b;
	struct sctp_paddrparams params;
	struct sctp_assoc_value value;
	int optlen;

	/* Note that these messages are in ascending length.  */
        uint8_t *messages[] = {
                "associate",
                "1",
                "22",
                "333",
                "4444",
                "55555",
                "666666",
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
        loop1a.sin_family = AF_INET;
        loop1a.sin_addr.s_addr = SCTP_ADDR_ETH0;
        loop1a.sin_port = htons(SCTP_TESTPORT_1);
        loop1b.sin_family = AF_INET;
        loop1b.sin_addr.s_addr = SCTP_ADDR_ETH1;
        loop1b.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&loop1a, sizeof(loop1a));
        if (error != 0) { DUMP_CORE; }

	error = test_bindx(sk1, (struct sockaddr *)&loop1b, sizeof(loop1b),
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { 
		printf("Error %d\n", error);
		DUMP_CORE;
	}

        loop2a.sin_family = AF_INET;
        loop2a.sin_addr.s_addr = SCTP_ADDR_ETH0;
        loop2a.sin_port = htons(SCTP_TESTPORT_2);
        loop2b.sin_family = AF_INET;
        loop2b.sin_addr.s_addr = SCTP_ADDR_ETH1;
        loop2b.sin_port = htons(SCTP_TESTPORT_2);
        
        error = test_bind(sk2, (struct sockaddr *)&loop2a, sizeof(loop2a));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	error = test_bindx(sk2, (struct sockaddr *)&loop2b, sizeof(loop2b),
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	/* Setup SACK delay for sk2 to be shorter. */
	setup_paddrparams(&params, NULL, NULL);
	params.spp_flags |= SPP_SACKDELAY_ENABLE;
	params.spp_sackdelay = SACK_DELAY_2;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	value.assoc_id = 0;
	optlen = sizeof(value);
	error = sctp_getsockopt(sk2, IPPROTO_SCTP, SCTP_DELAYED_ACK_TIME,
				(char *)&value, &optlen);
	if (error) {
		printf("error %d\n", error);
		DUMP_CORE;
	}
	if (value.assoc_value != SACK_DELAY_2)
		DUMP_CORE;

        /* Send the first message.  This will create the association.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2a, messages[0]);
        
	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}
	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}

#ifndef NO_COOKIE_ECHO_BUNDLE
	/* We expect DATA bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
#endif /* !NO_COOKIE_ECHO_BUNDLE */

	/* We expect a COOKIE ACK.  */
	if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}

#ifdef NO_COOKIE_ECHO_BUNDLE
	if (test_step(SCTP_CID_DATA, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}

	if (test_step(SCTP_CID_SACK, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}
#else
        /* We should see a SACK next.
	 * We ARE truly clever and bundle the SACK with the COOKIE ACK.
	 */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

#endif  /* NO_COOKIE_ECHO_BUNDLE */

	/* Process the COOKIE ACK and the SACK.  */
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1); 
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	/* Test SACK delay parameters for asoc2 (make sure
	 * they came through from the socket)
	 */
	setup_paddrparams(&params, asoc2, NULL);
	params.spp_sackdelay = SACK_DELAY_2;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = test_paddrparams(sk2, &params, asoc2, NULL, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2a);
	error = test_paddrparams(sk2, &params, asoc2, peer2a, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2b);
	error = test_paddrparams(sk2, &params, asoc2, peer2b, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which we sent.  */
        test_frame_get_message(sk2, messages[0]);
       
	/* Make sure that heartbeats are sent and all the paths are 
	 * confirmed.
	 */
        jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

        /* Now the real testing begins... */

	/* Send a single message.  */
	printf("----->Sending to loop2b\n");
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2b,
        			 messages[1], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH1);
	if (error < 0) { DUMP_CORE; }

	/* We should NOT see a SACK yet.  */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* See that we DID generate a SACK.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Process that SACK. */
        error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* Start over by sending another message.  */
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2a,
        			 messages[2], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* Confirm that we do not see a SACK yet.  */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Send a second message.  */
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2a,
        			 messages[3], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* The second message should have triggered a SACK.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

	/* Consume that SACK!  */
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* If we see a SACK, we failed to cancel the timer.  */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

        /* Collect the retransmitted messages in order.  */
        test_frame_get_message(sk2, messages[1]);
        test_frame_get_message(sk2, messages[2]);
        test_frame_get_message(sk2, messages[3]);

	/* Now test modification of the SACK delay parameters. */

	/* Test disable SACK delay. */
	setup_paddrparams(&params, asoc2, peer2a);
	params.spp_flags     = SPP_SACKDELAY_DISABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* Start over by sending another message.  */
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2a,
        			 messages[1], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* Confirm that we do see a SACK immediately.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

	/* Consume that SACK!  */
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* Send a second message.  */
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2b,
        			 messages[2], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH1);
	if (error < 0) { DUMP_CORE; }

	/* The second message should not have triggered a SACK.  */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Now we should see a SACK.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Consume that SACK!  */
        error = test_run_network_once(TEST_NETWORK_ETH1);
	if (error < 0) { DUMP_CORE; }

	/* And send one more message.  */
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2a,
        			 messages[3], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* Confirm that we do see a SACK immediately.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

	/* Consume that SACK!  */
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

        /* Collect the retransmitted messages in order.  */
        test_frame_get_message(sk2, messages[1]);
        test_frame_get_message(sk2, messages[2]);
        test_frame_get_message(sk2, messages[3]);

	/* Now test transport specific SACK delay timeouts. */
	setup_paddrparams(&params, asoc2, peer2a);
	params.spp_sackdelay = SACK_DELAY_2;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, asoc2, peer2b);
	params.spp_sackdelay = SACK_DELAY_2b;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* Send a message to the first peer address. */
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2a,
        			 messages[1], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* The message should not have triggered a SACK.  */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Verify the timeout which will be used. */
	if (asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] !=
	    msecs_to_jiffies(SACK_DELAY_2))
		DUMP_CORE;

	/* Move time forward to just before SACK timeout.  */
        jiffies += msecs_to_jiffies(SACK_DELAY_2) - 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Still should not see a SACK. */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Now move time forward to just after SACK timeout. */
        jiffies += 2;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Now we should see a SACK.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

	/* Consume that SACK!  */
        error = test_run_network_once(TEST_NETWORK_ETH0);
	if (error < 0) { DUMP_CORE; }

	/* Send a message to the second peer address. */
        test_frame_send_message2(sk1, (struct sockaddr *)&loop2b,
        			 messages[2], 0, 0, 0, SCTP_ADDR_OVER);
        error = test_run_network_once(TEST_NETWORK_ETH1);
	if (error < 0) { DUMP_CORE; }

	/* The message should not have triggered a SACK.  */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Verify the timeout which will be used. */
	if (asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] !=
	    msecs_to_jiffies(SACK_DELAY_2b))
		DUMP_CORE;

	/* Move time forward to just before SACK timeout.  */
        jiffies += msecs_to_jiffies(SACK_DELAY_2b) - 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Still should not see a SACK. */
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Now move time forward to just after SACK timeout. */
        jiffies += 2;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Now we should see a SACK.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK_ETH1)) {
		DUMP_CORE;
	}

	/* Consume that SACK!  */
        error = test_run_network_once(TEST_NETWORK_ETH1);
	if (error < 0) { DUMP_CORE; }

        /* Collect the retransmitted messages in order.  */
        test_frame_get_message(sk2, messages[1]);
        test_frame_get_message(sk2, messages[2]);

	/* Finish testing SCTP_DELAYED_ACK_TIME. */
 	value.assoc_id = 0;
 	value.assoc_value = SACK_DELAY_3;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_DELAYED_ACK_TIME,
				(char *)&value, sizeof(value));
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, asoc2, NULL);
	params.spp_sackdelay = SACK_DELAY_2;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = test_paddrparams(sk2, &params, asoc2, NULL, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, NULL, NULL);
	params.spp_sackdelay = SACK_DELAY_3;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = test_paddrparams(sk2, &params, NULL, NULL, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

 	value.assoc_id = sctp_assoc2id(asoc2);
 	value.assoc_value = SACK_DELAY_2b;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_DELAYED_ACK_TIME,
				(char *)&value, sizeof(value));
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, asoc2, NULL);
	params.spp_sackdelay = SACK_DELAY_2b;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = test_paddrparams(sk2, &params, asoc2, NULL, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2a);
	error = test_paddrparams(sk2, &params, asoc2, peer2a, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2b);
	error = test_paddrparams(sk2, &params, asoc2, peer2b, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, NULL, NULL);
	params.spp_sackdelay = SACK_DELAY_3;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = test_paddrparams(sk2, &params, NULL, NULL, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

 	value.assoc_id = sctp_assoc2id(asoc2);
 	value.assoc_value = 0;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_DELAYED_ACK_TIME,
				(char *)&value, sizeof(value));
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, asoc2, NULL);
	params.spp_sackdelay = SACK_DELAY_2b;
	params.spp_flags     = SPP_SACKDELAY_DISABLE;

	error = test_paddrparams(sk2, &params, asoc2, NULL, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2a);
	error = test_paddrparams(sk2, &params, asoc2, peer2a, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2b);
	error = test_paddrparams(sk2, &params, asoc2, peer2b, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, NULL, NULL);
	params.spp_sackdelay = SACK_DELAY_3;
	params.spp_flags     = SPP_SACKDELAY_ENABLE;

	error = test_paddrparams(sk2, &params, NULL, NULL, SPP_SACKDELAY);
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, asoc2, NULL);
	params.spp_flags     = SPP_SACKDELAY_DISABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	value.assoc_id = sctp_assoc2id(asoc2);
	optlen = sizeof(value);
	error = sctp_getsockopt(sk2, IPPROTO_SCTP, SCTP_DELAYED_ACK_TIME,
				(char *)&value, &optlen);
	if (error)
		DUMP_CORE;
	if (value.assoc_value != 0)
		DUMP_CORE;

      /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	/* The SHUTDOWN sequence starts with a SHUTDOWN message.  */
	if (!test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

	/* Next we expect a SHUTDOWN ACK.  */
	if (test_step(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}

	/* Finally, we should see a SHUTDOWN COMPLETE.  */
	if (test_step(SCTP_CID_SHUTDOWN_COMPLETE, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}

	/* Force the SHUTDOWN COMPLETE to deliver.  */
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);
        sctp_close(sk2, /* timeout */ 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

        /* Indicate successful completion.  */
        exit(0);
} /* main() */
