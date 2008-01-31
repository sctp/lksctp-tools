/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is the Functional Test for the ability to handle a lost
 * link during data transmission for the SCTP kernel reference
 * implementation state machine. 
 *
 * It walks the state machine through a modified complete data
 * exchange where we set up an association with two paths, send one data
 * message successfully, tear down the primary path, then send data
 * messages and retransmit them until the primary path gets marked as
 * inactive.  Finally, tear down the association cleanly.
 *
 * In the future, it would make sense to bring the link back up and
 * see that traffic returns to the primary link.  This requires
 * heartbeats, which we have not yet implemented.
 * 
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Daisy Chang <daisyc@us.ibm.com>
 * Sridhar Samudrala <sri@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

#define MAX_RETRANS 3

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
        struct sockaddr_in big_a1;
        struct sockaddr_in big_a2;
        union sctp_addr *peer1a = (union sctp_addr *)&loop2;
        union sctp_addr *peer1b = (union sctp_addr *)&big_a2;
        union sctp_addr *peer2a = (union sctp_addr *)&loop1;
        union sctp_addr *peer2b = (union sctp_addr *)&big_a1;
	struct sctp_paddrparams params;
        uint8_t *messages[] = {
                "associate",
                "strike1",
                "strike2",
                "strike3",
                "strikeout",
                "steal",
                "The test frame has a bug!", /* We should NEVER see this... */
        };
        int error = 0;

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

	/* Set the default path error threshold to allow only 3
	 * retransmissions.
	 */
	sctp_max_retrans_path = 3;

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_ADDR_ETH0;
        loop1.sin_port = htons(SCTP_TESTPORT_1);
        big_a1.sin_family = AF_INET;
        big_a1.sin_addr.s_addr = SCTP_ADDR_ETH1;
        big_a1.sin_port = htons(SCTP_TESTPORT_1);
        
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        error = test_bindx(sk1, (struct sockaddr *)&big_a1,
			   sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR);
        if (error != 0) { DUMP_CORE; }
        
        loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_ADDR_ETH0;
        loop2.sin_port = htons(SCTP_TESTPORT_2);
        big_a2.sin_family = AF_INET;
        big_a2.sin_addr.s_addr = SCTP_ADDR_ETH1;
        big_a2.sin_port = htons(SCTP_TESTPORT_2);
        
        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }
        error = test_bindx(sk2, (struct sockaddr *)&big_a2,
			   sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR);
        if (error != 0) { DUMP_CORE; }

        /* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	/* Setup Path Max Retrans for sk2 to allow only 3
	 * retransmissions.
	 */
	setup_paddrparams(&params, NULL, NULL);
	params.spp_pathmaxrxt = MAX_RETRANS;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

        /* Send the first message.  This will create the association.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[0]);
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* We should have seen a SACK in there... */

	ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1); 
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

        if (!sctp_outq_is_empty(&asoc1->outqueue)) {
                DUMP_CORE;
        }
        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */

	if (asoc1->peer.active_path == asoc1->peer.retran_path) {
		DUMP_CORE;
	}

	if (asoc2->peer.active_path == asoc2->peer.retran_path) {
		DUMP_CORE;
	}

	/* Test max retrans parameters for asoc2 (make sure
	 * they came through from the socket)
	 */
	setup_paddrparams(&params, asoc2, NULL);
	params.spp_pathmaxrxt = MAX_RETRANS;

	error = test_paddrparams(sk2, &params, asoc2, NULL, 0);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2a);
	error = test_paddrparams(sk2, &params, asoc2, peer2a, 0);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, peer2b);
	error = test_paddrparams(sk2, &params, asoc2, peer2b, 0);
	if (error)
		DUMP_CORE;

	/* Test max retrans parameters for asoc1 (make sure
	 * they came through from the socket)
	 */
	setup_paddrparams(&params, asoc1, NULL);
	params.spp_pathmaxrxt = sctp_max_retrans_path;

	error = test_paddrparams(sk1, &params, asoc1, NULL, 0);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc1, peer1a);
	error = test_paddrparams(sk1, &params, asoc1, peer1a, 0);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc1, peer1b);
	error = test_paddrparams(sk1, &params, asoc1, peer1b, 0);
	if (error)
		DUMP_CORE;

	/* Now set max retrans parameters for asoc1 also. */
	/* First set them for one peer. */
	change_paddrparams(&params, asoc1, peer1b);
	params.spp_pathmaxrxt = MAX_RETRANS;

 	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc1, peer1b);
	error = test_paddrparams(sk1, &params, asoc1, peer1b, 0);
	if (error)
		DUMP_CORE;

	/* Test the association and other peer. */
	setup_paddrparams(&params, asoc1, NULL);
	params.spp_pathmaxrxt = sctp_max_retrans_path;

	error = test_paddrparams(sk1, &params, asoc1, NULL, 0);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc1, peer1a);
	error = test_paddrparams(sk1, &params, asoc1, peer1a, 0);
	if (error)
		DUMP_CORE;

	/* Now set them for the association. */
	change_paddrparams(&params, asoc1, NULL);
	params.spp_pathmaxrxt = MAX_RETRANS;

 	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* And test. */
	setup_paddrparams(&params, asoc1, NULL);
	error = test_paddrparams(sk1, &params, asoc1, NULL, 0);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc1, peer1a);
	error = test_paddrparams(sk1, &params, asoc1, peer1a, 0);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc1, peer1b);
	error = test_paddrparams(sk1, &params, asoc1, peer1b, 0);
	if (error)
		DUMP_CORE;

	/* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent.  */
        test_frame_get_message(sk2, messages[0]);
        
        /* Now the real testing begins... */

	test_break_network(TEST_NETWORK_ETH0);

        /* Send a message and see that it goes through on network 1.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[1]);

        if (is_empty_network(TEST_NETWORK_ETH0)) { DUMP_CORE; }
        if (!is_empty_network(TEST_NETWORK_ETH1)) { DUMP_CORE; }

        error = test_run_network();

        /* The message should not get through right away.  */
        test_frame_get_message(sk2, NULL);

        /* Force the retransmit timeout and see that it goes through
         * on the other network.
         */
        jiffies += asoc1->peer.primary_path->rto + 1;
        test_run_timeout();
        if (!is_empty_network(TEST_NETWORK_ETH0)) { DUMP_CORE; }
        if (is_empty_network(TEST_NETWORK_ETH1)) { DUMP_CORE; }

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_message(sk2, messages[1]);

        /* Cause two more strikes against the primary address.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[2]);
        jiffies += asoc1->peer.primary_path->rto + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[3]);
        jiffies += asoc1->peer.primary_path->rto + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_message(sk2, messages[2]);
        test_frame_get_message(sk2, messages[3]);

        /* Check that the primary address is still "active".  */
        if (asoc1->peer.primary_path->state == SCTP_INACTIVE) {
                DUMP_CORE;
        }

        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Cause a fourth strike and confirm that we went "inactive".
         */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[4]);

        if (is_empty_network(TEST_NETWORK_ETH0)) { DUMP_CORE; }
        if (!is_empty_network(TEST_NETWORK_ETH1)) { DUMP_CORE; }

        jiffies += asoc1->peer.primary_path->rto + 1;
        test_run_timeout();

        if (is_empty_network(TEST_NETWORK_ETH0)) { DUMP_CORE; }
        if (is_empty_network(TEST_NETWORK_ETH1)) { DUMP_CORE; }

        /* Confirm that we struck out.  */
        if (asoc1->peer.primary_path->state != SCTP_INACTIVE) {
                DUMP_CORE;
        }
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        if (!is_empty_network(TEST_NETWORK_ETH0)) { DUMP_CORE; }
        if (!is_empty_network(TEST_NETWORK_ETH1)) { DUMP_CORE; }

#if 0 /* THIS IS A BIG RATHOLE.  THE API CHANGES ARE PAINFUL... */
        /* Collect the notification that the link went down.  */
        test_frame_get_event(sk1, SCTP_PEER_ADDR_CHANGE, ADDRESS_UNREACHABLE);
#endif
        /* Collect the final strike from the network.  */
        test_frame_get_message(sk2, messages[4]);

        /* Send a final message and see that it goes through WITHOUT a
         * timeout.
         */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[5]);

        if (!is_empty_network(TEST_NETWORK_ETH0)) { DUMP_CORE; }
        if (is_empty_network(TEST_NETWORK_ETH1)) { DUMP_CORE; }
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_message(sk2, messages[5]);

	test_fix_network(TEST_NETWORK_ETH0);

        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

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
