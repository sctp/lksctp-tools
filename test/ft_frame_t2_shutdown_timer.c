/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is the Functional Test for testing T2-shutdown timeout functionality 
 * for UDP-style socket.
 * 
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sock *sk1, *sk2;
	struct sockaddr_in loop1, loop2;
	uint8_t *message = "Hello, World!!!\n";
	uint32_t rto;
	int error;
	int i;

	/* Do all that random stuff needed to make a sensible universe.  */
	sctp_init();
	sctp_hb_interval = 100000;
	
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

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) { DUMP_CORE; }
        
	/* Send the first message. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, message);

	/* Send a couple of messages from sk1 to sk2.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	/* Close sk1 to start the graceful shutdown process.  */
	sctp_close(sk1, 0);

	/* Verify that the asoc1 state is changed to SHUTDOWN_PENDING as 
	 * there are 2 data messages that are still pending.  
	 */ 
	if (SCTP_STATE_SHUTDOWN_PENDING != asoc1->state) {
		DUMP_CORE;
	}

	/* Process the first data message sent from sk1 to sk2. */
	error = test_run_network_once(TEST_NETWORK0);
	if (error < 0) { DUMP_CORE; }

	/* Process the second data message sent from sk1 to sk2. */
	error = test_run_network_once(TEST_NETWORK0);
	if (error < 0) { DUMP_CORE; }

	/* Process the SACK sent from sk2 to sk1. */
	error = test_run_network_once(TEST_NETWORK0);
	if (error < 0) { DUMP_CORE; }

	/* Verify that the asoc1 state is updated to SHUTDOWN_SENT after 
	 * the SACK is received for the pending data.
	 */ 
	if (SCTP_STATE_SHUTDOWN_SENT != asoc1->state) {
		DUMP_CORE;
	}

	/* Get the 2 messages sent from sk1 to sk2. */
	test_frame_get_message(sk2, message);
	test_frame_get_message(sk2, message);

	/* At this point there should be a SHUTDOWN chunk on the network that
	 * is sent from sk1. Drop the shutdown chunk and make sure that 
	 * retransmission of the same chunk occurs with proper RTO backoff
	 * and the association's overall error counter is incremented. 
	 */ 
	rto = asoc1->peer.primary_path->rto;

	/* Look for the SHUTDOWN chunk on the network. */
	if (test_for_chunk(SCTP_CID_SHUTDOWN,TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Drop the packet. */
	test_kill_next_packet(SCTP_CID_SHUTDOWN);
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	/* Move time forward by a T2-shutdown timeout.  */
	jiffies += asoc1->peer.active_path->rto + 1;
	test_run_timeout();

	/* Check that the RTO is updated as expected. */	
	if (asoc1->peer.primary_path->rto != min(2*rto, asoc1->rto_max)) {
		DUMP_CORE;
	}

	/* Verify that asoc1's overall_error_count is incremented. */
	if (1 != asoc1->overall_error_count) {
			DUMP_CORE;
	}

	/* Send a message from sk2 to sk1 to verify that reception of data
	 * in SHUTDOWN_SENT state is handled correctly.
	 */ 
	test_frame_send_message(sk2, (struct sockaddr *)&loop1, message);

	/* Look for the retransmitted SHUTDOWN chunk. */
	if (test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN and look for DATA chunk. */
	if (test_step(SCTP_CID_DATA, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Verify that the asoc2 state is updated to SHUTDOWN_RECEIVED after 
	 * the SACK is received for the pending data.
	 */ 
	if (SCTP_STATE_SHUTDOWN_RECEIVED != asoc2->state) {
		DUMP_CORE;
	}

	/* Process the DATA chunk and look for SACK chunk. */
	if (test_step(SCTP_CID_SACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Once the data is received asoc1's overall error counter should be
	 * reset.
	 */
	if (0 != asoc1->overall_error_count) {
		DUMP_CORE;
	}

	/* Process the SACK chunk and look for SHUTDOWN chunk that is sent
	 * whenever DATA is received in SHUTDOWN_SENT state. 
	 */

	if (test_step(SCTP_CID_SHUTDOWN, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN chunk and look for SHUTDOWN_ACK chunk. */
	if (test_step(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* At this point there should be a SHUTDOWN_ACK chunk on the network 
	 * that is sent from sk2. Drop this SHUTDOWN_ACK chunk and make sure 
	 * that retransmission of the same chunk occurs with proper RTO backoff
	 * and the association's overall error counter is incremented upto
	 * the threshold value. 
	 */ 
	for (i = 0; i <= asoc2->max_retrans; i++) {
		rto = asoc2->peer.primary_path->rto;

		/* Look for the SHUTDOWN_ACK chunk on the network. */
		if (test_for_chunk(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK0) 
								      <= 0) {
			DUMP_CORE;
		}

		/* Drop the packet. */
		test_kill_next_packet(SCTP_CID_SHUTDOWN_ACK);
        	error = test_run_network();
        	if (error != 0) { DUMP_CORE; }

		/* Move time forward by a T2-shutdown timeout.  */
        	jiffies += asoc2->peer.active_path->rto + 1;
		test_run_timeout();

		/* Once the association's overall error count reaches the
		 * threshold, the association is closed.
		 */
		if (i == asoc2->max_retrans) {
			/* Verify that the association is marked as dead. */
			if (1 != asoc2->base.dead) {
				DUMP_CORE;
			}
			break;
		}

		/* Check that the RTO is updated as expected. */	
		if (asoc2->peer.primary_path->rto != 
				min(2*rto, asoc2->rto_max)) {
			DUMP_CORE;
		}

		/* Verify that asoc2's overall_error_count is incremented. */
		if (asoc2->overall_error_count != i+1) {
			DUMP_CORE;
		}
	}

	/* We should see the COMMUNICATION_LOST event after the error 
	 * threshold value is reached.
	 */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_LOST);

	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
