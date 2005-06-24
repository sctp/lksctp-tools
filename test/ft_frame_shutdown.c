/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is a Functional Test for verifying the T5-SHUTDOWN guard timer and
 * a couple of SHUTDOWN related race conditions. 
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
	int error;

	/* Do all that random stuff needed to make a sensible universe.  */
	sctp_init();
	sctp_hb_interval = 1000000;
	
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

	/* TEST #1: Verify that SHUTDOWN_ACK is retransmitted once T2 timer
	 * expires when SHUTDOWN_COMPLETE is lost.  
	 */
	/* Close sk1 to start the graceful shutdown process.  */
	sctp_close(sk1, 0);

	if (test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN and look for SHUTDOWN_ACK from sk2 to sk1. */
	if (test_step(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN ACK and look for SHUTDOWN COMPLETE message 
	 * from sk1 to sk2. 
	 */
	if (test_step(SCTP_CID_SHUTDOWN_COMPLETE, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Drop the SHUTDOWN_COMPLETE chunk. */
	test_kill_next_packet(SCTP_CID_SHUTDOWN_COMPLETE);
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	/* Move time forward by a T2-shutdown timeout.  */
	jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_T2_SHUTDOWN] + 1;
	error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Look for the retransmitted SHUTDOWN_ACK from sk2 to sk1.  */
	if (test_for_chunk(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN ACK and look for SHUTDOWN COMPLETE message 
	 * from sk1 to sk2. 
	 */
	if (test_step(SCTP_CID_SHUTDOWN_COMPLETE, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	/* TEST #2: Verify the handling of lost SHUTDOWN_COMPLETE followed
	 * by the endpoint attempting to bring up a new association with the
	 * same peer. 
	 */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

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

	/* Close sk1 to start the graceful shutdown process.  */
	sctp_close(sk1, 0);

	if (test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN and look for SHUTDOWN_ACK from sk2 to sk1. */
	if (test_step(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN ACK and look for SHUTDOWN COMPLETE message 
	 * from sk1 to sk2. 
	 */
	if (test_step(SCTP_CID_SHUTDOWN_COMPLETE, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Drop the SHUTDOWN_COMPLETE chunk. */
	test_kill_next_packet(SCTP_CID_SHUTDOWN_COMPLETE);
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	/* Open a new socket and bring up a new association with the same
	 * peer.
	 */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	/* Sending a message on the new socket should trigger the INIT
	 * chunk to be sent to the peer.
	 */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* The peer is still waiting for SHUTDOWN_COMPLETE, but it sees the
	 * INIT. It should ignore INIT and retranmsit SHUTDOWN-ACK.
	 */
	if (test_step(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the SHUTDOWN ACK and look for SHUTDOWN COMPLETE message 
	 * from sk1 to sk2. 
	 */
	if (test_step(SCTP_CID_SHUTDOWN_COMPLETE, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* The retransmitted SHUTDOWN COMPLETE will cause asoc2 to be
	 * closed.
	 */
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	/* Move time forward by a T1-init timeout.  */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
	error = test_run_timeout();
	if (error != 0) { DUMP_CORE; }

	/* After T1 expiry, INIT is retransmitted and should start a new
	 * association.
	 */
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the message that was sent from sk1 to sk2.  */
	test_frame_get_message(sk2, message);

	/* TEST #3: Verify that the assoication is aborted on T5-SHUTDOWN 
	 * Guard timer expiry.
	 */
	/* Close sk1 to start the graceful shutdown process.  */
	sctp_close(sk1, 0);

	if (test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	
	/* Process the SHUTDOWN and look for SHUTDOWN_ACK from sk2 to sk1. */
	if (test_step(SCTP_CID_SHUTDOWN_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Drop the SHUTDOWN_ACK chunk. */
	test_kill_next_packet(SCTP_CID_SHUTDOWN_ACK);
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	/* Move time forward by asoc1's T5 shutdown guard timeout.  This will
	 * also cause T2-shutdown timers on asoc1 and asoc2 to go off.
	 */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD] + 1;
	error = test_run_timeout();
	if (error != 0) { DUMP_CORE; }

	/* Drop the SHUTDOWN and SHUTDOWN ACK chunks generated by the 
	 * expiration of T2 timers.
	 */
	test_kill_next_packet(SCTP_CID_SHUTDOWN);
	error = test_run_network_once(TEST_NETWORK0);
	if (error < 0) { DUMP_CORE; }

	test_kill_next_packet(SCTP_CID_SHUTDOWN_ACK);
	error = test_run_network_once(TEST_NETWORK0);
	if (error < 0) { DUMP_CORE; }

	/* Now we should see the ABORT chunk generated by t5 timer expiry. */
	if (test_for_chunk(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
