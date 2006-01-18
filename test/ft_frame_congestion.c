/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2004
 *
 * This is a Functional Test to verify Congestion control functionality 
 * over a UDP-style SCTP socket.
 * 
 * Sridhar Samudrala <sri@us.ibm.com>
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
	struct sctp_transport *t1, *t2;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
	struct list_head *lchunk1;
	struct sctp_chunk *chunk1;
	void *msg_buf;
	int error;

        /* Do all that random stuff needed to make a sensible universe.  */
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	/* This test assumes that rwnd is initialised to 32768. */
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

	msg_buf = test_build_msg(1);
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

	/* Verify the initial Congestion Parameters. */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 0);

	/* TEST #1: Verify that congestion parameters are updated correctly
	 * in slow start phase.
	 */
        /* Send 2 messages. */
	msg_buf = test_build_msg(1352);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Congestion parameters should not change as flight_size is less 
	 * than the cwnd.
	 */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 0);

        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);

	/* Send 3 messages. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/*
	 * The SACK for the 3rd message hasn't yet arrived. So the flight_size
	 * should be equal to 1 message size. 
	 */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 1352);

        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);

	/* Process the rwnd update SACK sent after the 3rd msg is received. */ 
	if (0 != test_run_network()) { DUMP_CORE; }

	/* At this point, the receiver has acked all the sent data. */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 0);

	/* Send 4 messages. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* At this point we are in slow start phase and cwnd gets incremented 
	 * by pmtu based on the slow start algorithm. 
	 */
	test_verify_congestion_parameters(t1, 5880, 32768, 0, 0);

	/* TEST #2: Verify that Max.Burst limits the number of new data chunks
	 * that can be sent. 
	 */
	/* Send 6 messages. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* The SACK for the first 2 messages should increase the cwnd by 
	 * 1 MTU.
	 */
	test_verify_congestion_parameters(t1, 7380, 32768, 0, 0);

	/* This message will trigger the following Max.Burst limit for new
	 * Data chunks as the cwnd exceeds the max burst value. 
         *      if ((flightsize + Max.Burst*MTU) < cwnd)
         *              cwnd = flightsize + Max.Burst*MTU
	 */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 1352);

	/* Send one more message to generate a SACK and clear the outstanding
	 * data.
	 */ 
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 0);

        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);

	/* Process the rwnd update SACKs */
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Send 6 messages. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* The SACK for the first 2 messages in the above set should increase 
	 * the cwnd by 1 MTU. 
	 */
	test_verify_congestion_parameters(t1, 7500, 32768, 0, 0);

	/* TEST #3: Verify that cwnd is adjusted to max(cwnd/2, 4*pmtu) when an
	 * endpoint does not transmit data within an RTO. In our implementation 
	 * we do this check when a heartbeat timer goes off. 
	 */

	/* Force t1's heartbeat timer. */
        jiffies += t1->hbinterval + t1->rto + 1;
	/* Delete t2's hb_timer so that it doesn't interfere with the tests by
	 * generating an HEARTBEAT packet.
	 */ 
	del_timer(&t2->hb_timer);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 0);

	/* TEST #4: Verify that congestion parameters are updated correctly
	 * after a fast retransmit.
	 */
	/* Drop the next packet. */
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_verify_congestion_parameters(t1, 6000, 32768, 0, 1352);

	/* Get a reference to the chunk from the transmitted list. */
	lchunk1 = sctp_list_dequeue(&t1->transmitted);	
	chunk1 = list_entry(lchunk1, struct sctp_chunk, transmitted_list);

	/* Put the chunk back on the transmitted list. */
	list_add_tail(&chunk1->transmitted_list, &t1->transmitted);

	/* Send the first message after the drop. This should trigger a 
	 * SACK causing the dropped chunk's tsn_missing_report to be 
	 * incremented. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	if (1 != chunk1->tsn_missing_report) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 1352);

	/* Send the second message after the drop. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	if (2 != chunk1->tsn_missing_report) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 1352);

	/* Send the third message after the drop. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	if (3 != chunk1->tsn_missing_report) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 32768, 0, 1352);

	/* Send the fourth message after the drop. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	/* Once the tsn_missing_report reaches 4, the chunk should be marked 
	 * for fast_retransmit and retransmitted immediately.
	 */

	/* The congestion parameters should be updated based on the cwnd
	 * reduction and ssthresh change algorithm due to fast retransmit.
	 *   ssthresh = max(cwnd/2, 4*mtu)
	 *   cwnd = ssthresh
	 *   partial_bytes_acked = 0
	 */
	test_verify_congestion_parameters(t1, 6000, 6000, 0, 1352);

        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 6000, 6000, 0, 0);

#if 0
	/* With the new updates to cwnd/ssthresh manipulation based on the
	 * sctpimpguide modifications, i could not find an easy way to
	 * simulate congestion avoidance test case. So commenting out this
	 * test case for now.
	 */
	/* TEST #5: Verify that congestion parameters are updated correctly
	 * in Congestion Avoidance phase. 
	 */
	/* Send 5 messages so that cwnd becomes greater than ssthresh and
	 * the transport goes into congestion avoidance phase.
	 */ 
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
	test_verify_congestion_parameters(t1, 7500, 6000, 0, 1352);

	if (0 != test_run_network()) { DUMP_CORE; }

	test_verify_congestion_parameters(t1, 7500, 6000, 0, 0);

	/* Send 4 more messages and verify that congestion parameters are
	 * updated correctly in congestion avoidance phase.
	 */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_verify_congestion_parameters(t1, 4500, 3000, 0, 5408);

	/* Put the first message on the network. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 4500, 3000, 0, 5408);

	/* Put the second message on the network. This should generate a SACK. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 4500, 3000, 0, 5408);

	/* Put the third message on the network. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 4500, 3000, 0, 5408);

	/* Put the fourth message on the network. This should generate a SACK. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 4500, 3000, 0, 5408);

	/* Put the first SACK on the network. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	/* Verify that in congestion avoidance phase, partial_bytes_acked
	 * fields is incremented correctly.
	 */
	test_verify_congestion_parameters(t1, 4500, 3000, 2704, 2704);

	/* Put the second SACK on the network. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 4500, 3000, 2704, 0);

        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
#endif
	/* TEST #6: Verify that congestion parameters are updated correctly
	 * after retransmission timeout.
	 */
	/* Start retransmission timeout test.  Drop the next 4 packets. */
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_kill_next_packet(SCTP_CID_DATA);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	/* Verify that flight_size is adjusted properly. */
	test_verify_congestion_parameters(t1, 6000, 6000, 0, 5408);

	/* Force the retransmission timer. */
	jiffies += t1->rto + 1;
	/* This will retransmit the first lost packet. */
	if (0 != test_run_network()) { DUMP_CORE; }

	/* The retransmission timer triggers the retransmit code causing the
	 * cwnd, ssthresh and partial_bytes_acked to be changed as below.
	 *  ssthresh = max(cwnd/2, 4*mtu)
	 *  cwnd = mtu
	 *  partial_bytes_acked = 0;
	 */
	test_verify_congestion_parameters(t1, 1500, 6000, 0, 1352);

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	/* This should generate the delayed SACK. */
	if (0 != test_run_timeout()) { DUMP_CORE; }

	/* The delayed SACK will trigger the retransmit of the next 2 lost
	 * packets that can be sent based on the cwnd.
	 */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 1500, 6000, 0, 2704);

	/* Process the 2 retransmitted packets. This triggers a SACK to be
	 * sent which in turn causes the 4th lost packet to be retransmitted.
	 */  
	if (0 != test_run_network()) { DUMP_CORE; }
	test_verify_congestion_parameters(t1, 3000, 6000, 0, 1352);

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;

	/* This will generate the SACK for the 4th retransmitted packet. */
	if (0 != test_run_network()) { DUMP_CORE; }

	test_verify_congestion_parameters(t1, 3000, 6000, 0, 0);

        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);
        test_frame_get_message(sk2, msg_buf);

	sctp_close(sk1, 0);
	if (0 != test_run_network()) { DUMP_CORE; }
	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
