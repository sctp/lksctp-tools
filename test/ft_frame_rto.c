/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is a Functional Test for verifying RTT/RTO measurements. The following
 * tests are done in sequence.
 * - Verify that a new RTT measurement is started when a data chunk is sent.
 * - Verify that a RTT measurement is done only once per round trip time.
 * - Verify that a RTT measurement is not done with a retransmitted chunk.
 * - Verify that RTO is updated as expected.
 *
 * Sridhar Samudrala <sri@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

#define TEST_RTT	1001

/* Returns the RTO calculated using the input rtt, srtt and rttvar based
 * on the rules listed in RFC2960.
 */
static uint32_t
get_expected_rto(uint32_t rtt, uint32_t srtt, uint32_t rttvar)
{
	uint32_t rto;

	if (rttvar || srtt) {
		/* 6.3.1 C3) When a new RTT measurement R' is made, set
		 * RTTVAR <- (1 - RTO.Beta) * RTTVAR + RTO.Beta * |SRTT - R'|
		 * SRTT <- (1 - RTO.Alpha) * SRTT + RTO.Alpha * R'
		 */
		rttvar = (uint32_t)
			(((double)(1.0 - 0.25) * (double)rttvar) +
			 (double)(0.25 * (double)abs(srtt - rtt)));
		srtt = (uint32_t)
			(((double)(1.0 - 0.125) * (double)srtt) +
			 (double)(0.125 * (double)rtt));
	} else {
		/* 6.3.1 C2) When the first RTT measurement R is made, set
		 * SRTT <- R, RTTVAR <- R/2.
		 */
		srtt = rtt;
		rttvar = rtt/2;
	}

	/* 6.3.1 G1) Whenever RTTVAR is computed, if RTTVAR = 0, then
	 * adjust RTTVAR <- G, where G is the CLOCK GRANULARITY.
	 */
	if (rttvar == 0) {
		rttvar = SCTP_CLOCK_GRANULARITY;
	}

	/* 6.3.1 C3) After the computation, update RTO <- SRTT + 4 * RTTVAR. */
	rto = srtt + 4 * rttvar;

	/* 6.3.1 C6) Whenever RTO is computed, if it is less than RTO.Min
	 * seconds then it is rounded up to RTO.Min seconds.
	 */
	if (rto < SCTP_RTO_MIN) {
		rto = SCTP_RTO_MIN;
	}

	/* 6.3.1 C7) A maximum value may be placed on RTO provided it is
	 * at least RTO.max seconds.
	 */
	if (rto > SCTP_RTO_MAX) {
		rto = SCTP_RTO_MAX;
	}

	printf("get_expected_rto: rtt: %d, srtt: %d rttvar: %d, "
			  " rto: %d\n", rtt, srtt, rttvar, rto);

	return (rto);

} /* get_expected_rto() */

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep;
        struct sctp_association *asoc;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
	uint8_t *message = "Hello, World!!!\n";
	struct list_head *lchunk1, *lchunk2;
	struct sctp_chunk *chunk1, *chunk2;
	struct sctp_transport *t;
	uint32_t rto;
	int error;
	int i;

        /* Do all that random stuff needed to make a sensible universe. */
        sctp_init();

        /* Create the two endpoints which will talk to each other. */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind this sockets to the test ports. */
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

        /* Send the first message. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	ep = sctp_sk(sk1)->ep;
	asoc = test_ep_first_asoc(ep);

   	if (0 != test_run_network()) { DUMP_CORE; }

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent. */
        test_frame_get_message(sk2, message);

	/* TEST #1: Verify that a new RTT measurement is started when a data
	 * chunk is sent.
	 */

	/* Get the primary transport. */
	t = asoc->peer.primary_path;

	/* Send a message. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	/* Verify that rto_pending is set indicating that RTT measurement is
	 * being done.
	 */
	if (!t->rto_pending) { DUMP_CORE; }

	/* Verify that T3-rtx timer is started. */
	if (!timer_pending(&t->T3_rtx_timer)) { DUMP_CORE; }

	/* Get the chunk from the transmitted list. */
	lchunk1 = sctp_list_dequeue(&t->transmitted);
	chunk1 = list_entry(lchunk1, struct sctp_chunk, transmitted_list);

	/* Make sure that chunk's rtt_in_progress field is set. */
	if (!chunk1->rtt_in_progress) { DUMP_CORE; }

	/* Put the chunk back on the transmitted list. */
	list_add_tail(&chunk1->transmitted_list, &t->transmitted);

	/* Process the data chunk. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }

	/* Move time forward by a SACK timeout so that the SACK is generated. */
        jiffies += asoc->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	test_run_timeout();

	/* Process the SACK. */
	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* Verify that rto_pending is reset after the SACK is processed. */
	if (t->rto_pending) { DUMP_CORE; }

	/* Verify that T3-rtx timer is stopped when all outstanding data is
	 * acknowledged.
	 */
	if (timer_pending(&t->T3_rtx_timer)) { DUMP_CORE; }

	/* Get the message. */
        test_frame_get_message(sk2, message);

	/* TEST #2:  Verify that a RTT measurement is done only once per
	 * round trip time.
	 */

	/* Send 2 messages. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	/* Get the chunks from the transmitted list. */
	lchunk1 = sctp_list_dequeue(&t->transmitted);
	lchunk2 = sctp_list_dequeue(&t->transmitted);
	chunk1 = list_entry(lchunk1, struct sctp_chunk, transmitted_list);
	chunk2 = list_entry(lchunk2, struct sctp_chunk, transmitted_list);

	/* Check that the first chunk is being used for RTT measurement. */
	if (!chunk1->rtt_in_progress) { DUMP_CORE; }

	/* Check that the second chunk is not being used for RTT measurement. */
	if (chunk2->rtt_in_progress) { DUMP_CORE; }

	/* Put the chunks back on the transmitted list. */
	list_add_tail(&chunk1->transmitted_list, &t->transmitted);
	list_add_tail(&chunk2->transmitted_list, &t->transmitted);

	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* Get the 2 messages. */
        test_frame_get_message(sk2, message);
        test_frame_get_message(sk2, message);

	/* TEST #3: Verify that a RTT measurement is not done with a
	 * retransmitted chunk.
	 */

	rto = t->rto;

	/* Send a message. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	/* Drop it. */
	test_kill_next_packet(SCTP_CID_DATA);
	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* Force the retransmission timer. */
	jiffies += t->rto + 1;
	test_run_timeout();

	/* Verify that the RTO is doubled to indicate the timer backoff. */
	if (t->rto != 2*rto) { DUMP_CORE; }

	rto = t->rto;

	/* Get the chunk from the transmitted list. */
	lchunk1 = sctp_list_dequeue(&t->transmitted);
	chunk1 = list_entry(lchunk1, struct sctp_chunk, transmitted_list);

	/* Put the chunk back on the transmitted list. */
	list_add_tail(&chunk1->transmitted_list, &t->transmitted);

	/* Process the data chunk. */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }

	/* Move time forward by a SACK timeout so that a SACK is generated. */
        jiffies += asoc->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	test_run_timeout();
	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* Check that the chunk's num_times_sent counter is increased and
	 * RTO is not changed.
	 * This indicates that a retransmitted chunk is not used for RTT
	 * measurements.
	 */
	if ((!chunk1->resent) || (rto != t->rto)) { DUMP_CORE; }

        test_frame_get_message(sk2, message);

	/* TEST #4: Verify that RTO is updated as expected.  */

	t->rttvar = t->srtt = 0;
	t->rto = TEST_RTT + 1;

	/* Send a few messages and verify that RTO is updated as expected. */
	for (i = 0; i <= 10; i++) {

		/* Get the next expected RTO based on a RTT of TEST_RTT. */
		rto = get_expected_rto(TEST_RTT, t->srtt, t->rttvar);

        	test_frame_send_message(sk1, (struct sockaddr *)&loop2,
					message);

		if (test_run_network_once(TEST_NETWORK0) < 0) {
			DUMP_CORE;
		}

		/* Increment jiffies by TEST_RTT. */
		jiffies += TEST_RTT;

		if ( 0 != test_run_network()) { DUMP_CORE; }

		/* Verify that the updated RTO is within 10 jiffies from the
		 * expected RTO.
		 */
		if (abs(rto - t->rto) > 10) {
			printf("rto differs by %d\n", abs(rto - t->rto));
			DUMP_CORE;
		}

        	test_frame_get_message(sk2, message);
	}

	sctp_close(sk1, 0);
	if ( 0 != test_run_network()) { DUMP_CORE; }

	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
