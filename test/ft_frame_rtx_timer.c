/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is the Functional Test for testing retransmission timeout functionality 
 * for UDP-style socket.
 * 
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
        struct sctp_endpoint *ep1, *ep2;
        struct sctp_association *asoc1, *asoc2;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
	uint8_t *message = "Hello, World!!!\n";
	sctp_data_chunk_t *data_chunk;
	uint32_t rto;
	uint32_t tsn;
	int error;
	int i;

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();
	
	sctp_hb_interval = 60000;

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

	/* Figure out the expected TSN of the next DATA chunk. */
	tsn = asoc1->next_tsn;

	/* Test #1: Test association close after max retransmission 
	 * attempts. 
	 */

	/* Initial RTO. */
	rto = asoc1->peer.primary_path->rto;

        /* Send a message. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	/* Drop the packets and make sure that retransmission of the same
	 * packet occurs upto the association's error threshold value with
	 * proper RTO backoff.
	 */ 
	for (i = 0; i <= asoc1->max_retrans; i++) {
		rto = asoc1->peer.primary_path->rto;

		/* Look for the data chunk with the expected tsn. */
		if (!(data_chunk = (sctp_data_chunk_t *)test_find_chunk(
				    TEST_NETWORK0, SCTP_CID_DATA, NULL, NULL))) {
			DUMP_CORE;
		}
		if (tsn != ntohl(data_chunk->data_hdr.tsn)) { DUMP_CORE; }

		/* Drop the packet. */
		test_kill_next_packet(SCTP_CID_DATA);
        	error = test_run_network();
        	if (error != 0) { DUMP_CORE; }

		/* Force the retransmission timer. */
		jiffies += rto + 1;
		test_run_timeout();

		if (i == asoc1->max_retrans) {
			break;
		}

		/* Check that the RTO is updated as expected. */	
		if (asoc1->peer.primary_path->rto != 
				min(2*rto, asoc1->rto_max)) {
			DUMP_CORE;
		}
	}

	/* We should see the COMMUNICATION_LOST event after the error 
	 * threshold value is reached.
	 */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_LOST);

	sctp_close(sk1, 0);
	test_run_network();
	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */



