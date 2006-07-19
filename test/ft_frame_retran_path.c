/* SCTP Kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * The SCTP reference implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * The SCTP reference implementation  is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.  
 * 
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 * 
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by: 
 *    Sridhar Samudrala <sri@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 * 
 */

/* TEST #1
 * Verify that a message is retransmitted among all the active transports of a
 * multi-homed association in a round-robin fashion.
 * TEST #2
 * Verify that SHUTDOWN is retransmitted among all the active transports of a
 * multi-homed association in a round-robin fashion.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
        struct sock *sk1, *sk2;
        struct sctp_endpoint *ep1, *ep2;
        struct sctp_association *asoc1, *asoc2;
	struct sctp_transport *asoc1_t1, *asoc1_t2, *asoc1_t3;
        struct sockaddr_in sk1addr1, sk1addr2, sk1addr3;
        struct sockaddr_in sk2addr1, sk2addr2, sk2addr3;
	uint8_t *message = "Hello, World!!!\n";
	struct sctp_chunk *chunk, *chunk1;

        /* Do all that random stuff needed to make a sensible universe. */
        sctp_init();

        /* Create the two endpoints which will talk to each other. */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind this sockets to the test ports. */
        sk1addr1.sin_family = AF_INET;
        sk1addr1.sin_addr.s_addr = SCTP_ADDR_ETH0;
        sk1addr1.sin_port = htons(SCTP_TESTPORT_1);
        sk1addr2.sin_family = AF_INET;
        sk1addr2.sin_addr.s_addr = SCTP_ADDR_ETH1;
        sk1addr2.sin_port = htons(SCTP_TESTPORT_1);
        sk1addr3.sin_family = AF_INET;
        sk1addr3.sin_addr.s_addr = SCTP_ADDR_ETH2;
        sk1addr3.sin_port = htons(SCTP_TESTPORT_1);

        if (test_bind(sk1, (struct sockaddr *)&sk1addr1, sizeof(sk1addr1)))
		DUMP_CORE;
	if (test_bindx(sk1, (struct sockaddr *)&sk1addr2, sizeof(sk1addr2),
		       SCTP_BINDX_ADD_ADDR))
		DUMP_CORE;
	if (test_bindx(sk1, (struct sockaddr *)&sk1addr3, sizeof(sk1addr3),
		       SCTP_BINDX_ADD_ADDR))
		DUMP_CORE;

        sk2addr1.sin_family = AF_INET;
        sk2addr1.sin_addr.s_addr = SCTP_ADDR_ETH0;
        sk2addr1.sin_port = htons(SCTP_TESTPORT_2);
        sk2addr2.sin_family = AF_INET;
        sk2addr2.sin_addr.s_addr = SCTP_ADDR_ETH1;
        sk2addr2.sin_port = htons(SCTP_TESTPORT_2);
        sk2addr3.sin_family = AF_INET;
        sk2addr3.sin_addr.s_addr = SCTP_ADDR_ETH2;
        sk2addr3.sin_port = htons(SCTP_TESTPORT_2);

        if (test_bind(sk2, (struct sockaddr *)&sk2addr1, sizeof(sk2addr1)))
		DUMP_CORE;
	if (test_bindx(sk2, (struct sockaddr *)&sk2addr2, sizeof(sk2addr2),
		       SCTP_BINDX_ADD_ADDR))
		DUMP_CORE;
	if (test_bindx(sk2, (struct sockaddr *)&sk2addr3, sizeof(sk2addr3),
		       SCTP_BINDX_ADD_ADDR))
		DUMP_CORE;

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }

        /* Send the first message. */
        test_frame_send_message(sk1, (struct sockaddr *)&sk2addr1, message);

   	if (0 != test_run_network()) { DUMP_CORE; }

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent. */
        test_frame_get_message(sk2, message);

	/* Make sure that heartbeats are sent and all the paths are
	 * confirmed.
	 */
	jiffies += (1.5 * SCTP_RTO_INITIAL + 1);
	if (test_run_network())
		DUMP_CORE;

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	/* Store the 3 transports. */ 
	asoc1_t1 = asoc1->peer.primary_path;
	asoc1_t2 = list_entry(asoc1_t1->transports.next, struct sctp_transport,
			      transports);
	asoc1_t3 = list_entry(asoc1_t2->transports.next, struct sctp_transport,
			      transports);

	if (asoc1_t2 != asoc1->peer.retran_path)
		DUMP_CORE;

	/* TEST #1
	 * Verify that a message is retransmitted among all the active
	 * transports of a multi-homed association in a round-robin fashion.
	 */
	/* Mark all the 3 networks down so that the message cannot be sent on
	 * any of the transports.
	 */ 
	test_break_network(TEST_NETWORK_ETH0);
	test_break_network(TEST_NETWORK_ETH1);
	test_break_network(TEST_NETWORK_ETH2);

	/* Send a message. */ 
	test_frame_send_message(sk1, (struct sockaddr *)&sk2addr1, message);

	/* Get the chunk stored on the asoc1_t1's transmitted list. */ 
	chunk1 = test_get_chunk(&asoc1_t1->transmitted, 1);
	if (!chunk1)
		DUMP_CORE;

	if (0 != test_run_network()) { DUMP_CORE; }

        /* Move time forward by asoc1_t1's RTX timeout.  */
	jiffies += asoc1_t1->rto + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Verify the retran path and the chunk should have now moved to
	 * asoc1_t2's transmitted list.
	 */
	if (asoc1_t2 != asoc1->peer.retran_path)
		DUMP_CORE;
	chunk = test_get_chunk(&asoc1_t2->transmitted, 1);
	if (chunk != chunk1)
		DUMP_CORE;

        /* Move time forward by asoc1_t2's RTX timeout.  */
	jiffies += asoc1_t2->rto + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Verify the retran path and the chunk should have now moved to
	 * asoc1_t3's transmitted list.
	 */
	if (asoc1_t3 != asoc1->peer.retran_path)
		DUMP_CORE;
	chunk = test_get_chunk(&asoc1_t3->transmitted, 1);
	if (chunk != chunk1)
		DUMP_CORE;

        /* Move time forward by asoc1_t3's RTX timeout.  */
	jiffies += asoc1_t3->rto + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Verify the retran path and the chunk should have now moved back to
	 * asoc1_t1's transmitted list.
	 */
	if (asoc1_t1 != asoc1->peer.retran_path)
		DUMP_CORE;
	chunk = test_get_chunk(&asoc1_t1->transmitted, 1);
	if (chunk != chunk1)
		DUMP_CORE;

	/* Fix ETH1 network so that the packet can be sent. */
	test_fix_network(TEST_NETWORK_ETH1);

        /* Move time forward by asoc1_t1's RTX timeout.  */
	jiffies += asoc1_t1->rto + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Verify the retran path and the chunk should have now moved to
	 * asoc1_t2's transmitted list.
	 */
	chunk = test_get_chunk(&asoc1_t2->transmitted, 1);
	if (chunk != chunk1)
		DUMP_CORE;
	if (asoc1_t2 != asoc1->peer.retran_path)
		DUMP_CORE;

        test_frame_get_message(sk2, message);

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* TEST #2
	 * Verify that SHUTDOWN is retransmitted among all the active
	 * transports of a multi-homed association in a round-robin fashion.
	 */
	test_break_network(TEST_NETWORK_ETH1);

	/* Close sk1 to initiate the SHUTDOWN. */
	sctp_close(sk1, 0);

	/* Verify the shutdown transport used. */
	if (asoc1_t1 != asoc1->shutdown_last_sent_to)
		DUMP_CORE;

	/* Move time forward by a T2-shutdown timeout.  */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T2_SHUTDOWN] + 1;
	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* Verify the shutdown transport used. */
	if (asoc1_t2 != asoc1->shutdown_last_sent_to)
		DUMP_CORE;

	/* Move time forward by a T2-shutdown timeout.  */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T2_SHUTDOWN] + 1;
	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* Verify the shutdown transport used. */
	if (asoc1_t3 != asoc1->shutdown_last_sent_to)
		DUMP_CORE;

	/* Move time forward by a T2-shutdown timeout.  */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T2_SHUTDOWN] + 1;
	if ( 0 != test_run_network()) { DUMP_CORE; }

	/* Verify the shutdown transport used. */
	if (asoc1_t1 != asoc1->shutdown_last_sent_to)
		DUMP_CORE;

	/* Fix ETH1 network so that SHUTDOWN can be sent. */
	test_fix_network(TEST_NETWORK_ETH1);

	/* Move time forward by a T2-shutdown timeout.  */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T2_SHUTDOWN] + 1;
	if ( 0 != test_run_network()) { DUMP_CORE; }

	if (asoc1_t2 != asoc1->shutdown_last_sent_to)
		DUMP_CORE;

	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

	/* Indicate successful completion.  */
	exit(0);

} /* main() */
