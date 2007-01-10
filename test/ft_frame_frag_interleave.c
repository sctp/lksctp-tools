/* SCTP kernel reference Implementation
 * (C) Copyright 2006 Hewlett-Packard Development Company, L.P.
 *
 * This file is part of the SCTP kernel reference Implementation
 *
 * The SCTP reference implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * The SCTP reference implementation is distributed in the hope that it
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
 *    Vlad Yasevich <vladislav.yasevich@hp.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * Test to verify data interleave during  partial delivery.
 *
 * Here is the test case:
 * 	1. Setup 3 sockets, one server and 2 clients.
 * 	2. Establish associations between client and serve sockets
 * 	   creating a server endpoint with multiple associations.
 * 	3. From one of the clients, send a message larger then server's
 * 	   receive buffer.  This places server's associatoin in partial
 * 	   delivery mode.
 * 	4. From the other client send some data.
 * 	5. Verify that the data reads on the server are interleaved.
 */

#include <net/ip.h>
#include <net/sctp/sctp.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock *sk1, *sk2, *sk3;
	struct sctp_endpoint *ep1, *ep2, *ep3;
	struct sctp_association *asoc1, *asoc2to1, *asoc3, *asoc2to3;
	struct sockaddr_in loop1, loop2;
	void *msg_buf, *msg_buf2;
	struct sctp_event_subscribe subscribe;
	int error;
	int on = 1, pd_point;
	int num_interleave;

	/* Do all that random stuff needed to make a sensible universe.  */
	sctp_init();

	sctp_rcvbuf_policy = 1;

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Set rcvbuf to hold 8 MTU of data so that
	 * our receive window is only 4 MTUs.
	 */
	sk2->sk_rcvbuf = 8*(1500 + sizeof(struct sk_buff));

	sk3 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Test without patial data delivery by upping the send 
	 * and receive buffers.
	 */
	sk1->sk_sndbuf = 8*(1500 + sizeof(struct sk_buff));
	sk3->sk_sndbuf = 8*(1500 + sizeof(struct sk_buff));

	/* Bind this sockets to the test ports.  */
	loop1.sin_family = AF_INET;
	loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.sin_port = 0;

	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }

	loop2.sin_family = AF_INET;
	loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.sin_port = htons(SCTP_TESTPORT_2);

	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Enable SCTP_PARTIAL_DELIVERY_EVENT which is not on by default.
	 *
	 */
	memset(&subscribe, 0, sizeof(struct sctp_event_subscribe));
	subscribe.sctp_data_io_event = 1;
	subscribe.sctp_association_event = 1;
	subscribe.sctp_partial_delivery_event = 1;
	if (0 !=  sctp_setsockopt(sk2, SOL_SCTP, SCTP_EVENTS, 
				  (char *)&subscribe,
				  sizeof(struct sctp_event_subscribe))) {
		DUMP_CORE;
	}

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }

	error = test_bind(sk3, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }

	/* We now do Cookie-Echo bundling as much as possible, so
	 * get this out of the way for the rest of the tests.
	 */
	msg_buf = test_build_msg(100);

	/*
	 * TEST 1:
	 *
	 * With fragment interleave ON, put one association into Partial
	 * Delivery and send a small message on the other assocation.
	 * Make sure that we can recieve the small message intereleaved
	 * into the partial delivery.
	 */

	/* enable Fragment Interleave */
	if (0 != sctp_setsockopt(sk2, SOL_SCTP, SCTP_FRAGMENT_INTERLEAVE,
				 (char*)&on, sizeof(on))) {
		DUMP_CORE;
	}

	/* Send the first messages.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2to1 = test_ep_first_asoc(ep2);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, msg_buf);

	/* Now start a second association on sk2. */
	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf);

	ep3 = sctp_sk(sk3)->ep;
	asoc3 = test_ep_first_asoc(ep3);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk3, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, msg_buf);

	/* Get the second assocation from ep2, and make sure
	 * it's not the same as the 2-to-1 association
	 */
	asoc2to3 = test_ep_last_asoc(ep2);
	if (asoc2to1 == asoc2to3)
		DUMP_CORE;

	free(msg_buf);

	/* Now, get into the partial delivery state on the
	 * first assocaition, by sending more then the receive window
	 * can hold.
	 */

	msg_buf = test_build_msg(1500*5);

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Now send the packet that we would expect to be
	 * interleaved
	 */
	msg_buf2 = test_build_msg(100);
	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Check that we entered partial delivery */
	if (atomic_read(&sctp_sk(asoc2to1->base.sk)->pd_mode) == 0)
		DUMP_CORE;

	/* Now, we need to read data to see if we get interleaved
	 * messages
	 */
	num_interleave =
		    test_frame_get_message_interleave(sk2, msg_buf, msg_buf2);
	if (!num_interleave)
		DUMP_CORE;

	printk("\nTEST1: Messages Interleaved %d times.\n", num_interleave);

	if (0 != test_run_network()) { DUMP_CORE; }

	/*
	 * TEST 2:
	 *
	 * Now place both associations into Partial delivery, by sending
	 * more then the recieve buffer can take.  Receive interleaved
	 * data.
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	
	/* Check that we entered partial delivery on the first association */
	if (!asoc2to1->ulpq.pd_mode)
		DUMP_CORE;

	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Run the SACK timeout to force second assocition into pd */
	jiffies += asoc2to3->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Check the second association as well */
	if (!asoc2to3->ulpq.pd_mode)
		DUMP_CORE;

	/* Now, we need to read data to see if we get interleaved
	 * messages
	 */
	num_interleave =
		    test_frame_get_message_interleave(sk2, msg_buf, msg_buf);
	if (!num_interleave)
		DUMP_CORE;

	printk("\nTEST2: Messages Interleaved %d times.\n", num_interleave);

	/*
	 * TEST 3
	 *
	 * Combine interleave and partial delivery point.
	 * This is like TEST 2, but we also set partial delivery
	 * point option so that partial delivery is forced earlier.
	 */

	/* enable PD point */
	pd_point = 1000;
	if (0 != sctp_setsockopt(sk2, SOL_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
				 (char*)&pd_point, sizeof(pd_point))) {
		DUMP_CORE;
	}

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	
	/* Check that we entered partial delivery on the first association */
	if (!asoc2to1->ulpq.pd_mode)
		DUMP_CORE;

	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Check the second association as well */
	if (!asoc2to3->ulpq.pd_mode)
		DUMP_CORE;

	/* Now, we need to read data to see if we get interleaved
	 * messages
	 */
	num_interleave =
	    test_frame_get_message_interleave(sk2, msg_buf, msg_buf);
	if(!num_interleave)
		DUMP_CORE;

	printk("\nTEST3: Messages Interleaved %d times.\n", num_interleave);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	sctp_close(sk3, 0);
	if (0 != test_run_network()) { DUMP_CORE; }

	printk("\n\n%s passed\n\n\n", argv[0]);

	exit(0);

} /* main() */
