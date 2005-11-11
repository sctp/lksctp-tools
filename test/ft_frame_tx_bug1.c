/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2002, 2004
 * Copyright (c) 1999-2001 Motorola, Inc.
 *
 * This file is part of the SCTP kernel reference Implementation
 *
 * A testcase to regression test a bug we had where
 * new small data can sneak by data that is waiting in the
 * retransmit queue due to window limits.
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
 *    Jon Grimm   <jgrimm@us.ibm.com>
 *    Sridhar Samudrala <sri@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
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
	void *msg_nofrag;
	void *small_msg;
	int error;

	/* Do all that random stuff needed to make a sensible universe.  */
	sctp_init();

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk1->sk_rcvbuf = 65536;
	sk2->sk_rcvbuf = 65536;

	/* Bind this sockets to the test ports.  */
	loop1.sin_family = AF_INET;
	loop1.sin_addr.s_addr = SCTP_ADDR_ETH1;
	loop1.sin_port = htons(SCTP_TESTPORT_1);

	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }
	loop1.sin_addr.s_addr = SCTP_ADDR_ETH0;
	error = test_bindx(sk1, (struct sockaddr *)&loop1,
			   sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	loop2.sin_family = AF_INET;
	loop2.sin_addr.s_addr = SCTP_ADDR_ETH0;
	loop2.sin_port = htons(SCTP_TESTPORT_2);

	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }	
	loop2.sin_addr.s_addr = SCTP_ADDR_ETH1;
	error = test_bindx(sk2, (struct sockaddr *)&loop2,
			   sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }

	msg_nofrag = test_build_msg(1001);
	small_msg = test_build_msg(1);

	/* Send the first messages.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_nofrag);

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
	test_frame_get_message(sk2, msg_nofrag);

	/* Verify the initial Congestion Parameters. */
	test_verify_congestion_parameters(t1, 4380, 32768, 0, 0);

	/* Here's the plan of attack.
	 * 1) Drop 4 1001 byte messages.
	 * 2) Timeout retransmit.  This should send 1 packet (and only
	 * the first message.
	 * 3) Sending a 1 byte message.
	 * 
	 * There is a bug where this 1 byte message can bypass the 
	 * retransmit data.  But retransmit data MUST always precede
	 * new data.
	 * 
	 */

	/* Send 4 messages and drop them all.  */
	/* The SACK received for these messages will increase the cwnd by
	 * 1 mtu.
	 */
	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_nofrag);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_nofrag);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_nofrag);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_kill_next_packet(SCTP_CID_DATA);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_nofrag);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Kill the SACK that can happen as part of the 
	 * retransmit packet. 
	 */
	test_kill_next_packet(SCTP_CID_SACK);

        /* Move time forward by a RTX timeout.  */
	jiffies += asoc1->peer.primary_path->rto + 1;
	error = test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Now, send that 1 byte message. */
	test_frame_send_message2(sk1, (struct sockaddr *)&loop2, small_msg,
				 (sctp_assoc_t)asoc1, 1, 0, SCTP_UNORDERED);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Make sure we send a SACK back just in case. */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	error = test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message(sk2, msg_nofrag);
	test_frame_get_message(sk2, msg_nofrag);
	test_frame_get_message(sk2, msg_nofrag);
	/* This next line fails when the bug is in place, as
	 * the smaller message bypasses the retransmit data.
	 */
	test_frame_get_message(sk2, msg_nofrag);
	test_frame_get_message(sk2, small_msg);

	if (0 != test_run_network()) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (0 != test_run_network()) { DUMP_CORE; }

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}
	exit(0);
} /* main() */
