/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
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
 *    Jon Grimm   <jgrimm@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * Test to verify send and receive of a data message larger than can 
 * fit inside a single chunk and that partial delivery can really 
 * delivery it.  
 *
 * Advanced tests:
 *   * Test multiple association and that partial delivery is both honored and
 *   can be recovered from when the partial delivery finishes.
 *   * Test abort of a partial delivery association sends event and that
 *   non-pd associations on the same socket are started up again.
 *   * Test peeloff & partial delivery
 *      a) peeloff partial delivery association
 *      b) peeloff non-partial delivery association
 */

#include <net/ip.h>
#include <net/sctp/sctp.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock *sk1, *sk2, *sk3;
	struct socket *peeloff1, *peeloff2;
	struct sctp_endpoint *ep1, *ep2, *ep3;
	struct sctp_association *asoc1, *asoc2, *asoc3;
	struct msghdr outmsg1;
	struct cmsghdr *outcmsg1;
	char infobuf1[CMSG_SPACE_SNDRCV] = {0};
	struct sctp_sndrcvinfo *sinfo1;
	struct sockaddr_in loop1, loop2;
	void *msg_buf, *msg_buf2, *msg_buf3;
	struct sctp_event_subscribe subscribe;
	int bytes_sent;
	int error;

	/* Do all that random stuff needed to make a sensible universe.  */
	sctp_init();

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	/* Set rcvbuf to a large value so that we don't run into drops
	 * due to out of receive buffer space.
	 */
	sk2->sk_rcvbuf = (1<<18);

	sk3 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Test without patial data delivery by upping the send 
	 * and receive buffers.
	 */
	sk1->sk_sndbuf = (1<<18);	
	sk3->sk_sndbuf = (1<<18);	

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

	/* Send the first messages.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	if (0 != test_run_network()) { DUMP_CORE; }

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

	free(msg_buf);

	/* Now send and receive a big (size  >= 2^16 ). */

	/* Note: the frametest framework breaks down much beyond this
	 * without reworking the sock glue.
	 */
	msg_buf = test_build_msg((1<<16) + 500);

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* This SACK timeout and others like it our to get the test
	 * frame into a similar state.   The SACK rules have one
	 * SACKing every other packet, so we do a SACK timeout to get
	 * the sender into a known state regardless of the even/odd
	 * number of packets sent.  
	 */
	jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK]+1;
	test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Now be evil; send on the other socket too. */
	msg_buf2 = test_build_msg(5);
	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK]+1;
	test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }


	test_frame_get_message_all(sk2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_get_message_all(sk2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }
	
	jiffies += asoc3->peer.primary_path->rto +1;
	test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message_all(sk2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	test_run_network();

	jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK]+1;
	test_run_timeout();

	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* OK.  We should have a partial delivery sitting in the
	 * receive queue for sk1 and sk3 must wait. 
	 * Now ABORT sk1.  
	 */
	/* Build up a msghdr structure we can use for all sending.  */
	outmsg1.msg_name = &loop2;
	outmsg1.msg_namelen = sizeof(loop2);
 	outmsg1.msg_flags = 0;
	outmsg1.msg_iov = NULL;
	outmsg1.msg_iovlen = 0;

        /* Build up a SCTP_SNDRCV CMSG. */
	outmsg1.msg_control = infobuf1;
	outmsg1.msg_controllen = sizeof(infobuf1);
	outcmsg1 = CMSG_FIRSTHDR(&outmsg1);
	outcmsg1->cmsg_level = IPPROTO_SCTP;
	outcmsg1->cmsg_type = SCTP_SNDRCV;
	outcmsg1->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	sinfo1 = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg1);
	memset(sinfo1, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo1->sinfo_flags |= SCTP_ABORT;

	/* Call sendmsg() to abort the association.  */
	bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg1, 0);
	if (bytes_sent != 0) { DUMP_CORE; }
	test_run_network();

	/* This will read until we get the partial message delivery abort. */
	test_frame_get_message_pd(sk2, msg_buf, 1);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Now we can get the message that sk3 sent. */
	test_frame_get_message_all(sk2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Get the communication lost message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_LOST);


	/* Start another association from sk1 to sk2. */

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Get the communication up from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_message_all(sk2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Lets initiate an association both from and back to sk2.   Fun with
	 * auto-accepting/connecting multi-association sockets */
	test_frame_send_message(sk2, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Get the communication up from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_message_all(sk2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* OK. There are three associations up. */  
       
	/* Send a small message that can move up to the receive queue. */
	msg_buf3 = test_build_msg(100);
	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf3);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Send a message to force partial delivery. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Send messages on the other two associations, which will get
	 * blocked up.
	 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	test_frame_send_message(sk2, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_send_message(sk3, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Peel off a partial delivery association. */
	if (sctp_do_peeloff(asoc2, &peeloff1))
		DUMP_CORE;

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Send another message to the socket in pd_mode. */
	asoc2 = test_ep_first_asoc(ep2);
	if (sctp_do_peeloff(asoc2, &peeloff2))
		DUMP_CORE;


	/* Now for the fun.  Each of the three associations are
	 * on different sockets.  The partial delivery socket
	 * is on peeloff2 now.  
	 */
	
	/* This message wasn't blocked, so this is really just testing
	 * that I haven't broken normal peeloff.
	 */
	test_frame_get_message_all(peeloff1->sk, msg_buf3);

	/* The next message is for the association that is left on the
	 * original socket.  It is no longer blocked by the partial
	 * delivery socket.  
	 */
	test_frame_get_message_all(sk2, msg_buf2);

	/* This message was also blocked by the partial delivery association,
	 * but no longer as it has been peeled off.  
	 */
	test_frame_get_message_all(peeloff1->sk, msg_buf2);

	/* Test the message that had to be partially delivered. */
	test_frame_get_message_all(peeloff2->sk, msg_buf);

	/* Finally, did we get the message that was sent after 
	 * first peeloff (to make sure the partial delivery condition
	 * did not get bypassed.
	 */
	test_frame_get_message_all(peeloff2->sk, msg_buf2);

	sctp_close(sk1, 0);
	sctp_close(sk3, 0);
	sctp_close(sk2, 0);
	sctp_close(peeloff2->sk, 0);
	sctp_close(peeloff1->sk, 0);

	if (0 != test_run_network()) { DUMP_CORE; }

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	exit(0);

} /* main() */
