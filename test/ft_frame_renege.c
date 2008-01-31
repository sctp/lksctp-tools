/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This file is part of the SCTP kernel Implementation
 *
 * The SCTP implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * The SCTP implementation is distributed in the hope that it
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
 * Test to test a bit of code to enable reneging to make room for
 * the next fragment to fill in a gap.  The only way I figured to do
 * this is to pretend to be a malicious (or at least confused sender)
 * in that I'll drop the needed fragment, but fill up the receiver's
 * receive buffers.
 */

#include <net/ip.h>
#include <net/sctp/sctp.h>
#include <funtest.h>

#define TEST_SMALL_BUF(x) (sctp_frag_point(sctp_sk((x)), 1500) *3+1)

int main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sctp_transport *t1;
	struct sockaddr_in loop1, loop2;
	void *msg_buf, *msg_buf2;
	struct sctp_event_subscribe subscribe;
	int inflight;
	int smallbuf;
	int error;

	/* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Test without patial data delivery by upping the send 
	 * and receive buffers.
	 */
	sk1->sk_sndbuf = (1<<18);
	smallbuf = TEST_SMALL_BUF(sk1); 
	sk2->sk_rcvbuf = smallbuf;

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


	/* We now do Cookie-Echo bundling as much as possible, so
	 * get this out of the way for the rest of the tests.
	 */
	msg_buf = test_build_msg(1000);

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

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, msg_buf);

	
        /* Verify the initial Congestion Parameters. */
	test_verify_congestion_parameters(t1, 4380, smallbuf/2, 0, 0);

	/* Note: the frametest framework breaks down much beyond this
	 * without reworking the sock glue.
	 */
	msg_buf2 = test_build_msg(sctp_frag_point(sctp_sk(sk1), 1500)*4+2);

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf2);

	test_kill_next_packet(SCTP_CID_DATA);

	test_run_network_once(TEST_NETWORK0);
	test_run_network_once(TEST_NETWORK0);
	test_run_network_once(TEST_NETWORK0);     
	test_run_network_once(TEST_NETWORK0);   
	
	/* Be malicious and send even though we have data already
	 * in flight... this is the only way I've figured out
	 * how to trigger a need for renege.  This models
	 * a variation on a teardrop attack.. though really we
	 * are being nice and make room to fill in this gap if
	 * possible.   An attacker wouldn't bother filling in the gap. 
	 */
	inflight = asoc1->outqueue.outstanding_bytes;
	asoc1->outqueue.outstanding_bytes -= sctp_frag_point(sctp_sk(sk1), 
							     1500);
	test_run_network_once(TEST_NETWORK0);
	test_run_network_once(TEST_NETWORK0);
	asoc1->outqueue.outstanding_bytes = inflight;

	asoc1->outqueue.outstanding_bytes -= sctp_frag_point(sctp_sk(sk1), 
							     1500);
	test_run_network_once(TEST_NETWORK0);
	test_run_network_once(TEST_NETWORK0);
	asoc1->outqueue.outstanding_bytes = inflight;

	if (0 != test_run_network()) { DUMP_CORE; }
	
	jiffies += asoc1->peer.primary_path->rto +1;
	test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }

	jiffies += asoc1->peer.primary_path->rto +1;
	test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message_all(sk2, msg_buf2);
	if (0 != test_run_network()) { DUMP_CORE; }

#if 0	
	jiffies += asoc3->peer.primary_path->rto +1;
	test_run_timeout();
	if (0 != test_run_network()) { DUMP_CORE; }
#endif 

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (0 != test_run_network()) { DUMP_CORE; }

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	exit(0);

} /* main() */
