/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
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
 *    Sridhar Samudrala  <sri@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * Test to verify SCTP PMTU discovery process.
 */

#include <net/ip.h>
#include <net/sctp/sctp.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sctp_transport *t1, *t2;
	struct sockaddr_in loop1, loop2;
	union sctp_addr *peer1 = (union sctp_addr *)&loop2;
	union sctp_addr *peer2 = (union sctp_addr *)&loop1;
	struct sk_buff *skb;
	sctp_data_chunk_t *data_chunk;
	uint32_t tsn;
	void *msg_buf;
	int error;
	struct sctp_paddrparams params1, params2;

	/* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();

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

	/* Set pmtu parameters for socket 2. */
	setup_paddrparams(&params2, NULL, NULL);
	params2.spp_pathmtu    = 1200;
	params2.spp_flags      = SPP_PMTUD_DISABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params2, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	error = test_paddrparams(sk2, &params2, NULL, NULL, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }

	/* We now do Cookie-Echo bundling as much as possible, so
	 * get this out of the way for the rest of the tests.
	 */
	msg_buf = test_build_msg(100);

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

	free(msg_buf);
	msg_buf = test_build_msg(1352);

	/* Test parameters for asoc2 (make sure they came
	 * through from the socket)
	 */
	setup_paddrparams(&params2, asoc2, NULL);
	params2.spp_pathmtu    = 1200;
	params2.spp_flags      = SPP_PMTUD_DISABLE;

	error = test_paddrparams(sk2, &params2, asoc2, NULL, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params2, asoc2, peer2);
	error = test_paddrparams(sk2, &params2, asoc2, peer2, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	/* Disable heartbeats. */
	t1->param_flags = (t1->param_flags & ~SPP_HB) | SPP_HB_DISABLE;
	t2->param_flags = (t2->param_flags & ~SPP_HB) | SPP_HB_DISABLE;

	/* Verify the default pmtu is set correctly. */
	if ((asoc1->pathmtu != 1500) || (t1->pathmtu != 1500) ||
	    (dst_mtu(t1->dst) != 1500)) {
		DUMP_CORE;
	}

	/* Lower the pmtu to 1200. */
	test_set_ip_mtu(1200);

	/* Send a message larger than the new pmtu. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	/* Peek the skb and store the value of tsn for later comparision. */
	if ((skb = test_peek_packet(TEST_NETWORK0)) == NULL)
		DUMP_CORE;
	data_chunk = (sctp_data_chunk_t *)(skb->data + sizeof(struct iphdr) +
					   sizeof(struct sctphdr));
	tsn = ntohl(data_chunk->data_hdr.tsn);

	/* Verify that the DF bit is set in the ip header for this packet. */
	if (!(ip_hdr(skb)->frag_off & htons(IP_DF)))
		DUMP_CORE;

	/* Put the message on the network. This should result in the SCTP error
	 * handler to be called with ICMP frag. needed error, causing the
	 * message to be retransmitted with DF bit not set.
	 */
	if (test_run_network_once(TEST_NETWORK0) < 0) { DUMP_CORE; }

	if ((skb = test_peek_packet(TEST_NETWORK0)) == NULL)
		DUMP_CORE;
	data_chunk = (sctp_data_chunk_t *)(skb->data + sizeof(struct iphdr) +
					   sizeof(struct sctphdr));
	/* Verify that the same packet is retransmitted by comparing the tsn. */
	if (tsn != ntohl(data_chunk->data_hdr.tsn))
		DUMP_CORE;
	/* Verify that the DF bit is not set in the ip header for this
	 * packet.
	 */
	if (ip_hdr(skb)->frag_off & htons(IP_DF))
		DUMP_CORE;

	if (0 != test_run_network()) { DUMP_CORE; }

	/* Verify that pmtu is updated to the lowered value of 1200. */
	if ((asoc1->pathmtu != 1200) || (t1->pathmtu != 1200) ||
	    (dst_mtu(t1->dst) != 1200)) {
		DUMP_CORE;
	}

	test_frame_get_message(sk2, msg_buf);

	/* Increase the pmtu back to 1500. */
	test_set_ip_mtu(1500);

	/* Send and get a message. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_get_message(sk2, msg_buf);

	/* Verify that pmtu is still 1200. */
	if ((asoc1->pathmtu != 1200) || (t1->pathmtu != 1200) ||
	    (dst_mtu(t1->dst) != 1200)) {
		DUMP_CORE;
	}

	/* Generate and handle the delayed SACK. */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Let the dst expire. */
	jiffies += t1->dst->expires + 1;
	if (0 != test_run_timeout()) { DUMP_CORE; }

	/* Verify that the dst is marked obsolete. */
	if (t1->dst->obsolete != 2)
		DUMP_CORE;

	/* Send a message and verify that the pmtu is now updated to the new
	 * value after the dst expiry.
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	if ((asoc1->pathmtu != 1500) || (t1->pathmtu != 1500) ||
	    (dst_mtu(t1->dst) != 1500)) {
		DUMP_CORE;
	}
	test_frame_get_message(sk2, msg_buf);

	/* Now test setting and controlling the pmtu options for sk1. */
	setup_paddrparams(&params1, asoc1, NULL);
	params1.spp_pathmtu    = 1200;
	params1.spp_flags      = SPP_PMTUD_DISABLE;

	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params1, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	error = test_paddrparams(sk1, &params1, asoc1, NULL, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	error = test_paddrparams(sk1, &params1, asoc1, peer1, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	/* Send and get a message. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }
	test_frame_get_message(sk2, msg_buf);

	/* Verify that pmtu is still 1200. */
	error = test_paddrparams(sk1, &params1, asoc1, NULL, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	error = test_paddrparams(sk1, &params1, asoc1, peer1, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	/* Generate and handle the delayed SACK. */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	dst_set_expires(t1->dst, 0);

	/* Let the dst expire. */
	jiffies += t1->dst->expires + 1;
	if (0 != test_run_timeout()) { DUMP_CORE; }

	/* Verify that the dst is marked obsolete. */
	if (t1->dst->obsolete != 2)
		DUMP_CORE;

	/* Send a message and verify that the pmtu is still the same
	 * value after the dst expiry.
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	error = test_paddrparams(sk1, &params1, asoc1, NULL, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	error = test_paddrparams(sk1, &params1, asoc1, peer1, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	test_frame_get_message(sk2, msg_buf);

	/* Generate and handle the delayed SACK. */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Now re-enable path mtu discovery. */
	params1.spp_flags      = SPP_PMTUD_ENABLE;

	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params1, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* Verify that pmtu is now 1500. */
	params1.spp_pathmtu    = 1500;
	error = test_paddrparams(sk1, &params1, asoc1, NULL, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	error = test_paddrparams(sk1, &params1, asoc1, peer1, SPP_PMTUD);
	if (error)
		DUMP_CORE;

	/* Send and get a message. */
	free(msg_buf);
	msg_buf = test_build_msg(2000);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	sk1->sk_lock.owned = 1;
	/* Set the mtu to 512 */
	test_set_ip_mtu(512);

	if (0 != test_run_network()) { DUMP_CORE; }

	sk1->sk_lock.owned = 0;

	if (asoc1->pmtu_pending != 1) { DUMP_CORE; }

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	if (asoc1->pathmtu != 512 || dst_mtu(t1->dst) != 512)
		DUMP_CORE;

	/* We need to wait for a retransmit before we can get both packets */
        jiffies += t1->rto + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message(sk2, msg_buf);
	test_frame_get_message(sk2, msg_buf);

	/* Generate and handle the delayed SACK. */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	if (0 != test_run_network()) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	exit(0);

} /* main() */
