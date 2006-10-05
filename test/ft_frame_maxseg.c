/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 *
 * This is a testframe functional test to verify the data fragmentation,
 * reassembly support, and SCTP_MAXSEG socket option.
 * The following tests are done in sequence.
 * - Verify SCTP_DISABLE_FRAGMENTS socket option by doing a setsockopt()
 *   followed by a getsockopt().
 * - Verify that a message size exceeding the association fragmentation
 *   point cannot be sent when fragmentation is disabled.
 * - Use SCTP_MAXSEG to fragment smaller than PMTU allows. 
 * - Verify that the data is fragmented correctly by looking at the TSN and
 *   the flags fields in the data chunks and the TSN in the SACK chunks.
 * - Send and receive a set of messages that are bigger than the path mtu.
 *   The different message sizes to be tested are specified in the array
 *   msg_sizes[].
 *
 * To compile the v6 version, set the symbol TEST_V6 to 1.
 *
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Narasimha Budihal <narsi@refcode.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <sri@us.ibm.com>
 * Jon Grimm         <jgrimm@us.ibm.com>
 *
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

int msg_sizes[] = {1353, 2000, 5000, 10000, 20000, 32768};

int
main(int argc, char *argv[])
{
	int pf_class;
	struct sock *sk1;
        struct sock *sk2;
        struct sctp_association *asoc1;
        struct sctp_association *asoc2;
	struct sctp_endpoint *ep1;
	struct sctp_endpoint *ep2;
        union sctp_addr loop1;
        union sctp_addr loop2;
	int error, maxseg;
	void *msg_buf;
	int i, msg_cnt;
	struct msghdr msg;
	struct iovec iov;
	int nfrags, disable_frag, frag_no;
	int msg_size, optlen;
	uint32_t tsn, cum_tsn_ack;
	sctp_data_chunk_t *data_chunk;
	sctp_sack_chunk_t *sack_chunk;
	uint32_t rwnd;

#if TEST_V6
	struct in6_addr ipv6_loopback = SCTP_IN6ADDR_LOOPBACK_INIT;
#endif /* TEST_V6 */

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
        sctp_init();

	/* Set some basic values which depend on the address family. */
#if TEST_V6
	pf_class = PF_INET6;
        loop1.v6.sin6_family = AF_INET6;
        loop1.v6.sin6_addr = ipv6_loopback;
        loop1.v6.sin6_port = htons(SCTP_TESTPORT_1);
        loop2.v6.sin6_family = AF_INET6;
        loop2.v6.sin6_addr = ipv6_loopback;
        loop2.v6.sin6_port = htons(SCTP_TESTPORT_2);
#else
	pf_class = PF_INET;
        loop1.v4.sin_family = AF_INET;
        loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.v4.sin_port = htons(SCTP_TESTPORT_1);
        loop2.v4.sin_family = AF_INET;
        loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.v4.sin_port = htons(SCTP_TESTPORT_2);
#endif /* TEST_V6 */

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2->sk_rcvbuf = 70000;

	/* Bind these sockets to the test ports.  */
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	msg_buf = test_build_msg(10);
	/* Send the first message.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

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
        test_frame_get_message_all(sk2, msg_buf);

	free(msg_buf);

	/* Disable Fragmentation. */
	disable_frag = 1;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_DISABLE_FRAGMENTS,
				(void *)&disable_frag, sizeof(disable_frag));
	if (error != 0) { DUMP_CORE; }

	/* Do a getsockopt() and verify that fragmentation is disabled. */
	disable_frag = 0;
	optlen = sizeof(disable_frag);
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_DISABLE_FRAGMENTS,
				(void *)&disable_frag, &optlen);
	if ((error != 0) && (disable_frag != 1)) { DUMP_CORE; }


	/* There should be no user-specified MAXSEG yet. */
	maxseg = 1;
	optlen = sizeof(maxseg);
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_MAXSEG,
				(void *)&maxseg, &optlen);
	if ((error != 0) || (maxseg != 0)) { DUMP_CORE; }

	/* Set someting large enough to not affect the next tests.  */
	maxseg = SCTP_DEFAULT_MAXSEGMENT;
	optlen = sizeof(maxseg);
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_MAXSEG,
				(void *)&maxseg, optlen);
	if (error != 0) { DUMP_CORE; }

	/* Check whether we can recover the MAXSEG.  */
	maxseg = 1;
	optlen = sizeof(maxseg);
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_MAXSEG,
				(void *)&maxseg, &optlen);
	if ((error != 0) || (maxseg != SCTP_DEFAULT_MAXSEGMENT)) { DUMP_CORE; }


	msg_size = 30000;
	msg_buf = test_build_msg(msg_size);

	msg.msg_name = &loop2;
	switch (pf_class) {
	case AF_INET:
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;
	default:
		DUMP_CORE;
		break;
	}

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov->iov_base = msg_buf;
	msg.msg_iov->iov_len = msg_size;

	/* This call to sendmsg() should fail as the message size exceeds the
	 * association fragmentation point.
	 */
	error = sctp_sendmsg(NULL, sk1, &msg, msg_size);
	if (error != -EMSGSIZE) { DUMP_CORE; }

	/* Enable Fragmentation. */
	disable_frag = 0;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_DISABLE_FRAGMENTS,
				(void *)&disable_frag, sizeof(disable_frag));
	if (error != 0) { DUMP_CORE; }


	/* Now we should fragment smaller than allowed by PMTU. */
	maxseg = 1200;
	optlen = sizeof(maxseg);
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_MAXSEG,
				(void *)&maxseg, optlen);
	if (error != 0) { DUMP_CORE; }

	/* Check whether we can recover the MAXSEG.  */
	maxseg = 1;
	optlen = sizeof(maxseg);
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_MAXSEG,
				(void *)&maxseg, &optlen);
	if ((error != 0) || (maxseg >= SCTP_DEFAULT_MAXSEGMENT)) { DUMP_CORE; }


	/* Set cwnd equal to rwnd and max_burst to a high value so that data
	 * packets are not blocked by the low inital value of cwnd and to
	 * simplify the test.
	 */
	asoc1->peer.primary_path->cwnd = asoc1->peer.rwnd;
	asoc1->max_burst = 50;

	/* Regression test a bug where we were throwing away packets
	 * that were just over our fragmentation point.
	 */
	asoc1->pathmtu = asoc1->pathmtu+4;

	/* Figure out the expected TSN of the next DATA chunk. */
	tsn = asoc1->next_tsn;

	/* This should be the Cumulative TSN ACK reported with the first
	 * SACK.
	 */
	cum_tsn_ack = tsn+1;

        error = sctp_sendmsg(NULL, sk1, &msg, msg_size);
	if (error != msg_size) { DUMP_CORE; }

	/* These are the number of data chunks that should be present on the
	 * network at this point.
	 */
	nfrags = ((msg_size/maxseg) +
			((msg_size % maxseg) ? 1 : 0));

	/* Step through all the data fragments on the network and verify
	 * their TSN and the flags fields.
	 */
	for (frag_no = 1; frag_no <= nfrags; frag_no++, tsn++) {
		if (!(data_chunk = (sctp_data_chunk_t *)test_find_chunk(
				    TEST_NETWORK0, SCTP_CID_DATA, NULL, NULL)))
			DUMP_CORE;

		if (tsn != ntohl(data_chunk->data_hdr.tsn)) { DUMP_CORE; }

		switch (data_chunk->chunk_hdr.flags) {
		case SCTP_DATA_FIRST_FRAG:
			if (frag_no != 1) { DUMP_CORE; }
			break;
		case SCTP_DATA_MIDDLE_FRAG:
			if ((frag_no == 1) || (frag_no == nfrags)) {
				DUMP_CORE;
			}
			break;
		case SCTP_DATA_LAST_FRAG:
			if (frag_no != nfrags) { DUMP_CORE; }
			break;
		default:
			DUMP_CORE;
			break;
		}

		if (test_run_network_once(TEST_NETWORK0) < 0) {
			DUMP_CORE;
		}
	}

	/* The above for loop would have caused SACKs to be generated for
	 * every 2 data chunks. Step through the SACKs and verify their TSN.
	 */
	for (i = 0; i < (nfrags/2); i++, cum_tsn_ack+=2) {
		if (!(sack_chunk = (sctp_sack_chunk_t *)test_find_chunk(
				    TEST_NETWORK0, SCTP_CID_SACK, NULL, NULL)))
			DUMP_CORE;

		if (cum_tsn_ack != ntohl(sack_chunk->sack_hdr.cum_tsn_ack)) {
			printk("XXX:cum_tsn_ack:%x, pkt:%x\n",
			       cum_tsn_ack,
			       ntohl(sack_chunk->sack_hdr.cum_tsn_ack));
			DUMP_CORE;
		}

		if (test_run_network_once(TEST_NETWORK0) < 0) {
			DUMP_CORE;
		}
	}

	/* If the number of data chunks is odd, the SACK for the last data
	 * chunk will be sent only after a SACK timeout. Verify that the
	 * SACK is seen after the timeout.
	 */
	if (nfrags % 2) {
		/* Move time forward by a SACK timeout.  */
        	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
		test_run_timeout();

		if (!(sack_chunk = (sctp_sack_chunk_t *)test_find_chunk(
				    TEST_NETWORK0, SCTP_CID_SACK, NULL, NULL))) {
			DUMP_CORE;
		}

		/* Adjust the expected cum_tsn_ack to care of the fact that
		 * in the above for loop cum_tsn_ack is incremented by 2.
		 */
		cum_tsn_ack--;
		if (cum_tsn_ack != ntohl(sack_chunk->sack_hdr.cum_tsn_ack)) {
			DUMP_CORE;
		}
	}

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	test_frame_get_message(sk2, msg_buf);

	free(msg_buf);

	/* Reset cwnd, max_burst and pmtu back to the expected values for the
	 * remaining tests.
	 */
	asoc1->peer.primary_path->cwnd = 2*asoc1->pathmtu;
	asoc1->max_burst = 4;
	asoc1->pathmtu = SCTP_DEFAULT_MAXSEGMENT;

	msg_cnt = sizeof(msg_sizes) / sizeof(int);

	/* Send and receive the messages of different sizes specified in the
	 * msg_sizes array in a loop.
	 */
	for (i = 0; i < msg_cnt; i++) {

		msg_buf = test_build_msg(msg_sizes[i]);

		test_frame_send_message(sk1, (struct sockaddr *)&loop2,
					msg_buf);

		error = test_run_network();
		if (0 != error) { DUMP_CORE; }

        	test_frame_get_message_all(sk2, msg_buf);

		/* Move time forward by a SACK timeout.  */
        	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;

		error = test_run_network();
		if (0 != error) { DUMP_CORE; }

		free(msg_buf);
	}

	/* Verify that we handle packets that are fragmented and reassembled
	 * by ip.
	 */
	rwnd = asoc2->rwnd;
	msg_buf = test_build_msg(3000);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	/* Let ip do fragmentation/reassembly. */

	error = test_set_ip_mtu(1000);
	if (0 != error) { DUMP_CORE; }

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	if (asoc1->pathmtu != 1000)
		DUMP_CORE;

	/* Verify that rwnd is decreased correctly.after receiving the data. */
	if (asoc2->rwnd != (rwnd - 3000))
		DUMP_CORE;

	test_frame_get_message(sk2, msg_buf);

	/* Verify that rwnd is increased after the data is read by the user. */
	if (asoc2->rwnd != rwnd)
		DUMP_CORE;

	free(msg_buf);

	/* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

        /* Get the shutdown complete message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
