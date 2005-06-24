/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 *
 * This is a testframe functional test to verify the various SCTP level
 * socket options that can be used to get information about existing SCTP
 * associations and to configure certain parameters.
 * To compile the v6 version, set the symbol TEST_V6 to 1.
 *
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Narasimha Budihal <narsi@refcode.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Hui Huang <hui.huang@nokia.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * Dajiang Zhang <dajiang.zhang@nokia.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/cache.h> /* For SMP_CACHE_BYTES */
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
	int pf_class;
        struct sock *sk1;
        struct sock *sk2;
        struct sctp_association *asoc1;
        struct sctp_association *asoc2;
	struct sctp_endpoint *ep1;
	struct sctp_endpoint *ep2;
        union sctp_addr loop1;
        union sctp_addr loop2;
        uint8_t *message = "hello, world!\n";
	int error;
	struct sctp_event_subscribe subscribe;
	struct sctp_initmsg initmsg;
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

	/* Bind these sockets to the test ports.  */
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}


	/* TEST #1: SCTP_STATUS socket option. */
	/* Make sure that SCTP_STATUS getsockopt on a socket with no
	 * association fails.
	 */
	error =  test_frame_getsockopt(sk1, 0, SCTP_STATUS);
	if (error != -EINVAL) {
		DUMP_CORE;
	}

	/* Send the first message.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	/* Get SCTP_STATUS for sk1's first association. */
	if (0 != test_frame_getsockopt(sk1, sctp_assoc2id(asoc1),
				       SCTP_STATUS)) {
        	printf("getsockopt(SCTP_STATUS): error: %d\n", error);
        	DUMP_CORE;
	}

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	if (!sctp_outq_is_empty(&asoc1->outqueue)) {
		DUMP_CORE;
	}

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent.  */
        test_frame_get_message(sk2, message);

	/* Get SCTP_STATUS for sk2's first association. */
	if (0 != test_frame_getsockopt(sk2, sctp_assoc2id(asoc2),
				       SCTP_STATUS)) {
        	printf("getsockopt(SCTP_STATUS): error: %d\n", error);
        	DUMP_CORE;
	}

	/* Get SCTP_STATUS for sk1's given association. */
	if (0 != test_frame_getsockopt(sk1, sctp_assoc2id(asoc1),
				       SCTP_STATUS)) {
        	printf("getsockopt(SCTP_STATUS): error: %d\n", error);
        	DUMP_CORE;
	}

	/* Make sure that SCTP_STATUS getsockopt with invalid associd fails. */
	error =  test_frame_getsockopt(sk1, sctp_assoc2id(asoc2), SCTP_STATUS);
	if (error != -EINVAL) {
		DUMP_CORE;
	}

	/* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

        /* Get the shutdown complete message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	sctp_close(sk2, /* timeout */ 0);

	/* TEST #2: SCTP_EVENTS socket option. */
        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind these sockets to the test ports.  */
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	/* Display the default events that are enabled on sk1. */
	if (0 !=  test_frame_getsockopt(sk1, 0, SCTP_EVENTS)) {
		DUMP_CORE;
	}

	/* Display the default events that are enabled on sk2. */
	if (0 !=  test_frame_getsockopt(sk2, 0, SCTP_EVENTS)) {
		DUMP_CORE;
	}

	/* Disable all the events on sk2 except for the data io event. */
	memset(&subscribe, 0, sizeof(struct sctp_event_subscribe));
	subscribe.sctp_data_io_event = 1;
	subscribe.sctp_shutdown_event = 1;
	if (0 !=  test_frame_setsockopt(sk2, 0, SCTP_EVENTS,
					(char *)&subscribe)) {
		DUMP_CORE;
	}

	/* Display the updated list of enabled events on sk2. */
	if (0 !=  test_frame_getsockopt(sk2, 0, SCTP_EVENTS)) {
		DUMP_CORE;
	}

	/* Send the first message.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	if (0 != test_run_network()) {
		DUMP_CORE;
	}

        /* As association events are not enabled on sk2, we should not
	 * receive any COMM_UP notification. Instead,  the first message
	 * should be the data.
	 */
        test_frame_get_message(sk2, message);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	/* Get the SHUTDOWN_EVENT notification on sk2 as it is enabled and
	 * it has received SHUTDOWN from sk1.
	 */ 
        test_frame_get_event(sk2, SCTP_SHUTDOWN_EVENT, 0);

	sctp_close(sk2, /* timeout */ 0);

	/* TEST #3: SCTP_INITMSG socket option. */
	/* Create a socket. */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind this socket to the test port.  */
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }

	/* Display the default parameters for association initialization. */
	if (0 !=  test_frame_getsockopt(sk1, 0, SCTP_INITMSG)) {
		DUMP_CORE;
	}

	/* Change the parameters for association initialization. */
	initmsg.sinit_num_ostreams = 5;
	initmsg.sinit_max_instreams = 5;
	initmsg.sinit_max_attempts = 3;
	initmsg.sinit_max_init_timeo = 30;
	if (0 !=  test_frame_setsockopt(sk1, 0, SCTP_INITMSG,
					(char *)&initmsg)) {
		DUMP_CORE;
	}

	/* Display the updated parameters for association initialization. */
	if (0 !=  test_frame_getsockopt(sk1, 0, SCTP_INITMSG)) {
		DUMP_CORE;
	}

	/* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
