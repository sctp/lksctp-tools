/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 *
 * This is a functional test to verify the SCTP peer addr param
 * options that application can enable or disable heartbeat for
 * any peer address of an associations, modify an address's
 * heartbeat interval, force a heartbeat to be sent immediately,
 * and adjust the address's maximum number of retransmission
 * sent before an address is considered unreachable.
 *
 * Ardelle Fan <ardelle.fan@intel.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

#define HB_INTERVAL_1 50000
#define HB_INTERVAL_2 100000

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1, *ep2;
        struct sctp_association *asoc1, *asoc2;
	struct sctp_transport *t1[3];
	struct sctp_transport *t2[3];
        struct sock *sk1, *sk2;
        union sctp_addr loop1[3], loop2[3];
        union sctp_addr *peer1 = loop2;
        union sctp_addr *peer2 = loop1;
	void *msg_buf;
	int error, bufsize;
	int optlen;
	struct sctp_paddrparams params;
	char addr_buf[sizeof(struct sockaddr_in6)*3];
	int pf_class;
	unsigned long rto_min_jif;

        /* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
        sctp_init();

        /* The following makes sure all transports have the same rto
         * (which makes all their transport timers end at the same time.
         */
        sctp_rto_initial = SCTP_RTO_MIN;
	rto_min_jif = msecs_to_jiffies(SCTP_RTO_MIN);

	/* Initialize the server and client addresses. */
#if TEST_V6
	pf_class = PF_INET6;
	loop1[0].v6.sin6_family = AF_INET6;
	loop1[0].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
	loop1[0].v6.sin6_scope_id = 0;
	loop1[0].v6.sin6_port = htons(SCTP_TESTPORT_1);
	loop1[1].v6.sin6_family = AF_INET6;
	loop1[1].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH1;
	loop1[1].v6.sin6_scope_id = 0;
	loop1[1].v6.sin6_port = htons(SCTP_TESTPORT_1);
	loop1[2].v4.sin_family = AF_INET;
	loop1[2].v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	loop1[2].v4.sin_port = htons(SCTP_TESTPORT_1);

	loop2[0].v6.sin6_family = AF_INET6;
	loop2[0].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
	loop2[0].v6.sin6_scope_id = 0;
	loop2[0].v6.sin6_port = htons(SCTP_TESTPORT_2);
	loop2[1].v6.sin6_family = AF_INET6;
	loop2[1].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH1;
	loop2[1].v6.sin6_scope_id = 0;
	loop2[1].v6.sin6_port = htons(SCTP_TESTPORT_2);
	loop2[2].v4.sin_family = AF_INET;
	loop2[2].v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	loop2[2].v4.sin_port = htons(SCTP_TESTPORT_2);
#else
	pf_class = PF_INET;
	loop1[0].v4.sin_family = AF_INET;
	loop1[0].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	loop1[0].v4.sin_port = htons(SCTP_TESTPORT_1);
	loop1[1].v4.sin_family = AF_INET;
	loop1[1].v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	loop1[1].v4.sin_port = htons(SCTP_TESTPORT_1);
	loop1[2].v4.sin_family = AF_INET;
	loop1[2].v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	loop1[2].v4.sin_port = htons(SCTP_TESTPORT_1);

	loop2[0].v4.sin_family = AF_INET;
	loop2[0].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	loop2[0].v4.sin_port = htons(SCTP_TESTPORT_2);
	loop2[1].v4.sin_family = AF_INET;
	loop2[1].v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	loop2[1].v4.sin_port = htons(SCTP_TESTPORT_2);
	loop2[2].v4.sin_family = AF_INET;
	loop2[2].v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	loop2[2].v4.sin_port = htons(SCTP_TESTPORT_2);
#endif

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1[0], ADDR_LEN(loop1[0]));
        if (error != 0) { DUMP_CORE; }

	bufsize = fill_addr_buf(addr_buf, loop1, 1, 2);
	error = test_bindx(sk1, (struct sockaddr *)addr_buf, bufsize,
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2[0], ADDR_LEN(loop2[0]));
        if (error != 0) { DUMP_CORE; }

	bufsize = fill_addr_buf(addr_buf, loop2, 1, 2);
	error = test_bindx(sk2, (struct sockaddr *)addr_buf, bufsize,
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	/* Setup parameters for sk2 different */
	setup_paddrparams(&params, NULL, NULL);
	params.spp_hbinterval = HB_INTERVAL_2;
	params.spp_flags      = SPP_HB_DISABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }

	/* Send the first messages.  This will create the association.  */
	msg_buf = test_build_msg(1);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, msg_buf);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent.  */
        test_frame_get_message(sk2, msg_buf);

	/* Test that the proper connection was made. */
	test_assoc_peer_transports(asoc1, &loop2[0], 3);
	test_assoc_peer_transports(asoc2, &loop1[0], 3);

	/* Fetch the transport addresses. */
	get_assoc_peer_transports(asoc1, t1, 3);
	get_assoc_peer_transports(asoc2, t2, 3);

	/* Test parameters for asoc2 (make sure they came
	 * through from the socket)
	 */
	setup_paddrparams(&params, asoc2, NULL);
	params.spp_flags      = SPP_HB_DISABLE;

	error = test_paddrparams(sk2, &params, asoc2, NULL, SPP_HB);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, &peer2[0]);
	error = test_paddrparams(sk2, &params, asoc2, &peer2[0], SPP_HB);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, &peer2[1]);
	error = test_paddrparams(sk2, &params, asoc2, &peer2[0], SPP_HB);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, &peer2[2]);
	error = test_paddrparams(sk2, &params, asoc2, &peer2[0], SPP_HB);
	if (error)
		DUMP_CORE;

	/* Enable heartbeat on asoc2 */
	setup_paddrparams(&params, asoc2, NULL);
	params.spp_hbinterval = HB_INTERVAL_2;
	params.spp_flags = SPP_HB_ENABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, asoc2, NULL);
	params.spp_hbinterval = HB_INTERVAL_2;
	params.spp_flags      = SPP_HB_ENABLE;

	error = test_paddrparams(sk2, &params, asoc2, NULL, SPP_HB);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, &peer2[0]);
	error = test_paddrparams(sk2, &params, asoc2, &peer2[0], SPP_HB);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, &peer2[1]);
	error = test_paddrparams(sk2, &params, asoc2, &peer2[0], SPP_HB);
	if (error)
		DUMP_CORE;

	change_paddrparams(&params, asoc2, &peer2[2]);
	error = test_paddrparams(sk2, &params, asoc2, &peer2[0], SPP_HB);
	if (error)
		DUMP_CORE;

	/* Test Case #1 SCTP_PEER_ADDR_PARAMS */
	/* The heartbeat should be enabled by default, 0 stands for disabled */
	setup_paddrparams(&params, asoc1, &peer1[0]);
	params.spp_flags = SPP_HB_ENABLE;

	error = test_paddrparams(sk1, &params, asoc1, &peer1[0], SPP_HB);
	if (error)
		DUMP_CORE;

	params.spp_hbinterval = HB_INTERVAL_1;
	params.spp_pathmaxrxt = 3;
	params.spp_flags |= SPP_PMTUD_ENABLE;

	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* Check results. */                                    	
	error = test_paddrparams(sk1, &params, asoc1, &peer1[0], SPP_HB);
	if (error)
		DUMP_CORE;

	if (3 != t1[0]->pathmaxrxt || HB_INTERVAL_1 != jiffies_to_msecs(t1[0]->hbinterval))
		DUMP_CORE;

	error = test_paddrparams(sk1, &params, asoc1, &peer1[1], SPP_HB);
	if (!error)
		DUMP_CORE;

	if (3 == t1[1]->pathmaxrxt || HB_INTERVAL_1 == jiffies_to_msecs(t1[1]->hbinterval))
		DUMP_CORE;

	/* Now set the parameters for all transports. */
	change_paddrparams(&params, asoc1, NULL);
	
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	setup_paddrparams(&params, asoc2, NULL);
	params.spp_hbinterval = HB_INTERVAL_2;
	params.spp_flags      = SPP_HB_ENABLE;

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* Validate that the first transports are in ACTIVE state. */
	if ((t1[0]->state != SCTP_ACTIVE) || (t2[0]->state != SCTP_ACTIVE))
		DUMP_CORE;

	/* Validate that the remaining transports are in UNCONFIRMED state. */ 
	if ((t1[1]->state != SCTP_UNCONFIRMED) ||
	    (t1[2]->state != SCTP_UNCONFIRMED) ||
	    (t2[1]->state != SCTP_UNCONFIRMED) ||
	    (t2[2]->state != SCTP_UNCONFIRMED))
		DUMP_CORE;

	/* Make sure that heartbeats are sent and all the paths are 
	 * confirmed.
	 */
	jiffies += (1.5 * rto_min_jif + 1);
	if (test_run_network())
		DUMP_CORE;

	/* Reset all the timers so all heartbeats occur at the same time. */
	sctp_transport_reset_timers(t1[0]);
	sctp_transport_reset_timers(t1[1]);
	sctp_transport_reset_timers(t1[2]);
	sctp_transport_reset_timers(t2[0]);
	sctp_transport_reset_timers(t2[1]);
	sctp_transport_reset_timers(t2[2]);

	/* Test that heartbeat is actually sent. */
	printf("About to cause heartbeats to happen\n");
	jiffies += msecs_to_jiffies(HB_INTERVAL_1) - rto_min_jif / 2 - 1;
	printf("About to run timeout\n");
	test_run_timeout();

	/* We should NOT have a HEARTBEAT sitting on the Internet. */
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH0))
		DUMP_CORE;
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH1))
		DUMP_CORE;
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH2))
		DUMP_CORE;

	jiffies += 2 * rto_min_jif + 2;
	test_run_timeout();

	/* We should have a HEARTBEAT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH0))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH1))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH2))
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH0);
	if (0 > error)
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH1);
	if (0 > error)
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH2);
	if (0 > error)
		DUMP_CORE;

	/* We should have a HEARTBEAT_ACK sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK_ETH0))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK_ETH1))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK_ETH2))
		DUMP_CORE;

	/* Now test other association, disable HB for asoc1 */
	setup_paddrparams(&params, asoc1, NULL);
	params.spp_flags = SPP_HB_DISABLE;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH0))
		DUMP_CORE;
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH1))
		DUMP_CORE;
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH2))
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH0);
	if (0 > error)
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH1);
	if (0 > error)
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH2);
	if (0 > error)
		DUMP_CORE;

	printf("About to test timeout on asoc2\n");
	jiffies += msecs_to_jiffies(HB_INTERVAL_2 - HB_INTERVAL_1) -
		    rto_min_jif - 2;
	test_run_timeout();

	/* We should NOT have a HEARTBEAT sitting on the Internet. */
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH0))
		DUMP_CORE;
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH1))
		DUMP_CORE;
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH2))
		DUMP_CORE;

	jiffies += rto_min_jif + 2;
	test_run_timeout();

	/* We should have a HEARTBEAT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH0))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH1))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH2))
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH0);
	if (0 > error)
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH1);
	if (0 > error)
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH2);
	if (0 > error)
		DUMP_CORE;

	/* We should have a HEARTBEAT_ACK sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK_ETH0))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK_ETH1))
		DUMP_CORE;
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK_ETH2))
		DUMP_CORE;

	error = test_run_network();
	if (0 != error)
		DUMP_CORE;

        /* Test Case #2 REQUESTHEARTBEAT */
	params.spp_flags = SPP_HB_DEMAND;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	/* We should have a HEARTBEAT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK_ETH0))
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK_ETH0);
	if (0 > error)
		DUMP_CORE;

	/* We should have a HEARTBEAT_ACK sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK_ETH0))
		DUMP_CORE;

	error = test_run_network();
	if (0 != error)
		DUMP_CORE;

        /* Test Case #3 disable the heartbeat */
	params.spp_flags = SPP_HB_DISABLE;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, sizeof(struct sctp_paddrparams));
	if (error)
		DUMP_CORE;

	error = test_paddrparams(sk1, &params, asoc1, &peer1[0], SPP_HB);
	if (error)
		DUMP_CORE;

	if (t1[0]->param_flags & SPP_HB_ENABLE)
		DUMP_CORE;

	error = test_run_network();
	if (0 != error)
		DUMP_CORE;

	sctp_close(sk1, 0);
	if (0 != test_run_network()) { DUMP_CORE; }
	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
