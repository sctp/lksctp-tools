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

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1, *ep2;
        struct sctp_association *asoc1, *asoc2;
	struct sctp_transport *t1, *t2;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
	void *msg_buf;
	int error;
	int optlen;
	struct sctp_paddrparams params;

        /* Do all that random stuff needed to make a sensible universe.  */
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

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }

	msg_buf = test_build_msg(1);
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

	optlen = sizeof(struct sctp_paddrparams);

	/* Test Case #1 SCTP_PEER_ADDR_PARAMS */
	params.spp_assoc_id = sctp_assoc2id(asoc1);
	memcpy(&(params.spp_address), &loop2, sizeof(loop2));

	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, &optlen);
	if (error)
		DUMP_CORE;

	/* The heartbeat should be enabled by default, 0 stands for disabled */
	if (0 == params.spp_hbinterval)
		DUMP_CORE;

	if (sctp_assoc2id(asoc1) != params.spp_assoc_id)
		DUMP_CORE;

	params.spp_hbinterval = 200;
	params.spp_pathmaxrxt = 3;

	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, optlen);
	if (error)
		DUMP_CORE;
                                    	
	params.spp_hbinterval = 0;
	params.spp_pathmaxrxt = 0;
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, &optlen);
	if (error)
		DUMP_CORE;

	if (200 != params.spp_hbinterval)
		DUMP_CORE;
		
	if (3 != params.spp_pathmaxrxt || 3 != t1->max_retrans)
		DUMP_CORE;

        /* Test Case #2 REQUESTHEARTBEAT */
	params.spp_hbinterval = 0xffffffff;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, optlen);
	if (error)
		DUMP_CORE;


	/* We should have and HEARTBEAT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK0))
		DUMP_CORE;

	error = test_run_network_once(TEST_NETWORK0);
	if (0 > error)
		DUMP_CORE;

	/* We should have and SHUTDOWN_ACK sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK0))
		DUMP_CORE;

	error = test_run_network();
	if (0 != error)
		DUMP_CORE;

        /* Test Case #3 disable the heartbeat */
	params.spp_hbinterval = 0;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, optlen);
	if (error)
		DUMP_CORE;

	params.spp_hbinterval = 100;
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
				(char *)&params, &optlen);
	if (error)
		DUMP_CORE;

	if(0 != params.spp_hbinterval || 0 != t1->hb_allowed)
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
