/* 
 * (C) Copyright IBM Corp. 2003
 * Copyright (c) 2003 Intel Corp.
 *
 * This is a Functional Test to verify SFR-CACC (Split Fast Retransmit - 
 * Changeover Aware Congestion Control) algorithms, according to the scenario
 * in draft-ietf-iyengar-sctp-cacc-01.txt
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
	struct sock *sk1, *sk2;
	struct sockaddr_in loop1, loop2, eth2;
	struct sockaddr_in bindx_addr;
	uint8_t *message = "Hello, World through loop!!!\n";
	uint8_t *message_e = "Hello, World through eth0!!!\n";
	int error;
        int optlen;
        struct sctp_setpeerprim ssp;
        struct sockaddr_in *sin;
        struct sctp_transport *asoc1_t;
	int orig_cwnd, net, net_e;

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

	loop2.sin_family = AF_INET;
	loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.sin_port = htons(SCTP_TESTPORT_2);

	eth2.sin_family = AF_INET;
	eth2.sin_addr.s_addr = SCTP_ADDR_ETH0;
	eth2.sin_port = htons(SCTP_TESTPORT_2);

	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }
      
	bindx_addr.sin_family = AF_INET;
	bindx_addr.sin_addr.s_addr = SCTP_ADDR_ETH0;
	bindx_addr.sin_port = htons(SCTP_TESTPORT_1);

	error = test_bindx(sk1, (struct sockaddr *)&bindx_addr,
			   sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR);
	if (error != 0) {
		DUMP_CORE;
	}

	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	bindx_addr.sin_family = AF_INET;
	bindx_addr.sin_addr.s_addr = SCTP_ADDR_ETH0;
	bindx_addr.sin_port = htons(SCTP_TESTPORT_2);

	error = test_bindx(sk2, (struct sockaddr *)&bindx_addr,
			   sizeof(struct sockaddr_in) , SCTP_BINDX_ADD_ADDR);
	if (error != 0) {
		DUMP_CORE;
	}

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }
 
	/* Send the first message. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

        asoc1_t = asoc1->peer.primary_path;
        if (asoc1_t->ipaddr.v4.sin_family != AF_INET ||
            asoc1_t->ipaddr.v4.sin_addr.s_addr != SCTP_IP_LOOPBACK ||
            asoc1_t->ipaddr.v4.sin_port != htons(SCTP_TESTPORT_2))
                DUMP_CORE;

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, message);

	/* Make sure that heartbeats are sent and all the paths are
	 * confirmed.
	 */
	jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

        net = test_get_network_sctp_addr(&asoc1->peer.primary_path->ipaddr);

	/* Send a couple of messages to loop2. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        if (!test_for_chunk(SCTP_CID_DATA, net)) {
                DUMP_CORE;
        }

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        if (!test_for_chunk(SCTP_CID_DATA, net)) {
                DUMP_CORE;
        }

	/* steal the two messages from network */
	test_steal_network(net);

        if (test_for_chunk(SCTP_CID_DATA, net)) {
                DUMP_CORE;
        }

	error = test_run_network();

        /* Now change the primary address. */
        optlen = sizeof(ssp);
        ssp.sspp_assoc_id = sctp_assoc2id(asoc1);
        error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
                                (void *)&ssp, &optlen);

        if (error || ((struct sockaddr_in *)&ssp.sspp_addr)->sin_addr.s_addr != SCTP_IP_LOOPBACK)
                DUMP_CORE;
        ssp.sspp_assoc_id = sctp_assoc2id(asoc1);

        sin = (struct sockaddr_in *)&ssp.sspp_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = SCTP_ADDR_ETH0;

        error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
                                (void *)&ssp, optlen);

        /* This should pass. */
        if (error)
                DUMP_CORE;

	orig_cwnd = asoc1->peer.primary_path->cwnd;

        net_e = test_get_network_sctp_addr(&asoc1->peer.primary_path->ipaddr);
	/* Send 4 messages arrive peer before the last two stolen messages
	 * so that the chunk's missing report will exceed 4, may cause cwnd
	 * if no CACC algorithm in SCTP stack.
	 */
	test_frame_send_message(sk1, (struct sockaddr *)&eth2, message_e);
        if (!test_for_chunk(SCTP_CID_DATA, net_e)) {
                DUMP_CORE;
        }
	test_frame_send_message(sk1, (struct sockaddr *)&eth2, message_e);
        if (!test_for_chunk(SCTP_CID_DATA, net_e)) {
                DUMP_CORE;
        }
	test_frame_send_message(sk1, (struct sockaddr *)&eth2, message_e);
        if (!test_for_chunk(SCTP_CID_DATA, net_e)) {
                DUMP_CORE;
        }
	test_frame_send_message(sk1, (struct sockaddr *)&eth2, message_e);
        if (!test_for_chunk(SCTP_CID_DATA, net_e)) {
                DUMP_CORE;
        }
        while (1) {
		error = test_run_network_once(net_e);
		if (error < 0)
			DUMP_CORE;
		if (error == 0) break;
	}

	/* Force the retransmission timer to timeout. */
	jiffies = asoc1_t->T3_rtx_timer.expires + 1;
	test_run_timeout();	
        if (test_for_chunk(SCTP_CID_DATA, net)) {
                DUMP_CORE;
        }

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	if (orig_cwnd != asoc1->peer.primary_path->cwnd)
		DUMP_CORE;

	/* Restore what we steal back to the network */
	test_restore_network(net);

        if (!test_for_chunk(SCTP_CID_DATA, net)) {
                DUMP_CORE;
        }

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }
	test_frame_get_message(sk2, message);
	test_frame_get_message(sk2, message);
	test_frame_get_message(sk2, message_e);
	test_frame_get_message(sk2, message_e);
	test_frame_get_message(sk2, message_e);
	test_frame_get_message(sk2, message_e);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
