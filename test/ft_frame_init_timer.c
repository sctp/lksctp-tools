/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is the Functional Test for testing init timeout functionality for 
 * UDP-style socket
 * 
 * Jon Grimm <jgrimm@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
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

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
	struct cmsghdr *outcmsg;
	struct msghdr outmsg;
	char buf[CMSG_SPACE_INITMSG + CMSG_SPACE_SNDRCV];
	struct iovec out_iov;
	struct sctp_initmsg *initmsg;
	uint8_t *message = "Hello, World!!!\n";
	int error, bytes_sent, i;

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();
	
	/* Do a little cheating to manipulate the protocol defaults to 
	 * something easier to test. 
	 */
	sctp_max_retrans_init = 2;

	/* Test #1: Test max_init_attempts. */

        /* Create a single endpoint which will attempt to contact
	 * an unreachable peer.  
	 */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind this sockets to the test ports.  */
        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        
        loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.sin_port = htons(SCTP_TESTPORT_2);
        
	/* Since the testframe only knows about SCTP-aware reachable hosts,
	 * break reachability, so we don't overlap the OOTB behavior.
	 */
	test_break_network(TEST_NETWORK0);

        /* Send the first message, using the default init parameters. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	/* Walk through the startup sequence.  */

	/* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Next we do NOT expect an INIT ACK, since there is no peer. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) > 0) {
		DUMP_CORE;
	}

	/* We should NOT_ have an INIT sitting on the Internet. */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	/* run timeout */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
	test_run_timeout();
	for (i = 0; i < sctp_max_retrans_init; i++) {

		/* We should have an INIT sitting on the Internet. */
		if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
			DUMP_CORE;
		}

		/* Next we do NOT expect an INIT ACK, since there is no peer. */
		if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) > 0) {
			DUMP_CORE;
		}

		/* We should NOT_ have an INIT sitting on the Internet. */
		if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
			DUMP_CORE;
		}

		/* run timeout */
		jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
		test_run_timeout();
	}
	/* We should NOT_ have an INIT sitting on the Internet. */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);
	sctp_close(sk1, 0);
	test_run_network();

	/* Test #2: Test max_init_timeo. */

        /* Do a little cheating to manipulate the protocol defaults to 
	 * something easier to test. 
	 */
	sctp_max_retrans_init = 5;
	/* The maximum initial timeout wait is derived from the rto.max. */
	sctp_rto_max = msecs_to_jiffies(SCTP_RTO_INITIAL)*3;

        /* Create a single endpoint which will attempt to contact
	 * a unreachable peer.
	 */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind this sockets to the test ports.  */
        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        
        loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.sin_port = htons(SCTP_TESTPORT_2);
        
	test_break_network(TEST_NETWORK0);

        /* Send the first message, using the default init parameters. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	if (asoc1->max_init_timeo != msecs_to_jiffies(sctp_rto_max))
		DUMP_CORE;

	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Next we do NOT expect an INIT ACK, since there is no peer.  */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) > 0) {
		DUMP_CORE;
	}

	/* We should NOT have an INIT sitting on the Internet. */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
	test_run_timeout();

	for (i = 0; i < sctp_max_retrans_init; i++) {
		/* We should again have an INIT sitting on the Internet. */
		if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
			DUMP_CORE;
		}

		/* Next we do NOT expect an INIT ACK, since there is no peer.  
		 * Note: this also gets our INIT off the network. 
		 */
		if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) > 0) {
			DUMP_CORE;
		}

		jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
		test_run_timeout();

		/* Make sure that T1-INIT timeout doesn't exceed
		 * max_init_timeo.
		 */
		if (asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] >
			 				asoc1->max_init_timeo)
			DUMP_CORE;
	}

	/* We should NOT have an INIT sitting on the Internet,
	 * since we've exceeded the maximum INIT timeout. 
	 */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);
	sctp_close(sk1, 0);
	test_run_network();


	/* Start over and test COOKIE-ECHO loss. */

        /* Do a little cheating to manipulate the protocol defaults to 
	 * something easier to test. 
	 */
	sctp_max_retrans_init = 2;

	/* Test #3:  Test COOKIE-ECHO loss. */

        /* Set an arbitrary timeout high enough that it is out of the
	 * way for the purposes of this test.  
	 */
	sctp_rto_max = msecs_to_jiffies(SCTP_RTO_INITIAL) * 5;

        /* Create a two endpoints. 
	 */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Fix up reachability, in case a previous test broke it. */
	test_fix_network(TEST_NETWORK0);

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

	error = test_listen(sk2, 1);
	if (error != 0) { DUMP_CORE; }
        
        /* Send the first message, using the default init parameters. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Set up the network to drop the next COOKIE_ECHO it sees. */
	test_kill_next_packet(SCTP_CID_COOKIE_ECHO);
	
	/* Next we DO expect an INIT ACK.  */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Check that the COOKIE_ECHO got dropped. */
	test_run_network();
        /* We should NOT have a COOKIE ECHO sitting on the Internet. */
	if (test_for_chunk(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* We should not have DATA either. */
	if (test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_COOKIE] + 1;
	test_run_timeout();

	/* We should again have a COOKIE-ECHO sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0)) {
		DUMP_CORE;
	}

        /* We should again have DATA since we bundled the first time. */
	if (!test_for_chunk(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* This time we'll let initialization complete. */
	test_run_network();
       
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which we sent.  */
        test_frame_get_message(sk2, message);
	sctp_close(sk1, 0);
	
	test_run_network();
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	sctp_close(sk2, 0);

	/* Test #4 test SCTP_INITMSG ancillary data. */
       
	/* Set the defaults to something rather 
	 * large, as we will override with the SCTP_INITMSG control. 
	 */
	sctp_max_retrans_init = 100;
	sctp_rto_max = msecs_to_jiffies(SCTP_RTO_INITIAL) * 20;

        /* Create a single endpoint which will attempt to contact
	 * an unreachable peer.  
	 */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	test_break_network(TEST_NETWORK0);

	/* Bind this sockets to the test ports.  */
        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        
        loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.sin_port = htons(SCTP_TESTPORT_2);
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
	outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        outmsg.msg_flags = 0;
        
        /* Build up a SCTP_INIT CMSG. */
	outmsg.msg_control = buf;
	outmsg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_initmsg));
	outcmsg = CMSG_FIRSTHDR(&outmsg);
	outcmsg->cmsg_level = IPPROTO_SCTP;
	outcmsg->cmsg_type = SCTP_INIT;
	outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_initmsg));

	initmsg = (struct sctp_initmsg *)CMSG_DATA(outcmsg);
	initmsg->sinit_num_ostreams = 5;
	initmsg->sinit_max_instreams = 5;
	initmsg->sinit_max_attempts = 2;
	initmsg->sinit_max_init_timeo = 0;
 
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent < 0) { 
		DUMP_CORE; 
	}

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Next we do NOT expect an INIT ACK, since there is no peer.  */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) > 0) {
		DUMP_CORE;
	}

	/* We should NOT have an INIT sitting on the Internet. */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
	test_run_timeout();

	/* We should again have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

        /* Next we do NOT expect an INIT ACK, since there is no peer.  
	 * Note: this also gets our INIT off the network. 
	 */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) > 0) {
		DUMP_CORE;
	}


	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
	test_run_timeout();

	/* We should again have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

        /* Next we do NOT expect an INIT ACK, since there is no peer.  
	 * Note: this also gets our INIT off the network. 
	 */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) > 0) {
		DUMP_CORE;
	}


	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
	test_run_timeout();

	/* We should NOT have an INIT sitting on the Internet,
	 * since we've exceeded the maximum INIT timeout. 
	 */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);
	sctp_close(sk1, 0);
	test_run_network();

	/* Test #5: Test init timer with a peer which will
	 * ABORT us (e.g. socket not listening) 
	 */
	sctp_max_retrans_init = 2;

        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind this sockets to the test ports.  */
        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.sin_port = htons(SCTP_TESTPORT_2);

	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }

	/* Fix up the network, in case a previous network needed it 
	 * broken. 
	 */
	test_fix_network(TEST_NETWORK0);

        /* Send the first message, using the default init parameters. */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}
       
	/* Next we expect an ABORT since the peer is not 'listening'. */
	if (!test_step(SCTP_CID_ABORT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	if (test_step(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
	test_run_timeout();

	/* We should NOT have an INIT sitting on the Internet,
	 * since we've been aborted.
	 */
	if (test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);
	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	test_run_network();

	exit(0);

} /* main() */
