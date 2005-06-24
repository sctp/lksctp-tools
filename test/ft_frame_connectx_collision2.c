/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
 * Copyright (c) Nokia, 2002
 *
 * This file is part of the SCTP kernel reference Implementation
 *
 * This is Functional Test 4 for the SCTP kernel reference
 * implementation state machine.
 *
 * Case Study 2: Initialization Collision
 * Scenario 2.  a variation form Scenario 1. Due to network reordering event
 * the INIT that endpoint Z sends crosses ahead of its previously sent
 * INIT-ACK.
 *
 * Set up a link, send message from sk1 to sk2 first. But INIT_ACK is delayed.
 * Then send message from sk2 to sk1. This will cause overlapping INIT chunk.
 * See the association is up and messages appear. Send the messages once more.
 * Then go home.
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
 *    La Monte H.P. Yarroll <piggy@acm.org>
 *    Narasimha Budihal     <narsi@refcode.org>
 *    Karl Knutson          <karl@athena.chicago.il.us>
 *    Jon "Taz" Mischo      <taz@refcode.org>
 *    Sridhar Samudrala     <samudrala@us.ibm.com>
 *    Dajiang Zhang         <dajiang.zhang@nokia.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
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
#include <errno.h>
#include <funtest.h>
#include <test_kernel.h>

#define NSOCK 4

int
main(int argc, char *argv[])
{
	struct sock *sk[NSOCK];
	struct sctp_endpoint *ep[NSOCK];
	struct sctp_association *asoc[NSOCK];
	union sctp_addr loop[6];
	int netw[6];
	char addr_buf[sizeof(struct sockaddr_in6)*8];
	int pf_class, bufsize, flags;
	struct sk_buff *pkt1, *pkt2, *pkt3;
	int error, i;

	/* Do all that random stuff needed to make a sensible universe. */
	sctp_init();
	init_Internet();

	/* Initialize the server addresses. */
#if TEST_V6
	pf_class = PF_INET6;
	loop[0].v6.sin6_family = AF_INET6;
	loop[0].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
	loop[0].v6.sin6_scope_id = 0;
	loop[0].v6.sin6_port = htons(SCTP_TESTPORT_1);
	netw[0] = TEST_NETWORK_ETH0;

	loop[1].v6.sin6_family = AF_INET6;
	loop[1].v6.sin6_addr = (struct in6_addr) SCTP_B_ADDR6_SITELOCAL_ETH0;
	loop[1].v6.sin6_scope_id = 0;
	loop[1].v6.sin6_port = htons(SCTP_TESTPORT_1);
	netw[1] = TEST_NETWORK_ETH0;

	loop[2].v6.sin6_family = AF_INET6;
	loop[2].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH1;
	loop[2].v6.sin6_scope_id = 0;
	loop[2].v6.sin6_port = htons(SCTP_TESTPORT_1);
	netw[2] = TEST_NETWORK_ETH1;

	loop[3].v6.sin6_family = AF_INET6;
	loop[3].v6.sin6_addr = (struct in6_addr) SCTP_C_ADDR6_SITELOCAL_ETH0;
	loop[3].v6.sin6_scope_id = 0;
	loop[3].v6.sin6_port = htons(SCTP_TESTPORT_1);
	netw[3] = TEST_NETWORK_ETH0;

	loop[4].v4.sin_family = AF_INET;
	loop[4].v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	loop[4].v4.sin_port = htons(SCTP_TESTPORT_1);
	netw[4] = TEST_NETWORK_ETH2;

	loop[5].v6.sin6_family = AF_INET6;
	loop[5].v6.sin6_addr = (struct in6_addr) SCTP_D_ADDR6_SITELOCAL_ETH0;
	loop[5].v6.sin6_scope_id = 0;
	loop[5].v6.sin6_port = htons(SCTP_TESTPORT_1);
	netw[5] = TEST_NETWORK_ETH0;
#else
	pf_class = PF_INET;
	loop[0].v4.sin_family = AF_INET;
	loop[0].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	loop[0].v4.sin_port = htons(SCTP_TESTPORT_1);
	netw[0] = TEST_NETWORK_ETH0;

	loop[1].v4.sin_family = AF_INET;
	loop[1].v4.sin_addr.s_addr = SCTP_B_ETH0;
	loop[1].v4.sin_port = htons(SCTP_TESTPORT_1);
	netw[1] = TEST_NETWORK_ETH0;

	loop[2].v4.sin_family = AF_INET;
	loop[2].v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	loop[2].v4.sin_port = htons(SCTP_TESTPORT_1);
	netw[2] = TEST_NETWORK_ETH1;

	loop[3].v4.sin_family = AF_INET;
	loop[3].v4.sin_addr.s_addr = SCTP_C_ETH0;
	loop[3].v4.sin_port = htons(SCTP_TESTPORT_1);
	netw[3] = TEST_NETWORK_ETH0;

	loop[4].v4.sin_family = AF_INET;
	loop[4].v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	loop[4].v4.sin_port = htons(SCTP_TESTPORT_1);
	netw[4] = TEST_NETWORK_ETH2;

	loop[5].v4.sin_family = AF_INET;
	loop[5].v4.sin_addr.s_addr = SCTP_D_ETH0;
	loop[5].v4.sin_port = htons(SCTP_TESTPORT_1);
	netw[5] = TEST_NETWORK_ETH0;
#endif

	/* Create the endpoints which will talk to each other. */
	for (i = 0; i < NSOCK; i++ )
		sk[i] = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind socket 1 to the test ports.  */
	error = test_bind(sk[0], (struct sockaddr *)&loop[0],
				      ADDR_LEN(loop[0]));
	if (error != 0) { DUMP_CORE; }

	/* Bind socket 2 to the test ports.  */
	error = test_bind(sk[1], (struct sockaddr *)&loop[1],
				      ADDR_LEN(loop[0]));
	if (error != 0) { DUMP_CORE; }

	bufsize = fill_addr_buf(addr_buf, loop, 2, 2);
	error = test_bindx(sk[1], (struct sockaddr *)addr_buf, bufsize,
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	/* Bind socket 3 to the test ports.  */
	error = test_bind(sk[2], (struct sockaddr *)&loop[3],
				      ADDR_LEN(loop[0]));
	if (error != 0) { DUMP_CORE; }

	bufsize = fill_addr_buf(addr_buf, loop, 4, 4);
	error = test_bindx(sk[2], (struct sockaddr *)addr_buf, bufsize,
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	/* Bind socket 4 to the test ports.  */
	error = test_bind(sk[3], (struct sockaddr *)&loop[5],
				      ADDR_LEN(loop[5]));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk[1] and sk[2] as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk[1], 1)) {
		DUMP_CORE;
	}
	if (0 != sctp_seqpacket_listen(sk[2], 1)) {
		DUMP_CORE;
	}

	printk("----------------------------------------------------\n"
	       "Setup done\n"
	       "----------------------------------------------------\n");

	/* Set sk[0] as non-blocking. */
	flags = sk[0]->sk_socket->file->f_flags;
	sk[0]->sk_socket->file->f_flags |= O_NONBLOCK;

	/* Do a non-blocking connect from sk[0] to sk[1]/3 */
	bufsize = fill_addr_buf(addr_buf, loop, 1, 4);
	error = test_connectx(sk[0], (struct sockaddr *)addr_buf, bufsize);

	/* Non-blocking connect should return immediately with EINPROGRESS. */
	if (error != -EINPROGRESS) { DUMP_CORE; }

	/* Walk through the startup sequence.  */
	/* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, netw[0])) {
		DUMP_CORE;
	}
	printk("\n 1->2/3 INIT\n\n");

	/* Next we expect an INIT ACK, but it will be delayed. */
	if (test_step(SCTP_CID_INIT_ACK, netw[0]) <=0 ) {
		DUMP_CORE;
	}

	printk("\n 2->1 INIT_ACK will be delayed\n\n");
	pkt1 = test_steal_packet(netw[0]);
	if (test_for_chunk(SCTP_CID_INIT_ACK, netw[0])) {
		DUMP_CORE;
	}

	/* Now, let sk[1] and sk[2] connect to sk[0] to cause INIT collision.
	 */

	/* Mark sk[0] as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk[0], 1)) {
		DUMP_CORE;
	}

	/* Set sk[1] as non-blocking. */
	flags = sk[1]->sk_socket->file->f_flags;
	sk[1]->sk_socket->file->f_flags |= O_NONBLOCK;

	/* Do a non-blocking connect from sk[1] to sk[0] */
	printk("\n Connect 2->1\n\n");
	bufsize = fill_addr_buf(addr_buf, loop, 0, 0);
	error = test_connectx(sk[1], (struct sockaddr *)addr_buf, bufsize);

	/* Non-blocking connect should return immediately with EINPROGRESS. */
	if (error != -EINPROGRESS) { DUMP_CORE; }

	/* 2 sends INIT to 1. */
	printk("\n 2->1 INIT\n\n");
	if (!test_for_chunk(SCTP_CID_INIT, netw[0])) {
		DUMP_CORE;
	}

	printk("\n 1->2 INIT ACK\n\n");
	if (test_step(SCTP_CID_INIT_ACK, netw[0])<= 0 ) {
		DUMP_CORE;
	}
	printk("\n Hold 1-2> INIT ACK\n\n");
	pkt2 = test_steal_packet(netw[0]);

	/* Set sk[2] as non-blocking. */
	flags = sk[2]->sk_socket->file->f_flags;
	sk[2]->sk_socket->file->f_flags |= O_NONBLOCK;

	/* Do a non-blocking connect from sk[2] to sk[0] */
	printk("\n Connect 3->1\n\n");
	bufsize = fill_addr_buf(addr_buf, loop, 0, 0);
	error = test_connectx(sk[2], (struct sockaddr *)addr_buf, bufsize);

	/* Non-blocking connect should return immediately with EINPROGRESS. */
	if (error != -EINPROGRESS) { DUMP_CORE; }

	/* 3 sends INIT to 1. */
	printk("\n 3->1 INIT\n\n");
	if (!test_for_chunk(SCTP_CID_INIT, netw[0])) {
		DUMP_CORE;
	}

	ep[0] = sctp_sk(sk[0])->ep;
	asoc[0] = test_ep_first_asoc(ep[0]);
	ep[1] = sctp_sk(sk[1])->ep;
	asoc[1] = test_ep_first_asoc(ep[1]);
	printk("\n Association 0 (%p):\n", asoc[0]);
	print_assoc_peer_transports(asoc[0]);
	printk("\n Association 1 (%p):\n", asoc[1]);
	print_assoc_peer_transports(asoc[1]);
	test_assoc_peer_transports(asoc[0], &loop[1], 4);
	test_assoc_peer_transports(asoc[1], &loop[0], 1);

	printk("\n 1->3 INIT ACK\n\n");
	if (test_step(SCTP_CID_INIT_ACK, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	printk("\n 1->3 INIT_ACK will be delayed\n\n");
	pkt3 = test_steal_packet(netw[0]);
	if (test_for_chunk(SCTP_CID_INIT_ACK, netw[0])) {
		DUMP_CORE;
	}

	/* Set sk[3] as non-blocking. */
	flags = sk[3]->sk_socket->file->f_flags;
	sk[3]->sk_socket->file->f_flags |= O_NONBLOCK;

	/* Do a non-blocking connect from sk[3] to sk[0] */
	printk("\n Connect 4->1\n\n");
	bufsize = fill_addr_buf(addr_buf, loop, 0, 0);
	error = test_connectx(sk[3], (struct sockaddr *)addr_buf, bufsize);

	/* Non-blocking connect should return immediately with EINPROGRESS. */
	if (error != -EINPROGRESS) { DUMP_CORE; }

	/* 4 sends INIT to 1. */
	printk("\n 4->1 INIT\n\n");
	if (!test_for_chunk(SCTP_CID_INIT, netw[0])) {
		DUMP_CORE;
	}

	printk("\n 1->3 INIT ACK\n\n");
	if (test_step(SCTP_CID_INIT_ACK, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	printk("\n 3->1 COOKIE ECHO\n\n");
	if (test_step(SCTP_CID_COOKIE_ECHO, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	printk("\n 1->3 COOKIE ACK\n\n");
	if (test_step(SCTP_CID_COOKIE_ACK, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	if (test_run_network_once(netw[0]) < 0) {
		DUMP_CORE;
	}

	/* Return 2->1 INIT ACK to queue. */
	printk("\n Return 2->1 INIT ACK to queue.\n\n");
	test_inject_packet(netw[0], pkt1);

	if (test_step(SCTP_CID_COOKIE_ECHO, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	/* Hold 1->2 COOKIE ECHO. */
	printk("\n Hold 1->2 COOKIE ECHO.\n\n");
	pkt1 = test_steal_packet(netw[0]);

	/* Return 1->2 INIT ACK to queue. */
	printk("\n Return 1->2 INIT ACK to queue.\n\n");
	test_inject_packet(netw[0], pkt2);

	printk("\n 2->1 COOKIE ECHO\n\n");
	if (test_step(SCTP_CID_COOKIE_ECHO, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	/* Hold 2->1 COOKIE ECHO. */
	printk("\n Hold 1->2 COOKIE ECHO.\n\n");
	pkt2 = test_steal_packet(netw[0]);

	/* Return 1->2 COOKIE ECHO to queue. */
	printk("\n Return 1->2 COOKIE ECHO to queue.\n\n");
	test_inject_packet(netw[0], pkt1);

	printk("\n 1->2 COOKIE ECHO DROPPED\n\n");
	if (test_step(SCTP_CID_COOKIE_ACK, netw[0])> 0 ) {
		DUMP_CORE;
	}

	printk("\n Association 0 (%p):\n", asoc[0]);
	print_assoc_peer_transports(asoc[0]);
	printk("\n Association 1 (%p):\n", asoc[1]);
	print_assoc_peer_transports(asoc[1]);
	test_assoc_peer_transports(asoc[0], &loop[1], 2);
	test_assoc_peer_transports(asoc[1], &loop[0], 1);

	/* Return 2->1 COOKIE ECHO to queue. */
	printk("\n Return 2->1 COOKIE ECHO to queue.\n\n");
	test_inject_packet(netw[0], pkt2);

	printk("\n 1->2 COOKIE ACK\n\n");
	if (test_step(SCTP_CID_COOKIE_ACK, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	if (test_run_network_once(netw[0]) < 0) {
		DUMP_CORE;
	}

	/* Return 1->3 INIT ACK to queue. */
	printk("\n Return 1->3 INIT ACK to queue.\n\n");
	test_inject_packet(netw[0], pkt3);

	printk("\n 3->1 COOKIE ECHO\n\n");
	if (test_step(SCTP_CID_COOKIE_ECHO, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	printk("\n 1->3 COOKIE ACK\n\n");
	if (test_step(SCTP_CID_COOKIE_ACK, netw[0])<= 0 ) {
		DUMP_CORE;
	}

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	printk("Test asoc[0] state ESTABLISHED\n");
	if (!sctp_state(asoc[0], ESTABLISHED)) {
		DUMP_CORE;
	}

	printk("Test asoc[1] state ESTABLISHED\n");
	if (!sctp_state(asoc[1], ESTABLISHED)) {
		DUMP_CORE;
	}

	ep[2] = sctp_sk(sk[2])->ep;
	asoc[2] = test_ep_first_asoc(ep[2]);
	ep[3] = sctp_sk(sk[3])->ep;
	asoc[3] = test_ep_first_asoc(ep[3]);

	printk("Test asoc[2] state ESTABLISHED\n");
	if (!sctp_state(asoc[2], ESTABLISHED)) {
		DUMP_CORE;
	}

	printk("Test asoc[3] state ESTABLISHED\n");
	if (!sctp_state(asoc[3], ESTABLISHED)) {
		DUMP_CORE;
	}

	printk("\n Association 0 (%p):\n", asoc[0]);
	print_assoc_peer_transports(asoc[0]);
	printk("\n Association 1 (%p):\n", asoc[1]);
	print_assoc_peer_transports(asoc[1]);
	printk("\n Association 2 (%p):\n", asoc[2]);
	print_assoc_peer_transports(asoc[2]);
	printk("\n Association 3 (%p):\n", asoc[3]);
	print_assoc_peer_transports(asoc[3]);
	test_assoc_peer_transports(asoc[0], &loop[1], 2);
	test_assoc_peer_transports(asoc[1], &loop[0], 1);
	test_assoc_peer_transports(asoc[2], &loop[0], 1);
	test_assoc_peer_transports(asoc[3], &loop[0], 1);

	/* If we get to this point, the test has passed.  The rest is
	 * just clean-up.
	 */
	/* Shut down the link.  */
	sctp_close(sk[0], /* timeout */ 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	sctp_close(sk[1], /* timeout */ 0);
	sctp_close(sk[2], /* timeout */ 0);
	sctp_close(sk[3], /* timeout */ 0);

	if (0 == error) {
		printk("\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */



