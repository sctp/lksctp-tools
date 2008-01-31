/*
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2001 Motorola, Inc.
 *
 * Test sctp_connectx T1 timer operations.
 *
 * This SCTP implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This SCTP implementation is distributed in the hope that it
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
 *    Sridhar Samudrala		<sri@us.ibm.com>
 *    Frank Filz            <ffilzlnx@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* This is a testframe functional test to verify the udp-style sctp_connectx()
 * support in blocking and non-blocking modes.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

#define NUM_SRV_ADDR 5
#define LAST_SRV_ADDR (NUM_SRV_ADDR - 1 )
#define LAST_VALID_SRV_ADDR (LAST_SRV_ADDR - 1)
#define NUM_VALID_SRV_ADDR (NUM_SRV_ADDR - 2)

int
main(int argc, char *argv[])
{
	struct sock *svr_sk, *clt_sk1, *clt_sk2;
	struct sctp_endpoint *svr_ep, *clt_ep1;//, *clt_ep2;
	struct sctp_association *svr_asoc, *clt_asoc1;//, *clt_asoc2;
	int error, flags, bufsize;
	int i, j, init_to, init_cnt = 0;
	union sctp_addr svr_loop[NUM_SRV_ADDR];
	union sctp_addr *addr;
	int svr_netw[NUM_SRV_ADDR];
	int svr_cntr[NUM_SRV_ADDR];
	union sctp_addr clt_loop[4];
	char addr_buf[sizeof(struct sockaddr_in6)*NUM_SRV_ADDR];
	int pf_class;

	/* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
	sctp_init();

	memset(svr_cntr, sizeof(svr_cntr), 0);

	/* Initialize the server and client addresses. */
#if TEST_V6
	pf_class = PF_INET6;
	svr_loop[0].v6.sin6_family = AF_INET6;
	svr_loop[0].v6.sin6_addr = (struct in6_addr) SCTP_B_ADDR6_SITELOCAL_ETH0;
	svr_loop[0].v6.sin6_scope_id = 0;
	svr_loop[0].v6.sin6_port = htons(SCTP_TESTPORT_1);
	svr_netw[0] = TEST_NETWORK_ETH0;
	svr_loop[2].v6.sin6_family = AF_INET6;
	svr_loop[2].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
	svr_loop[2].v6.sin6_scope_id = 0;
	svr_loop[2].v6.sin6_port = htons(SCTP_TESTPORT_1);
	svr_netw[2] = TEST_NETWORK_ETH0;
	svr_loop[1].v6.sin6_family = AF_INET6;
	svr_loop[1].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH1;
	svr_loop[1].v6.sin6_scope_id = 0;
	svr_loop[1].v6.sin6_port = htons(SCTP_TESTPORT_1);
	svr_netw[1] = TEST_NETWORK_ETH1;
	svr_loop[3].v6.sin6_family = AF_INET6;
	svr_loop[3].v6.sin6_addr = (struct in6_addr) SCTP_C_ADDR6_SITELOCAL_ETH0;
	svr_loop[3].v6.sin6_scope_id = 0;
	svr_loop[3].v6.sin6_port = htons(SCTP_TESTPORT_1);
	svr_netw[3] = TEST_NETWORK_ETH0;
	svr_loop[4].v6.sin6_family = AF_INET6;
	svr_loop[4].v6.sin6_addr = (struct in6_addr) SCTP_B_ADDR6_SITELOCAL_ETH0;
	svr_loop[4].v6.sin6_scope_id = 0;
	svr_loop[4].v6.sin6_port = htons(SCTP_TESTPORT_1);
	svr_netw[4] = TEST_NETWORK_ETH0;

	clt_loop[0].v6.sin6_family = AF_INET6;
	clt_loop[0].v6.sin6_addr = (struct in6_addr) SCTP_C_ADDR6_SITELOCAL_ETH0;
	clt_loop[0].v6.sin6_scope_id = 0;
	clt_loop[0].v6.sin6_port = htons(SCTP_TESTPORT_2);
	clt_loop[1].v6.sin6_family = AF_INET6;
	clt_loop[1].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
	clt_loop[1].v6.sin6_scope_id = 0;
	clt_loop[1].v6.sin6_port = htons(SCTP_TESTPORT_2);
	clt_loop[2].v6.sin6_family = AF_INET6;
	clt_loop[2].v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
	clt_loop[2].v6.sin6_scope_id = 0;
	clt_loop[2].v6.sin6_port = htons(SCTP_TESTPORT_2+1);
	clt_loop[3].v4.sin_family = AF_INET;
	clt_loop[3].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	clt_loop[3].v4.sin_port = htons(SCTP_TESTPORT_2+2);
#else
	pf_class = PF_INET;
	svr_loop[0].v4.sin_family = AF_INET;
	svr_loop[0].v4.sin_addr.s_addr = SCTP_B_ETH0;
	svr_loop[0].v4.sin_port = htons(SCTP_TESTPORT_1);
	svr_netw[0] = TEST_NETWORK_ETH0;
	svr_loop[2].v4.sin_family = AF_INET;
	svr_loop[2].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	svr_loop[2].v4.sin_port = htons(SCTP_TESTPORT_1);
	svr_netw[2] = TEST_NETWORK_ETH0;
	svr_loop[1].v4.sin_family = AF_INET;
	svr_loop[1].v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	svr_loop[1].v4.sin_port = htons(SCTP_TESTPORT_1);
	svr_netw[1] = TEST_NETWORK_ETH1;
	svr_loop[3].v4.sin_family = AF_INET;
	svr_loop[3].v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	svr_loop[3].v4.sin_port = htons(SCTP_TESTPORT_1);
	svr_netw[3] = TEST_NETWORK_ETH2;
	svr_loop[4].v4.sin_family = AF_INET;
	svr_loop[4].v4.sin_addr.s_addr = SCTP_B_ETH0;
	svr_loop[4].v4.sin_port = htons(SCTP_TESTPORT_1);
	svr_netw[4] = TEST_NETWORK_ETH0;

	clt_loop[0].v4.sin_family = AF_INET;
	clt_loop[0].v4.sin_addr.s_addr = SCTP_C_ETH0;
	clt_loop[0].v4.sin_port = htons(SCTP_TESTPORT_2);
	clt_loop[1].v4.sin_family = AF_INET;
	clt_loop[1].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	clt_loop[1].v4.sin_port = htons(SCTP_TESTPORT_2);
	clt_loop[2].v4.sin_family = AF_INET;
	clt_loop[2].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	clt_loop[2].v4.sin_port = htons(SCTP_TESTPORT_2+1);
	clt_loop[3].v4.sin_family = AF_INET;
	clt_loop[3].v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	clt_loop[3].v4.sin_port = htons(SCTP_TESTPORT_2+2);
#endif

	/* Create the 3 sockets.  */
	svr_sk = sctp_socket(pf_class, SOCK_SEQPACKET);
	clt_sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	clt_sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind server addresses/ports to socket. */
	error = test_bind(svr_sk, (struct sockaddr *)&svr_loop[1],
			  ADDR_LEN(svr_loop[1]));
	if (error != 0) { printk("Error: %d\n", error); DUMP_CORE; }

	bufsize = fill_addr_buf(addr_buf, svr_loop, 2, LAST_VALID_SRV_ADDR);
	error = test_bindx(svr_sk, (struct sockaddr *)addr_buf, bufsize,
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	/* Bind client addresses/ports to sockets. */
	error = test_bind(clt_sk1, (struct sockaddr *)&clt_loop[1],
			  ADDR_LEN(clt_loop[1]));
	if (error != 0) { DUMP_CORE; }
	bufsize = fill_addr_buf(addr_buf, clt_loop, 0, 0);
	error = test_bindx(clt_sk1, (struct sockaddr *)addr_buf, bufsize,
		       SCTP_BINDX_ADD_ADDR);
	if (error != 0) { DUMP_CORE; }

	/* Mark svr_sk as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(svr_sk, 1)) { DUMP_CORE; }

	printk("----------------------------------------------------\n"
	       "Setup done\n"
	       "----------------------------------------------------\n");
	/* Set clt_sk1 as non-blocking. */
	flags = clt_sk1->sk_socket->file->f_flags;
	clt_sk1->sk_socket->file->f_flags |= O_NONBLOCK;

	/* Do a non-blocking connect from clt_sk1 to svr_sk */
	bufsize = fill_addr_buf(addr_buf, svr_loop, 0, LAST_VALID_SRV_ADDR);
	error = test_connectx(clt_sk1, (struct sockaddr *)addr_buf, bufsize);
	/* Non-blocking connect should return immediately with EINPROGRESS. */
	if (error != -EINPROGRESS) { DUMP_CORE; }

	/* Walk through the startup sequence.  */
	clt_ep1 = sctp_sk(clt_sk1)->ep;
	clt_asoc1 = test_ep_first_asoc(clt_ep1);
	clt_asoc1->max_init_attempts = 32;

	/* We should have an INIT sitting on the Internet. */
	printk("Sent INIT to invalid address\n");
	addr = &svr_loop[0];
	if (addr->sa.sa_family == AF_INET6) {
		printk("Expect an INIT:"
		       " addr: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
		       " port: %d\n",
		       NIP6(addr->v6.sin6_addr),
		       ntohs(addr->v6.sin6_port));
	} else {
		printk("Expect an INIT:"
		       " addr: %u.%u.%u.%u port: %d\n",
		       NIPQUAD(addr->v4.sin_addr.s_addr),
		       ntohs(addr->v4.sin_port));
	}
	if (!test_for_chunk(SCTP_CID_INIT, svr_netw[0])) {
		DUMP_CORE;
	}
	svr_cntr[0]++;
	init_cnt++;

	/* Next we do NOT expect an INIT ACK, since the peer address is invalid. */
	printk("Step once, should not see INIT ACK\n");
	if (test_step(SCTP_CID_INIT_ACK, svr_netw[0]) > 0) {
		DUMP_CORE;
	}

	/* We should NOT_ have an INIT sitting on the Internet. */
	printk("Or an INIT\n");
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[0])) {
		DUMP_CORE;
	}

	/* But we should have an ABORT sitting on the Internet. */
	printk("But we should see an ABORT\n");
	if (!test_for_chunk(SCTP_CID_ABORT, svr_netw[0])) {
		DUMP_CORE;
	}
	/* Process the ABORT. */
	printk("Process the ABORT, don't expect a new INIT\n");
	if (test_step(SCTP_CID_INIT, svr_netw[0]) > 0) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[1])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[2])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[3])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[4])) {
		DUMP_CORE;
	}

	printk("Free run network to complete failure of connection\n");
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* Get the communication up message from clt_sk1.  */
	printk("Check for SCTP_CANT_STR_ASSOC event, don't expect an INIT.\n");
	test_frame_get_event(clt_sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[0])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[1])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[2])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[3])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[4])) {
		DUMP_CORE;
	}

	/* Do a non-blocking connect from clt_sk1 to svr_sk */
	bufsize = fill_addr_buf(addr_buf, svr_loop, 1, LAST_SRV_ADDR);
	error = test_connectx(clt_sk1, (struct sockaddr *)addr_buf, bufsize);
	/* Non-blocking connect should return immediately with EINPROGRESS. */
	if (error != -EINPROGRESS) { DUMP_CORE; }

	/* Walk through the startup sequence.  */
	clt_ep1 = sctp_sk(clt_sk1)->ep;
	clt_asoc1 = test_ep_first_asoc(clt_ep1);
	clt_asoc1->max_init_attempts = 8 * (NUM_SRV_ADDR - 1);

	/* We should have an INIT sitting on the Internet. */
	printk("Sent INIT to valid address\n");
	addr = &svr_loop[1];
	if (addr->sa.sa_family == AF_INET6) {
		printk("Expect an INIT:"
		       " addr: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
		       " port: %d\n",
		       NIP6(addr->v6.sin6_addr),
		       ntohs(addr->v6.sin6_port));
	} else {
		printk("Expect an INIT:"
		       " addr: %u.%u.%u.%u port: %d\n",
		       NIPQUAD(addr->v4.sin_addr.s_addr),
		       ntohs(addr->v4.sin_port));
	}
	if (!test_for_chunk(SCTP_CID_INIT, svr_netw[1])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[0])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[2])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[3])) {
		DUMP_CORE;
	}
	if (test_for_chunk(SCTP_CID_INIT, svr_netw[4])) {
		DUMP_CORE;
	}
	init_cnt = 1;

	init_to = msecs_to_jiffies(SCTP_RTO_INITIAL);
	for (j = 1; j <= 7; j++) {	// this should be able to go to 8...
		for (i = 1; i <= LAST_SRV_ADDR; i++) {
			int next_init = i % LAST_SRV_ADDR + 1;
			addr = &svr_loop[next_init];

			printk("----------------------------------------------\n");
			printk("Timeout iteration j=%d i=%d\n", j, i);
			if (i != LAST_SRV_ADDR) {
				/* Now drop the INIT_ACK. */
				printk("Drop INIT_ACK %d\n", i);
				test_kill_next_packet(SCTP_CID_INIT_ACK);
			} else {
				/* Now drop the ABORT. */
				printk("Drop ABORT %d\n", i);
				test_kill_next_packet(SCTP_CID_ABORT);
			}
			error = test_run_network();
			if (0 != error) { DUMP_CORE; }

			if (init_to != clt_asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT]) {
				printk("Expected timeout to be: %d found: %d\n",
				       init_to,
				       clt_asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT]);
				DUMP_CORE;
			}
			printk("Allow T1 Timeout %d %d\n", i, clt_asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT]);
			jiffies += clt_asoc1->timeouts[SCTP_EVENT_TIMEOUT_T1_INIT] + 1;
			test_run_timeout();

#ifdef TEST_FAIL
			if (init_cnt == clt_asoc1->max_init_attempts) {
				printk("Don't expect an INIT\n");
				if (test_for_chunk(SCTP_CID_INIT, svr_netw[next_init])) {
					DUMP_CORE;
				}

				/* Indicate successful completion.  */
				printk("\n\n%s passed\n\n\n", argv[0]);
				exit(0);
			}
#endif

			/* We should again have an INIT sitting on the Internet. */
			if (addr->sa.sa_family == AF_INET6) {
				printk("Expect an INIT:"
				       " addr: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
				       " port: %d\n",
				       NIP6(addr->v6.sin6_addr),
				       ntohs(addr->v6.sin6_port));
			} else {
				printk("Expect an INIT:"
				       " addr: %u.%u.%u.%u port: %d\n",
				       NIPQUAD(addr->v4.sin_addr.s_addr),
				       ntohs(addr->v4.sin_port));
			}
			if (!test_for_chunk(SCTP_CID_INIT, svr_netw[next_init])) {
				DUMP_CORE;
			}
			svr_cntr[next_init]++;
			init_cnt++;

#ifndef TEST_FAIL
			if (init_cnt == clt_asoc1->max_init_attempts)
				break;
#endif
		}
		init_to *= 2;
		if (init_to > clt_asoc1->max_init_timeo)
			init_to = clt_asoc1->max_init_timeo;
#ifndef TEST_FAIL
		if (init_cnt == clt_asoc1->max_init_attempts)
			break;
#endif
	}

	printk("Free run network to complete connection\n");
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* Get the communication up message from clt_sk1.  */
	test_frame_get_event(clt_sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	/* Get the communication up message from svr_sk.  */
	test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Test that all associations have the correct
	 * set of peer transports.
	 */
	printk("Validate associations\n");

	svr_ep = sctp_sk(svr_sk)->ep;
	svr_asoc = test_ep_first_asoc(svr_ep);

	test_assoc_peer_transports(clt_asoc1, &svr_loop[1], NUM_VALID_SRV_ADDR);
	test_assoc_peer_transports(svr_asoc, &clt_loop[0], 2);

	/* Indicate successful completion.  */
	printk("\n\n%s passed\n\n\n", argv[0]);
	exit(0);

} /* main() */
