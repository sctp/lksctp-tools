/* SCTP kernel Implementation
 * Copyright 2008 Hewlett-Packard Development Company, L.P.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it
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
 * Please send any bug reports or fixes you make to one of the following
 * email addresses:
 *
 * Vlad Yasevich <vladislav.yasevich@hp.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *  
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */
                                                                        
/* 
 * This is a functional test for the SCTP kernel implementation.
 *
 * We test the SCTP bind() call with the following scenarios:
 *	- Wildcard binds with and without SO_REUSEADDR.
 *  	- Same address binds with and without SO_REUSEADDR.
 *  	- Mixed wildcard/address binds with and without SO_REUSEADDR.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr wild;
	union sctp_addr addr;
	int pf_class;
	int addr_len;

	/* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();

#if TEST_V6
	pf_class = PF_INET6;
	addr_len = sizeof(struct sockaddr_in6);
	addr.v6.sin6_family = AF_INET6;
	addr.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
	addr.v6.sin6_port = htons(SCTP_TESTPORT_1);
	memset(&wild, 0, addr_len);
	wild.v6.sin6_family = AF_INET6;
	wild.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	pf_class = PF_INET;
	addr_len = sizeof(struct sockaddr_in);
        addr.v4.sin_family = AF_INET;
	addr.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr.v4.sin_port = htons(SCTP_TESTPORT_1);
	memset(&wild, 0, addr_len);
	wild.v4.sin_family = AF_INET;
	wild.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif /* TEST_V6 */

	/* TEST 1
	 *
	 * Bind 2 wildcards.
	 */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&wild, addr_len)) {
		DUMP_CORE;
	}

	/* this one should fail */
	if (test_bind(sk2, (struct sockaddr *)&wild, addr_len) == 0) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	printk("Test 1 PASSED\n\n");

	/*
	 * Test 2:
	 *
	 * Bind 2 wildcards with SO_REUSEADDR
	 */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	sk1->sk_reuse = 1;
	sk2->sk_reuse = 1;

	if (test_bind(sk1, (struct sockaddr *)&wild, addr_len)) {
		DUMP_CORE;
	}

	/* this one should fail */
	if (test_bind(sk2, (struct sockaddr *)&wild, addr_len)) {
		DUMP_CORE;
	}

	/* No try listening */

	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	/* Second list should fail */
	if (0 == sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);

	/* It should now work */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	sctp_close(sk2, 0);
	printk("Test 2 PASSED\n\n");

	/* TEST 3: Bind addresses */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr, addr_len)) {
		DUMP_CORE;
	}

	/* this one should fail */
	if (test_bind(sk2, (struct sockaddr *)&addr, addr_len) == 0) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	printk("Test 3 PASSED\n\n");

	/* Test 4: Bind addresses with SO_REUSEADDR */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	sk1->sk_reuse = 1;
	sk2->sk_reuse = 1;

	if (test_bind(sk1, (struct sockaddr *)&addr, addr_len)) {
		DUMP_CORE;
	}

	/* this one should fail */
	if (test_bind(sk2, (struct sockaddr *)&addr, addr_len)) {
		DUMP_CORE;
	}

	/* No try listening */

	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	/* Second list should fail */
	if (0 == sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);

	/* It should now work */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	sctp_close(sk2, 0);
	printk("Test 4 PASSED\n\n");

	/* TEST 5: Wildcard and address, wildcard first */

	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&wild, addr_len)) {
		DUMP_CORE;
	}

	/* this one should fail */
	if (test_bind(sk2, (struct sockaddr *)&addr, addr_len) == 0) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	printk("Test 5 PASSED\n\n");

	/* TEST 6: Wildcard and address, address first */

	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr, addr_len)) {
		DUMP_CORE;
	}

	/* this one should fail */
	if (test_bind(sk2, (struct sockaddr *)&wild, addr_len) == 0) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	printk("Test 6 PASSED\n\n");

	/* TEST 7: Wildcard and address, REUSE_ADDR set */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk1->sk_reuse = 1;
	sk2->sk_reuse = 1;

	if (test_bind(sk1, (struct sockaddr *)&wild, addr_len)) {
		DUMP_CORE;
	}

	/* this one should fail */
	if (test_bind(sk2, (struct sockaddr *)&addr, addr_len)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	printk("Test 7 PASSED\n\n");
	return 0;
}

