/* SCTP kernel Implementation
 * Copyright 2008 Hewlett-Packard Development Company, L.P.
 *
 * This file is part of the SCTP Linux kernel implementation
 * 
 * This is a functional test for the SCTP kernel reference
 * implementation state machine.
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ^^^^^^^^^^^^^^^^^^^^^^^^
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
        struct sock *sk1, *sk2;
	union sctp_addr addr1;
	union sctp_addr addr2;
        int error;

        /* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();

	memset(&addr1, 0, sizeof(union sctp_addr));
	memset(&addr2, 0, sizeof(union sctp_addr));

	/* TEST 1:  BIND TESTS */

	/* TEST 1A:  Create 1 PF_INET and 1 PF_INET6 socket and
	 * attempt to do wildcard binds on the two.
	 */
	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);

	/* Initialize a v4 address. */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1);

	/* Initialize a V6 address */
        addr2.v6.sin6_family = AF_INET6;
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_1);

	/* Bind a v4 wildcard address to sk1. */
	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != 0) { DUMP_CORE; }
       
	/* Bind a v6 wildcard address to sk2. It should fail. */
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error == 0) { DUMP_CORE; }

	/* Set ipv6only on sk2 and bind v6 wildcard.  Should succeed */
	inet6_sk(sk2)->ipv6only = 1;
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error != 0) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	/* TEST 1B: Same as 1A, but in reverse order */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);

	/* Bind a v6 wildcard address to sk2. */
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error != 0) { DUMP_CORE; }

	/* Bind a v4 wildcard address to sk1. Should fail. */
	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error == 0) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	/* TEST 1C:  Same as 1B, but set v6only on the AF_INET6 socket */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);

	/* Set v6only and bind v6 wildcard on sk2 */
	inet6_sk(sk2)->ipv6only = 1;
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error != 0) { DUMP_CORE; }

	/* Bind a v4 wildcard address to sk1.  Should succeed*/
	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != 0) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	/* TEST 1D:  Try binding to IPv4 address and IPv4-mapped-IPv6 address
	 * on an IPv6 socket.
	 */
	sk1 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);

	/* addr1 is an IPv4 address */
	addr1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;

	/* addr2 is a v4-mapped address */
	addr2.v6.sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
	addr2.v6.sin6_addr.s6_addr32[3] = SCTP_IP_LOOPBACK;

	/* Bind v4 address.  Should succeed */
	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != 0) { DUMP_CORE; }
	sctp_close(sk1, 0);

	/* Bind the v4-mapped address.  Should succeed */
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error != 0) { DUMP_CORE; }
	sctp_close(sk2, 0);

	/* TEST 1E: Do the same test, but set v6 only on the socket.
	 * Both binds should fail.
	 */
	sk1 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	inet6_sk(sk1)->ipv6only = 1;
	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	inet6_sk(sk2)->ipv6only = 1;

	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error == 0) { DUMP_CORE; }
	sctp_close(sk1, 0);

	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error == 0) { DUMP_CORE; }
	sctp_close(sk2, 0);

	/* TEST 1F: Now attempt to do the same binds, but clear SCTP v4mapped
	 * option.  Now, only the v4-mapped bind should fail.
	 */
	sk1 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	sctp_sk(sk1)->v4mapped = 0;

	/* Try to bind the v4-mapped address.  Should fail. */
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error == 0) { DUMP_CORE; }

	/* Bind the v4 address.  Should succeed. */
	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != 0) { DUMP_CORE; }
	sctp_close(sk1, 0);

	printk("\nTEST 1 PASSED!\n");
	
	/* TEST 2:  Connection tests
	 *
	 * Test 2A: Attempt to connect and AF_INET socket to an AF_INET6 socket
	 */ 

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != 0) { DUMP_CORE; }

	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
	memset(&addr2.v6.sin6_addr, 0, sizeof(struct in6_addr));
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error != 0) { DUMP_CORE; }

	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE };

	addr1.v6.sin6_port = htons(SCTP_TESTPORT_2);

	if (0 != sctp_connect(sk1, (struct sockaddr *)&addr1, sizeof(addr1)))
		DUMP_CORE;

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	test_run_network();

	/* Test 2B: Attempt to connect from AF_INET to AF_INET6 v6only socket
	 */ 
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
	error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != 0) { DUMP_CORE; }

	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	inet6_sk(sk2)->ipv6only = 1;
        addr2.v6.sin6_family = AF_INET6;
	addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
	memset(&addr2.v6.sin6_addr, 0, sizeof(struct in6_addr));
	error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error != 0) { DUMP_CORE; }

	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE };

	addr1.v6.sin6_port = htons(SCTP_TESTPORT_2);

	if (0 == sctp_connect(sk1, (struct sockaddr *)&addr1, sizeof(addr1)))
		DUMP_CORE;

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	test_run_network();

	printk("\nTEST 2 PASSED!\n");


	return 0;
} /* main() */
