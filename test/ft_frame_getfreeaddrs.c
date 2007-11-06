/* SCTP Kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 2001-2002 Intel Corp.
 *
 * This file is part of the SCTP Linux kernel reference implementation.
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
 * Ardelle Fan <ardelle.fan@intel.com>
 * Sridhar Samudrala <sri@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *  
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 *
 * ft_frame_getfreeaddrs.c
 * This is a functional test for the SCTP kernel reference implementation.
 *
 * This program tests the getsockopt option:
 * 	SCTP_GET_PEER_ADDRS_NUM		SCTP_GET_PEER_ADDRS
 *	SCTP_GET_LOCAL_ADDRS_NUM	SCTP_GET_LOCAL_ADDRS
 *
 */

#include <net/sctp/sctp.h>
#include <errno.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
        struct sock *sk1;
        struct sock *sk2;
        union sctp_addr addr1, addr2;
        int error;
	char *message = "Don't worry, be happy!";
	union sctp_addr bindx_addr;
#if TEST_V6
	struct sockaddr_in6 *in6_addr;
#else
	struct sockaddr_in *in_addr;
#endif
	struct sctp_association *asoc1, *asoc2;
	int num, optlen;
	struct sctp_getaddrs_old param;
	int pf_class;
	int addr_len;

        /* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
        sctp_init();

 	/*    Open sk1, bind it with 2 addresses. Open sk2,
 	 *    bind it with one address, and establish an association with sk1.
	 *    While single stepping the establishment, between the INIT_ACK and
	 *    COOKIE_ECHO, bind sk1 with an additional address. After the
	 *    association is fully established, verify that the address list
	 *    of the association under sk1 contains the original 2 bound
	 *    addresses.
	 */

#if TEST_V6
	/* Bind sk1 with IN6ADDR_ANY.  */
	pf_class = PF_INET6;
        addr1.v6.sin6_family = AF_INET6;
        addr1.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
        addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
	bindx_addr.v6.sin6_family = AF_INET6;
	bindx_addr.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH1;
	bindx_addr.v6.sin6_port = htons(SCTP_TESTPORT_1);
        addr2.v6.sin6_family = AF_INET6;
        addr2.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
	addr_len = sizeof(struct sockaddr_in6);
#else	
	pf_class = PF_INET;
        addr1.v4.sin_family = AF_INET;
        addr1.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
	bindx_addr.v4.sin_family = AF_INET;
	bindx_addr.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	bindx_addr.v4.sin_port = htons(SCTP_TESTPORT_1);
        addr2.v4.sin_family = AF_INET;
        addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr2.v4.sin_port = htons(SCTP_TESTPORT_2);
	addr_len = sizeof(struct sockaddr_in);
#endif

        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind sk1 with 2 addresses. */
        error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
        if (error != 0) {
		DUMP_CORE;
	}

        error = test_bindx(sk1, (struct sockaddr *)&bindx_addr,
			   addr_len, SCTP_BINDX_ADD_ADDR);
        if (error != 0) {
		DUMP_CORE;
	}

	/* TEST #1: SCTP_GET_LOCAL_ADDRS_NUM	SCTP_GET_LOCAL_ADDRS */
	num = 0;
	optlen = sizeof(int);
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_GET_LOCAL_ADDRS_NUM_OLD,
				(void *)&num, &optlen);
	if (error != 2)
		DUMP_CORE;

	optlen = sizeof(struct sctp_getaddrs_old);
	param.addr_num = 2;
	param.assoc_id = 0;
	param.addrs = (struct sockaddr *)malloc(2 * 
						sizeof(struct sockaddr_in6));
	memset(param.addrs, 0, 2 * sizeof(struct sockaddr_in6));
	error = sctp_getsockopt(sk1, IPPROTO_SCTP, SCTP_GET_LOCAL_ADDRS_OLD,
				(void *)&param, &optlen);
	if (error)
		DUMP_CORE;
	
#if TEST_V6
	in6_addr = (struct sockaddr_in6 *)param.addrs;
	if (in6_addr->sin6_family != AF_INET6)
		 DUMP_CORE;
        if (ipv6_addr_cmp(&in6_addr->sin6_addr, &addr1.v6.sin6_addr))
		DUMP_CORE;
        if (ntohs(in6_addr->sin6_port) != SCTP_TESTPORT_1)
		DUMP_CORE;

	in6_addr++;
	if (in6_addr->sin6_family != AF_INET6)
		 DUMP_CORE;
        if (ipv6_addr_cmp(&in6_addr->sin6_addr, &bindx_addr.v6.sin6_addr))
		DUMP_CORE;
        if (ntohs(in6_addr->sin6_port) != SCTP_TESTPORT_1)
		DUMP_CORE;
#else
	in_addr = (struct sockaddr_in *)param.addrs;
	if (in_addr->sin_family != AF_INET)
		DUMP_CORE;
        if (in_addr->sin_addr.s_addr != SCTP_ADDR_ETH0)
		DUMP_CORE;
        if (ntohs(in_addr->sin_port) != SCTP_TESTPORT_1)
		DUMP_CORE;

	in_addr++;
	if (in_addr->sin_family != AF_INET)
		DUMP_CORE;
        if (in_addr->sin_addr.s_addr != SCTP_ADDR_ETH1)
		DUMP_CORE;
        if (ntohs(in_addr->sin_port) != SCTP_TESTPORT_1)
		DUMP_CORE;
#endif

        error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (error != 0) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

        /* Send a message from sk2 to sk1. This will create an association. */
	test_frame_send_message(sk2, (struct sockaddr *)&addr1, message);

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }
	
	/* One last check to make sure that endpoints believe that the
	 * association has been established.
	 */
        asoc1 = test_ep_first_asoc(sctp_sk(sk1)->ep);
	asoc2 = test_ep_first_asoc(sctp_sk(sk2)->ep);

        /* TEST #2: SCTP_GET_PEER_ADDRS_NUM	SCTP_GET_PEER_ADDRS */
	num = (int)sctp_assoc2id(asoc2);
	optlen = sizeof(int);
	error = sctp_getsockopt(sk2, IPPROTO_SCTP, SCTP_GET_PEER_ADDRS_NUM_OLD,
				(void *)&num, &optlen);
	if (error != 2)
		DUMP_CORE;

	optlen = sizeof(struct sctp_getaddrs_old);
	param.addr_num = 2;
	param.assoc_id = sctp_assoc2id(asoc2);
	memset(param.addrs, 0, 2 * sizeof(struct sockaddr_in6));
	error = sctp_getsockopt(sk2, IPPROTO_SCTP, SCTP_GET_PEER_ADDRS_OLD,
				(void *)&param, &optlen);
	if (error)
		DUMP_CORE;
	
#if TEST_V6
	in6_addr = (struct sockaddr_in6 *)param.addrs;
	if (in6_addr->sin6_family != AF_INET6)
		 DUMP_CORE;
        if (ipv6_addr_cmp(&in6_addr->sin6_addr, &addr1.v6.sin6_addr))
		DUMP_CORE;
        if (ntohs(in6_addr->sin6_port) != SCTP_TESTPORT_1)
		DUMP_CORE;

	in6_addr++;
	if (in6_addr->sin6_family != AF_INET6)
		 DUMP_CORE;
        if (ipv6_addr_cmp(&in6_addr->sin6_addr, &bindx_addr.v6.sin6_addr))
		DUMP_CORE;
        if (ntohs(in6_addr->sin6_port) != SCTP_TESTPORT_1)
		DUMP_CORE;
#else
	in_addr = (struct sockaddr_in *)param.addrs;
	if (in_addr->sin_family != AF_INET)
		DUMP_CORE;
        if (in_addr->sin_addr.s_addr != SCTP_ADDR_ETH0)
		DUMP_CORE;
        if (ntohs(in_addr->sin_port) != SCTP_TESTPORT_1)
		DUMP_CORE;

	in_addr++;
	if (in_addr->sin_family != AF_INET)
		DUMP_CORE;
        if (in_addr->sin_addr.s_addr != SCTP_ADDR_ETH1)
		DUMP_CORE;
        if (ntohs(in_addr->sin_port) != SCTP_TESTPORT_1)
		DUMP_CORE;
#endif

	free(param.addrs);

	if ((SCTP_STATE_ESTABLISHED != asoc1->state) ||
	    (SCTP_STATE_ESTABLISHED != asoc2->state)) {
		printk("Something went wrong during association.\n");
		printk("asoc1->state:%d\n", asoc1->state);
		printk("asoc2->state:%d\n", asoc2->state);
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

        exit(error);

} /* main() */
