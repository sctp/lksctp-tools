/*
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
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
 * Daisy Chang <daisyc@us.ibm.com>
 * Hui Huang <hui.huang@nokia.com>
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * Daisy Chang <daisyc@us.ibm.com>
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
 * We test the SCTP bindx() call with the following scenarios:
 *
 * 1. Bind sk1 with 3 addresses via bind() and bindx().  Establish an
 * association from sk2 to sk1 by using one of the sk1 addresses added
 * by bindx().  
 *
 * 2. Try to remove all the 3 bind addresses to sk1. This should fail.
 *
 * 3. Remove 2 of the 3 bind address from sk1 via bindx(). Look for the 
 * removed addresses in the bindx address list. They should not be there.
 *
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2;
	union sctp_addr bindx_addr1, bindx_addr2;
	union sctp_addr dest;
	char *messages = "Don't worry, be happy!";
	struct sctp_endpoint *tmp_ep;
	int pf_class;
	void *addr_buf;
	int addr_len;

	/* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();

#if TEST_V6
	pf_class = PF_INET6;
	addr1.v6.sin6_family = AF_INET6;
	addr1.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
	addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
	addr2.v6.sin6_family = AF_INET6;
	addr2.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
	addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
	bindx_addr1.v6.sin6_family = AF_INET6;
	bindx_addr1.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH1;
	bindx_addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
	bindx_addr2.v6.sin6_family = AF_INET6;
	bindx_addr2.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH2;
	bindx_addr2.v6.sin6_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in6);
#else
	pf_class = PF_INET;
        addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
        addr2.v4.sin_family = AF_INET;
        addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr2.v4.sin_port = htons(SCTP_TESTPORT_2);
	bindx_addr1.v4.sin_family = AF_INET;
        bindx_addr1.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
        bindx_addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
	bindx_addr2.v4.sin_family = AF_INET;
        bindx_addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
        bindx_addr2.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in);
#endif /* TEST_V6 */

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

        /* Bind sk1 with SCTP_ADDR_ETH0, port 1  */
	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	/* Bind sk2 with SCTP_ADDR_ETH0, port 2 */
	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Create an address buffer with the 2 bindx addresses and the 
	 * original address bind to sk1.
	 */ 
	addr_buf = malloc(3 * addr_len);
	memcpy(addr_buf, &bindx_addr1, addr_len);
	memcpy(addr_buf+addr_len, &bindx_addr2, addr_len);
	memcpy(addr_buf+2*addr_len, &addr1, addr_len);

	/**** Case 1 ****/

	/* Add two more addresses, eth1 and eth2, to be bound to sk1.  */
	if (test_bindx(sk1, (struct sockaddr *)addr_buf, 2 * addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	/* Send a message from sk2 to sk1 by using a sk1 address that was 
	 * added by bindx().  
	 * This will create the association from sk2 to sk1's ETH1.  
	 */
	test_frame_send_message(sk2, (struct sockaddr *)&bindx_addr1, messages);

	if ( test_run_network() ) DUMP_CORE;

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, messages);

	sctp_close(sk2, 0);

	printk("\n\n%s case 1 passed\n\n\n", argv[0]);

	/**** Case 2 ****/

	/* Try to remove all the 3 bind addresses from sk1. It should fail
	 * with EBUSY.
	 */
	if (-EBUSY != test_bindx(sk1, (struct sockaddr *)addr_buf, 3*addr_len,
		       SCTP_BINDX_REM_ADDR)) {
		printk("\n\nft_frame_bindx case 2 failed\n\n\n");
		DUMP_CORE;
	}

	printk("\n\n%s case 2 passed\n\n\n", argv[0]);

	/**** Case 2 ****/

	/* Now remove the original address bind to sk1 and the first bindx
	 * address.
	 */
	if (test_bindx(sk1, (struct sockaddr *)(addr_buf+addr_len), 2*addr_len,
		       SCTP_BINDX_REM_ADDR)) {
		printk("\n\nft_frame_bindx case 2 failed\n\n\n");
		DUMP_CORE;
	}


	/* Try to search for the removed sk1 addresses. This should fail, ie. 
	 * any packet destined to this address, including INIT chunk for any 
	 * attempt of new associations will be discarded and fail.
	 */

	/* Is this address bound to any endpoint? */
#if TEST_V6
	dest.v6.sin6_family = AF_INET6;	
	dest.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
	dest.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	dest.v4.sin_family = AF_INET;
        dest.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        dest.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif /* TEST_V6 */

	tmp_ep = sctp_lookup_endpoint(&dest);

	if (tmp_ep) {
		printk("\nFound tmp_ep = %x\n", (unsigned int)tmp_ep);
		printk("\n\nft_frame_bindx case 3 failed\n\n\n");
		DUMP_CORE;
	}

#if TEST_V6
	dest.v6.sin6_family = AF_INET6;	
	dest.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH2;
	dest.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	dest.v4.sin_family = AF_INET;
        dest.v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
        dest.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif /* TEST_V6 */

	tmp_ep = sctp_lookup_endpoint(&dest);

	if (tmp_ep) {
		printk("\nFound tmp_ep = %x\n", (unsigned int)tmp_ep);
		printk("\n\nft_frame_bindx case 3 failed\n\n\n");
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s case 3 passed\n\n\n", argv[0]);
	exit(0);

} /* main() */
