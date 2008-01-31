/* SCTP Kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * 
 * This is a functional test for the SCTP kernel implementation.
 * TEST #1 
 *    Open socket sk1, bind it with 2 addresses. Open socket sk2,
 *    bind it with one address, and establish an association with sk1. 
 *    While single stepping the establishment, between the INIT_ACK and
 *    COOKIE_ECHO, bind sk1 with an additional address. After the
 *    association is fully established, verify that the address list 
 *    of the association under sk1 contains the original 2 bound
 *    addresses.
 * TEST #2
 *    Verify that the correct source address is used while sending a packet
 *    over a symmetric association where both the endpoints are bound to
 *    all the available addresses.
 *    After the association is established between the 2 endpoints, the
 *    sender transmits a message to all the available peer addresses.
 *    The source address used in the transmitted packets is verified to 
 *    match with the corresponding local address bind at the sender. 
 * TEST #3
 *    Verify that the correct source address is used while sending a packet
 *    over an assymetric association where the sending endpoint is bound to a 
 *    single loopback address and the receiving endpoint is bound to all the
 *    available addresses.   
 *    After the association is established between the 2 endpoints, the
 *    sender transmits a message to all the available peer addresses.
 *    The source address used in the transmitted packets is verified to 
 *    match with the loopback address that is bound at the sender.
 *
 * The SCTP implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * The SCTP implementation  is distributed in the hope that it 
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
 * Please send any bug reports or fixes you make to one of the following email
 * addresses:
 * 
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Jon Grimm <jgrimm@us.ibm.com>
 * Daisy Chang <daisyc@us.ibm.com>
 * Sridhar Samudrala <sri@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 * 
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	int pf_class;
        struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
        int error, found;
	struct sctp_endpoint *test_ep;
	union sctp_addr bindx_addr1, bindx_addr2;
	char *message = "Don't worry, be happy!";
	struct sctp_association *asoc1, *asoc2;
	struct sctp_bind_addr *acopy;
	struct sctp_bind_addr bind_addr_buf;
	struct sctp_transport *transport;
        struct sctp_sockaddr_entry *addr, *addrcopy;
	struct list_head *pos, *pos2, *temp;
	struct sk_buff *skb;
	sctp_scope_t scope;
	int flags;
	int net;
	int addr_len;
        
        /* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
        sctp_init();

#if TEST_V6
	pf_class = PF_INET6;
        addr1.v6.sin6_family = AF_INET6;
        addr1.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
        addr2.v6.sin6_family = AF_INET6;
        addr2.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
	bindx_addr1.v6.sin6_family = AF_INET6;
	bindx_addr1.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH0;
	bindx_addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
	bindx_addr2.v6.sin6_family = AF_INET6;
	bindx_addr2.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH1;
	bindx_addr2.v6.sin6_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in6);
#else
	pf_class = PF_INET;
        addr1.v4.sin_family = AF_INET;
        addr1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
        addr2.v4.sin_family = AF_INET;
        addr2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        addr2.v4.sin_port = htons(SCTP_TESTPORT_2);
	bindx_addr1.v4.sin_family = AF_INET;
	bindx_addr1.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	bindx_addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
	bindx_addr2.v4.sin_family = AF_INET;
	bindx_addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	bindx_addr2.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in);
#endif /* TEST_V6 */

 	/*    TEST #1 
	 *    Open sk1, bind it with 2 addresses. Open sk2,
 	 *    bind it with one address, and establish an association with sk1. 
	 *    While single stepping the establishment, between the INIT_ACK and
	 *    COOKIE_ECHO, bind sk1 with an additional address. After the
	 *    association is fully established, verify that the address list 
	 *    of the association under sk1 contains the original 2 bound
	 *    addresses.
	 */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind sk1 with 2 addresses. */
        error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
        if (error != 0) { 
		DUMP_CORE; 
	}
        
        error = test_bindx(sk1, (struct sockaddr *)&bindx_addr1, addr_len,
			   SCTP_BINDX_ADD_ADDR);
        if (error != 0) { 
		DUMP_CORE; 
	}

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

        /* We should have an INIT sitting on the Internet, from sk2 to sk1. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Obtain a copy of the bind address list out of the sk1.  */
	test_ep = sctp_sk(sk1)->ep;

	sctp_bind_addr_init(&bind_addr_buf, 0);
	acopy = &bind_addr_buf; 

	scope = SCTP_SCOPE_LOOPBACK;
	flags = SCTP_ADDR6_ALLOWED | SCTP_ADDR4_PEERSUPP | SCTP_ADDR6_PEERSUPP;
	error = sctp_bind_addr_copy(acopy, &test_ep->base.bind_addr, scope, 
				    GFP_ATOMIC, flags);
	if (0 != error) {
		DUMP_CORE;
	}

	/* Next we expect an INIT ACK, from sk1 to sk2. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

       
	/* Now, bind another address to sk1. */
	error = test_bindx(sk1, (struct sockaddr *)&bindx_addr2, addr_len,
			   SCTP_BINDX_ADD_ADDR);
        if (error != 0) { 
		DUMP_CORE; 
	}

	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the rest of the network exchanges between sk1 and sk2 */
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }
	
	/* One last check to make sure that endpoints believe that the
	 * association has been established. 
	 */
        asoc1 = test_ep_first_asoc(sctp_sk(sk1)->ep);
	asoc2 = test_ep_first_asoc(sctp_sk(sk2)->ep);


	if ((SCTP_STATE_ESTABLISHED != asoc1->state) || 
	    (SCTP_STATE_ESTABLISHED != asoc2->state)) {
		printk("Something went wrong during association.\n");
		printk("asoc1->state:%d\n", asoc1->state);
		printk("asoc2->state:%d\n", asoc2->state);
		DUMP_CORE;
	} 

	/* Now check the new association's bind address list on the sk1 
	 * side. It should be the same as the copy obtained earlier.
	 */
	list_for_each(pos, &asoc1->base.bind_addr.address_list) {
		addr = list_entry(pos, struct sctp_sockaddr_entry, list);
		found = 0;
		list_for_each_safe(pos2, temp, &acopy->address_list) {
			addrcopy = list_entry(pos2, struct
					      sctp_sockaddr_entry, list);
			if (sctp_cmp_addr_exact(&addr->a, &addrcopy->a)) {
				/* found the exact match */
				found = 1;
				list_del(pos2);
				kfree(addrcopy);
				break;
			}
		} 
		if (!found) {
			printk("Bind address list is not correct!!!\n");
			DUMP_CORE;
		} 
	} /* for (all addresses bound to the association) */

	sctp_bind_addr_free(acopy);
	
	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

 	/* TEST #2
 	 * Verify that the correct source address is used while sending a
	 * packet over a symmetric association where both the endpoints are
	 * bound to all the available addresses.
	 * After the association is established between the 2 endpoints, the
	 * sender transmits a message to all the available peer addresses.
	 * The source address used in the transmitted packets is verified to 
	 * match with the corresponding local address bind at the sender. 
	 */	
#if TEST_V6
        addr1.v6.sin6_family = AF_INET6;
        addr1.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;
        addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
        addr2.v6.sin6_family = AF_INET6;
        addr2.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
        addr3.v6.sin6_family = AF_INET6;
        addr3.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_LOOPBACK_INIT;
        addr3.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = INADDR_ANY;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = INADDR_ANY;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2);
	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_ADDR_LO;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif /* TEST_V6 */

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Send a message from sk2 to sk1 using the loopback address.
	 * This will create the association.
         */
	test_frame_send_message(sk2, (struct sockaddr *)&addr3, message);

	if ( test_run_network() ) DUMP_CORE;

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, message);

	/* Make sure that heartbeats are sent and all the paths are
	 * confirmed.
	 */
	jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

        asoc1 = test_ep_first_asoc(sctp_sk(sk1)->ep);
	asoc2 = test_ep_first_asoc(sctp_sk(sk2)->ep);

	/* Send a message from sk2 to sk1 using all the available destination
	 * addresses and verify the source address used.
	 */
	list_for_each(pos, &asoc2->peer.transport_addr_list) {
		transport = list_entry(pos, struct sctp_transport, transports);

		if (transport->ipaddr.sa.sa_family == AF_INET) {
			addr3.v4.sin_addr.s_addr =
					transport->ipaddr.v4.sin_addr.s_addr;
			addr3.v4.sin_family = AF_INET;
		} else {
        		addr3.v6.sin6_addr =
					transport->ipaddr.v6.sin6_addr;
			addr3.v6.sin6_family = AF_INET6;
			addr3.v6.sin6_scope_id = 2;
		}

		test_frame_send_message2(sk2, (struct sockaddr *)&addr3,
					message, 0, 0, 0, SCTP_ADDR_OVER);

		net = test_get_network_sctp_addr(&transport->ipaddr);
		if ((skb = test_peek_packet(net)) == NULL)
			DUMP_CORE;

		/* Verify the source and destination addresses used. The 
		 * source address should match the transport's ip address as
		 * the testframe simulates local loopback. The destination
		 * address should match the transport's ip address.
		 */ 
		if (transport->ipaddr.sa.sa_family == AF_INET) {
			if (ip_hdr(skb)->saddr !=
					transport->ipaddr.v4.sin_addr.s_addr)
				DUMP_CORE;
			if (ip_hdr(skb)->daddr !=
					transport->ipaddr.v4.sin_addr.s_addr)
				DUMP_CORE;
#if TEST_V6
		} else {
			if (ipv6_addr_cmp(&ipv6_hdr(skb)->saddr,
					  &transport->ipaddr.v6.sin6_addr))
					DUMP_CORE;
			if (ipv6_addr_cmp(&ipv6_hdr(skb)->daddr,
					  &transport->ipaddr.v6.sin6_addr))
					DUMP_CORE;
#endif /* TEST_V6 */
		}

		if ( test_run_network() ) DUMP_CORE;

		test_frame_get_message(sk1, message);
	}		

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	/* Move time forward by a SACK timeout.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }
	
	/* TEST #3
	 * Verify that the correct source address is used while sending a
	 * packet over an assymetric association where the sending endpoint
	 * is bound to a single loopback address and the receiving endpoint
	 * is bound to all the available addresses.   
	 * After the association is established between the 2 endpoints, the
	 * sender transmits a message to all the available peer addresses.
	 * The source address used in the transmitted packets is verified to 
	 * match with the loopback address that is bound at the sender.
	 */	
#if TEST_V6
        addr1.v6.sin6_family = AF_INET6;
        addr1.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;
        addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
        addr2.v6.sin6_family = AF_INET6;
        addr2.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_LOOPBACK_INIT;
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
        addr3.v6.sin6_family = AF_INET6;
        addr3.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_LOOPBACK_INIT;
        addr3.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = INADDR_ANY;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2);
	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_ADDR_LO;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif /* TEST_V6 */
	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Send the first message from sk2 to sk1.
	 * This will create the association
         */
	test_frame_send_message(sk2, (struct sockaddr *)&addr3, message);

	if ( test_run_network() ) DUMP_CORE;

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, message);

        asoc1 = test_ep_first_asoc(sctp_sk(sk1)->ep);
	asoc2 = test_ep_first_asoc(sctp_sk(sk2)->ep);

	list_for_each(pos, &asoc2->peer.transport_addr_list) {
		transport = list_entry(pos, struct sctp_transport, transports);
	}
	/* Make sure that heartbeats are sent and all the paths are
	 * confirmed.
	 */
	jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

	/* Send a message from sk2 to sk1 using all the available destination
	 * addresses and verify the source address used.
	 */
	list_for_each(pos, &asoc2->peer.transport_addr_list) {
		transport = list_entry(pos, struct sctp_transport, transports);

#if TEST_V6
		if (transport->ipaddr.sa.sa_family == AF_INET)
			continue;
        	addr3.v6.sin6_addr = transport->ipaddr.v6.sin6_addr;
		addr3.v6.sin6_scope_id = 2;
#else
		addr3.v4.sin_addr.s_addr =
				transport->ipaddr.v4.sin_addr.s_addr;
#endif /* TEST_V6 */

		test_frame_send_message2(sk2, (struct sockaddr *)&addr3,
					message, 0, 0, 0, SCTP_ADDR_OVER);

		net = test_get_network_sctp_addr(&transport->ipaddr);
		if ((skb = test_peek_packet(net)) == NULL)
			DUMP_CORE;

		/* Verify the source and destination addresses used. As the
		 * only address that is bound is the loopback address, the
		 * source address should be the same as loopback address.
		 * The destination address should match the transport's 
		 * address.
		 */
		if (transport->ipaddr.sa.sa_family == AF_INET) {
			if (ip_hdr(skb)->saddr != addr2.v4.sin_addr.s_addr)
				DUMP_CORE;
			if (ip_hdr(skb)->daddr !=
				       	transport->ipaddr.v4.sin_addr.s_addr)
				DUMP_CORE;
#if TEST_V6
		} else {
			if (ipv6_addr_cmp(&ipv6_hdr(skb)->saddr,
					       	&addr2.v6.sin6_addr))
					DUMP_CORE;
			if (ipv6_addr_cmp(&ipv6_hdr(skb)->daddr,
					  &transport->ipaddr.v6.sin6_addr))
					DUMP_CORE;
#endif
		}

		if ( test_run_network() ) DUMP_CORE;

		test_frame_get_message(sk1, message);
	}		

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if ( test_run_network() ) DUMP_CORE;

	printk("\n\n%s passed\n\n\n", argv[0]);

        exit(error);

} /* main() */
