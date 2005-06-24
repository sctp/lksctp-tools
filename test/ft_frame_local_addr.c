/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
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
 * Daisy Chang <daisyc@us.ibm.com>
 * Hui Huang <hui.huang@nokia.com>
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *  
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-05.txt.
 *
 *                                                                       
 * ft_frame_local_addr.c
 * This is a functional test for the SCTP kernel reference implementation.
 *
 * This program tests the local addresses with the following scenario:
 * 
 * - sk1 is the receiver, bound with INADDR_ANY, and sk2 is the
 *   sender, bound to a specific address.  We establish an association
 *   between sk1 and sk2.  We bring up a new interface for sk1.  We
 *   then check to see that a packet inbound to the new address should
 *   NOT get routed to sk1's association.
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

extern struct net_device *dev_base;
extern struct net_device eth2_dev;

#if TEST_V6

static int test_v6_scoping(struct in6_addr dst, int scope)
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
	char *messages = "Don't worry, be happy!";
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	sctp_init_chunk_t *initchk;
	sctp_paramhdr_t *pahdr;
	uint8_t *p, *chkend;
	int rc = 0;
	int net;

	/* Bind sk1 with IN6ADDR_ANY.  */
        addr1.v6.sin6_family = AF_INET6;
        addr1.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;
        addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

        addr2.v6.sin6_family = AF_INET6;
        addr2.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Send the first message.  
         */
        addr3.v6.sin6_family = AF_INET6;
        addr3.v6.sin6_addr = (struct in6_addr) dst;
        addr3.v6.sin6_port = htons(SCTP_TESTPORT_1);
	if (scope == IPV6_ADDR_LINKLOCAL)
		addr3.v6.sin6_scope_id = 2;
	test_frame_send_message(sk2, (struct sockaddr *)&addr3, messages);

	net = test_get_network_sctp_addr(&addr3);
	/* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, net)) {
		DUMP_CORE;
	}

	/* Look through the INIT addresses and make sure we aren't 
	 * sending something with an unexpected scope.
	 */
	skb = test_peek_packet(net);
       
	/* Look through the INIT-ACK addresses and make sure we aren't 
	 * sending something with an unexpected scope.
	 */
	skb = test_peek_packet(net);
	packet = test_get_sctp(skb->data);
	initchk = (sctp_init_chunk_t *)&packet->ch;
	p = &initchk->init_hdr.params[0];
	chkend = (char *)&packet->ch 
		+ WORD_ROUND(ntohs(initchk->chunk_hdr.length));
	pahdr = (sctp_paramhdr_t *)p;	

	while (pahdr) {
		if (SCTP_PARAM_IPV6_ADDRESS == pahdr->type) {
			int type;

			type = ipv6_addr_type((struct in6_addr *)(pahdr+1));
			switch (scope) {
			case IPV6_ADDR_LOOPBACK:
				/* Allow everything. */
				break;		
			case IPV6_ADDR_LINKLOCAL:
				/* Disallow loopback. */
				if (type & IPV6_ADDR_LOOPBACK) 
					goto out;
				break;
			case IPV6_ADDR_SITELOCAL:
				/* Disallow linklocal & loopback. */
				if ((type & IPV6_ADDR_LOOPBACK) ||
				    (type & IPV6_ADDR_LINKLOCAL)) 
					goto out;
				break;
		
			default:
				/* Disallow linklocal & loopback. */
				if ((type & IPV6_ADDR_LOOPBACK) || 
				    (type & IPV6_ADDR_LINKLOCAL) ||
				    (type & IPV6_ADDR_SITELOCAL))
					goto out;
				break;
			}
		}
		
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		
		if (p == chkend)
			pahdr = NULL;
		else if (p > (chkend - sizeof(sctp_paramhdr_t)))
			DUMP_CORE;
		
	}
	

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, net) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(net);
	packet = test_get_sctp(skb->data);
	initchk = (sctp_init_chunk_t *)&packet->ch;

	p = &initchk->init_hdr.params[0];
	chkend = (char *)&packet->ch 
		+ WORD_ROUND(ntohs(initchk->chunk_hdr.length));
	pahdr = (sctp_paramhdr_t *)p;	

	while (pahdr) {
		if (SCTP_PARAM_IPV6_ADDRESS == pahdr->type) {
			int type;

			type = ipv6_addr_type((struct in6_addr *)(pahdr+1));
			switch (scope) {
			case IPV6_ADDR_LOOPBACK:
				/* Allow everything. */
				break;		
			case IPV6_ADDR_LINKLOCAL:
				/* Disallow loopback. */
				if (type & IPV6_ADDR_LOOPBACK) 
					goto out;
				break;
			case IPV6_ADDR_SITELOCAL:
				/* Disallow linklocal & loopback. */
				if ((type & IPV6_ADDR_LOOPBACK) ||
				    (type & IPV6_ADDR_LINKLOCAL)) 
					goto out;
				break;
		
			default:
				/* Disallow linklocal & loopback. */
				if ((type & IPV6_ADDR_LOOPBACK) || 
				    (type & IPV6_ADDR_LINKLOCAL) ||
				    (type & IPV6_ADDR_SITELOCAL))
					goto out;
				break;
			}
		} 
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		
		if (p == chkend)
			pahdr = NULL;
		else if (p > (chkend - sizeof(sctp_paramhdr_t)))
			DUMP_CORE;
	}
	
	rc = 1;

out:
	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	if ( test_run_network() ) DUMP_CORE;


	return rc;
}


#endif


int main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
	char *messages = "Don't worry, be happy!";
	struct sctp_association *test_asoc;
	struct sctp_transport *transport;
	union sctp_addr source, dest;
	int pf_class;

	/* Do all that random stuff needed to make a sensible
	 * universe.
	 */
	init_Internet();
	sctp_init();

#if TEST_V6
	/* Bind sk1 with IN6ADDR_ANY.  */
	pf_class = PF_INET6;
        addr1.v6.sin6_family = AF_INET6;
        addr1.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;
        addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else	
	/* Bind sk1 with INADDR_ANY.  */
	pf_class = PF_INET;
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = INADDR_ANY;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
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

#if TEST_V6
        addr2.v6.sin6_family = AF_INET6;
        addr2.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
#else
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2);
#endif /* TEST_V6 */

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Send the first message.  This will create the association
         * from sk2(SCTP_ADDR_ETH0 or SCTP_ADDR6_GLOBAL_ETH0) to sk1's ETH0.
         */
#if TEST_V6
        addr3.v6.sin6_family = AF_INET6;
        addr3.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
        addr3.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif /* TEST_V6 */
	test_frame_send_message(sk2, (struct sockaddr *)&addr3, messages);

	if ( test_run_network() ) DUMP_CORE;

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, messages);

	/* Case 1
	 * Add a new interface to sk1(INADDR_ANY).  Now suppose sk2
         * sent a packet to the new address.  The lookup for
         * association should fail.
	 */
	printk("\nAbout to add eth2\n\n");
	test_add_dev(&eth2_dev);

#if TEST_V6
        source.v6.sin6_family = dest.v6.sin6_family = AF_INET6;
        source.v6.sin6_addr  = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
        source.v6.sin6_port = SCTP_TESTPORT_2;
        dest.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH2;
        dest.v6.sin6_port = SCTP_TESTPORT_1;
#else	
	source.v4.sin_family = dest.v4.sin_family = AF_INET;
	source.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	source.v4.sin_port = SCTP_TESTPORT_2;
	dest.v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	dest.v4.sin_port = SCTP_TESTPORT_1;
#endif /* TEST_V6 */

	test_asoc = sctp_lookup_association(&source, &dest, &transport);
        
	if (test_asoc) {
		printk("\n\n%s Case 1 failed\n\n\n", argv[0]);
		DUMP_CORE;
	}

	printk("\n\n%s Case 1 passed \n\n\n", argv[0]);

#if TEST_V6
	 /* Case 2
         * Sent a packet to SCTP_ADDR6_GLOBAL_ETH2.  The lookup for 
	 * association should be OK.
         */

	test_asoc = sctp_lookup_association(&source, &dest, &transport);

        if (test_asoc) {
                printk("\n\n%s Case 2 failed\n\n\n", argv[0]);
                DUMP_CORE;
        }

        printk("\n\n%s Case 2 passed \n\n\n", argv[0]);

        /* Case 3
         * draft-stewart-tsvwg-sctpipv6-00
         * The INIT or INIT-ACK chunk should not include any IPv6 Link Local 
	 * address parameters unless the source or destination address in 
	 * the IPv6 header is a Link Local address.
         *
         * The INIT or INIT-ACK chunk should not include any IPv6 Site 
	 * Local address parameters unless the source or destination address 
	 * in the IPv6 header is a Site Local address.
         * Now suppose sk2 sent a packet to the LINKLOCAL or SITELOCAL 
	 * address of ETH0,
         * The lookup for association should fail.
         */

        dest.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_LINKLOCAL_ETH0;
	dest.v6.sin6_scope_id = 2;
        dest.v6.sin6_port = SCTP_TESTPORT_1;

        test_asoc = sctp_lookup_association(&source, &dest, &transport);

        if (test_asoc) {
                printk("\n\n%s Case 3 failed\n\n\n", argv[0]);
                DUMP_CORE;
        }


        dest.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
        dest.v6.sin6_port = SCTP_TESTPORT_1;

        test_asoc = sctp_lookup_association(&source, &dest, &transport);

        if (test_asoc) {
                printk("\n\n%s Case 3 failed\n\n\n", argv[0]);
                DUMP_CORE;
        }

        printk("\n\n%s Case 3 passed \n\n\n", argv[0]);
#endif /* TEST_V6 */

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	if ( test_run_network() ) DUMP_CORE;

#if TEST_V6
	/* Bind sk1 with IN6ADDR_ANY.  */
        pf_class = PF_INET6;
        addr1.v6.sin6_family = AF_INET6;
        addr1.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;
        addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);

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

        addr2.v6.sin6_family = AF_INET6;
	addr2.v6.sin6_addr = (struct in6_addr) SCTP_IN6ADDR_ANY_INIT;      
        addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Send the first message.  This will create the association
         * from sk2(SCTP_ADDR_ETH0 or SCTP_ADDR6_GLOBAL_ETH0) to sk1's ETH0.
         */
        addr3.v6.sin6_family = AF_INET6;
        addr3.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_LINKLOCAL_ETH0;
	addr3.v6.sin6_scope_id = 2;
        addr3.v6.sin6_port = htons(SCTP_TESTPORT_1);

	test_frame_send_message(sk2, (struct sockaddr *)&addr3, messages);

	if ( test_run_network() ) DUMP_CORE;

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, messages);
	
	sctp_close(sk1, 0);
	sctp_close(sk2, 0);
	if ( test_run_network() ) DUMP_CORE;

	/* Test v6 scoping rules. */

#if 0
	/* Verify that our test function works.  Send to a Linklocal address,
	 * but enforce global scope rule. 
	 */
	if (test_v6_scoping((struct in6_addr) SCTP_ADDR6_LINKLOCAL_ETH0, 0))
		DUMP_CORE;

	/* Now check that Global destination gets only global addresses. */
	if (!test_v6_scoping( (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0, 0))
		DUMP_CORE;  

#endif
	/* Now check that Global destination gets only global addresses. */
	if (!test_v6_scoping((struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0, 0))
		DUMP_CORE;  

	/* Now check that Site-local doesn't send link-local or loopback. */
	if (!test_v6_scoping((struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0,
			      IPV6_ADDR_SITELOCAL))
		DUMP_CORE;  

	/* Now check that link-local doesn't send link-local or loopback. */
	if (!test_v6_scoping((struct in6_addr) SCTP_ADDR6_LINKLOCAL_ETH0, 
			     IPV6_ADDR_LINKLOCAL))
		DUMP_CORE;  

	if (!test_v6_scoping((struct in6_addr) SCTP_IN6ADDR_LOOPBACK_INIT,
			     IPV6_ADDR_LOOPBACK))
		DUMP_CORE;  


#endif /* TEST_V6 */
	
	printk("\n\n%s passed \n\n\n", argv[0]);

	exit(0);

} /* main() */
