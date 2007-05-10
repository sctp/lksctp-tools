/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999,2001 Cisco, Motorola
 * 
 * This file is part of the SCTP kernel reference Implementation.
 * 
 * This is a functional test for the SCTP kernel reference
 * implementation.
 * This test will test the SCTP ports with the following scenarios:
 * 
 * Set up a socket sk1, bind it with an address and a port.
 * 1. Bind the same socket with the same address again--we should get
 *    the error -EINVAL. 
 * 2. Set up another socket sk2; bind the same address and port to
 *    it--we should get the error -EADDRINUSE.
 * 3. Close sk1; try the same bind again on sk2.  It should succeed now.
 * 4. Open sk1 and try to bind INADDR_ANY with the same port # we used
 *    before.  This should fail with -EADDRINUSE.
 * 5. Now use a different port with INADDR_ANY for sk1.  The bind
 *    should succeed.  
 * 6. Next, close sk2, and try to see if we can lookup endpoint(sk1)
 *    with the loopback address. 
 * 7. Create an association with the endpoint on sk1 (bound by
 *    INADDR_ANY), and verify that the INIT chunk contains the right
 *    set of local addresses.
 * 8. Remove a device, then create another association to verify the
 *    new INIT address list. 
 *
 * Daisy Chang <daisyc@us.ibm.com>
 *
 * The SCTP reference implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * The SCTP reference implementation  is distributed in the hope that it 
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
 * Karl Knutson <karl@athena.chicago.il.us>
 * Daisy Chang <daisyc@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 * 
 */

#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h> 
#include <funtest.h>


int test_INIT_addr_list(struct sctp_endpoint *,
			struct sock *sk,
                        union sctp_addr *);
int is_a_sctp_local_addr(union sctp_addr *);
int total_sctp_local_addr(void);
extern struct net_device *dev_base;
extern struct net_device eth0_dev;

int
main(int argc, char *argv[])
{
        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in addr1;
        struct sockaddr_in addr_any;
        struct sockaddr_in addr2;
        union sctp_addr peeraddr, daddr;
        int error;
	struct sctp_endpoint *test_ep;

        
        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        addr1.sin_family = AF_INET;
        addr1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        addr1.sin_port = htons(SCTP_TESTPORT_1);

        addr_any.sin_family = AF_INET;
        addr_any.sin_addr.s_addr = INADDR_ANY;
        addr_any.sin_port = htons(SCTP_TESTPORT_1);

        addr2.sin_family = AF_INET;
        addr2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        addr2.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
        if (error != 0) { DUMP_CORE; }
        
	/* Case 1
	 * Bind sk1 again with the same address and port.
	 * We should fail with EINVAL.
	 */
        error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
        if (error != -EINVAL) { 
		printk("\n\n%s case 1 got error %d\n", argv[0], error);
		printk("\n\n%s case 1 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n%s case 1 passed. \n\n\n", argv[0]);

	/* Case 2
	 * Try to bind that address and port on ANOTHER socket.
	 * We should fail with EADDRINUSE.
	 */
        error = test_bind(sk2, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != -EADDRINUSE) { 
		printk("\n\n%s case 2 got error %d\n", argv[0], error);
		printk("\n\n%s case 2 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n%s case 2 passed. \n\n\n", argv[0]);
        
	/* Case 3
	 * Close the first socket (sk1), and THEN try binding its
	 * address on sk2.
	 * This should succeed.
	 */
	sctp_close(sk1, /* timeout */ 0);

        error = test_bind(sk2, (struct sockaddr *)&addr1, sizeof(addr1));
        if (error != 0) { 
		printk("\n\n%s case 3 got error %d\n", argv[0], error);
		printk("\n\n%s case 3 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n%s case 3 passed. \n\n\n", argv[0]);

	/* Case 4
	 * Try to bind INADDR_ANY on sk1 with the same port.
	 * This should fail with EADDRINUSE.
	 */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET); /* open sk1 again */
        error = test_bind(sk1, (struct sockaddr *)&addr_any, sizeof(addr_any));
        if (error != -EADDRINUSE) { 
		printk("\n\n%s case 4 test_bind got error %d\n",
		       argv[0], error);
		printk("\n\n%s case 4 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n%s case 4 passed. \n\n\n", argv[0]);

	/* Case 5
	 * Try INADDR_ANY with a DIFFERENT port.
	 * This should succeed.
	 */
        addr_any.sin_port = htons(SCTP_TESTPORT_2);
        error = test_bind(sk1, (struct sockaddr *)&addr_any, sizeof(addr_any));
        if (error != 0) { 
		printk("\n\n%s case 5 test_bind got error %d\n",
		       argv[0], error);
		printk("\n\n%s case 5 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
		 
        sctp_close(sk2, /* timeout */ 0);
	
	
	/* Case 6a
	 * Try to find the endpoint for an incoming packet with a
	 * random address and a destination port of SCTP_TESTPORT_2.
	 * This should not match the socket, since it is not listening.
	 */
 
	daddr.v4.sin_family = AF_INET;
	daddr.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	daddr.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_ep = sctp_lookup_endpoint(&daddr);

	if (test_ep) {
		printk("\n\n%s case 6a test_ep = %p\n", argv[0], test_ep);
		printk("\n\n%s case 6a failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n%s case 6a passed. \n\n\n", argv[0]);
	
        /* Case 6b
	 * Try to find the endpoint for an incoming packet with a
	 * random address and a destination port of SCTP_TESTPORT_2.
	 * This should match the wildcard address on sk1.
	 */
	test_listen(sk1, 1);
	daddr.v4.sin_family = AF_INET;
	daddr.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	daddr.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_ep = sctp_lookup_endpoint(&daddr);

	if (!test_ep || test_ep->base.sk != sk1) {
		printk("\n\n%s case 6b test_ep = %p\n", argv[0], test_ep);
		printk("\n\n%s case 6b failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n%s case 6b passed. \n\n\n", argv[0]);


	/* Case 7
	 * Create a new association with the endpoint and verify that
         * the INIT chunk will include the right set of local
         * addresses.
	 */

	
        peeraddr.v4.sin_family = AF_INET;
        peeraddr.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        peeraddr.v4.sin_port = htons(SCTP_TESTPORT_1);
	if (0 == test_INIT_addr_list(test_ep, sk1, &peeraddr)) {
		printk("\n\n%s case 7 failed. \n\n\n", argv[0]);
		DUMP_CORE; 
	}

	printk("\n\n%s case 7 passed. \n\n\n", argv[0]);
#if 0
        /* Case 8
         * Remove a device and verify that we get the correct INIT packet.
         */
	test_remove_dev(&eth0_dev);

	/* Create another association with the same endpoint and
         * verify that the INIT chunk reflects the interface changes
         * which occurred. 
	 */
        peeraddr.v4.sin_family = AF_INET;
        peeraddr.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        peeraddr.v4.sin_port = htons(SCTP_TESTPORT_FOO);
	if (0 == test_INIT_addr_list(test_ep, sk1, &peeraddr)) {
		printk("\n\n%s case 8 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
#endif

        sctp_close(sk1, /* timeout */ 0);

	printk("\n\n%s case 8 passed. \n\n\n", argv[0]);

        exit(error);
} /* main() */

   
/* Create an association and verify the address list in the INIT chunk.
 */ 
int 
test_INIT_addr_list(struct sctp_endpoint *ep, struct sock *sk,
	            union sctp_addr *peer)
{

	struct sctp_endpoint *tmp_ep;
	struct sctp_association *asoc;
	struct sctp_chunk *init_chunk;
	union sctp_addr_param *addrparm;
	union sctp_params param;
	struct sctp_sockaddr_entry *addr;
	union sctp_addr tmpaddr;
	int INIT_addr_num, bind_addr_num;
	struct list_head *pos;
	struct sctp_bind_addr *bp;
	struct sctp_bind_addr bind_addr_buf;
	sctp_scope_t scope;
	int error;
	int flags;
	struct sctp_af *af;

	asoc = sctp_association_new(ep, sk, 0 /* global_scope */, 
				    GFP_KERNEL);
	if (!asoc) {
		printk("\n\n *** sctp_association_new() failed");
		return(0);
	}

        /* Prime the peer's transport structures. */
        sctp_assoc_add_peer(asoc, peer, GFP_KERNEL, SCTP_ACTIVE);
	/* Register the association with the endpoint. */
	sctp_endpoint_add_asoc(ep, asoc);

	/* Build up the bind address list for the association based on
	 * info from the local endpoint and the remote peer.
	 */
	sctp_bind_addr_init(&bind_addr_buf, 0);
	bp = &bind_addr_buf;
	scope = sctp_scope(&asoc->peer.active_path->ipaddr);
	flags = (PF_INET6 == asoc->base.sk->sk_family) ? 
		SCTP_ADDR6_ALLOWED : 0;
	if (asoc->peer.ipv4_address) {
		flags |= SCTP_ADDR4_PEERSUPP;
	}
	if (asoc->peer.ipv6_address) {
		flags |= SCTP_ADDR6_PEERSUPP;
	}
	error = sctp_bind_addr_copy(bp, &asoc->ep->base.bind_addr,
				    scope, GFP_ATOMIC, flags);
	if (0 != error) { DUMP_CORE; }

        /* Build a control chunk (INIT). */
        init_chunk = sctp_make_init(asoc, bp, GFP_KERNEL, 0);

	if (NULL == init_chunk) {
		printk("\n\n *** sctp_make_init() failed");
		goto fail;
	}

	/* Save the bind address list in the association and free the 
	 * temporary holder. */
	asoc->base.bind_addr = *bp;

	/* Verify the address list in the INIT chunk. */
	INIT_addr_num = bind_addr_num = 0;

	sctp_walk_params(param, (sctp_init_chunk_t *)init_chunk->chunk_hdr,
			 init_hdr.params) {

		af = sctp_get_af_specific(param_type2af(param.p->type));
		if (!af)
			continue;	

		addrparm = param.addr;
		af->from_addr_param(&tmpaddr, addrparm,
				    ep->base.bind_addr.port, 0);
		/* Is this a valid address on this  machine?  */
		if (!is_a_sctp_local_addr(&tmpaddr)) {
			printk("\n\n *** 0x%x is not one of my addresses.",
			       tmpaddr.v4.sin_addr.s_addr);
			goto fail;
		}
		tmpaddr.v4.sin_port = htons(tmpaddr.v4.sin_port);
		/* Is this address bound to the endpoint? */
		tmp_ep = sctp_lookup_endpoint(&tmpaddr);
		if (!tmp_ep || tmp_ep != ep) {
			printk("\n\n *** 0x%x is not attached to any endpoint.",
			       tmpaddr.v4.sin_addr.s_addr);
			goto fail;
		}

		INIT_addr_num++;

	} /* for (loop through all parameters) */

        /* Count the addresses bound on this endpoint.  */

	list_for_each(pos, &ep->base.bind_addr.address_list) {
		addr = list_entry(pos, struct sctp_sockaddr_entry, list);
		
		if (addr->a.v4.sin_family == AF_INET) {
			if (addr->a.v4.sin_addr.s_addr == INADDR_ANY) {
				bind_addr_num += total_sctp_local_addr();
				continue;
			}
			bind_addr_num++;
		}

	} /* for (all addresses bound on the endpoint) */
	
	if (INIT_addr_num != bind_addr_num) {
		if (INIT_addr_num) {
			printk("\n\n *** INIT_addr_num = %d, "
			       "bind_addr_num = %d",
			       INIT_addr_num, bind_addr_num);
			goto fail;
		}
	}

	return 1;

 fail:
        return 0;

} /* test_INIT_addr_list() */

/* This function confirms that the given address belongs to the local
 * host.
 */
int
is_a_sctp_local_addr(union sctp_addr *addr)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;


        switch (addr->sa.sa_family) {

        case AF_INET:
                for_each_netdev(dev) {
                        
			if ( (in_dev = __in_dev_get_rcu(dev)) ) {
                                
                                for (ifa = in_dev->ifa_list;
                                     ifa;
                                     ifa = ifa->ifa_next) {
                                        
                                        if (!(LOOPBACK(ifa->ifa_local)) && 
                                            addr->v4.sin_addr.s_addr
                                            == ifa->ifa_local) {
                                                goto succeed;
                                        }
                                        
                                } /* for (walk this interface bucket) */
                                
			} /* if (this bucket is not empty) */

		} /* for (every network device) */
                break;

        case AF_INET6:
                /* FIXME - Walk the IPv6 addresses as well. */
                BUG();
                break;
        default:
                goto fail;
                
        } /* switch (sin_family) */

 fail:
        return 0;
 succeed:
        return 1;
} /* is_a_sctp_local_addr() */

/* This function counts the local addresses.  */
int
total_sctp_local_addr(void)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	int total = 0;


	for_each_netdev(dev) {
		in_dev = __in_dev_get_rcu(dev);
		for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
			if (!(LOOPBACK(ifa->ifa_local))) {
				total++;
			}
		}
		/* FIXME - walk the IPv6 addresses as well */
	}
	return(total);
} /* total_sctp_local_addr() */

