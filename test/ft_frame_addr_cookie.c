/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001
 * 
 * This file is part of the SCTP kernel reference Implementation.
 * 
 * This is a functional test for the SCTP kernel reference
 * implementation.
 * This test will test the SCTP ports with the following scenarios:
 * 
 *    Open socket sk1, bind it with 2 addresses. Open socket sk2,
 *    bind it with one address, and establish an association with sk1. 
 *    While single stepping the establishment, between the INIT_ACK and
 *    COOKIE_ECHO, remove one of the bound addresses from sk1. 
 *    After the association is fully established, verify that the 
 *    address list of the association under sk1 contains the 
 *    original 2 bound addresses.
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
        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in addr1;
        int error, bytes_sent, found;
	struct sctp_endpoint *test_ep;
	struct sockaddr_in bindx_addr;
	struct msghdr outmsg;
	char *message = "Don't worry, be happy!";
	struct iovec out_iov;
	struct sctp_association *asoc1;
	struct sctp_bind_addr *acopy;
	struct sctp_bind_addr bind_addr_buf;
        struct sctp_sockaddr_entry *addr, *addrcopy;
	struct list_head *pos, *pos2, *temp;
	sctp_scope_t scope;

        
        /* Do all that random stuff needed to make a sensible universe.  */
        sctp_init();

 	/*    Open sk1, bind it with 2 addresses. Open sk2,
 	 *    bind it with one address, and establish an association with sk1. 
	 *    While single stepping the establishment, between the INIT_ACK and
	 *    COOKIE_ECHO, remove one of the bound addresses from sk1. 
	 *    After the association is fully established, verify that the 
	 *    address list of the association under sk1 contains the 
	 *    original 2 bound addresses.
	 */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with 2 addresses. */
        addr1.sin_family = AF_INET;
        addr1.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr1.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
        if (error != 0) { 
		DUMP_CORE; 
	}
        
	bindx_addr.sin_family = AF_INET;
	bindx_addr.sin_addr.s_addr = SCTP_ADDR_ETH1;
	bindx_addr.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bindx(sk1, (struct sockaddr *)&bindx_addr,
			   sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR);
        if (error != 0) { 
		DUMP_CORE; 
	}

        addr1.sin_port = htons(SCTP_TESTPORT_2);
        error = test_bind(sk2, (struct sockaddr *)&addr1, sizeof(addr1));
	if (error != 0) { 
		DUMP_CORE; 
	}

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

        /* Send a message from sk2 to sk1. This will create an association. */
        addr1.sin_family = AF_INET;
        addr1.sin_addr.s_addr = SCTP_ADDR_ETH0;
        addr1.sin_port = htons(SCTP_TESTPORT_1);
        
	/* Build up a msghdr structure we use for sending.  */
	outmsg.msg_name = &addr1;
	outmsg.msg_namelen = sizeof(addr1);
	outmsg.msg_iov = &out_iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = NULL;
	outmsg.msg_controllen = 0;
	outmsg.msg_flags = 0;
        
	outmsg.msg_iov->iov_base = message;
	outmsg.msg_iov->iov_len = strlen(message) + 1;
	bytes_sent = sctp_sendmsg(NULL, sk2, &outmsg, strlen(message)+1);
	if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

        /* We should have an INIT sitting on the Internet, from sk2 to sk1. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK_ETH0)) {
		DUMP_CORE;
	}

	/* Obtain a copy of the bind address list out of the sk1.
	 */
	test_ep = sctp_sk(sk1)->ep;

	sctp_bind_addr_init(&bind_addr_buf, 0);
	acopy = &bind_addr_buf;

	scope = sctp_scope((union sctp_addr *)&bindx_addr);
	error = sctp_bind_addr_copy(acopy, &test_ep->base.bind_addr, scope, 
				    GFP_ATOMIC, SCTP_ADDR4_PEERSUPP);
	if (0 != error) {
		DUMP_CORE;
	}

	/* Next we expect an INIT ACK, from sk1 to sk2. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}

	/* Now, remove one of the bound addresses from sk1. */
        error = test_bindx(sk1, (struct sockaddr *)&bindx_addr,
			   sizeof(struct sockaddr_in), SCTP_BINDX_REM_ADDR);
        if (error != 0) { 
		DUMP_CORE; 
	}

	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK_ETH0) <= 0) {
		DUMP_CORE;
	}

	/* Process the rest of the network exchanges between sk1 and sk2 */
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* Now check the new association's bind address list on the sk1 
	 * side. It should be the same as the copy obtained earlier.
	 */

	test_ep = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(test_ep); 

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

		/* The implementatin changed a bit and we may not
		 * have any addresses embedded if there is only a single
		 * address.
		 */
		if (!found && !list_empty(&acopy->address_list)) {
			printk("Bind address list is not correct!!!\n");
			DUMP_CORE;
		} 
	} /* for (all addresses bound to the association) */

	sctp_bind_addr_free(acopy);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

        exit(error);
} /* main() */
