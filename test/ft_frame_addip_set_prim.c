/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2003
 * (C) Copyright Intel Corp. 2003
 *
 * This file is part of the SCTP kernel reference Implementation
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
 *    Gao, Kevin	<kevin.gao@intel.com>
 *    Sridhar Samudrala <sri@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * This is a Functional Test to verify ASCONF chunk with SET_PRIMARY parameter. 
 * 
 * - Set peer primary address before association is created, and verify that
 *   EINVAL is returned. 
 * - Set peer primary address after association is created, but before it is
 *   established and verify that ENOTCONN is returned.
 * - Set peer primary address after association is established, but with an
 *   invalid local address and verify that EADDRNOTAVAIL is returned.
 * - Set peer primary address after association is established and
 *   verify that it succeeds and an ASCONF chunk is sent. 
 */

#include <net/sctp/sm.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock		*sk1, *sk2;
	struct sctp_endpoint	*ep1, *ep2;
	struct sctp_association	*asoc1, *asoc2;
	union sctp_addr 	addr1, addr2;
	struct sctp_setpeerprim	prim;
	union sctp_addr		bindx_addr;
	char 			*messages = "I love the world!";
	int			pf_class;
	struct sk_buff_head	*network;
	struct bare_sctp_packet *packet;
	sctp_chunkhdr_t		*chunk;
	sctp_addiphdr_t		*addip_hdr;
	sctp_addip_param_t	*addip_param;
	struct sk_buff		*skb;
	int			addr_len, addr_param_len;
	int			retval;

	sctp_init();
	sctp_addip_enable = 1;

#if TEST_V6
	pf_class = PF_INET6;
	addr1.v6.sin6_family = AF_INET6;
	addr1.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
	addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
	addr2.v6.sin6_family = AF_INET6;
	addr2.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
	addr2.v6.sin6_port = htons(SCTP_TESTPORT_2);
	bindx_addr.v6.sin6_family = AF_INET6;
	bindx_addr.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH1;
	bindx_addr.v6.sin6_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in6);
	addr_param_len = sizeof(sctp_ipv6addr_param_t);
#else
	pf_class = PF_INET;
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2);
	bindx_addr.v4.sin_family = AF_INET;
	bindx_addr.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	bindx_addr.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in);
	addr_param_len = sizeof(sctp_ipv4addr_param_t);
#endif /* TEST_V6 */

	/* Create and bind the two endpoints which will talk to each other.
	 * Bind sk1 with SCTP_ADDR_ETH0, port 1. Bind sk2 with SCTP_ADDR_ETH0,
	 * port 2.
	 */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Add one more address: eth1, to be bound to sk1. */
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
	
	/* Set eth1 as peer primary address before an association is created.
	 * There is no association yet, asoc1 will be NULL and it should fail 
	 * with EINVAL.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	prim.sspp_assoc_id = (sctp_assoc_t)asoc1;
	memcpy(&prim.sspp_addr, &bindx_addr, addr_len);
	retval = sctp_setsockopt(sk1, SOL_SCTP, SCTP_SET_PEER_PRIMARY_ADDR,
				 (char *)&prim, sizeof(prim));
	if (-EINVAL != retval)
		DUMP_CORE;

	/* Send a message from sk1 to sk2. This will create the association. */
	test_frame_send_message(sk1, (struct sockaddr *)&addr2, messages);

	/* Set eth1 as peer primary address after the association is created,
	 * but before it is established. It should fail with ENOTCONN.
	 */
	asoc1 = test_ep_first_asoc(ep1);
	prim.sspp_assoc_id = (sctp_assoc_t)asoc1;
	memcpy(&prim.sspp_addr, &bindx_addr, addr_len);
	retval = sctp_setsockopt(sk1, SOL_SCTP, SCTP_SET_PEER_PRIMARY_ADDR,
				 (char *)&prim, sizeof(prim));
	if (-ENOTCONN != retval)
		DUMP_CORE;

	/* This will cause the association to be established. */
	if (test_run_network()) {
		DUMP_CORE;
	}

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, messages);

	/* Make sure that heartbeats are sent and all the paths are
	 * confirmed.
	 */
	jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

	/* Set peer primary address after the association is established,
	 * but with an invalid address. It should fail with EADDRNOTAVAIL.
	 */
	memcpy(&prim.sspp_addr, &addr2, sizeof(addr2));
	retval = sctp_setsockopt(sk1, SOL_SCTP, SCTP_SET_PEER_PRIMARY_ADDR,
				 (char *)&prim, sizeof(prim));
	if (-EADDRNOTAVAIL != retval)
		DUMP_CORE;

	/* Set peer primary address after the association is established,
	 * with a valid address. It should succeed.
	 */
	memcpy(&prim.sspp_addr, &bindx_addr, addr_len);
	retval = sctp_setsockopt(sk1, SOL_SCTP, SCTP_SET_PEER_PRIMARY_ADDR,
				 (char *)&prim, sizeof(prim));
	if (0 != retval)
		DUMP_CORE;

	network = get_Internet(TEST_NETWORK_ETH0);
	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;

	addip_hdr = (sctp_addiphdr_t *)packet->data;
	addip_param = (sctp_addip_param_t *)&addip_hdr->params[addr_param_len];

	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF != chunk->type || 
	    SCTP_PARAM_SET_PRIMARY != addip_param->param_hdr.type)
		DUMP_CORE;

	retval = test_run_network_once(TEST_NETWORK_ETH0);
	if (0 > retval)
		DUMP_CORE;

	network = get_Internet(TEST_NETWORK_ETH1);
	skb = network->next;

	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;
	addip_hdr = (sctp_addiphdr_t *)packet->data;

	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF_ACK != chunk->type)
		DUMP_CORE;

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	/* Verify that the peer primary address	is updated. */
	if (!(sctp_cmp_addr_exact(&asoc2->peer.primary_addr, &bindx_addr)))
		DUMP_CORE;

	if (test_run_network()) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);	
	return 0;
}
