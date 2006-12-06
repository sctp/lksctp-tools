/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2003
 * Copyright (c) 2003 Intel Corp.
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
 * This is a Functional Test to verify  basic functionality of
 * the SCTP ADDIP extension.
 * 
 * - Bind more than one addr before association is created, and see
 *   whether all the addresses are available. 
 * - Bind a new addr after association is established and check the 
 *   availablity of the new addr in the association.
 */

#include <net/sctp/sm.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock			*sk1, *sk2;
	struct sctp_endpoint		*ep1, *ep2;
	struct sctp_association		*asoc1, *asoc2;
	struct sctp_transport		*tp;
	struct sctp_sockaddr_entry	*addr_entry;
	struct sk_buff_head		*network;
	struct bare_sctp_packet		*packet;
	struct sk_buff          	*skb;
	sctp_chunkhdr_t         	*chunk;
	sctp_addiphdr_t         	*addip_hdr;
	sctp_addip_param_t      	*addip_param;
	union sctp_addr 		addr1, addr2;
	union sctp_addr			bindx_addr1, bindx_addr2;
	struct list_head		*p;	
	
	char	*messages = "I love the world!";
	int	pf_class;
	int	addr_found;
	int	addr_len, addr_param_len;

	init_Internet();
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
	bindx_addr1.v6.sin6_family = AF_INET6;
	bindx_addr1.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH1;
	bindx_addr1.v6.sin6_port = htons(SCTP_TESTPORT_1);
	bindx_addr2.v6.sin6_family = AF_INET6;
	bindx_addr2.v6.sin6_addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH2;
	bindx_addr2.v6.sin6_port = htons(SCTP_TESTPORT_1);	
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
	bindx_addr1.v4.sin_family = AF_INET;
	bindx_addr1.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
	bindx_addr1.v4.sin_port = htons(SCTP_TESTPORT_1);
	bindx_addr2.v4.sin_family = AF_INET;
	bindx_addr2.v4.sin_addr.s_addr = SCTP_ADDR_ETH2;
	bindx_addr2.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in);
	addr_param_len = sizeof(sctp_ipv4addr_param_t);
#endif

	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr1, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	test_frame_send_message(sk2, (struct sockaddr *)&bindx_addr1, messages);

	if (test_run_network()) {
		DUMP_CORE;
	}

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_message(sk1, messages);

	/* Verify that both the addresses bound to sk1 are available */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	p = asoc2->peer.transport_addr_list.next;
	tp = list_entry(p, struct sctp_transport, transports);
	if (!(sctp_cmp_addr_exact(&tp->ipaddr, &bindx_addr1)))
		DUMP_CORE;

	p = p->next;
	tp = list_entry(p, struct sctp_transport, transports);
	if (!(sctp_cmp_addr_exact(&tp->ipaddr, &addr1)))
		DUMP_CORE;

	/* Case 2 */
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr2, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	network = get_Internet(TEST_NETWORK_ETH0);
	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;

	addip_hdr = (sctp_addiphdr_t *)packet->data;
	addip_param = (sctp_addip_param_t *)&addip_hdr->params[addr_param_len];

	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF != chunk->type || 
	    SCTP_PARAM_ADD_IP != addip_param->param_hdr.type)
		DUMP_CORE;

	if (0 > test_run_network_once(TEST_NETWORK_ETH0))
		DUMP_CORE;

	network = get_Internet(TEST_NETWORK_ETH1);
	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;
	addip_hdr = (sctp_addiphdr_t *)packet->data;
	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF_ACK != chunk->type)
		DUMP_CORE;
	
	/* Verify that the new addr bound after the association in peer
	 * is created is also available.
	 */
	addr_found = 0;
	list_for_each(p, &asoc2->peer.transport_addr_list) {
		tp = list_entry(p, struct sctp_transport, transports);
		if (sctp_cmp_addr_exact(&tp->ipaddr, &bindx_addr2)) {
			addr_found = 1;
			break;
		}
	}

	if (!addr_found) {
		DUMP_CORE;
	}

	if (test_run_network()) {
		DUMP_CORE;
	}

	/* Verify that the new addr bound after the association in local
	 * is created is also available.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	
	addr_found = 0;
	list_for_each(p, &asoc1->base.bind_addr.address_list) {
		addr_entry = list_entry(p, struct sctp_sockaddr_entry, list);
		
		if (sctp_cmp_addr_exact(&addr_entry->a, &bindx_addr2)) {
			addr_found = 1;
			break;
		}
	}

	if (!addr_found) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);	
	
	return 0;	
}
