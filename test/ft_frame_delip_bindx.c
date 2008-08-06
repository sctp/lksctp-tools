/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2003
 * Copyright (c) 2003 Intel Corp.
 *
 * This file is part of the SCTP kernel Implementation
 * 
 * The SCTP implementation is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * The SCTP implementation is distributed in the hope that it 
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
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * This is a Functional Test to verify  basic functionality of
 * the SCTP DELETEIP extension.
 * 
 * - Delete an addr that is not use in association, and see whether
 *   it will failed.
 * - Delete an addr that is used in association, and see whether it is
 *   removed from peer site.
 * - Delete a wildcard.  This should remove all addresses except the source.
 * - Delete the last addr bind in assocaition, and see whether it can
 *   be deleted.
 */

#include <net/sctp/sm.h>
#include <net/sctp/checksum.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock			*sk1, *sk2;
	struct sctp_endpoint		*ep1, *ep2;
	struct sctp_association		*asoc1, *asoc2;
	struct sctp_transport		*tp;
	struct sctp_sockaddr_entry	*addr_entry;
	struct sk_buff_head     	*network;
	struct bare_sctp_packet 	*packet;
	struct sk_buff			*skb;
	sctp_chunkhdr_t         	*chunk;
	sctp_addiphdr_t         	*delip_hdr;
	sctp_addip_param_t      	*delip_param;
	union sctp_addr 		addr1, addr2;
	union sctp_addr			bindx_addr1, bindx_addr2, bindx_addr3;
	struct list_head		*p;	
	union sctp_addr_param		*addr_param;
	struct sctphdr			*sh;
	uint32_t			sum;

	
	char	*messages = "I love the world!";
	int	pf_class;
	int	addr_len, addr_param_len;

	init_Internet();
	sctp_init();
	sctp_addip_enable = 1;
	sctp_addip_noauth = 1;

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
	bindx_addr3.v6.sin6_family = AF_INET6;
	bindx_addr3.v6.sin6_addr = (struct in6_addr) SCTP_B_ADDR6_GLOBAL_ETH0;
	bindx_addr3.v6.sin6_port = htons(SCTP_TESTPORT_1);	
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
	bindx_addr3.v4.sin_family = AF_INET;
	bindx_addr3.v4.sin_addr.s_addr = SCTP_B_ETH0;
	bindx_addr3.v4.sin_port = htons(SCTP_TESTPORT_1);
	addr_len = sizeof(struct sockaddr_in);
	addr_param_len = sizeof(sctp_ipv4addr_param_t);
#endif /* TEST _V6 */

	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	/* Add two more address; eth1, to be bound to sk1.	*/
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr1, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr3, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	/* Mark sk1 as being able to accept new association.	*/
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

	/* Case 1:
	 * Delete one address that is not bind in association	*/
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr2, addr_len,
		       SCTP_BINDX_REM_ADDR) != -EINVAL) {
		DUMP_CORE;
	}

	printk("\n\n%s case 1 passed\n\n\n", argv[0]);

	/* Case 2
	 * Delete one address that is bind in association	*/
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr1, addr_len,
		       SCTP_BINDX_REM_ADDR)) {
		DUMP_CORE;
	}

	network = get_Internet(TEST_NETWORK_ETH0);
	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;

	delip_hdr = (sctp_addiphdr_t *)packet->data;
	delip_param = (sctp_addip_param_t *)&delip_hdr->params[addr_param_len];

	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF != chunk->type || 
	    SCTP_PARAM_DEL_IP != delip_param->param_hdr.type)
		DUMP_CORE;

	if (0 > test_run_network_once(TEST_NETWORK_ETH0))
		DUMP_CORE;

	network = get_Internet(TEST_NETWORK_ETH0);
	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;
	delip_hdr = (sctp_addiphdr_t *)packet->data;
	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF_ACK != chunk->type)
		DUMP_CORE;

	/* Check whether the address we deleted is still in use in
	 * peer's association.
	 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	bindx_addr1.v4.sin_port = ntohs(bindx_addr1.v4.sin_port);
	list_for_each(p, &asoc2->peer.transport_addr_list) {
		tp = list_entry(p, struct sctp_transport, transports);
		if (sctp_cmp_addr_exact(&tp->ipaddr, &bindx_addr1))
			DUMP_CORE;
	}

	if (test_run_network()) {
		DUMP_CORE;
	}

	/* Check whether the address we deleted is still in use in
	 * local association.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	list_for_each(p, &asoc1->base.bind_addr.address_list) {
		addr_entry = list_entry(p, struct sctp_sockaddr_entry, list);
		if (sctp_cmp_addr_exact(&addr_entry->a, &bindx_addr2))
			DUMP_CORE;
	}

	printk("\n\n%s case 2 passed\n\n\n", argv[0]);

	/* Case 3
	 * We only have 2 addresses left.  Delete one of them and modify
	 * the ASCONF chunk to contain a wildcard address.  This should
	 * result in removal of all addresses except source.
	 */
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr3, addr_len,
		       SCTP_BINDX_REM_ADDR)) {
		DUMP_CORE;
	}

	network = get_Internet(TEST_NETWORK_ETH0);
	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;

	delip_hdr = (sctp_addiphdr_t *)packet->data;
	delip_param = (sctp_addip_param_t *)&delip_hdr->params[addr_param_len];

	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF != chunk->type || 
	    SCTP_PARAM_DEL_IP != delip_param->param_hdr.type)
		DUMP_CORE;
    
	/* modify the the address parameter to be wildcard */
	addr_param = (union sctp_addr_param *)(delip_param + 1);
#if TEST_V6
	memset(&addr_param->v6.addr, 0, sizeof(struct in6_addr));
#else
	memset(&addr_param->v4.addr, 0, sizeof(struct in_addr));
#endif
	/* Recompute checksum */
	sh = &packet->sh;
	sum = sctp_start_cksum((uint8_t *)sh, skb->len -
#if TEST_V6
		sizeof(struct ipv6hdr));
#else
		sizeof(struct iphdr));
#endif
	sum = sctp_end_cksum(sum);
	sh->checksum = sum;

	if (0 > test_run_network_once(TEST_NETWORK_ETH0))
		DUMP_CORE;

	network = get_Internet(TEST_NETWORK_ETH0);
	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;
	delip_hdr = (sctp_addiphdr_t *)packet->data;
	/* Verify the chunk type and parameter type */	
	if (SCTP_CID_ASCONF_ACK != chunk->type)
		DUMP_CORE;

	/* Check whether the address we deleted is still in use in
	 * peer's association.
	 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	bindx_addr3.v4.sin_port = ntohs(bindx_addr3.v4.sin_port);
	list_for_each(p, &asoc2->peer.transport_addr_list) {
		tp = list_entry(p, struct sctp_transport, transports);
		if (sctp_cmp_addr_exact(&tp->ipaddr, &bindx_addr3))
			DUMP_CORE;
	}

	if (test_run_network()) {
		DUMP_CORE;
	}

	/* Check whether the address we deleted is still in use in
	 * local association.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	list_for_each(p, &asoc1->base.bind_addr.address_list) {
		addr_entry = list_entry(p, struct sctp_sockaddr_entry, list);
		if (sctp_cmp_addr_exact(&addr_entry->a, &bindx_addr3))
			DUMP_CORE;
	}

	printk("\n\n%s case 3 passed\n\n\n", argv[0]);

	/* Case 4:
	 * Remove last address bind in association.	*/
	if (test_bindx(sk1, (struct sockaddr *)&addr1, addr_len,
		       SCTP_BINDX_REM_ADDR) != -EBUSY) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s case 4 passed\n\n\n", argv[0]);	

	return 0;	
}
