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
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * This is a Functional Test to verify  basic functionality of
 * the SCTP T4-RTO support.
 * 
 * - Bind 1 address after association is created, delete the ASCONF packet
 *   Then see whether the T4 timer support functionality is available. And
 *   when error count above error threshold of transport, check whether
 *   the transport will be inactived.
 * - When error count of association above error threshold of association,
 *   see wheter the association will aborted.
 */

#include <net/sctp/sm.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock			*sk1, *sk2;
	struct sctp_endpoint		*ep1;
	struct sctp_association		*asoc1;
	struct sctp_transport		*tp1;
	union sctp_addr 		addr1, addr2;
	union sctp_addr			bindx_addr1;
	
	int	i;
	int	rto;
	char	*messages = "I love the world!";
	int	pf_class;
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

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	test_frame_send_message(sk1, (struct sockaddr *)&addr2, messages);

	if (test_run_network()) {
		DUMP_CORE;
	}

	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_message(sk2, messages);

	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr1, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	tp1 = asoc1->peer.active_path;

	if (tp1->state == SCTP_INACTIVE) {
		DUMP_CORE;
	}

	tp1->error_count = tp1->pathmaxrxt - 2;
	i = tp1->error_count;
	while (i <= tp1->pathmaxrxt) {
		rto = tp1->rto;
		
		printf("##*******************%d\n", asoc1->peer.active_path->error_count);
		test_kill_next_packet(SCTP_CID_ASCONF);
	
		if (test_run_network()) { 
			DUMP_CORE;
		}

		jiffies += rto + 1;
		test_run_timeout();
		i++;
	}

	if (tp1->state != SCTP_INACTIVE) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	if (test_run_network()) {
		DUMP_CORE;
	}
	sctp_close(sk2, 0);

	printk("\n\n%s Case 1 passed\n\n\n", argv[0]);	

	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	test_frame_send_message(sk1, (struct sockaddr *)&addr2, messages);

	if (test_run_network()) {
		DUMP_CORE;
	}

	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_message(sk2, messages);

	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr1, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	tp1 = asoc1->peer.active_path;

	asoc1->overall_error_count = asoc1->max_retrans - 2;
	i = asoc1->overall_error_count;
	while (i <= asoc1->max_retrans) {
		rto = tp1->rto;
		
		printf("##*******************%d\n", asoc1->overall_error_count);
		test_kill_next_packet(SCTP_CID_ASCONF);
	
		if (test_run_network()) { 
			DUMP_CORE;
		}

		jiffies += rto + 1;
		test_run_timeout();
		i++;
	}

	if (!sctp_state(asoc1, CLOSED)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s Case 2 passed\n\n\n", argv[0]);	

	return 0;	
}
