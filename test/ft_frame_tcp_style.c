/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2002, 2003
 * Copyright (c) 1999-2001 Motorola, Inc.
 *
 * This file is part of the SCTP kernel reference Implementation
 *
 * A testcase to regression test a bug we had where
 * new small data can sneak by data that is waiting in the
 * retransmit queue due to window limits.
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
 *    Sridhar Samudrala		<sri@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sctp/sctp.h>
#include <funtest.h>

#define MAX_CLIENTS	10

int
main(int argc, char *argv[])
{
	struct sock *listen_sk;
	struct sock *clt_sk[MAX_CLIENTS], *clt2_sk;
	struct sock *accept_sk[MAX_CLIENTS], *accept2_sk;
	struct sock *tmp_sk;
	struct sctp_endpoint *listen_ep;
	struct sctp_endpoint *clt_ep[MAX_CLIENTS];
	struct sctp_endpoint *accept_ep[MAX_CLIENTS];
	struct sctp_association *listen_asoc[MAX_CLIENTS];
	struct sctp_association *clt_asoc[MAX_CLIENTS]; 
	struct sctp_association *accept_asoc[MAX_CLIENTS]; 
	union sctp_addr svr_loop, svr2_loop, svr3_loop;
	union sctp_addr clt_loop[MAX_CLIENTS], clt2_loop;
	struct list_head *pos;
	void *msg_buf;
	int error, i;
	int pf_class;
        struct msghdr outmsg;
        struct iovec out_iov;
	struct sk_buff *skb;
	int addr_len;
#if TEST_V6
	struct ipv6hdr *ip6h;
#else
	struct iphdr *iph;
#endif /* TEST_V6 */

	/* Do all that random stuff needed to make a sensible universe. */
	sctp_init();

	/* Initialize the server and client addresses. */ 
#if TEST_V6
	pf_class = PF_INET6;
        svr_loop.v6.sin6_family = AF_INET6;
        svr_loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        svr_loop.v6.sin6_port = htons(SCTP_TESTPORT_1);
	svr2_loop.v6.sin6_family = AF_INET6;
	svr2_loop.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH0;
	svr2_loop.v6.sin6_port = htons(SCTP_TESTPORT_1);
	svr3_loop.v6.sin6_family = AF_INET6;
	svr3_loop.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH1;
	svr3_loop.v6.sin6_port = htons(SCTP_TESTPORT_1);
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	clt_loop[i].v6.sin6_family = AF_INET6;
        	clt_loop[i].v6.sin6_addr =
				(struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        	clt_loop[i].v6.sin6_port = htons(SCTP_TESTPORT_2 + i);
	}
        clt2_loop.v6.sin6_family = AF_INET6;
        clt2_loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        clt2_loop.v6.sin6_port = htons(SCTP_TESTPORT_2 + i);
	addr_len = sizeof(struct sockaddr_in6);
#else
	pf_class = PF_INET;
        svr_loop.v4.sin_family = AF_INET;
        svr_loop.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        svr_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
        svr2_loop.v4.sin_family = AF_INET;
        svr2_loop.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        svr2_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
        svr3_loop.v4.sin_family = AF_INET;
        svr3_loop.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
        svr3_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	clt_loop[i].v4.sin_family = AF_INET;
        	clt_loop[i].v4.sin_addr.s_addr = SCTP_ADDR_LO;
        	clt_loop[i].v4.sin_port = htons(SCTP_TESTPORT_2 + i);
	}
        clt2_loop.v4.sin_family = AF_INET;
        clt2_loop.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        clt2_loop.v4.sin_port = htons(SCTP_TESTPORT_2 + i);
	addr_len = sizeof(struct sockaddr_in);
#endif /* TEST_V6 */

	/* Create the listening server socket and the client sockets.  */
	listen_sk = sctp_socket(pf_class, SOCK_STREAM);
	for (i = 0; i < MAX_CLIENTS; i++) { 
		clt_sk[i] = sctp_socket(pf_class, SOCK_STREAM);
	}
	clt2_sk = sctp_socket(pf_class, SOCK_STREAM);

	/* Bind these sockets to the test ports.  */
	error = test_bind(listen_sk, (struct sockaddr *)&svr_loop,
			  sizeof(svr_loop));
	if (error != 0) { DUMP_CORE; }
	for (i = 0; i < MAX_CLIENTS; i++) { 
		error = test_bind(clt_sk[i], (struct sockaddr *)&clt_loop[i],
				  sizeof(clt_loop[i]));
		if (error != 0) { DUMP_CORE; }
	}
	error = test_bind(clt2_sk, (struct sockaddr *)&clt2_loop,
			  sizeof(clt2_loop));
	if (error != 0) { DUMP_CORE; }

	/* Try to do an accept on a non-listening socket. It should fail. */
	tmp_sk = sctp_accept(clt_sk[0], 0, &error); 
	if ((NULL != tmp_sk) && (-EINVAL != error)) { DUMP_CORE; }

	/* Mark listen_sk as being able to accept new associations. */
	if (0 != sctp_stream_listen(listen_sk, MAX_CLIENTS-1)) { DUMP_CORE; }

	/* Verify that the backlog values are initialized correctly. */
	if (MAX_CLIENTS-1 != listen_sk->sk_max_ack_backlog)
		DUMP_CORE;
	if (0 != listen_sk->sk_ack_backlog)
		DUMP_CORE;

	/* Try to do a connect from a listening socket. It should fail. */
	error = sctp_connect(listen_sk, (struct sockaddr *)&clt_loop[0],
			     sizeof(clt_loop[0])); 
	if (error != -EISCONN) { DUMP_CORE; }

	/* Do a blocking connect from all the client sockets to listen_sk */
	for (i = 0; i < MAX_CLIENTS; i++) { 
		error = sctp_connect(clt_sk[i], (struct sockaddr *)&svr_loop,
				     sizeof(svr_loop)); 
		if (error != 0) { DUMP_CORE; }
	}

	/* Verify that the acceptq backlog is increased to MAX_CLIENTS. */
	if (MAX_CLIENTS != listen_sk->sk_ack_backlog)
		DUMP_CORE;

	/* Verify that no more associations can be established after the
	 * acceptq backlog has reached the max value.
	 */ 
	error = sctp_connect(clt2_sk, (struct sockaddr *)&svr_loop,
			     sizeof(svr_loop)); 
	if (error != -ECONNREFUSED) { DUMP_CORE; }

        listen_ep = sctp_sk(listen_sk)->ep;
	i = 0;
	list_for_each(pos, &listen_ep->asocs) {
        	listen_asoc[i++] = list_entry(pos, struct sctp_association,
					      asocs);
	}
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	clt_ep[i] = sctp_sk(clt_sk[i])->ep;
        	clt_asoc[i] = test_ep_first_asoc(clt_ep[i]);
	}

	error = 0;
	/* Extract all the associations on the listening socket as new
	 * sockets.
	 */ 
	for (i = 0; i < MAX_CLIENTS; i++) { 
		accept_sk[i] = sctp_accept(listen_sk, 0, &error);
		if (!accept_sk)
			DUMP_CORE;

        	accept_ep[i] = sctp_sk(accept_sk[i])->ep;
        	accept_asoc[i] = test_ep_first_asoc(accept_ep[i]);
	}

	/* Verify that the acceptq backlog is reset to 0. */ 
	if (0 != listen_sk->sk_ack_backlog)
		DUMP_CORE;

	/* After the calls to accept, the associations on the listen
	 * socket should have migrated to the accept sockets.
	 */
	for (i = 0; i < MAX_CLIENTS; i++) { 
		if (accept_asoc[i] != listen_asoc[i])
			DUMP_CORE;
	}
		
	/* Try to do an accept on a established socket. It should fail. */
	tmp_sk = sctp_accept(accept_sk[0], 0, &error); 
	if ((NULL != tmp_sk) && (-EINVAL != error)) { DUMP_CORE; }
	tmp_sk = sctp_accept(clt_sk[0], 0, &error); 
	if ((NULL != tmp_sk) && (-EINVAL != error)) { DUMP_CORE; }

	msg_buf = test_build_msg(100);
	/* Send a message from the client socket to the server. */
	for (i = 0; i < MAX_CLIENTS; i++) { 
		test_frame_send_message(clt_sk[i], (struct sockaddr *)&svr_loop,
					msg_buf);
		if (0 != test_run_network()) { DUMP_CORE; }

		/* We should get the message on the newly accepted socket. */
		test_frame_get_message(accept_sk[i], msg_buf);
	}	

	/* Send a message from the accepted socket to the client. */
	for (i = 0; i < MAX_CLIENTS; i++) { 
		test_frame_send_message(accept_sk[i],
					(struct sockaddr *)&clt_loop[i],
					msg_buf);
		if (0 != test_run_network()) { DUMP_CORE; }

		/* Read the message from the client socket. */
		test_frame_get_message(clt_sk[i], msg_buf);
	}

        /* Shut down the link.  */
	for (i = 0; i < MAX_CLIENTS; i++) { 
		sctp_close(clt_sk[i], 0);
	}

	if (0 != test_run_network()) { DUMP_CORE; }

	for (i = 0; i < MAX_CLIENTS; i++) { 
        	sctp_close(accept_sk[i], 0);
	}

	if (0 != test_run_network()) { DUMP_CORE; }

	/* Testcase to verify accept of a CLOSED association. */
	/* Do a connect, send and close to create a CLOSED association on
	 * the listening socket.
	 */
	error = sctp_connect(clt2_sk, (struct sockaddr *)&svr_loop,
				     sizeof(svr_loop)); 
	if (error != 0) { DUMP_CORE; }

	/* Send a message from the client socket to the server. */
	test_frame_send_message(clt2_sk, (struct sockaddr *)&svr_loop,
					msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

        sctp_close(clt2_sk, 0);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Do an accept to get a socket with the CLOSED association. */ 
	accept2_sk = sctp_accept(listen_sk, 0, &error);
	if (!accept2_sk)
		DUMP_CORE;

	test_frame_get_message(accept2_sk, msg_buf);

        sctp_close(accept2_sk, 0);
	test_run_network();

	/* Verify that auto-connect can be done on a TCP-style socket using
	 * sendto/sendmsg.
	 */
	clt2_sk = sctp_socket(pf_class, SOCK_STREAM);
	error = test_bind(clt2_sk, (struct sockaddr *)&clt2_loop,
			  sizeof(clt2_loop));
	if (error != 0) { DUMP_CORE; }

	/* Bind a second address to the listening socket. */
	if (test_bindx(listen_sk, (struct sockaddr *)&svr2_loop, addr_len,
		       SCTP_BINDX_ADD_ADDR))
		DUMP_CORE;

	/* Do a sendmsg() without a connect() */
	test_frame_send_message(clt2_sk, (struct sockaddr *)&svr_loop,
					msg_buf);
	if (0 != test_run_network()) { DUMP_CORE; }

	/* Make sure that heartbeats are sent and all the paths are
	 * confirmed.
	 */
	jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

	accept2_sk = sctp_accept(listen_sk, 0, &error);
	if (!accept2_sk)
		DUMP_CORE;

	test_frame_get_message(accept2_sk, msg_buf);

	/* Send a message to the primary address(svr_loop) */ 
        outmsg.msg_name = &svr_loop;
        outmsg.msg_namelen = sizeof(svr_loop);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_flags = 0;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_iov->iov_base = msg_buf;
        outmsg.msg_iov->iov_len = strlen(msg_buf) + 1;
	error = sctp_sendmsg(NULL, clt2_sk, &outmsg, strlen(msg_buf)+1);
        if (error != strlen(msg_buf) + 1) { DUMP_CORE; }

        if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
                DUMP_CORE;
        }

	/* Verify that the dest. addr in the skb is the primary addr. */
        skb = test_peek_packet(TEST_NETWORK0);
        if (!skb)
                DUMP_CORE;
#if TEST_V6
	ip6h = (struct ipv6hdr *)skb->data;
	if (ipv6_addr_cmp(&ip6h->daddr, &svr_loop.v6.sin6_addr))
		DUMP_CORE;
#else
	iph = (struct iphdr *)skb->data;
	if (iph->daddr != SCTP_ADDR_LO)
		DUMP_CORE;
#endif /* TEST_V6 */

	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message(accept2_sk, msg_buf);

	/* Send a message to the alternate address(svr2_loop) */ 
        outmsg.msg_name = &svr2_loop;
        outmsg.msg_namelen = sizeof(svr2_loop);
	error = sctp_sendmsg(NULL, clt2_sk, &outmsg, strlen(msg_buf)+1);
        if (error != strlen(msg_buf) + 1) { DUMP_CORE; }

        if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK_ETH0)) {
                DUMP_CORE;
        }

	/* Verify that the dest. addr in the skb is the alternate addr. */
        skb = test_peek_packet(TEST_NETWORK_ETH0);
        if (!skb)
                DUMP_CORE;
#if TEST_V6
	ip6h = (struct ipv6hdr *)skb->data;
	if (ipv6_addr_cmp(&ip6h->daddr, &svr2_loop.v6.sin6_addr))
		DUMP_CORE;
#else
	iph = (struct iphdr *)skb->data;
	if (iph->daddr != SCTP_ADDR_ETH0)
		DUMP_CORE;
#endif /* TEST_V6 */

	if (0 != test_run_network()) { DUMP_CORE; }

	test_frame_get_message(accept2_sk, msg_buf);

	/* Try to send a message to an address not belonging to the
	 * association. It should faile.
	 */ 
        outmsg.msg_name = &svr3_loop;
        outmsg.msg_namelen = sizeof(svr3_loop);
	error = sctp_sendmsg(NULL, clt2_sk, &outmsg, strlen(msg_buf)+1);
	if ((-1 != error) && (-EADDRNOTAVAIL != error)) { DUMP_CORE; }

	error = 0;

	sctp_close(clt2_sk, 0);
	sctp_close(accept2_sk, 0);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* Verify SO_LINGER socket option. l_onoff = 0. */
	clt2_sk = sctp_socket(pf_class, SOCK_STREAM);
	error = test_bind(clt2_sk, (struct sockaddr *)&clt2_loop,
			  sizeof(clt2_loop));
	if (error != 0) { DUMP_CORE; }

	/* Clear linger flag and initialize linger time to zero. This should
	 * initate the normal shutdown process by sending a SHUTDOWN on close.
	 */  
	__clear_bit(SOCK_LINGER, &clt2_sk->sk_flags);
	clt2_sk->sk_lingertime = 0;

	error = sctp_connect(clt2_sk, (struct sockaddr *)&svr_loop,
				     sizeof(svr_loop)); 
	if (error != 0) { DUMP_CORE; }

	accept2_sk = sctp_accept(listen_sk, 0, &error);
	if (!accept2_sk)
		DUMP_CORE;

	sctp_close(clt2_sk, 0);

	/* We should have a SHUTDOWN sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK0))
		DUMP_CORE;

	sctp_close(accept2_sk, 0);

	if (0 != test_run_network()) { DUMP_CORE; }

	/* Verify SO_LINGER socket option. l_onoff = 1. */
	clt2_sk = sctp_socket(pf_class, SOCK_STREAM);
	error = test_bind(clt2_sk, (struct sockaddr *)&clt2_loop,
			  sizeof(clt2_loop));
	if (error != 0) { DUMP_CORE; }

	/* Set linger flag and initialize linger time to zero. This should
	 * generate an ABORT on close.
	 */  
	__set_bit(SOCK_LINGER, &clt2_sk->sk_flags);
	clt2_sk->sk_lingertime = 0;

	error = sctp_connect(clt2_sk, (struct sockaddr *)&svr_loop,
				     sizeof(svr_loop)); 
	if (error != 0) { DUMP_CORE; }


	accept2_sk = sctp_accept(listen_sk, 0, &error);
	if (!accept2_sk)
		DUMP_CORE;

	sctp_close(clt2_sk, 100);

	/* We should have an ABORT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_ABORT, TEST_NETWORK0))
		DUMP_CORE;

	sctp_close(accept2_sk, 0);

        sctp_close(listen_sk, 0);

	if (0 != test_run_network()) { DUMP_CORE; }

	printk("\n\n%s passed\n\n\n", argv[0]);

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
