/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001-2003 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 * Copyright (c) 2001 La Monte H.P. Yarroll
 *
 * This is the Functional Test for testing SCTP_ADDR_OVER flag to override the
 * primary address to a peer.  Additionally, a test is added for
 * SCTP_PRIMARY_ADDR get/setsockopt.  
 *
 * Written or Modified by:
 *   Ardelle Fan <ardelle.fan@intel.com>
 *   Jon Grimm   <jgrimm@us.ibm.com>
 *   Sridhar Samudrala	<sri@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */
#include <net/ip.h>
#include <net/sctp/sctp.h>
#include <errno.h>
#include <funtest.h>

#define BINDX_ADDR_COUNT 1

int main(int argc, char *argv[])
{
	int pf_class;
        struct sock *svr_sk, *clt_sk;
	struct sctp_endpoint *svr_ep, *clt_ep;
        struct sctp_association *svr_asoc, *clt_asoc;
        union sctp_addr svr_loop, clt_loop, svr_eth0, svr_eth1, svr_any;
        union sctp_addr svr_loop_h, clt_loop_h, svr_eth0_h;
       	union sctp_addr svr_eth1_h, svr_any_h;
        int error, bytes_sent;
        struct iovec out_iov;
	char buf[CMSG_SPACE_SNDRCV] = {0};
        struct cmsghdr *outcmsg;
        struct msghdr outmsg;
        struct sk_buff *skb;
        uint8_t *message = "hello, world!\n";
        uint8_t *telephone = "Watson, come here!  I need you!\n";
	int optlen;
	struct sctp_setpeerprim ssp;
	struct sctp_sndrcvinfo *sinfo;
	int addr_len;
#if TEST_V6
	struct ipv6hdr *ip6h;
#else
	struct iphdr *iph;
#endif /* TEST_V6 */

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
        sctp_init();

	/* Set some basic values which depend on the address family. */
	/* svr_loop_h, clt_loop_h and svr_eth0_h are addresses with port in host
	 * byte order and are used for comparisions with the transport's
	 * ip address.
	 */ 
#if TEST_V6
	pf_class = PF_INET6;
        svr_loop.v6.sin6_family = AF_INET6;
        svr_loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        svr_loop.v6.sin6_port = htons(SCTP_TESTPORT_1);
        svr_loop_h.v6.sin6_family = AF_INET6;
        svr_loop_h.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        svr_loop_h.v6.sin6_port = SCTP_TESTPORT_1;

        clt_loop.v6.sin6_family = AF_INET6;
        clt_loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        clt_loop.v6.sin6_port = htons(SCTP_TESTPORT_2);
        clt_loop_h.v6.sin6_family = AF_INET6;
        clt_loop_h.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        clt_loop_h.v6.sin6_port = SCTP_TESTPORT_2;

        svr_eth0.v6.sin6_family = AF_INET6;
        svr_eth0.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH0;
        svr_eth0.v6.sin6_port = htons(SCTP_TESTPORT_1);
        svr_eth0_h.v6.sin6_family = AF_INET6;
        svr_eth0_h.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH0;
        svr_eth0_h.v6.sin6_port = SCTP_TESTPORT_1;

        svr_eth1.v6.sin6_family = AF_INET6;
        svr_eth1.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH1;
        svr_eth1.v6.sin6_port = htons(SCTP_TESTPORT_1);
        svr_eth1_h.v6.sin6_family = AF_INET6;
        svr_eth1_h.v6.sin6_addr = (struct in6_addr)SCTP_ADDR6_GLOBAL_ETH1;
        svr_eth1_h.v6.sin6_port = SCTP_TESTPORT_1;

        svr_any.v6.sin6_family = AF_INET6;
        svr_any.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_ANY_INIT;
        svr_any.v6.sin6_port = htons(SCTP_TESTPORT_1);
        svr_any_h.v6.sin6_family = AF_INET6;
        svr_any_h.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_ANY_INIT;
        svr_any_h.v6.sin6_port = SCTP_TESTPORT_1;
	addr_len = sizeof(struct sockaddr_in6);
#else
	pf_class = PF_INET;
        svr_loop.v4.sin_family = AF_INET;
        svr_loop.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        svr_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
        svr_loop_h.v4.sin_family = AF_INET;
        svr_loop_h.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        svr_loop_h.v4.sin_port = SCTP_TESTPORT_1;

	clt_loop.v4.sin_family = AF_INET;
        clt_loop.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        clt_loop.v4.sin_port = htons(SCTP_TESTPORT_2);
	clt_loop_h.v4.sin_family = AF_INET;
        clt_loop_h.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        clt_loop_h.v4.sin_port = SCTP_TESTPORT_2;

        svr_eth0.v4.sin_family = AF_INET;
        svr_eth0.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        svr_eth0.v4.sin_port = htons(SCTP_TESTPORT_1);
        svr_eth0_h.v4.sin_family = AF_INET;
        svr_eth0_h.v4.sin_addr.s_addr = SCTP_ADDR_ETH0;
        svr_eth0_h.v4.sin_port = SCTP_TESTPORT_1;

        svr_eth1.v4.sin_family = AF_INET;
        svr_eth1.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
        svr_eth1.v4.sin_port = htons(SCTP_TESTPORT_1);
        svr_eth1_h.v4.sin_family = AF_INET;
        svr_eth1_h.v4.sin_addr.s_addr = SCTP_ADDR_ETH1;
        svr_eth1_h.v4.sin_port = SCTP_TESTPORT_1;

        svr_any.v4.sin_family = AF_INET;
        svr_any.v4.sin_addr.s_addr = INADDR_ANY;
        svr_any.v4.sin_port = SCTP_TESTPORT_1;
        svr_any_h.v4.sin_family = AF_INET;
        svr_any_h.v4.sin_addr.s_addr = INADDR_ANY;
        svr_any_h.v4.sin_port = SCTP_TESTPORT_1;
	addr_len = sizeof(struct sockaddr_in);
#endif /* TEST_V6 */

        /* Create the two endpoints which will talk to each other.  */
        svr_sk = sctp_socket(pf_class, SOCK_SEQPACKET);
        clt_sk = sctp_socket(pf_class, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(clt_sk, (struct sockaddr *)&clt_loop,
		       		sizeof(svr_loop));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(svr_sk, (struct sockaddr *)&svr_eth0,
		       	sizeof(svr_eth0));
        if (error != 0) { DUMP_CORE; }

        /* Add one more address loopback to be bound to svr_sk.  */
        if (test_bindx(svr_sk, (struct sockaddr *)&svr_loop, addr_len,
		       SCTP_BINDX_ADD_ADDR)) {
                DUMP_CORE;
        }

	/* Mark svr_sk as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(svr_sk, 1)) {
		DUMP_CORE;
	}

        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &svr_loop;
        outmsg.msg_namelen = sizeof(svr_loop);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_flags = 0;

        outmsg.msg_control = buf;
        outmsg.msg_controllen = CMSG_SPACE_SNDRCV;
        outcmsg = CMSG_FIRSTHDR(&outmsg);
        outcmsg->cmsg_level = IPPROTO_SCTP;
        outcmsg->cmsg_type = SCTP_SNDRCV;
        outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

        sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg);
        memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));

	/* Send the first message.  This will create the association.  */
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, clt_sk, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the communication up message from svr_sk.  */
        test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from clt_sk.  */
        test_frame_get_event(clt_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent.  */
        test_frame_get_message(svr_sk, message);

	/* Make sure that heartbeats are sent and all the paths are
	 * confirmed.
	 */
	jiffies += (1.5 * msecs_to_jiffies(SCTP_RTO_INITIAL) + 1);
	if (test_run_network())
		DUMP_CORE;

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */

	svr_ep = sctp_sk(svr_sk)->ep;
	svr_asoc = test_ep_first_asoc(svr_ep);
        clt_ep = sctp_sk(clt_sk)->ep;
	clt_asoc = test_ep_first_asoc(clt_ep);

	/* Verify that the peer primary addr is set correctly. */
	if (!sctp_cmp_addr_exact(&clt_asoc->peer.primary_path->ipaddr,
			       		&svr_loop_h))
		DUMP_CORE;

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Build up another msghdr structure for sending with
	 * SCTP_ADDR_OVER flag.
	 */
        outmsg.msg_name = &svr_eth0;
        outmsg.msg_namelen = sizeof(svr_eth0);

        sinfo->sinfo_flags |= SCTP_ADDR_OVER;

	/* Send the second message.  This will change the primary path.  */
        outmsg.msg_iov->iov_base = telephone;
        outmsg.msg_iov->iov_len = strlen(telephone) + 1;
        bytes_sent = sctp_sendmsg(NULL, clt_sk, &outmsg, strlen(telephone)+1);
        if (bytes_sent != strlen(telephone) + 1) { DUMP_CORE; }

        /* We should have an DATA sitting on the Internet. */
        if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK_ETH0)) {
                DUMP_CORE;
        }

        skb = test_peek_packet(TEST_NETWORK_ETH0);
        if (!skb)
                DUMP_CORE;
#if TEST_V6
	ip6h = (struct ipv6hdr *)skb->data;
	if (ipv6_addr_cmp(&ip6h->daddr, &svr_eth0.v6.sin6_addr))
		DUMP_CORE;
#else
	iph = (struct iphdr *)skb->data;
	if (iph->daddr != svr_eth0.v4.sin_addr.s_addr)
		DUMP_CORE;
#endif /* TEST_V6 */

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the second message which was sent.  */
        test_frame_get_message(svr_sk, telephone);

	/* Verify that the peer primary address is still the same. */
	if (!sctp_cmp_addr_exact(&clt_asoc->peer.primary_path->ipaddr,
			       		&svr_loop_h))
		DUMP_CORE;

        if (!sctp_outq_is_empty(&svr_asoc->outqueue)) {
                DUMP_CORE;
        }


	/* Simple test to change the peer primary address for the
	 * entire association.
	 */
	optlen = sizeof(ssp);
	ssp.sspp_assoc_id = sctp_assoc2id(clt_asoc);
	error = sctp_getsockopt(clt_sk, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
				(void *)&ssp, &optlen);
	if (error)
		DUMP_CORE;

	/* Now change the primary address.  First try a bogus address. */
	optlen = sizeof(ssp);
	ssp.sspp_assoc_id = sctp_assoc2id(clt_asoc);
	memcpy(&ssp.sspp_addr, &svr_eth1, sizeof(svr_eth1));
	error = sctp_setsockopt(clt_sk, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
				(void *)&ssp, optlen);
	if (-EINVAL != error)
		DUMP_CORE;

	/* Try valid associd and INADDR_ANY address. Should fail. */
	optlen = sizeof(ssp);
	ssp.sspp_assoc_id = sctp_assoc2id(clt_asoc);
	memcpy(&ssp.sspp_addr, &svr_any, sizeof(svr_any));
	error = sctp_setsockopt(clt_sk, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
				(void *)&ssp, optlen);
	if (-EINVAL != error)
		DUMP_CORE;

	/* Verify that the peer primary address hasn't changed. */
	if (!sctp_cmp_addr_exact(&clt_asoc->peer.primary_path->ipaddr, &svr_loop_h))
		DUMP_CORE;

	/* Now try a valid address and a valid associd. */
	optlen = sizeof(ssp);
	ssp.sspp_assoc_id = sctp_assoc2id(clt_asoc);
	memcpy(&ssp.sspp_addr, &svr_eth0, sizeof(svr_eth0));
	error = sctp_setsockopt(clt_sk, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
				(void *)&ssp, optlen);
	if (error)
		DUMP_CORE;

	/* Make sure that the primary address is changed to svr_eth0. */
	if (!sctp_cmp_addr_exact(&clt_asoc->peer.primary_path->ipaddr,
			       		&svr_eth0_h))
		DUMP_CORE;

	/* Now try a valid address and a zero associd. */
	optlen = sizeof(ssp);
	ssp.sspp_assoc_id = 0; 
	memcpy(&ssp.sspp_addr, &svr_loop, sizeof(svr_loop));
	error = sctp_setsockopt(clt_sk, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
				(void *)&ssp, optlen);
	if (error)
		DUMP_CORE;

	/* Make sure that the primary address is changed back to clt_loop. */
	if (!sctp_cmp_addr_exact(&clt_asoc->peer.primary_path->ipaddr,
			       		&svr_loop_h))
		DUMP_CORE;

        /* Shut down the link.  */
	sctp_close(clt_sk, /* timeout */ 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        error = 0;
        sctp_close(svr_sk, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
