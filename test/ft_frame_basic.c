/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 *
 * This is the Functional Test for basic functionality of
 * the SCTP kernel reference implementation state machine.
 * 
 * It walks the state machine through a complete data exchange--we set
 * up a link, send three data messages, and then tear down the link
 * cleanly.  Compile with TEST_V6=1 to get the v6 version of this test.
 *
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Narasimha Budihal <narsi@refcode.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Hui Huang <hui.huang@nokia.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * Dajiang Zhang <dajiang.zhang@nokia.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/cache.h> /* For SMP_CACHE_BYTES */
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	int pf_class, af_family;
	struct sctp_endpoint *ep1;
	struct sctp_endpoint *ep2;
	uint8_t *big_buffer;
        int addr_len;
        int error, bytes_sent;
        union sctp_addr loop1;
        union sctp_addr loop2;
	union sctp_addr loop3;
        struct sctp_association *asoc1;
        struct sctp_association *asoc2;
        struct sctp_cmsghdr cmsghdr;
        struct iovec iov;
        struct iovec out_iov;
        struct msghdr inmessage;
        struct msghdr outmsg;
        struct sock *sk1;
        struct sock *sk2;
        uint8_t *message = "hello, world!\n";
        uint8_t *telephone = "Watson, come here!  I need you!\n";
        uint8_t *telephone_resp = "I already brought your coffee...\n";
#if TEST_V6
	struct in6_addr ipv6_loopback = SCTP_IN6ADDR_LOOPBACK_INIT;
#endif /* TEST_V6 */

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

	/* Set some basic values which depend on the address family. */
#if TEST_V6
	pf_class = PF_INET6;
	af_family = AF_INET6;
        loop1.v6.sin6_family = AF_INET6;
        loop1.v6.sin6_addr = ipv6_loopback;
        loop1.v6.sin6_port = htons(SCTP_TESTPORT_1);
        loop2.v6.sin6_family = AF_INET6;
        loop2.v6.sin6_addr = ipv6_loopback;
        loop2.v6.sin6_port = htons(SCTP_TESTPORT_2);
#else
	pf_class = PF_INET;
	af_family = AF_INET;
        loop1.v4.sin_family = AF_INET;
        loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.v4.sin_port = htons(SCTP_TESTPORT_1);
        loop2.v4.sin_family = AF_INET;
        loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.v4.sin_port = htons(SCTP_TESTPORT_2);
#endif /* TEST_V6 */

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
	sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

	/* Bind these sockets to the test ports.  */
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }

	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

        
	/* Build up a msghdr structure we can use for all sending.  */
	outmsg.msg_name = &loop2;
	outmsg.msg_namelen = sizeof(loop2);
	outmsg.msg_iov = &out_iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = NULL;
	outmsg.msg_controllen = 0;
	outmsg.msg_flags = 0;
        
	/* Send the first message.  This will create the association.  */
	outmsg.msg_iov->iov_base = message;
	outmsg.msg_iov->iov_len = strlen(message) + 1;
	bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
	if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }
        
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	/* Check that an association is created on ep1 */ 
	if (list_empty(&ep1->asocs)) {
		DUMP_CORE;
	}

	/* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* As we haven't done listen(), new associations should not be 
	 * accepted and we should have an ABORT sitting on the Internet. 
	 */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Process the ABORT chunk */
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* The ABORT chunk should have freed the association */
	if (!list_empty(&ep1->asocs)) {
		DUMP_CORE;
	}

        /* Cleanup.  */
	sctp_close(sk1, /* timeout */ 0);
	sctp_close(sk2, /* timeout */ 0);

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        /* Make sure that duplicate binding fails.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != -EINVAL) { DUMP_CORE; }
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Send the first message.  This will create the association.  */
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

        
	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Simulate Race condition that we submit a second message
	 * before initialization has completed. 
	 */
	outmsg.msg_iov->iov_base = telephone;
        outmsg.msg_iov->iov_len = strlen(telephone) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(telephone)+1);
        if (bytes_sent != strlen(telephone) + 1) { DUMP_CORE; }       

	if (test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}	
	
	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

#ifndef NO_COOKIE_ECHO_BUNDLE
	/* We expect DATA bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}
#endif /* !NO_COOKIE_ECHO_BUNDLE */
	

	/* We expect a COOKIE ACK.  */
	if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	
	/* Test that we don't send DATA while in the COOKIE-ECHOED
	 * state.   This is a regression test against a bug. 
	 */
	outmsg.msg_iov->iov_base = telephone_resp;
        outmsg.msg_iov->iov_len = strlen(telephone_resp) + 1;
	bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(telephone_resp)+1);
        if (bytes_sent != strlen(telephone_resp) + 1) { DUMP_CORE; }       
	
#ifdef JUNK
	if (test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}
#endif


#ifdef NO_COOKIE_ECHO_BUNDLE

	if (test_step(SCTP_CID_DATA, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	if (test_step(SCTP_CID_SACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
#else 
        /* We should see a SACK next.
	 * We ARE truly clever and bundle the SACK with the COOKIE ACK.
	 */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}       

#endif /* NO_COOKIE_ECHO_BUNDLE */

	/* Process the COOKIE ACK and the SACK.  */
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
        ep1 = sctp_sk(sk1)->ep;
        asoc1 = test_ep_first_asoc(ep1);
        ep2 = sctp_sk(sk2)->ep;
        asoc2 = test_ep_first_asoc(ep2);

        memset(&inmessage, 0, sizeof(inmessage));

        /* NOW initialize inmessage with enough space for DATA... */
	big_buffer = kmalloc(REALLY_BIG, GFP_KERNEL);
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        /* or a control message.  */
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

	

        /* Get the communication up message from sk2.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) {
                printk("recvmsg:  Something went wrong, error: %d\n",
		       error);
                DUMP_CORE;
        }

	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);

    
        /* Restore the altered values for the next call... */
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        /* Get the communication up message from sk1.  */
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
				 /* noblock */ 1, /* flags */ 0,
				 &addr_len);
        if (error < 0) {
                printk("recvmsg:  Something went wrong, error: %d\n",
		       error);
		DUMP_CORE;
        }
	

	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);
      
        /* Restore the altered values for the next call... */
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
	inmessage.msg_name = &loop3;
	inmessage.msg_namelen = sizeof(loop3);

        /* Get the first message which was sent.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
				 /* noblock */ 1, /* flags */ 0,
				 &addr_len);
        if (error < 0) { DUMP_CORE; }


        test_frame_check_message(&inmessage,
                                 /* orig */
                                 sizeof(struct sctp_cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
                                 sizeof(struct sctp_sndrcvinfo),
                                 strlen(message) + 1,
                                 message,
                                 SCTP_SNDRCV);

        /* Send another message, to cause a second SACK.  */
 
 

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Get those two messages.  */
        /* Restore the altered values for the next call.  */
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
				 /* noblock */ 1, /* flags */ 0,
				 &addr_len);
        if (error < 0) { DUMP_CORE; }
        test_frame_check_message(&inmessage,
                                 /* orig */
                                 sizeof(struct sctp_cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
                                 sizeof(struct sctp_sndrcvinfo),
                                 strlen(telephone) + 1,
                                 telephone,
                                 SCTP_SNDRCV);
        
        /* Restore the altered values for the next call.  */
        iov.iov_len = REALLY_BIG;
	iov.iov_base = big_buffer;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }
        test_frame_check_message(&inmessage,
                                 /* orig */
                                 sizeof(struct sctp_cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
                                 sizeof(struct sctp_sndrcvinfo),
                                 strlen(telephone_resp) + 1,
                                 telephone_resp,
                                 SCTP_SNDRCV);
        
        /* Check to see that nothing can be read from sk1. */
        iov.iov_len = REALLY_BIG;
	iov.iov_base = big_buffer;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error != -EAGAIN) { DUMP_CORE; }
	
        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	/* Force a final SACK.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Run a little bit longer in case there was a race with
	 * asoc1 resending DATA at the same time the SACK 
	 * got sent out.
	 */

        error = test_run_network();
        if (0 != error) { DUMP_CORE; }

        /* Get the shutdown complete notification. */
        /* Restore the altered values for the next call.  */
        iov.iov_len = REALLY_BIG;
	iov.iov_base = big_buffer;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }

	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_SHUTDOWN_COMP);

        
        sctp_close(sk2, /* timeout */ 0);
	test_run_network();

	/* NOW let's do the whole thing over again!  */

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        
        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Send the first message.  This will create the association.  */
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }
        

        memset(&inmessage, 0, sizeof(inmessage));

        /* NOW initialize inmessage with enough space for DATA... */
	big_buffer = kmalloc(REALLY_BIG, GFP_KERNEL);
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        /* or a control message.  */
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        /* Get the communication up message from sk2.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) {
                printk("recvmsg:  Something went wrong, error: %d\n", error);
                DUMP_CORE;
        }

	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);

        /* We have two established associations.  Let's extract some
	 * useful details.
	 */
        ep1 = sctp_sk(sk1)->ep;
        asoc1 = test_ep_first_asoc(ep1);
        ep2 = sctp_sk(sk2)->ep;
        asoc2 = test_ep_first_asoc(ep2);

        /* Restore the altered values for the next call... */
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        /* Get the communication up message from sk1.  */
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) {
                printk("recvmsg:  Something went wrong, error: %d\n", error);
                DUMP_CORE;
        }
	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);
        
        /* Restore the altered values for the next call... */
	iov.iov_base = big_buffer;
	iov.iov_len = REALLY_BIG;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        /* Get the first message which was sent.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);

        if (error < 0) { DUMP_CORE; }
        test_frame_check_message(&inmessage,
                                 /* orig */
                                 sizeof(struct sctp_cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
				 sizeof(struct sctp_sndrcvinfo),
                                 strlen(message) + 1,
                                 message,
                                 SCTP_SNDRCV);


        /* Send two more messages, to cause a second SACK.  */
        outmsg.msg_iov->iov_base = telephone;
        outmsg.msg_iov->iov_len = strlen(telephone) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(telephone)+1);
        if (bytes_sent != strlen(telephone) + 1) { DUMP_CORE; }

        outmsg.msg_iov->iov_base = telephone_resp;
        outmsg.msg_iov->iov_len = strlen(telephone_resp) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(telephone_resp)+1);
        if (bytes_sent != strlen(telephone_resp) + 1) { DUMP_CORE; }
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Get those two messages.  */
        /* Restore the altered values for the next call.  */
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }
        test_frame_check_message(&inmessage,
                                 /* orig */
                                 sizeof(struct sctp_cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
				 sizeof(struct sctp_sndrcvinfo),
                                 strlen(telephone) + 1,
                                 telephone,
                                 SCTP_SNDRCV);

        /* Restore the altered values for the next call.  */
        iov.iov_len = REALLY_BIG;
	iov.iov_base = big_buffer;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }
        test_frame_check_message(&inmessage,
                                 /* orig */
                                 sizeof(struct sctp_cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
                                 sizeof(struct sctp_sndrcvinfo),
                                 strlen(telephone_resp) + 1,
                                 telephone_resp,
                                 SCTP_SNDRCV);

        /* Check to see that nothing can be read from sk1. */
        iov.iov_len = REALLY_BIG;
	iov.iov_base = big_buffer;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error != -EAGAIN) { DUMP_CORE; }


	/* Send one more message. */
	outmsg.msg_iov->iov_base = telephone;
	outmsg.msg_iov->iov_len = strlen(telephone) + 1;
	bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(telephone)+1);
	if (bytes_sent != strlen(telephone) + 1) { DUMP_CORE; }

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }
	
	/* Test receiving exact message length. */        
	iov.iov_len = strlen(telephone) + 1;
	iov.iov_base = big_buffer;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	inmessage.msg_control = &cmsghdr;
	inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
	error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
			     /* noblock */ 1, /* flags */ 0,
			     &addr_len);
	if (error < 0) { DUMP_CORE; }
	test_frame_check_message(&inmessage,
				 /* orig */
				 sizeof(struct sctp_cmsghdr),
				 strlen(telephone) + 1,
				 big_buffer,
				 /* expected */
				 sizeof(struct sctp_sndrcvinfo),
				 strlen(telephone) + 1,
				 telephone,
				 SCTP_SNDRCV);		
	
        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

        /* Force a final SACK.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }

	/* Run a little bit longer in case there was a race with
	 * asoc1 resending DATA at the same time the SACK 
	 * got sent out.
	 */
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the shutdown complete notification. */
        /* Restore the altered values for the next call.  */
        iov.iov_len = REALLY_BIG;
	iov.iov_base = big_buffer;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }
	error = 0;

       
        test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_SHUTDOWN_COMP);
	
	  
        sctp_close(sk2, /* timeout */ 0);


	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */

