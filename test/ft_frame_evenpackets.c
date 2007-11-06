/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
 * 
 * This file is part of the SCTP Linux kernel reference implementation
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *                 ************************
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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
 * Narasimha Budihal <narsi@refcode.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* ft_frame_evenpackets.c
 * This is the Functional Test for receiving (and sacking) an even
 * number of packets in the SCTP kernel reference implementation state machine.
 * 
 * It walks the state machine through a complete data exchange--we set
 * up a link, send three data messages, and then tear down the link
 * cleanly.
 *
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
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

int
main(int argc, char *argv[])
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;
        struct sctp_endpoint *ep2;
        struct sctp_association *asoc2;

        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in loop;
        struct msghdr outmsg;
        struct sctp_cmsghdr cmsghdr;
        struct iovec iov;
        struct iovec out_iov;
        struct msghdr inmessage;
	uint8_t *big_buffer;
        uint8_t *message = "hello, world!\n";
        uint8_t *telephone = "Watson, come here!  I need you!\n";
        uint8_t *telephone_resp = "I already brought your coffee...\n";
        int error, bytes_sent;
        int ihavenoclue;        /* I do not know what this arg is for.
                                 * It is called "addr_len" but is used
                                 * as a POINTER, not an actual int.
                                 *
                                 * It must be some kind of return value.
                                 */


        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        loop.sin_family = AF_INET;
        loop.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        
        /* Bind these sockets to the test ports.  */
        loop.sin_port = htons(SCTP_TESTPORT_1);
        error = test_bind(sk1, (struct sockaddr *)&loop, sizeof(loop));
        if (error != 0) { DUMP_CORE; }
        
        loop.sin_port = htons(SCTP_TESTPORT_2);
        error = test_bind(sk2, (struct sockaddr *)&loop, sizeof(loop));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

        /* Set up both msghdr structures.  */
        outmsg.msg_name = &loop;
        outmsg.msg_namelen = sizeof(loop);
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
        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */
        if (error != 0) { DUMP_CORE; }

        /* We should have seen a SACK in there... */
        ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1); 
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
        if (!sctp_outq_is_empty(&asoc1->outqueue)) {
                DUMP_CORE;
        }
        /*  Initialize inmessage. */
	big_buffer = kmalloc(REALLY_BIG, GFP_KERNEL);
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;

        memset(&inmessage, 0, sizeof(inmessage));

        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        /* Get the communication up message from sk2.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &ihavenoclue);
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

        /* Get the communication up message from sk1.  */
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &ihavenoclue);
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
                             &ihavenoclue);
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

        /* Send one more message, to require a SACK timeout.  */
        outmsg.msg_iov->iov_base = telephone;
        outmsg.msg_iov->iov_len = strlen(telephone) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(telephone)+1);
        if (bytes_sent != strlen(telephone) + 1) { DUMP_CORE; }
        
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
                             &ihavenoclue);
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

        /* We should not have seen a SACK yet. */
        if (sctp_outq_is_empty(&asoc1->outqueue)) {
                DUMP_CORE;
        }

        /* Advance time past the SACK timeout, then simulate timeouts
         * and the net.
         */
        jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	test_run_timeout(); /* Internet fast-forward */
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }
        
        /* Check that the SACK DID get processed.  */
        if (!sctp_outq_is_empty(&asoc1->outqueue)) {
                DUMP_CORE;
        }

        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

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
                             &ihavenoclue);
        if (error < 0) { DUMP_CORE; }

	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_SHUTDOWN_COMP);
	  
        sctp_close(sk2, /* timeout */ 0);

	/* NOW let's do the whole thing over again!  */

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        loop.sin_family = AF_INET;
        loop.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        
        /* Bind these sockets to the test ports.  */
        loop.sin_port = htons(SCTP_TESTPORT_1);
        error = test_bind(sk1, (struct sockaddr *)&loop, sizeof(loop));
        if (error != 0) { DUMP_CORE; }
        
        loop.sin_port = htons(SCTP_TESTPORT_2);
        error = test_bind(sk2, (struct sockaddr *)&loop, sizeof(loop));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop;
        outmsg.msg_namelen = sizeof(loop);
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
        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */
        if (error != 0) { DUMP_CORE; }

        /* We should have seen a SACK in there... */


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
                             &ihavenoclue);
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

        /* Get the communication up message from sk1.  */
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &ihavenoclue);
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
                             &ihavenoclue);
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
                             &ihavenoclue);
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
                             &ihavenoclue);
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
                             &ihavenoclue);
        if (error != -EAGAIN) { DUMP_CORE; }
	
        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

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
                             &ihavenoclue);
        if (error < 0) { DUMP_CORE; }
	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_SHUTDOWN_COMP);
	error = 0;
	  
        sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);
} /* main() */
