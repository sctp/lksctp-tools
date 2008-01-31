/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
 *
 * This file is part of the SCTP Linux kernel implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it
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
 * Please send any bug reports or fixes you make to one of the following
 * email addresses:
 *
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *  
 */

/* ft_frame_lostpacket.c
 * This is the Functional Test for the ability to handle a lost
 * packet during data transmission for the SCTP kernel reference
 * implementation state machine. 
 *
 * It walks the state machine through a modified complete data
 * exchange where we set up a link, send one data message
 * successfully, send another data message and have it get lost, time
 * out and retransmit the second message, and then tear down the link
 * cleanly.
 *
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 *
 * We use functions which approximate the user level API defined in
 * draft-stewart-sctpsocket-sigtran-01.txt.  */

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
        struct sock *sk1;
        struct sock *sk2;
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;
	struct sctp_transport *tran1;
        struct sctp_endpoint *ep2;
        struct sctp_association *asoc2;
	struct sctp_transport *tran2;

        struct sockaddr_in loop;
        struct msghdr outmsg;
        struct sctp_cmsghdr cmsghdr;
        struct iovec iov;
        struct iovec out_iov;
        struct msghdr inmessage;
	uint8_t *big_buffer;
        uint8_t *messages[] = {
		"associate",
		"strike1",
		"strike2",
		"strike3",
		"strikeout",
		"steal",
		"home run",
		"The test frame has a bug!", /* We should NEVER see this... */
        };
        int error = 0;
        int bytes_sent;
        int addr_len; 

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

        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop;
        outmsg.msg_namelen = sizeof(loop);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Send the first message.  This will create the association.  */
        outmsg.msg_iov->iov_base = messages[0];
        outmsg.msg_iov->iov_len = strlen(messages[0]) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(messages[0])+1);
        if (bytes_sent != strlen(messages[0]) + 1) { DUMP_CORE; }
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Extract all those nice internal structures we like to muck
         * with...
         */
        ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);
	tran1 = (struct sctp_transport *)asoc1->peer.transport_addr_list.next;
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	tran2 = (struct sctp_transport *)asoc1->peer.transport_addr_list.next;

        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */

        /* NOW initialize inmessage with enough space for DATA... */
        memset(&inmessage, 0, sizeof(inmessage));
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
	if (error < 0) {DUMP_CORE;}

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


        /* Get the first message which was sent.  */
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
			   strlen(messages[0]) + 1,
			   messages[0],
			   SCTP_SNDRCV);

        /* Send another message. (And lose it! Mwahahaha!)  */
        outmsg.msg_iov->iov_base = messages[1];
        outmsg.msg_iov->iov_len = strlen(messages[1]) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(messages[1])+1);
        if (bytes_sent != strlen(messages[1]) + 1) { DUMP_CORE; }

	test_kill_next_packet(SCTP_CID_DATA);
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Confirm that we did NOT get the message.  */

        /* Restore the altered values for the message receive attempt.  */
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);

	if (-EAGAIN != error) {
                DUMP_CORE;
        }

	/* Make the timeout happen.  */
        jiffies += asoc1->peer.primary_path->rto + 1;
	test_run_timeout(); /* Internet fast-forward */

	/* Rerun the network.  */

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Confirm that we get the retransmitted message.  */

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
			   strlen(messages[1]) + 1,
			   messages[1],
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
	
        /* Send another packet because we need a sack.  Yeah, this
         * will be fixed one day...
         */
        outmsg.msg_iov->iov_base = messages[2];
        outmsg.msg_iov->iov_len = strlen(messages[2]) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(messages[2])+1);
        if (bytes_sent != strlen(messages[2]) + 1) { DUMP_CORE; }
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }
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
			   strlen(messages[2]) + 1,
			   messages[2],
			   SCTP_SNDRCV);

	/* 2nd round: network down for 2 consecutive RTO.  See if
	 * DATA goes through in the 3rd retran attempt.
	 */

	/* Lose the first transmission */
	test_frame_send_message(sk1, (struct sockaddr *)&loop, messages[3]);
	test_kill_next_packet(SCTP_CID_DATA);
	if ( test_run_network() ) {
		DUMP_CORE;
	} 

	/* We should NOT see the packet. */
	test_frame_get_message(sk2, NULL);

	/* Force the RTO and see the retransmission.  */
	jiffies += asoc1->peer.primary_path->rto + 1;
	test_run_timeout();
	test_for_chunk(SCTP_CID_DATA, 0);

	/* Lose the retransmission.  */
	test_kill_next_packet(SCTP_CID_DATA);
	if ( test_run_network() ) {
		DUMP_CORE;
	} 

	/* We should NOT see the packet.  */
	test_frame_get_message(sk2, NULL);

	/* Force the RTO again and see that it goes through.  */
	jiffies += asoc1->peer.primary_path->rto + 1;
	if ( test_run_network() ) {
		DUMP_CORE;
	} 

	/* We should now see the packet. */
	test_frame_get_message(sk2, messages[3]);

	/* Force the SACK.  */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	if ( test_run_network() ) {
		DUMP_CORE;
	} 
	/* Test for delayed SHUTDOWN_ACK: let sk2 close the link first,
	 * in the meantime, sk1 still has a backlogged packet to send.
	 * Not until sk1 clears its sendQ, can it generate SHUTDOWN-ACK.
	 */

	test_frame_send_message(sk1, (struct sockaddr *)&loop, messages[4]) ;

	if ( test_run_network() ) {
		DUMP_CORE;
	}

	test_frame_get_message(sk2, messages[4]) ;

	sctp_close(sk2, 0);

	/* Force out SACK.  */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
	if ( test_run_network() ) {
		DUMP_CORE
	}
	
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);
	sctp_close(sk1, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(0);
} /* main() */
