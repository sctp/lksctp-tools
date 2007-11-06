/* SCTP kernel reference Implementation 
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
 *
 * This file is part of the SCTP Linux kernel reference implementation
 * 
 * This is a functional test for the SCTP kernel reference
 * implementation state machine.
 * 
 * Set up a link, send an abort with the originator's verification
 * tag, see that the receiving association is down.  Set up a second
 * link, send an abort with the receiver's verification tag, see that
 * the receiving association is down. 
 *
 * Adding a second test to test the ABORT response to a zero length
 * payload DATA chunk. 
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ^^^^^^^^^^^^^^^^^^^^^^^^
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
 * Ardelle Fan <ardelle.fan@intel.com>
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

void send_abort(struct sctp_association *, uint32_t vtag, int tbit);

int
main(int argc, char *argv[])
{
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
        struct msghdr outmsg;
        struct iovec iov;
        struct iovec out_iov;
        struct msghdr inmessage;
        uint8_t *messages[] = {
                "associate",
                "kerpow!",
                "reassociate",
                "The test frame has a bug!", /* We should NEVER see this... */
        };
        int error, bytes_sent;
        
        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);

        loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.sin_port = htons(SCTP_TESTPORT_2);

        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != test_listen(sk2, 1)) {
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
        outmsg.msg_iov->iov_base = messages[0];
        outmsg.msg_iov->iov_len = strlen(messages[0]) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(messages[0])+1);
        if (bytes_sent != strlen(messages[0]) + 1) { DUMP_CORE; }
        
        error = test_run_network();
        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */
        if (error != 0) { DUMP_CORE; }

        /* We should have seen a SACK in there... */


	/* Grub around to find our association.  */
	ep1 = sctp_sk(sk1)->ep;
        ep2 = sctp_sk(sk2)->ep;
	asoc1= test_ep_first_asoc(ep1);

	/* Send the first ABORT!!!!  Mwah-ha-ha!!!. */
        /* It has the originator's V-Tag without T bit set. */
	send_abort(asoc1, asoc1->c.my_vtag, 0);

	/* Simulate the Internet.  */
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Test to see if the abort happened.  */
	if (list_empty(&ep2->asocs)) { DUMP_CORE; }

	/* Send the first ABORT!!!!  Mwah-ha-ha!!!. */
        /* It has the originator's V-Tag. */
	send_abort(asoc1, asoc1->c.my_vtag, 1);

	/* Simulate the Internet.  */
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Test to see if the abort happened.  */
	if (!list_empty(&ep2->asocs)) { DUMP_CORE; }
	
	/* Send another message.  This should cause an ABORT.  */
        outmsg.msg_iov->iov_base = messages[1];
        outmsg.msg_iov->iov_len = strlen(messages[1]) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(messages[1])+1);
        if (bytes_sent != strlen(messages[1]) + 1) { DUMP_CORE; }

	/* Simulate the Internet.  */
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Test to see if we died.  */
	if (list_empty(&ep1->asocs)) { DUMP_CORE; }
	
        /* Now we get to start over again, almost from scratch... */

	/* Send another message.  This should reassociate.  */
        outmsg.msg_iov->iov_base = messages[2];
        outmsg.msg_iov->iov_len = strlen(messages[2]) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(messages[2])+1);
        if (bytes_sent != strlen(messages[2]) + 1) { DUMP_CORE; }

	/* Simulate the Internet.  */
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Grub around to find our association.  */
	asoc1 = test_ep_first_asoc(ep1);

	/* Send the second ABORT!!!!  Mwah-ha-ha!!!. */
        /* It has the receiver's V-Tag. */
	send_abort(asoc1, asoc1->c.peer_vtag, 0);

	/* Simulate the Internet.  */
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* Test to see if the second abort sent happened.  */
        if (!list_empty(&ep2->asocs)) { DUMP_CORE; }
	
	
	
	/* If we get to this point, the test has passed.  The rest is
	 * just clean-up.
	 */

        /* Shut down the link.  Incidentally, this should cause
         * another ABORT...
         */
	sctp_close(sk1, /* timeout */ 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Get the shutdown complete notification. */
        /* Restore the altered values for the next call.  */
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */

/* Generate a ABORT packet on the given association.  */
void
send_abort(struct sctp_association *asoc, uint32_t vtag,int tbit)
{
	struct sctp_chunk *abort;  /* Build the abort here. */

	abort = sctp_make_chunk(asoc, SCTP_CID_ABORT, tbit & 0x1, 0);
	asoc->peer.i.init_tag = vtag;
	sctp_outq_tail(&asoc->outqueue, abort);

} /* send_abort() */
