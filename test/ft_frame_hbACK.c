/* SCTP Kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
 * 
 * This file is part of the SCTP kernel reference Implementation
 *
 * $Id: ft_frame_hbACK.c,v 1.14 2002/08/21 18:34:04 jgrimm Exp $
 * 
 * This is Functional Test 4 for the SCTP kernel reference
 * implementation state machine.
 * 
 * Set up a link, send a heartbeat, see a hbACK, go home.
 *These functions frob the sctp nagle structure.
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
 *    La Monte H.P. Yarroll <piggy@acm.org>
 *    Narasimha Budihal     <narsi@refcode.org>
 *    Karl Knutson          <karl@athena.chicago.il.us>
 *    Jon "Taz" Mischo      <taz@refcode.org>
 *    Sridhar Samudrala     <samudrala@us.ibm.com>
 *    Hui Huang             <hui.huang@nokia.com>
 *    Dajiang Zhang         <dajiang.zhang@nokia.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */
static char *cvs_id __attribute__ ((unused)) = "$Id: ft_frame_hbACK.c,v 1.14 2002/08/21 18:34:04 jgrimm Exp $";

/* ft_frame_hbACK.c
 * 
 * We use functions which approximate the user level API defined in
 * draft-stewart-sctpsocket-sigtran-01.txt.
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
#include <errno.h>
#include <funtest.h>

extern struct timeval ytime;

int
main(int argc, char *argv[])
{
	struct sctp_association *asoc; /* Thanks, Randy! */
        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in loop;
        struct msghdr outmsg;
        struct iovec out_iov;
        uint8_t *message = "hello, world!\n";
	struct timeval hbtime;	/* When did we send the last heartbeat? */
        int error, bytes_sent;
	struct sctp_transport * t;
	uint32_t rto;
        
        /* Do all that random stuff needed to make a sensible
         * universe.
         */
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
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }
     
	/* Get the RTO that will be used to calculate the hearbeat time when 
	 * the timer is started. The RTO can change once we send a message and
	 * receive a SACK.
	 */ 
	asoc = test_ep_first_asoc(sctp_sk(sk1)->ep);
        t = asoc->peer.active_path;
	rto = t->rto;

        error = test_run_network();
        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */
        if (error != 0) { DUMP_CORE; }

	/* Send the first heartbeat. */
	gettimeofday(&ytime, NULL);
        hbtime = ytime;

        /* Let Heartbeat timeout through modifying jiffies. */
        if ( !t->error_count) {
        	printf("Prepare to send first Hearbeat.\n");
	}
        jiffies += t->hb_interval + rto + 1;

        /* HB_ACK should reset errorCount to 0 and stateActive to 1. */
        t->error_count = 1;
        t->state = SCTP_INACTIVE;
 
        /* Simulate the Internet.  */                 	      	
        error = test_run_network();

        if ( !t->error_count && t->state != SCTP_INACTIVE) {
        	printf ("Hearbeat_ACK received. \n");
        } else { 
		DUMP_CORE; 
	}
	
	/* If we get to this point, the test has passed.  The rest is
	 * just clean-up.
	 */

        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);
        sctp_close(sk2, /* timeout */ 0);   

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
