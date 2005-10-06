/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco And Motorola
 *
 * This is the Functional Test for testing the behavior when rolling over 
 * the tsn map.  Just beating on the thing to make sure we don't lose 
 * any messages.
 *
 * This file is part of the SCTP kernel reference Implementation
 * 
 * The SCTP reference implementation is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation; either
 * version 2, or (at your option) any later version.
 * 
 * the SCTP reference implementation  is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ^^^^^^^^^^^^^^^^^^^^^^^^
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 * 
 * Jon Grimm <jgrimm@us.ibm.com>
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Sridhar Samudrala <samudrala@us.ibm.com>
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
        struct sockaddr_in loop1;
        struct sockaddr_in loop2;
	int i;
        uint8_t *messages[] = {
                "associate",
                "st",
                "The test frame has a bug!", /* We should NEVER see this... */
        };
        int error = 0;
	int msglen;

	printk("Start %s test\n", argv[0]);
	

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);

        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }
        
        loop2.sin_family = AF_INET;
        loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.sin_port = htons(SCTP_TESTPORT_2);
        
        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        /* Send the first message.  This will create the association.  */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, messages[0]);
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* We should have seen a SACK in there... */
   

        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */
	ep1 = sctp_sk(sk1)->ep;
        asoc1 = test_ep_first_asoc(ep1);
        ep2 = sctp_sk(sk2)->ep;
        asoc2 = test_ep_first_asoc(ep2);

        /* Get the communication up message from sk2.  */
        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message from sk1.  */
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the first message which was sent.  */
        test_frame_get_message(sk2, messages[0]);
	
	msglen = strlen(messages[1]) + 1;

        /* Now the real testing begins... */

#if 1
        /* A quarter million lines of output is a lot.  We don't
	 * REALLY need to see it all.
	 */
	printk("This is going to take a LONG time...\n");
	freopenk("/dev/null", "w", 1);
#endif
	
	/* 
	 *   Test #1 
	 *      Roll the tsn map several times over.  Make sure we don't 
	 *   lose any messages.
	 */

	for (i = 0;i <= SCTP_TSN_MAP_SIZE * 4;i++) {

		/* Send a message.  */
		test_frame_send_message(sk1, (struct sockaddr *)&loop2, 
					messages[1]);
		error = test_run_network();

		if ( error != 0){
			fprintk(2,
				"Error %d: test #1 sending message #%x\n",
				error, i);
			DUMP_CORE;
		}

		/* Get the message which was sent.  */
		test_frame_get_message(sk2, messages[1]);

				
#if 0
		/* I like to watch.  */		
		fprintk(2, "rwnd = %x\n", atomic_read(&asoc2->rwnd));

#endif

	} /* while (looping a bunch of times) */


        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);
        
	/* Give peer the time to SACK.  */
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        jiffies += asoc2->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		fprintk(2, "\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(0);

} /* main() */