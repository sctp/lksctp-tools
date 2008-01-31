/* SCTP Kernel Implementation
 * (C) HP Corp. 
 * 
 * This file is part of the SCTP kernel Implementation
 *
 * This is Functional Test for the SCTP kernel reference
 * implementation state machine.
 * 
 * Set up an association, kill the network, and send heartbeats untill
 * we time out.
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
 *    Vlad Yasevich         <vladislav.yasevich@hp.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* ft_frame_hb_rtx.c
 * 
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

int
main(int argc, char *argv[])
{
	struct sctp_association *asoc1;
	struct sctp_association *asoc2;
        struct sock *sk1;
        struct sock *sk2;
        struct sockaddr_in loop;
        struct msghdr outmsg;
        struct iovec out_iov;
        uint8_t *message = "hello, world!\n";
        int error, bytes_sent;
	struct sctp_transport *t;
	int	i;
        
        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

	sctp_max_retrans_association = 5;

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
     
	/* get the usefull structure pointers for the future */
	asoc1 = test_ep_first_asoc(sctp_sk(sk1)->ep);
        t = asoc1->peer.active_path;

        error = test_run_network();
        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */
        if (error != 0) { DUMP_CORE; }

	/* get rid the other hb timer so it doesn't get in the way */
	asoc2 = test_ep_first_asoc(sctp_sk(sk2)->ep);
	del_timer(&asoc2->peer.active_path->hb_timer);

	/* break the network so we'll get timeouts */
	test_break_network(TEST_NETWORK0);

        /* Let Heartbeat timeout through modifying jiffies. */
        if ( !t->error_count) {
        	printf("Prepare to send first Hearbeat.\n");
	}

	for (i = 0; i < asoc1->max_retrans; i++) {
		jiffies = t->hb_timer.expires + 1;
		test_run_timeout();

		/* We should have a HB on the Internet */
		if (!test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK0))
			DUMP_CORE;

		/* No ACK */
		if (test_step(SCTP_CID_HEARTBEAT_ACK, TEST_NETWORK0))
			DUMP_CORE;

	}
	jiffies = t->hb_timer.expires + 1;
	test_run_timeout();

	/* We should have a HB on the Internet */
	if (test_for_chunk(SCTP_CID_HEARTBEAT, TEST_NETWORK0))
		DUMP_CORE;

	/* If we are here, then the test passed */
	test_fix_network(TEST_NETWORK0);

        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);
        sctp_close(sk2, /* timeout */ 0);   

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
