/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2002, 2003
 * Copyright (c) 1999-2001 Motorola, Inc.
 *
 * This file is part of the SCTP kernel Implementation
 *
 * A testcase to regression test a bug we had where
 * new small data can sneak by data that is waiting in the
 * retransmit queue due to window limits.
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
 *    Sridhar Samudrala		<sri@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* This is a testframe functional test to verify
 * 1. MSG_EOR flag is set correctly when a single message is read using multiple
 *    recvmsg() calls. 
 * 2. MSG_PEEK support. 
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sock *svr_sk, *clt_sk;
	union sctp_addr svr_loop, clt_loop;
	void *msg_buf;
	void *msgp;
	int error, i;
	

	/* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
	sctp_init();

	/* Initialize the server and client addresses. */ 
        svr_loop.v4.sin_family = AF_INET;
        svr_loop.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        svr_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
        clt_loop.v4.sin_family = AF_INET;
        clt_loop.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        clt_loop.v4.sin_port = htons(SCTP_TESTPORT_2);

	/* Create the 2 sockets.  */
	svr_sk = sctp_socket(PF_INET, SOCK_SEQPACKET);
	clt_sk = sctp_socket(PF_INET, SOCK_SEQPACKET);
	svr_sk->sk_rcvbuf = 65536;

	/* Bind these sockets to the test ports.  */
	error = test_bind(svr_sk, (struct sockaddr *)&svr_loop,
			  sizeof(svr_loop));
	if (error != 0) { DUMP_CORE; }
	error = test_bind(clt_sk, (struct sockaddr *)&clt_loop,
			  sizeof(clt_loop));
	if (error != 0) { DUMP_CORE; }

	/* Mark svr_sk as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(svr_sk, 1)) { DUMP_CORE; }

	msg_buf = test_build_msg(30000);
	/* Send a big message.  This will create the association.  */
	test_frame_send_message(clt_sk, (struct sockaddr *)&svr_loop, msg_buf);

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the communication up message from clt_sk.  */
        test_frame_get_event(clt_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
        /* Get the communication up message from svr_sk.  */
        test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Read the big 30000 byte message using multiple recvmsg() calls in
	 * a loop with 2000 bytes per read.
	 */ 
	for (i = 0; i <= 14; i++) {
		msgp = msg_buf + i*2000;
        	test_frame_get_message2(svr_sk, msgp, 2000, MSG_PEEK,
					(i == 14)?MSG_EOR:0);
        	test_frame_get_message2(svr_sk, msgp, 2000, 0,
					(i == 14)?MSG_EOR:0);
	}

        sctp_close(clt_sk, 0);
        sctp_close(svr_sk, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
