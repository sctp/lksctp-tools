/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
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

/* This is a testframe functional test to verify the udp-style connect()
 * support in blocking and non-blocking modes.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sock *svr_sk, *clt_sk1, *clt_sk2, *peeloff_sk;
	struct sctp_endpoint *svr_ep, *clt_ep1, *clt_ep2;
	struct sctp_association *svr_asoc[2], *clt_asoc1, *clt_asoc2;
	struct socket *peeloff_sock;
	int error, i;
	union sctp_addr svr_loop, clt_loop1, clt_loop2, clt_loop3;
	struct list_head *pos;
	int flags;

	/* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
	sctp_init();

	/* Initialize the server and client addresses. */ 
        svr_loop.v4.sin_family = AF_INET;
        svr_loop.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        svr_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
        clt_loop1.v4.sin_family = AF_INET;
        clt_loop1.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        clt_loop1.v4.sin_port = htons(SCTP_TESTPORT_2);
        clt_loop2.v4.sin_family = AF_INET;
        clt_loop2.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        clt_loop2.v4.sin_port = htons(SCTP_TESTPORT_2+1);
        clt_loop3.v4.sin_family = AF_INET;
        clt_loop3.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        clt_loop3.v4.sin_port = htons(SCTP_TESTPORT_2+2);

	/* Create the 3 sockets.  */
	svr_sk = sctp_socket(PF_INET, SOCK_SEQPACKET);
	clt_sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	clt_sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind these sockets to the test ports.  */
	error = test_bind(svr_sk, (struct sockaddr *)&svr_loop,
			  sizeof(svr_loop));
	if (error != 0) { DUMP_CORE; }
	error = test_bind(clt_sk1, (struct sockaddr *)&clt_loop1,
			  sizeof(clt_loop1));
	if (error != 0) { DUMP_CORE; }
	error = test_bind(clt_sk2, (struct sockaddr *)&clt_loop2,
			  sizeof(clt_loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark svr_sk as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(svr_sk, 1)) { DUMP_CORE; }

	/* Set clt_sk1 as non-blocking. */ 
	flags = clt_sk1->sk_socket->file->f_flags;
	clt_sk1->sk_socket->file->f_flags |= O_NONBLOCK;

	/* Do a non-blocking connect from clt_sk1 to svr_sk */      
	error = sctp_connect(clt_sk1, (struct sockaddr *)&svr_loop,
			     sizeof(svr_loop));
	/* Non-blocking connect should return immediately with EINPROGRESS. */
	if (error != -EINPROGRESS) { DUMP_CORE; }

	/* Doing a connect on a socket to create an association that is
	 * in the process of being established should return EALREADY.
	 */ 
	error = sctp_connect(clt_sk1, (struct sockaddr *)&svr_loop,
			     sizeof(svr_loop));
	if (error != -EALREADY) { DUMP_CORE; }

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the communication up message from clt_sk1.  */
        test_frame_get_event(clt_sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
        /* Get the communication up message from svr_sk.  */
        test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Doing a connect on a socket to create an association that is
	 * is already established should return EISCONN.
	 */
	error = sctp_connect(clt_sk1, (struct sockaddr *)&svr_loop,
			     sizeof(svr_loop));
	if (error != -EISCONN) { DUMP_CORE; }

	/* Do a blocking connect from clt_sk2 to svr_sk */      
	error = sctp_connect(clt_sk2, (struct sockaddr *)&svr_loop,
			     sizeof(svr_loop)); 
	/* Blocking connect should block until the association is established
	 * and return success.
	 */
	if (error != 0) { DUMP_CORE; }

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the communication up message from sk2.  */
        test_frame_get_event(clt_sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
        /* Get the communication up message from sk1.  */
        test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* We have 4 established associations - 2 off svr_sk and one each off
	 * clt_sk1 and clt_sk2.  Let's extract some useful details.
	 */
        svr_ep = sctp_sk(svr_sk)->ep;
	i = 0;	
	list_for_each(pos, &svr_ep->asocs) {
		svr_asoc[i++] = list_entry(pos, struct sctp_association, asocs);
	}
        clt_ep1 = sctp_sk(clt_sk1)->ep;
        clt_asoc1 = test_ep_first_asoc(clt_ep1);
        clt_ep2 = sctp_sk(clt_sk2)->ep;
        clt_asoc2 = test_ep_first_asoc(clt_ep2);

	error = sctp_do_peeloff(svr_asoc[0], &peeloff_sock);
	if (error < 0) {
		printf("\tpeeloff failed\n");
		DUMP_CORE;
	}
	peeloff_sk = peeloff_sock->sk;

	/* Doing a connect on a peeled off socket should fail. */
	error = sctp_connect(peeloff_sk, (struct sockaddr *)&clt_loop3,
			     sizeof(clt_loop3));
	if (error != -EISCONN) { DUMP_CORE; }

	/* Trying to create an association on a socket that matches an 
	 * existing peeled-off association should fail.
	 */
	error = sctp_connect(svr_sk, (struct sockaddr *)&clt_loop1,
			     sizeof(clt_loop1));
	if (error != -EADDRNOTAVAIL) { DUMP_CORE; }

        /* Shut down the link.  */
	sctp_close(svr_sk, 0);

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        sctp_close(clt_sk1, 0);
        sctp_close(clt_sk2, 0);
        sctp_close(peeloff_sk, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
