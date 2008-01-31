/* SCTP kernel Implementation
 * Copyright (c) 2002 Intel Corp.
 *
 * This file is part of the SCTP kernel Implementation
 *
 * This is a functional test to verify the SCTP stale cookie functionality.
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
 *
 * 	Ardelle Fan <ardelle.fan@intel.com>
 * 	Ryan Layer  <rmlayer@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
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
#include <errno.h> /* for sys_errlist[] */
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	struct sockaddr_in loop1, loop2;
	int error;
	uint8_t *message = "First message from A!\n";
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	sctp_chunkhdr_t *hdr;
	struct sctp_errhdr *errhdr;
	union sctp_params param;
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sctp_assocparams assocparams;

	/* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
	sctp_init();
	/* Set Valid.Cookie.Life to 2 seconds to accelerate */
	/* Create the two endpoints which will talk to each other.  */
	assocparams.sasoc_cookie_life = 2000;
	assocparams.sasoc_asocmaxrxt = 0;
	assocparams.sasoc_assoc_id = 0;

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	error = sctp_setsockopt(sk1, SOL_SCTP, SCTP_ASSOCINFO,
				(char *)&assocparams, 
				sizeof (struct sctp_assocparams));

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	error = sctp_setsockopt(sk2, SOL_SCTP, SCTP_ASSOCINFO,
				(char *)&assocparams, 
				sizeof (struct sctp_assocparams));

	loop1.sin_family = AF_INET;
	loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.sin_port = htons(SCTP_TESTPORT_1);
	loop2.sin_family = AF_INET;
	loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.sin_port = htons(SCTP_TESTPORT_2);

	/* Bind these sockets to the test ports.  */        
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }        
        
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk1 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);

	/* Walk through the startup sequence.  */
	/* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	printf("\n\n A->Z INIT! \n\n");

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	printf("\n\n Z->A INIT_ACK! \n\n");

	/* Produce a stale cookie by sleeping. Zz... */
	printf("\n\n Now sleep a while to produce a stale cookie. Zz...\n\n");
	sleep(2);

	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	printf("\n\n A->Z COOKIE_ECHO with stale cookie! \n\n");

	/* Z sends STALE COOKIE Error to A. */
	if (test_step(SCTP_CID_ERROR, TEST_NETWORK0) <=0 ) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		sctp_walk_errors(errhdr, hdr) {
			if (errhdr->cause == SCTP_ERROR_STALE_COOKIE)
				goto with_stale_cookie;
		}
		if (errhdr->cause != SCTP_ERROR_STALE_COOKIE)
			DUMP_CORE;
with_stale_cookie:
		;
	} else
		DUMP_CORE;

	printf("\n\n Z->A STALE_COOKIE Error! \n\n");

	/* Next we expect an INIT again. */
	if (test_step(SCTP_CID_INIT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* The INIT should have a preservative parameter */
	error = 1;
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		sctp_walk_params(param, (sctp_init_chunk_t *)hdr,
							init_hdr.params) {
			switch(param.p->type) {
			case SCTP_PARAM_COOKIE_PRESERVATIVE:
				error = 0;
				break;
			}
		}
	} else
		DUMP_CORE;

	if (error)
		DUMP_CORE;

	printf("\n\n A->Z INIT again with cookie preserv parameter! \n\n");

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	printf("\n\n Z->A INIT_ACK! \n\n");

	/* Produce a stale cookie by sleeping. Zz... */
	printf("\n\n Now sleep a while to check stale cookie. Zz...\n\n");
	sleep(1);
	
	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	printf("\n\n A->Z COOKIE_ECHO! \n\n");

	/* We expect a COOKIE ACK.  */
	if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	printf("\n\n Z->A COOKIE_ACK! \n\n");

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* Send the first message. */
	test_frame_send_message(sk2, (struct sockaddr *)&loop1, message);

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, message);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk1, message);

	/* Shut down the link.  */
	sctp_close(sk2, /* timeout */ 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }	
	
	/* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }	

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);
}
