/* SCTP kernel reference Implementation
 * (C) Copyright HP  2004
 * (C) Copyright IBM Corp 2000, 2003
 * Copyright (C) 1999 Cisco and Motorola
 * Copyright (c) Nokia, 2002
 *
 * This file is part of the SCTP kernel reference Implementation
 *
 * $Id: ft_frame_restart.c, 
 * 
 * This is Functional Test 4 for the SCTP kernel reference
 * implementation state machine.
 * 
 * Case Study 2: Peer Restart
 * Scenario: One endpoint restart before the other detects it.
 *  
 * Set up a link, send one message for sk1 to sk2 and two messages from sk2
 * to sk1, see the message appear. Close sk1, create a new sk1 using former
 * transport, see both the second message sk2 has sent and the new message 
 * sent fromsk1 appear. Let each side send one message and see them appear. 
 * Then test wrong cases.  
 * 1) Adding a new address to sk1, it will cause restart fail. 
 * Then go home. 
 * 2) Add a new address to sk1 after the origional source address.
 * The association will be accepted as a new one by peer. 
 * 3) The stale data form former sk1 should be discard.
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
 *    Vladislav Yasevich    <vladislav.yasevich@hp.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* ft_frame_restart.c
 * 
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int resend_expected = 0;

/* Generate a ABORT packet on the given association.  */
void
send_abort(struct sctp_association *asoc, uint32_t vtag)
{
	struct sctp_chunk *abort;  /* Build the abort here. */

	abort = sctp_make_chunk(asoc, SCTP_CID_ABORT, 0, 0);
	sctp_outq_tail(&asoc->outqueue, abort);

} /* send_abort() */

int
main(int argc, char *argv[])
{
        struct sock *sk1;
        struct sock *sk2;
	struct sock *peel_sk;
	struct socket *peeloff_socket;
        struct sockaddr_in addr1, addr2;
        uint8_t *message0 = "hello, world!\n";
	uint8_t *message1 = "first msg from sk2!\n";
	uint8_t *message2 = "second msg from sk2!\n";
	uint8_t *message3 = "third msg from sk2!\n";        
	uint8_t *peel_msg = "testing peeloff\n";
	int error;
	struct sockaddr_in bindx_addr;
	struct sctp_endpoint *ep2;
	struct sctp_association *asoc2;
	struct sctp_endpoint *peel_ep;
	struct sctp_association *peel_assoc;
	
        /* Do all that random stuff needed to make a sensible universe. */
        sctp_init();

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        addr1.sin_family = AF_INET;   
   	addr1.sin_addr.s_addr = SCTP_ADDR_ETH1;
	addr1.sin_port = htons(SCTP_TESTPORT_1);
	addr2.sin_family = AF_INET;
	addr2.sin_addr.s_addr = SCTP_ADDR_ETH2;
	addr2.sin_port = htons(SCTP_TESTPORT_2);

        /* Bind these sockets to the test ports.  */        
        error = test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
        if (error != 0) { DUMP_CORE; }

        bindx_addr.sin_family = AF_INET;
        bindx_addr.sin_addr.s_addr = SCTP_ADDR_ETH2;
        bindx_addr.sin_port = htons(SCTP_TESTPORT_1);
	
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr,
		       sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}          
       
        error = test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
        if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
	/* Send the first message.  This will create the association. */ 
	test_frame_send_message(sk1, (struct sockaddr *)&addr2, peel_msg);
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }
	
	printf("There is an association now.\n\n");

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Peel off association from sk2 */
	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	if (sctp_do_peeloff(asoc2, &peeloff_socket) < 0)
		DUMP_CORE;

	peel_sk = peeloff_socket->sk;

	/* get the message on the peeled-off association */
	test_frame_get_message(peel_sk, peel_msg);

	/* 
	 * Send ABORT to sk1 and force it to restart.  Do this
	 * from our peeled-off association.
	 */
	peel_ep = sctp_sk(peel_sk)->ep;
	peel_assoc = test_ep_first_asoc(peel_ep);
	send_abort(peel_assoc, asoc2->c.my_vtag);
   	error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* ge the comm_lost event and restart */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_LOST);
	test_frame_send_message(sk1, (struct sockaddr *)&addr2, peel_msg);
        
       	error = test_run_network();
        if (error != 0) { DUMP_CORE; }
	
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(peel_sk, SCTP_ASSOC_CHANGE, SCTP_RESTART);

	sctp_close(peel_sk, 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	printf("Peel-off restart OK. \n\n");
		
	/* re-establish the association. Testing non-peeloff restart*/
	test_frame_send_message(sk1, (struct sockaddr *)&addr2, message0);
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }
	
	printf("There is a new association now.\n\n");

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_message(sk2, message0);

	/* Now, let sk2 send data to sk1. 
	 * Mark sk1 as being able to accept new associations. 
	 */
	if (0 != sctp_seqpacket_listen(sk1, 1)) {
		DUMP_CORE;
	}
	
	/* Send message1 from Z to A.  */ 
	printf("Send message1 from Z to A.\n\n");
	test_frame_send_message(sk2, (struct sockaddr *)&addr1, message1);
        
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }
	
	test_frame_get_message(sk1, message1);

	printf("Send message2 from Z to A.\n\n");
	test_frame_send_message(sk2, (struct sockaddr *)&addr1, message2);

	error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	test_frame_get_message(sk1, message2);
	
	/* Force an ABORT to get sent to get the peer to bring down
	 * its association and then try to restart. 
	 */

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	send_abort(asoc2, asoc2->c.my_vtag);
   	error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_LOST);
	test_frame_send_message(sk1, (struct sockaddr *)&addr2, message0);
        
       	error = test_run_network();
        if (error != 0) { DUMP_CORE; }
	
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_RESTART);

	printf("Restart OK. \n\n");

        /* If we decide to implement resending restarted DATA,
	 * set 'resend_expected'. 
	 */

	if (resend_expected) {
		test_frame_get_message(sk1, message2);	
	}
	test_frame_get_message(sk2, message0);	

	/* Send a new message from sk2 to sk1. */	
	printf("Send message3 from Z to A.\n\n");
	test_frame_send_message(sk2, (struct sockaddr *)&addr1, message3);
        
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }	
       
	test_frame_get_message(sk1, message3);

	/* Send a new message from sk1 to sk2. */
	test_frame_send_message(sk1, (struct sockaddr *)&addr2, message0);
        	
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }	
	
	test_frame_get_message(sk2, message0);

	/* Now test the wrong cases when restart.*/ 
	printf("Test wrong cases.\n\n");

	/* Wrong case 1: Add a new address to sk1, which will cause restart
	 * fail. 
	 */
	/* Force an ABORT to get sent to get the peer to bring down
	 * its association and then try to restart. 
	 */

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);
	send_abort(asoc2, asoc2->c.my_vtag);
   	error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_LOST);

	/* Add a new address to sk1. */
        bindx_addr.sin_family = AF_INET;
        bindx_addr.sin_addr.s_addr = SCTP_ADDR_ETH0;
        bindx_addr.sin_port = htons(SCTP_TESTPORT_1);
	
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr,
		       sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	test_frame_send_message(sk1, (struct sockaddr *)&addr2, message0);
        
       	error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* We should see the restart fail here. */
	printf("Restart fail due to new address added.\n\n");        

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);

	/* Move the addresses around a bit and try it again. */

	bindx_addr.sin_family = AF_INET;
        bindx_addr.sin_addr.s_addr = SCTP_ADDR_ETH1;
        bindx_addr.sin_port = htons(SCTP_TESTPORT_1);
	
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr,
		       sizeof(struct sockaddr_in), SCTP_BINDX_REM_ADDR)) {
		DUMP_CORE;
	}  
	if (test_bindx(sk1, (struct sockaddr *)&bindx_addr,
		       sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}  

	test_frame_send_message(sk1, (struct sockaddr *)&addr2, message0);
        
       	error = test_run_network();
        if (error != 0) { DUMP_CORE; }

	/* We should see the restart fail here. */
	printf("Restart fail due to new address added.\n\n");        

	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC);

	/* If we get to this point, the test has passed.  The rest is
	 * just clean-up.
	 */
	sctp_close(sk1, 0);
        sctp_close(sk2, 0);   

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
