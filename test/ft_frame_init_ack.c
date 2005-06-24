/* SCTP kernel reference Implementation 
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999-2001 Cisco, Motorola, and Intel
 *
 * This file is part of the SCTP kernel reference Implementation
 * 
 * This is the Functional Test for the ability to handle INIT_ACK
 * whose source IPv4 address doesn't match the destination IPv4 of a
 * previous INIT, yet the latter address is carried by INIT_ACK
 * in one of its address TLVs.
 *
 * It creates two endpoints, A and Z, each with 2 IP addresses.
 * Upon receiving INIT, endpoint Z returns an INIT_ACK to the source
 * address of the INIT, however, using a different source address.
 * The test stops after both endpoint receives COMM_UP event.
 *
 * The SCTP reference implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * the SCTP reference implementation  is distributed in the hope that it 
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
 * Please send any bug reports or fixes you make to one of the
 * following email addresses:
 *
 * Xingang Guo <xingang.guo@intel.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * Daisy Chang <daisyc@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

#define	SCTP_IP_A htonl(0x0a000001)
#define	SCTP_IP_B htonl(0x0a000002)

int
main(int argc, char *argv[])
{

	struct sock *sk1, *sk2;
	struct sockaddr_in big_b1, big_b2;
	struct sockaddr_in big_a1, big_a2;
	char *messages = "mars needs coffee";

	/* Do all that random stuff needed to make a sensible
	 * universe.
	 */
	sctp_init();

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind these sockets to the test ports.  */
	/* Make sure that we use the two networks which have 
	 * got the same scope, i.e., don't use loopback address
	 * with other addresses.
	 */

	big_a1.sin_family = AF_INET;
	big_a1.sin_addr.s_addr = SCTP_ADDR_ETH0;
	big_a1.sin_port = htons(SCTP_TESTPORT_1);

	big_b1.sin_family = AF_INET;
	big_b1.sin_addr.s_addr = SCTP_ADDR_ETH1;
	big_b1.sin_port = htons(SCTP_TESTPORT_1);


	/* big_a1 is the 'default' primary path of sk1 */
	if (test_bind(sk1, (struct sockaddr *)&big_a1, sizeof(big_a1))) {
		DUMP_CORE;
	}
	if (test_bindx(sk1, (struct sockaddr *)&big_b1,
		       sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	big_a2.sin_family = AF_INET;
	big_a2.sin_addr.s_addr = SCTP_ADDR_ETH1;
	big_a2.sin_port = htons(SCTP_TESTPORT_2);

	big_b2.sin_family = AF_INET;
	big_b2.sin_addr.s_addr = SCTP_ADDR_ETH0;
	big_b2.sin_port = htons(SCTP_TESTPORT_2);

	/* big_a2 is the 'default' primary path of sk2 */
	if (test_bind(sk2, (struct sockaddr *)&big_a2, sizeof(big_a2))) {
		DUMP_CORE;
	}
	if (test_bindx(sk2, (struct sockaddr *)&big_b2,
		       sizeof(struct sockaddr_in), SCTP_BINDX_ADD_ADDR)) {
		DUMP_CORE;
	}

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	/* Make sure that the INIT ACK does NOT come back from the
	 * address that the INIT was sent to.  In the test frame, we
	 * can control this by modifying sk->saddr.
	 *
	 * We send message to big_a2 with SCTP_ADDR_ETH0, so explicitly set
	 * our source address to SCTP_ADDR_ETH1.
	 */
	inet_sk(sk2)->saddr = SCTP_ADDR_ETH1;

	/* Send the first message.  This will create the association.  */
	test_frame_send_message(sk1, (struct sockaddr *)&big_a2, messages);
	

	if ( test_run_network() ) DUMP_CORE;

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, messages);

	return 0;
} /* main() */
