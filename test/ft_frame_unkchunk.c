/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2002 Intel Corp.
 * Copyright (c) 2002 Nokia, Inc.
 * Copyright (c) 2002 La Monte H.P. Yarroll
 * 
 * This file is part of the SCTP kernel Implementation
 * 
 * These functions frob the sctp nagle structure.
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
 *    La Monte H.P. Yarroll <piggy@acm.org>
 *    Daisy Chang <tcdc@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* 
 * This is a functional test for the SCTP kernel implementation.
 *
 * RFC 3.2.
 * Chunk Types are encoded such that the highest-order two bits specify
 * the action that must be taken if the processing endpoint does not
 * recognize the Chunk Type.
 *
 * 00 - Stop processing this SCTP packet and discard it, do not process
 *      any further chunks within it.
 *
 * 01 - Stop processing this SCTP packet and discard it, do not process
 *      any further chunks within it, and report the unrecognized
 *      chunk in an 'Unrecognized Chunk Type'.
 *
 * 10 - Skip this chunk and continue processing.
 *
 * 11 - Skip this chunk and continue processing, but report in an ERROR
 *      Chunk using the 'Unrecognized Chunk Type' cause of error.
 *
 * We test the SCTP unknown chunk type handling with the following 
 * scenarios :
 *
 * 1. Open sk1 and sk2.  Send a message from sk1 to sk2. Catch the COOKIE_ECHO
 * chunk and modify it to be a bad chunk type.  The highest order two bits of 
 * the chunk type will be 00. Since the association is not up yet, this 
 * packet would fall into the OOTB category on the receiving side.  As a result
 * of that, an ABORT is expected to be sent from sk2.
 *
 * 2. Repeat Case #1 except that the packet containing bad chunk types will 
 * be injected after the association is up.  The packet will have two bad 
 * chunks bundled together.  The highest order two bits of the chunk types 
 * will be 00 and 11.  The packet should be discarded without any response.
 *
 * 3. Repeat Case #2 except that the highest order two bits of the chunk
 * types will be 01 and 11.  The packet should be discarded after one ERROR 
 * is returned.
 *
 * 4. Repeat Case #2 except that the highest order two bits of the chunk
 * type will be 10 and 11.  The first chunk should be skipped and an ERROR
 * should be returned for the second chunk.
 *
 * 5. Repeat Case #2 except that the highest order two bits of the chunk
 * type will be 11 and 11.  There should be two ERROR returned for the 
 * two bad chunks.
 *
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h> 
#include <funtest.h>


int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
	char *messages = "Don't worry, be happy!";
	struct sk_buff *skb, *nskb2, *nskb3, *nskb4, *nskb5;
	struct bare_sctp_packet *packet;
	sctp_chunkhdr_t *hdr;
	struct sctphdr *sh;
	struct sctp_errhdr *errhdr;
	uint32_t val;


	/* Do all that random stuff needed to make a sensible
	 * universe.
	 */
	init_Internet();
	sctp_init();

	/* Disable PR-SCTP so that FWD-TSN parameter/chunk is not sent. */
	sctp_prsctp_enable = 0;

	/**** Case 1 ****/
 	/* Open sk1 and sk2.  Send a message from sk1 to sk2. Catch the 
	 * COOKIE_ECHO chunk and modify it to be a bad chunk type.  The 
	 * highest order two bits of the chunk type will be 00.  Since the 
	 * association is not up yet, this packet would fall into the OOTB 
	 * category on the receiving side.  As a result of that, an ABORT 
	 * is expected to be sent from sk2.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Start the INIT and INIT_ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	/* We expect a COOKIE ECHO bundled with DATA. */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Modify the chunk type of COOKIE ECHO to make an unknown
	 * chunk.
	 */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		hdr->type |= 0x30;	

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = htonl(val);
	} else {
		DUMP_CORE;
	}

	/* We expect an ABORT from the receiver.
	 */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	if (test_run_network()) {
		DUMP_CORE;
	}
	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s case 1 passed\n\n\n", argv[0]);

	/**** Case 2 ****/
 	/* Repeat Case #1 except that the packet containing bad chunk 
	 * types will be injected after the association is up.  The packet 
	 * will have two bad chunks bundled together.  The highest order 
	 * two bits of the chunk types will be 00 and 11.  The packet 
	 * should be discarded without any response.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 100);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 100);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 100);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Start the INIT and INIT_ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	/* We expect a COOKIE ECHO bundled with DATA. */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Hijack the bundled COOKIE ECHO packet and inject a bad chunk
	 * to the network.  
	 */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		/* Obtain copies of it. */
		nskb2 = skb_copy(skb, GFP_KERNEL);
		nskb3 = skb_copy(skb, GFP_KERNEL);
		nskb4 = skb_copy(skb, GFP_KERNEL);
		nskb5 = skb_copy(skb, GFP_KERNEL);
	} else {
		DUMP_CORE;
	}

	if (nskb2) {
		/* Hand made a bad chunk type in the copied packet. */
		packet = test_get_sctp(nskb2->data);
		hdr = &packet->ch;
		hdr->type |= 0x30;
		/* Screw up the next chunk as well. */
		hdr = (struct sctp_chunkhdr *)((__u8 *)hdr + ntohs(hdr->length));
		hdr->type |= SCTP_CID_ACTION_SKIP_ERR;

		/* Re-calculate the checksum. */
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh, 
				       nskb2->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = htonl(val);
		 
		/* Set the skb info. */
		nskb2->sk = nskb3->sk = nskb4->sk = nskb5->sk = skb->sk;
	} else {
		DUMP_CORE;
	}

	/* Let the association be established. */
	if (test_run_network()) {
		DUMP_CORE;
	}

	/*
	 * From sk2, we should be able to get the first message.
	 */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
	test_frame_get_message(sk2, messages); 

	/* Then, inject the hand-made packet to the network. */
	test_inject_packet(TEST_NETWORK0, nskb2);

	/* We expect nothing in return. */
	if (test_run_network_once(TEST_NETWORK0)) {
		DUMP_CORE;
	}
	if (!is_empty_network(TEST_NETWORK0)) {
		DUMP_CORE;
	}

	printk("\n\n%s case 2 passed\n\n\n", argv[0]);

	/**** Case 3 ****/
 	/* Repeat Case #2 except that the highest order two bits of the chunk
 	 * types will be 01 and 11.  The packet should be discarded after 
	 * one ERROR is returned.
	 */

	if (nskb3) {
		/* Hand made a bad chunk type in the copied packet. */
		packet = test_get_sctp(nskb3->data);
		hdr = &packet->ch;
		hdr->type |= SCTP_CID_ACTION_DISCARD_ERR;
		/* Screw up the next chunk as well. */
		hdr = (struct sctp_chunkhdr *)((__u8 *)hdr + ntohs(hdr->length));
		hdr->type |= SCTP_CID_ACTION_SKIP_ERR;

		/* Re-calculate the checksum. */
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh, 
				       nskb3->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = htonl(val);
		 
	} else {
		DUMP_CORE;
	}

	/* Then, inject the hand made packet to the network. */
	test_inject_packet(TEST_NETWORK0, nskb3);

	/* We expect an ERROR back with SCTP_ERROR_UNKNOWN_CHUNK for 
	 * the first chunk - bad COOKIE_ECHO. */
	if (test_step(SCTP_CID_ERROR, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t *)hdr + 
			sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_UNKNOWN_CHUNK) {
			DUMP_CORE;
		}
		/* Is it a bad COOKIE_ECHO? */
		if ((errhdr->variable[0] & ~SCTP_CID_ACTION_MASK) 
				!= SCTP_CID_COOKIE_ECHO) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	/* We expect nothing after this. */
	if (test_run_network_once(TEST_NETWORK0)) {
		DUMP_CORE;
	}
	if (!is_empty_network(TEST_NETWORK0)) {
		DUMP_CORE;
	}

	printk("\n\n%s case 3 passed\n\n\n", argv[0]);

	/**** Case 4 ****/
 	/* Repeat Case #2 except that the highest order two bits of the chunk
 	 * type will be 10 and 11.  The first chunk should be skipped and 
	 * an ERROR should be returned for the second chunk.
	 */
	if (nskb4) {
		/* Hand made a bad chunk type in the copied packet. */
		packet = test_get_sctp(nskb4->data);
		hdr = &packet->ch;
		hdr->type |= SCTP_CID_ACTION_SKIP;
		/* Screw up the next chunk as well. */
		hdr = (struct sctp_chunkhdr *)((__u8 *)hdr + ntohs(hdr->length));
		hdr->type |= SCTP_CID_ACTION_SKIP_ERR;

		/* Re-calculate the checksum. */
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh, 
				       nskb4->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = htonl(val);
	} else {
		DUMP_CORE;
	}

	/* Then, inject the hand made packet to the network. */
	test_inject_packet(TEST_NETWORK0, nskb4);

	/* We expect an ERROR back for the second chunk - the bad 
	 * DATA chunk. */
	if (test_step(SCTP_CID_ERROR, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t *)hdr + 
			sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_UNKNOWN_CHUNK) {
			DUMP_CORE;
		}
		/* Is it a bad DATA? */
		if ((errhdr->variable[0] & ~SCTP_CID_ACTION_MASK) 
				!= SCTP_CID_DATA) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	/* We expect nothing after this. */
	if (test_run_network_once(TEST_NETWORK0)) {
		DUMP_CORE;
	}
	if (!is_empty_network(TEST_NETWORK0)) {
		DUMP_CORE;
	}

	printk("\n\n%s case 4 passed\n\n\n", argv[0]);

	/**** Case 5 ****/
 	/* Repeat Case #2 except that the highest order two bits of the chunk
 	 * type will be 11 and 11.  There should be two ERROR returned for the 
 	 * two bad chunks.
	 */

	if (nskb5) {
		/* Hand made a bad chunk type in the copied packet. */
		packet = test_get_sctp(nskb5->data);
		hdr = &packet->ch;
		hdr->type |= SCTP_CID_ACTION_SKIP_ERR;
		/* Screw up the next chunk as well. */
		hdr = (struct sctp_chunkhdr *)((__u8 *)hdr + ntohs(hdr->length));
		hdr->type |= SCTP_CID_ACTION_SKIP_ERR;

		/* Re-calculate the checksum. */
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh, 
				       nskb5->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = htonl(val);
	} else {
		DUMP_CORE;
	}

	/* Then, inject the hand made packet to the network. */
	test_inject_packet(TEST_NETWORK0, nskb5);

	/* We expect an ERROR back with SCTP_ERROR_UNKNOWN_CHUNK for
	 * the first chunk - bad COOKIE_ECHO. 
	 */
	if (test_step(SCTP_CID_ERROR, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t *)hdr + 
			sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_UNKNOWN_CHUNK) {
			DUMP_CORE;
		}
		/* Is it a bad COOKIE_ECHO? */
		if ((errhdr->variable[0] & ~SCTP_CID_ACTION_MASK) 
				!= SCTP_CID_COOKIE_ECHO) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	/* And there should be another ERROR for the second bad chunk. */
	if (test_step(SCTP_CID_ERROR, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t *)hdr + 
			sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_UNKNOWN_CHUNK) {
			DUMP_CORE;
		}
		/* Is it a bad DATA? */
		if ((errhdr->variable[0] & ~SCTP_CID_ACTION_MASK) 
				!= SCTP_CID_DATA) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}


	printk("\n\n%s case 5 passed\n\n\n", argv[0]);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);


	exit(0);

} /* main() */
