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
 * This test is focused on testing the unrecognized parameter error handling.
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
 *    Daisy Chang           <tcdc@us.ibm.com>
 *    Jon Grimm             <jgrimm@us.ibm.com>
 *    Ryan Layer            <rmlayer@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * This is a functional test for the SCTP kernel implementation.
 *
 * RFC 3.2.1 & the Implementers Guide 2.2.
 *
 * The Parameter Types are encoded such that the highest-order two bits
 * specify the action that must be taken if the processing endpoint does
 * not recognize the Parameter Type.
 *
 * 00 - Stop processing this SCTP chunk and discard it, do not process
 *	any further chunks within it.
 *
 * 01 - Stop processing this SCTP chunk and discard it, do not process
 *	any further chunks within it, and report the unrecognized
 *	parameter in an 'Unrecognized Parameter Type' (in either an
 *	ERROR or in the INIT ACK).
 *
 * 10 - Skip this parameter and continue processing.
 *
 * 11 - Skip this parameter and continue processing but report the
 *	unrecognized parameter in an 'Unrecognized Parameter Type' (in
 *	either an ERROR or in the INIT ACK).
 *
 * We test the SCTP unrecognized paramter type handling with the following
 * scenarios :
 *
 * 1. Open sk1 and sk2.  Send a message from sk1 to sk2.  Catch the INIT
 * chunk and modify it to be with two unknown parameters.  The highest order
 * two bits of the first parameter type would be 00, while these two bits
 * in the second parameter type being 11.  This chunk should be
 * discarded and an INIT_ACK would be generated with no errors.
 *
 * 2. Repeat Case #1 except that the highest order two bits of the first
 * unknown parameter type would be 01.  An INIT_ACK packet would be returned
 * to the sender with "Unrecognized Parameter Type" cause, for the first
 * parameter only.
 *
 * 3. Repeat Case #1 except that the highest order two bits of the first
 * unknown parameter type would be 10.  An INIT_ACK is expected to be returned
 * to the sender, and the "Unrecognized Parameter Type" will be included in
 * the chunk for the second bad paramter.
 *
 * 4. Repeat Case #1 except that the highest order two bits of the unknown
 * parameter types would be 11.  An INIT_ACK is expected to be returned
 * to the sender and the "Unrecognized Parameter Type" will be included in
 * the chunk for the two bad parameters.
 *
 * 5. Repeat Case #1 except that we are going to catch the INIT_ACK
 * chunk.  Modify it to be with one unknown parameter, and the highest order
 * two bits of the bad parameter type being 00.  This chunk should be
 * discarded and a COOKIE_ECHO will be generated with no cause.
 *
 * 6. Repeat Case #5 except that the highest order two bits of the
 * unknown parameter type is set to 01.  A COOKIE_ECHO packet will be
 * returned to the sender with either a cause "Unrecognized Parameter Type" 
 * for the bad parameter, or a separate ERROR packet is returned.
 *
 * 7. Repeat Case #5 except that the highest order two bits of the unknown
 * parameter type is set to 10.  A COOKIE_ECHO packet would be returned to
 * continue establishing the association.  No ERROR of "Unrecognized
 * Parameter Type" would be reported.
 *
 * 8. Repeat Case #5 except that the highest order two bits of the unknown
 * parameter type is set to 11.  A COOKIE_ECHO packet would be returned to
 * continue establishing the association. Also, either an ERROR packet would be
 * returned to the sender with "Unrecognized Parameter Type" for the bad
 * parameter, or the COOKIE_ECHO packet would contain the error.
 *
 * 9. Add testcase for HOSTNAME Parameter handling.  This should
 * generate an ABORT(Unresolvable Address).
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/checksum.h>
#include <errno.h>
#include <funtest.h>

int main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	union sctp_addr addr1, addr2, addr3;
	char *messages = "Don't worry, be happy!";
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	sctp_init_chunk_t *initchk;
	sctp_initack_chunk_t *initackchk;
	sctp_paramhdr_t *pahdr, *pahdr2;
	sctp_chunkhdr_t *hdr;
	uint8_t *p, *chkend;
	uint16_t type, type2;
	struct sctphdr *sh;
	struct sctp_errhdr *errhdr;
	uint32_t val;
	int found;

	/* Do all that random stuff needed to make a sensible
	 * universe.
	 */
	init_Internet();
	sctp_init();

	/* Disable PR-SCTP so that FWD-TSN parameter/chunk is not sent. */
	sctp_prsctp_enable = 0;

	/**** Case 1 ****/
 	/* Open sk1 and sk2.  Send a message from sk1 to sk2.  Catch the INIT
 	 * chunk and modify it to be with two unknown parameters.
	 * The highest order two bits of the first parameter type would be 00,
	 * while these two bits in the second parameter type being 11.
	 * An INTI_ACK should be sent and the rest of the INIT should be
	 * discarded.
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

	/* Catch the INIT chunk and modify it with unknown paramters.  */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initchk = (sctp_init_chunk_t *)&packet->ch;
		/* Is this an INIT chunk? */
		if (SCTP_CID_INIT != initchk->chunk_hdr.type) {
			DUMP_CORE;
		}
		p = &initchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type = htons(0x00f0);
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP_ERR;
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		printf("Test 1 Failed.\n");
		DUMP_CORE;
	}

	/* We expect an INIT_ACK with no causes. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		printf("Test 1 Failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		chkend = (uint8_t *)initackchk +
			WORD_ROUND(ntohs(initackchk->chunk_hdr.length));
		found = 0;
		for (p = &initackchk->init_hdr.params[0]; p < chkend;
				p += WORD_ROUND(ntohs(pahdr->length))) {
			pahdr = (sctp_paramhdr_t *)p;
			if (SCTP_PARAM_UNRECOGNIZED_PARAMETERS == pahdr->type) {
				found = 1;
				pahdr2 = (sctp_paramhdr_t *)(p +
					sizeof(sctp_paramhdr_t));
				/* Is it for the second bad parameter? */
				if ((type & ~SCTP_PARAM_ACTION_MASK) !=
						(pahdr2->type &
						~(SCTP_PARAM_ACTION_MASK))) {
					printf("Test 1 Failed.\n");
					DUMP_CORE;
				}
			}
		}
		if (found) {
			printf("Test 1 Failed.\n");
			DUMP_CORE;
		}
	} else {
		printf("Test 1 Failed.\n");
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (test_run_network()) {
		DUMP_CORE;
	}


	printk("\n\n%s case 1 passed\n\n\n", argv[0]);

	/**** Case 2 ****/
	/* Repeat Case #1 except that the highest order two bits of the first
 	 * unknown parameter type would be 01.  An INIT_ACK packet would be
	 * returned to the sender with "Unrecognized Parameter Type" as the
	 * cause, for the first parameter only.
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

	/* Catch the INIT chunk and modify it with unknown paramters.  */
	skb = test_peek_packet(TEST_NETWORK0);

	
	if (skb) {
		packet = test_get_sctp(skb->data);
		initchk = (sctp_init_chunk_t *)&packet->ch;
		/* Is this an INIT chunk? */
		if (SCTP_CID_INIT != initchk->chunk_hdr.type) {
			DUMP_CORE;
		}
		p = &initchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		type = pahdr->type;
		pahdr->type |= SCTP_PARAM_ACTION_DISCARD_ERR;
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP_ERR;

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}
	/* We expect an INIT_ACK with causes. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		printf("Test 2 Failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		chkend = (uint8_t *)initackchk +
			WORD_ROUND(ntohs(initackchk->chunk_hdr.length));
		found = 0;
		for (p = &initackchk->init_hdr.params[0]; p < chkend;
				p += WORD_ROUND(ntohs(pahdr->length))) {
			pahdr = (sctp_paramhdr_t *)p;
			if (SCTP_PARAM_UNRECOGNIZED_PARAMETERS == pahdr->type) {
				found = 1;
				pahdr2 = (sctp_paramhdr_t *)(p +
					sizeof(sctp_paramhdr_t));
				/* Is it for the second bad parameter? */
				if ((type & ~SCTP_PARAM_ACTION_MASK) !=
						(pahdr2->type &
						~(SCTP_PARAM_ACTION_MASK))) {
					printf("Test 2 Failed.\n");
					DUMP_CORE;
				}
			}
		}
		if (!found) {
			printf("Test 2 Failed.\n");
			DUMP_CORE;
		}
	} else {
		printf("Test 1 Failed.\n");
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (test_run_network()) 
		DUMP_CORE;

	printk("\n\n%s case 2 passed\n\n\n", argv[0]);


	/**** Case 3 ****/
	/* Repeat Case #1 except that the highest order two bits of the first
 	 * unknown parameter type would be 10.  An INIT_ACK is expected
	 * to be returned to the sender, and the "Unrecognized Parameter Type"
	 * will be included in the chunk for the second bad paramter.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 120);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 120);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 120);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Catch the INIT chunk and modify it with unknown paramters.  */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initchk = (sctp_init_chunk_t *)&packet->ch;
		/* Is this an INIT chunk? */
		if (SCTP_CID_INIT != initchk->chunk_hdr.type) {
			DUMP_CORE;
		}
		p = &initchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP;
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		type = pahdr->type;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP_ERR;

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}

	/* An INIT_ACK is expected with an unrecognized parameter. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		chkend = (uint8_t *)initackchk +
			WORD_ROUND(ntohs(initackchk->chunk_hdr.length));
		found = 0;
		for (p = &initackchk->init_hdr.params[0]; p < chkend;
				p += WORD_ROUND(ntohs(pahdr->length))) {
			pahdr = (sctp_paramhdr_t *)p;
			if (SCTP_PARAM_UNRECOGNIZED_PARAMETERS == pahdr->type) {
				found = 1;
				pahdr2 = (sctp_paramhdr_t *)(p +
					sizeof(sctp_paramhdr_t));
				/* Is it for the second bad parameter? */
				if ((type & ~SCTP_PARAM_ACTION_MASK) !=
						(pahdr2->type &
						~(SCTP_PARAM_ACTION_MASK))) {
					DUMP_CORE;
				}
			}
		}
		if (!found) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	if (test_run_network()) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (test_run_network()) {
		DUMP_CORE;
	}

	printk("\n\n%s case 3 passed\n\n\n", argv[0]);

	/**** Case 4 ****/
 	/* Repeat Case #1 except that the highest order two bits of the unknown
 	 * parameter types would be 11.  An INIT_ACK is expected to be returned
 	 * to the sender and the "Unrecognized Parameter Type" will be
	 * included in the chunk for the two bad parameters.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 130);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 130);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 130);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Catch the INIT chunk and modify it with unknown paramters.  */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initchk = (sctp_init_chunk_t *)&packet->ch;
		/* Is this an INIT chunk? */
		if (SCTP_CID_INIT != initchk->chunk_hdr.type) {
			DUMP_CORE;
		}
		p = &initchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		type = pahdr->type;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP_ERR;
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		type2 = pahdr->type;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP_ERR;

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}

	/* An INIT_ACK is expected with an unrecognized parameter. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		chkend = (uint8_t *)initackchk +
			WORD_ROUND(ntohs(initackchk->chunk_hdr.length));
		found = 0;
		for (p = &initackchk->init_hdr.params[0]; p < chkend;
				p += WORD_ROUND(ntohs(pahdr->length))) {
			pahdr = (sctp_paramhdr_t *)p;
			if (SCTP_PARAM_UNRECOGNIZED_PARAMETERS == pahdr->type) {

				pahdr2 = (sctp_paramhdr_t *)(p +
					sizeof(sctp_paramhdr_t));
				/* Is it for the first bad parameter? */
				if ((type & ~SCTP_PARAM_ACTION_MASK) !=
				    (pahdr2->type & 
				     ~(SCTP_PARAM_ACTION_MASK))) {
					if (1 == found) {
						DUMP_CORE;
					}
					found++;
				}
				/* Is it for the second bad parameter? */
				if ((type2 & ~SCTP_PARAM_ACTION_MASK) ==
				    (pahdr2->type &
				     ~(SCTP_PARAM_ACTION_MASK))) {
					if (2 == found) {
						DUMP_CORE;
					}
					found += 2;
				}
			}
		}
		if (3 != found) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	if (test_run_network()) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (test_run_network()) {
		DUMP_CORE;
	}
	printk("\n\n%s case 4 passed\n\n\n", argv[0]);

	/**** Case 5 ****/
 	/* Repeat Case #1 except that we are going to catch the INIT_ACK
	 * chunk.  Modify it to be with one unknown parameter, and the
	 * highest order two bits of the bad parameter type being 00.
	 * This chunk should be discarded and an ABORT would be generated
	 * with no cause.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = 0;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 140);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = 0;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 140);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 140);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Catch the INIT_ACK chunk and modify the first parameter to be
	 * an unknown paramter.
	 */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		p = &initackchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type = htons(0x00f0);
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}

	if (test_for_chunk(SCTP_CID_ERROR, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if(test_run_network())
		DUMP_CORE;

	printk("\n\n%s case 5 passed\n\n\n", argv[0]);

	/**** Case 6 ****/
 	/* Repeat Case #5 except that the highest order two bits of the
 	 * unknown parameter type is set to 01.  An ABORT packet would be
	 * returned to the sender with cause "Unrecognized Parameter Type" for
	 * the bad parameter.  The chunk will be discarded so nothing else
	 * will be returned after the ABORT.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = 0;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 150);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = 0;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 150);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 150);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Catch the INIT_ACK chunk and modify the first parameter to be
	 * an unknown paramter.
	 */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		p = &initackchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type |= SCTP_PARAM_ACTION_DISCARD_ERR;

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}

	/* We expect a COOKIE_ECHO returned as normal. */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* ERROR should be generated. */
	if (!test_for_chunk(SCTP_CID_ERROR, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if(test_run_network())
		DUMP_CORE;

	printk("\n\n%s case 6 passed\n\n\n", argv[0]);

	/**** Case 7 ****/
 	/* Repeat Case #5 except that the highest order two bits of the
	 * unknown parameter type is set to 10.  A COOKIE_ECHO packet would
	 * be returned to continue establishing the association.
	 * No ERROR of "Unrecognized Parameter Type" would be reported.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = 0;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 160);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = 0;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 160);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 160);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Catch the INIT_ACK chunk and modify the first parameter to
	 * be an unknown paramter.
	 */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		p = &initackchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP;

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}

	/* We expect a COOKIE_ECHO returned as normal. */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* No ERROR should be generated. */
	if (test_for_chunk(SCTP_CID_ERROR, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (test_run_network()) {
		DUMP_CORE;
	}

	printk("\n\n%s case 7 passed\n\n\n", argv[0]);

	/**** Case 8 ****/
 	/* Repeat Case #5 except that the highest order two bits of the unknown
 	 * parameter type is set to 11.  An ERROR packet would be returned
	 * to the sender with "Unrecognized Parameter Type" for the bad
	 * parameter.  Also, a COOKIE_ECHO packet would be returned to
	 * continue establishing the association.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = 0;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 170);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = 0;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 170);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 170);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Catch the INIT_ACK chunk and modify the first parameter to
	 * be an unknown paramter.
	 */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		p = &initackchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->type |= SCTP_PARAM_ACTION_SKIP_ERR;

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}

	/* A COOKIE_ECHO should be returned. */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* We expect an ERROR as well. */
	if (!test_for_chunk(SCTP_CID_ERROR, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Verify the ERROR chunk.
	 *
	 * We now bundle the ERROR chunk as recommended by the 
	 * implementor's guide.
	 */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		hdr = (struct sctp_chunkhdr *)
			((char *)hdr + WORD_ROUND(ntohs(hdr->length)));
		errhdr = (struct sctp_errhdr *)((uint8_t *)hdr +
			sizeof(sctp_chunkhdr_t));
		if (SCTP_ERROR_UNKNOWN_PARAM != errhdr->cause) {
			DUMP_CORE;
		}
		/* Is it for the first bad parameter? */
		if (SCTP_PARAM_IPV4_ADDRESS !=
			((*((uint16_t *)(&errhdr->variable[0]))) &
			~SCTP_PARAM_ACTION_MASK)) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (test_run_network()) {
		DUMP_CORE;
	}

	printk("\n\n%s case 8 passed\n\n\n", argv[0]);

	/**** Case 9  ****/
	/* Repeat Case #2 except that the parameter in question is is the
	 * HOST_NAME_ADDRESS parameter.  We expect to be ABORTed with
	 * an "Unresolvable Address" cause.
	 */

	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk1 with loopback, port 1.  */
	addr1.v4.sin_family = AF_INET;
	addr1.v4.sin_addr.s_addr = 0;
	addr1.v4.sin_port = htons(SCTP_TESTPORT_1 + 200);

	if (test_bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1))) {
		DUMP_CORE;
	}

	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind sk2 with loopback, port 2.  */
	addr2.v4.sin_family = AF_INET;
	addr2.v4.sin_addr.s_addr = 0;
	addr2.v4.sin_port = htons(SCTP_TESTPORT_2 + 200);

	if (test_bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2))) {
		DUMP_CORE;
	}

	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2 + 200);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Catch the INIT chunk and modify it with unknown paramters.  */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initchk = (sctp_init_chunk_t *)&packet->ch;
		/* Is this an INIT chunk? */
		if (SCTP_CID_INIT != initchk->chunk_hdr.type) {
			DUMP_CORE;
		}
		p = &initchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;

		/* Abuse the first parm.
		 * Change the type to SCTP_PARAM_HOST_NAME_ADDRESS.
		 * Filling in a hostname in the variable part of the 
		 * needs more work. Simply treat whatever is present in the
		 * variable part as the hostname.
		 */
		pahdr->type = SCTP_PARAM_HOST_NAME_ADDRESS;

		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		DUMP_CORE;
	}
	/* We expect an ABORT with causes. */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		if(test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0)
			printf("INIT_ACK recieved.\n");

		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		/* Is there any causes after the chunk header? */
		if (ntohs(hdr->length) <= sizeof(sctp_chunkhdr_t)) {
			DUMP_CORE;
		}
		errhdr = (struct sctp_errhdr *)((uint8_t *)hdr +
			sizeof(sctp_chunkhdr_t));
		if (SCTP_ERROR_DNS_FAILED!= errhdr->cause) {
			DUMP_CORE;
		}

		pahdr2 = (sctp_paramhdr_t *)&errhdr->variable[0];
		/* Is it for the first bad parameter? */
		if (SCTP_PARAM_HOST_NAME_ADDRESS != pahdr2->type) {
			DUMP_CORE;
		}

		/* We expect nothing after this. */
		chkend = (uint8_t *)hdr + WORD_ROUND(ntohs(hdr->length));
		pahdr = (sctp_paramhdr_t *)&errhdr->variable[0];
		p = (uint8_t *)pahdr;
		if ((p += WORD_ROUND(ntohs(pahdr->length))) < chkend) {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

	/* We expect nothing after this. */
	if (test_run_network_once(TEST_NETWORK0)) {
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	printk("\n\n%s case 9 passed\n\n\n", argv[0]);

	exit(0);

} /* main() */
