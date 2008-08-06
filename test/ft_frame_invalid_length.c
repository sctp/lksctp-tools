/* SCTP kernel Implementation
 * (C) Copyright Hewlett-Packard Corp. 
 *
 * This file is part of the SCTP kernel Implementation
 *
 * This test is focused on testing the invalid paramater and chunk lengths.
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
 *    Vladislav Yasevich            <vladislav.yasevich@hp.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/*
 * This is a functional test for the SCTP kernel implementation.
 *
 * RFC 3.2.1
 *
 * Chunk Parameter Length:  16 bits (unsigned integer)
 *
 *    The Parameter Length field contains the size of the parameter in
 *    bytes, including the Parameter Type, Parameter Length, and
 *    Parameter Value fields.  Thus, a parameter with a zero-length
 *    Parameter Value field would have a Length field of 4.  The
 *    Parameter Length does not include any padding bytes.
 *
 * Scenario:
 *
 *  Open sk1 and sk2 and Bind them.
 *  Set up sk2 as listening socket.
 *
 * TEST CASE 1: Set a Paramter Length in INIT chunk to 0.
 *
 * Send a message from sk1 to sk2.  Catch the INIT
 * chunk and modify one of the TLV encoded parameters to contain a length
 * of 0.   The expectation (as agreen on the mailing list) is to send
 * an ABORT chunk with a PROTOCOL VIOLATION error couase.  As additional
 * information, the 'variable' field of the sctp_errhdr_t contains a
 * NULL terminated error string directly followed by the parameter header
 * that caused the violation.
 *
 * TEST CASE 2: Set a Parameter Length in INIT-ACK chunk to 0.
 *
 * Same as TEST CASE 1, only the parameter in the INIT-ACK chunk is modified.
 *
 * TEST CASE 3: Set a Parameter Length in INIT chunk to 65535
 *
 * Same as TEST CASE 1, only the parameter length is set to be longer then
 * the length of the chunk.  The chunk length is not modified.  In this case,
 * I am not treating this as a partial chunk, but sending ABORT with a PROTOCOL
 * VIOLATION cause code.  The encoding is the same.
 *
 * TEST CASE 4: Set a chunk length to 0
 *
 * Tests the invalid chunk length.
 * 1. We open 2 sockets and try to send data.
 * 2. Intercept an INIT-ACK chunk and modify the chunk header length
 *    to have a value of 0.
 * 3. We expect an ABORT with PROTOCOL VIOLATION code back.  The encoding of
 *    the 'variable' field in the sctp_errhdr_t contains a NULL terminated
 *    error string directly followed by the chunk type (sent as 16 bit value)
 *    and chunk length.
 *
 * TEST CASE 5:
 * Same as TEST_CASE 4, except the COOKIE-ECHO (the first chunk in the bundle)
 * is modified with a chunk length of 1.  The DATA chunk should not be
 * processed and an ABORT should be sent.
 *
 * TEST CASE 6:
 * Based on TEST_CASE4.  Here we trap a SACK chunk modify it's chunk length
 * to have a value of 8.  This is too short to be a valid SACK, so we expect
 * an ABORT.
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

char *hostname = "www.bogus.net";

int main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	struct sctp_endpoint *ep1, *ep2;
	union sctp_addr addr1, addr2, addr3;
	char *messages = "Don't worry, be happy!";
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	sctp_init_chunk_t *initchk;
	sctp_initack_chunk_t *initackchk;
	sctp_paramhdr_t *pahdr;
	sctp_chunkhdr_t *hdr;
	uint8_t *p;
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

	/**** Case 1 ****/
 	/* Open sk1 and sk2.  Send a message from sk1 to sk2.  Catch the INIT
 	 * chunk and modify it to  have a TLV encoded parameter with a length
	 * set to 0.  This should result in an ABORT with a Protocol Violation
	 * error.
	 */
	printk("Case 1: A Parameter length in INIT is set to 0\n\n");

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
		/* look for paramter length of 1 */
		p = &initchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->length = 0;
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		printf("Case 1 Failed.\n");
		DUMP_CORE;
	}

	/* We expect an ABORT */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		printf("Case 1 Failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t*)hdr +
						sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_PROTO_VIOLATION) {
			printf("Case 1 Failed.\n");
			DUMP_CORE;
		}

		printf("Received this error: %s ", errhdr->variable);
		p = errhdr->variable + WORD_ROUND(strlen(errhdr->variable) + 1); 
		pahdr = (sctp_paramhdr_t *)p;
		printf("type = %d, length = %d\n",
			ntohs(pahdr->type), ntohs(pahdr->length));
	}

	/* process ABORT */
	if (test_run_network())  DUMP_CORE;

	/* Verify that both associations were destroyed */
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	if (!list_empty(&ep1->asocs)) { DUMP_CORE; }
	if (!list_empty(&ep2->asocs)) { DUMP_CORE; }

	printk("\n\n%s Case 1 passed\n\n\n", argv[0]);

	/**** Case 2 ****/
 	/*  Send a message from sk1 to sk2.  Catch the INIT-ACK
 	 * chunk and modify it to  have a TLV encoded parameter with a length
	 * set to 0.  This should result in an ABORT with a Protocol Violation
	 * error.
	 */
	printk("Case 2: A Parameter length in INIT-ACK is set to 0\n\n");

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0)
		DUMP_CORE;
		
	/* Catch the INIT-ACK chunk and modify it with unknown paramters.  */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		/* Is this an INIT-ACK chunk? */
		if (SCTP_CID_INIT_ACK != initackchk->chunk_hdr.type) {
			DUMP_CORE;
		}
		/* look for paramter length of 1 */
		p = &initackchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->length = 0;
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		printf("Case 2 Failed.\n");
		DUMP_CORE;
	}

	/* We expect an ABORT */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		printf("Case 2 Failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t*)hdr +
						sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_PROTO_VIOLATION) {
			printf("Case 2 Failed.\n");
			DUMP_CORE;
		}

		printf("Received this error: %s ", errhdr->variable);
		p = errhdr->variable + WORD_ROUND(strlen(errhdr->variable) + 1); 
		pahdr = (sctp_paramhdr_t *)p;
		printf("type = %d, length = %d\n",
			ntohs(pahdr->type), ntohs(pahdr->length));
	}

	if (test_run_network())  DUMP_CORE;

	/* Verify that both associations were destroyed */
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	if (!list_empty(&ep1->asocs)) { DUMP_CORE; }
	if (!list_empty(&ep2->asocs)) { DUMP_CORE; }

	printk("\n\n%s Case 2 passed\n\n\n", argv[0]);

	/**** Case 3 ****/
 	/* Send a message from sk1 to sk2.  Catch the INIT
 	 * chunk and modify it to  have a TLV encoded parameter with a length
	 * set to be longer then the packet.  This should result in an ABORT
	 * with a Protocol Violation error.
	 */
	printk("Case 3: A Parameter length in INIT is set to 65535\n\n");

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
		/* look for paramter length of 1 */
		p = &initchk->init_hdr.params[0];
		pahdr = (sctp_paramhdr_t *)p;
		pahdr->length = htons(65535);
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		printf("Case 3 Failed.\n");
		DUMP_CORE;
	}

	/* We expect an ABORT */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		printf("Case 3 Failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t*)hdr +
						sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_PROTO_VIOLATION) {
			printf("Case 3 Failed.\n");
			DUMP_CORE;
		}

		printf("Received this error: %s ", errhdr->variable);
		p = errhdr->variable + WORD_ROUND(strlen(errhdr->variable) + 1); 
		pahdr = (sctp_paramhdr_t *)p;
		printf("type = %d, length = %d\n",
			ntohs(pahdr->type), ntohs(pahdr->length));
	}

	if (test_run_network())  DUMP_CORE;

	/* Verify that both associations were destroyed */
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	if (!list_empty(&ep1->asocs)) { DUMP_CORE; }
	if (!list_empty(&ep2->asocs)) { DUMP_CORE; }

	printk("\n\n%s Case 3 passed\n\n\n", argv[0]);

	/*
	 * Case 4:  Here we intercept an INIT-ACK and modify it's legth
	 * to be 0.
	 */
	printk("Case 4: Chunk header length of INIT-ACK chunk is set to 0\n\n");

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		printf ("Case 4 failed\n");
		DUMP_CORE;
	}

	/* Catch the INIT-ACK chunk and modify it with unknown paramters.  */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		initackchk = (sctp_initack_chunk_t *)&packet->ch;
		/* Is this an INIT-ACK chunk? */
		if (SCTP_CID_INIT_ACK != initackchk->chunk_hdr.type) {
			DUMP_CORE;
		}
		/* modify chunk length */
		initackchk->chunk_hdr.length = htons(0);
		sh = &packet->sh;
		val = sctp_start_cksum((uint8_t *)sh,
				       skb->len - sizeof(struct iphdr));
		val = sctp_end_cksum(val);
		sh->checksum = val;
	} else {
		printf("Case 4 Failed.\n");
		DUMP_CORE;
	}

	/* We expect an ABORT */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		printf("Case 4 Failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t*)hdr +
						sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_PROTO_VIOLATION)
			DUMP_CORE;

		printf("Received this error: %s ", errhdr->variable);
		p = errhdr->variable + WORD_ROUND(strlen(errhdr->variable) + 1); 
		pahdr = (sctp_paramhdr_t *)p;
		printf("type = %d, length = %d\n",
			ntohs(pahdr->type), ntohs(pahdr->length));
	}

	if (test_run_network())  DUMP_CORE;

	/* Verify that both associations were destroyed */
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	if (!list_empty(&ep1->asocs)) { DUMP_CORE; }
	if (!list_empty(&ep2->asocs)) { DUMP_CORE; }

	printk("\n\n%s Case 4 passed\n\n\n", argv[0]);

	/*
	 * Case 5:  Here we intercept a DATA and modify it's legth
	 * to be 3.
	 */
	printk("Case 5: Chunk header length of DATA chunk is set to 1\n\n");

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2);

	/* This will cause us to re-associate */
	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		printf ("Case 5 failed\n");
		DUMP_CORE;
	}

	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		printf ("Case 5 failed\n");
		DUMP_CORE;
	}

	/* catch a DATA chunk and reset it's length to 3 */
	hdr = test_find_chunk(TEST_NETWORK0, SCTP_CID_DATA, NULL, NULL);
	if (hdr == NULL) {
		/* DATA was not bundled. Hosed for now? */
		printf ("Case 5 failed\n");
		DUMP_CORE;
	}

	/* modify chunk length */
	hdr->length = htons(1);

	/* update checksum. we know that we have an SKB */
	skb = test_peek_packet(TEST_NETWORK0);
	packet = test_get_sctp(skb->data);
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
				skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = val;


	/* run through COOKIE_ACK since this will be returned first */
	if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK0) <= 0) {
		printf ("Case 5 failed\n");
		DUMP_CORE;
	}

	/* The next chunk is bad data so we expect it to be handled
	 * and ABORT sent back bundled.
	 */
	if (test_for_chunk(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		printf("Case 5 Failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		while (hdr->type != SCTP_CID_ABORT)
		    hdr = (void *)hdr + WORD_ROUND(ntohs(hdr->length));

		errhdr = (struct sctp_errhdr *)((uint8_t*)hdr +
						sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_PROTO_VIOLATION)
			DUMP_CORE;

		printf("Received this error: %s ", errhdr->variable);
		p = errhdr->variable + WORD_ROUND(strlen(errhdr->variable) + 1); 
		pahdr = (sctp_paramhdr_t *)p;
		printf("type = %d, length = %d\n",
			ntohs(pahdr->type), ntohs(pahdr->length));
	}

	if (test_run_network())  DUMP_CORE;

	/* Verify that both associations were destroyed */
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	if (!list_empty(&ep1->asocs)) { DUMP_CORE; }
	if (!list_empty(&ep2->asocs)) { DUMP_CORE; }

	printk("\n\n%s Case 5 passed\n\n\n", argv[0]);

	/*
	 * Case 6:  Here we intercept a SACK and modify it's legth
	 * to be 3.
	 */
	printk("Case 6: Chunk header length of SACK chunk is set to 8\n\n");

	addr3.v4.sin_family = AF_INET;
	addr3.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	addr3.v4.sin_port = htons(SCTP_TESTPORT_2);

	test_frame_send_message(sk1, (struct sockaddr *)&addr3, messages);

	/* Find the packet with a SACK */
	while (!test_step(SCTP_CID_SACK, TEST_NETWORK0)) {
	}

	hdr = test_find_chunk(TEST_NETWORK0, SCTP_CID_SACK, NULL, NULL);
	if (hdr == NULL) {
		/* SACK was not found. Hosed for now? */
		printf ("Case 6 failed\n");
		DUMP_CORE;
	}

	/* modify chunk length */
	hdr->length = htons(8);

	/* update checksum. we know that we have an SKB */
	skb = test_peek_packet(TEST_NETWORK0);
	packet = test_get_sctp(skb->data);
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
				skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = val;

	/* we should see an abort after SACK is processed */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) == 0) {
		printf ("Case 6 failed.\n");
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
		hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t*)hdr +
						sizeof(sctp_chunkhdr_t));
		if (errhdr->cause != SCTP_ERROR_PROTO_VIOLATION)
			DUMP_CORE;

		printf("Received this error: %s ", errhdr->variable);
		p = errhdr->variable + WORD_ROUND(strlen(errhdr->variable) + 1); 
		pahdr = (sctp_paramhdr_t *)p;
		printf("type = %d, length = %d\n",
			ntohs(pahdr->type), ntohs(pahdr->length));
	}

	if (test_run_network()) {
		DUMP_CORE;
	}

	/* Verify that both associations were destroyed */
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	if (!list_empty(&ep1->asocs)) { DUMP_CORE; }
	if (!list_empty(&ep2->asocs)) { DUMP_CORE; }

	printk("\n\n%s Case 6 passed\n\n\n", argv[0]);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (test_run_network()) {
		DUMP_CORE;
	}

	exit(0);
} /* main() */
