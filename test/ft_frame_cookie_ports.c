/* SCTP kernel Implementation
 * (C) Copyright Hewlett-Packard
 *
 * This file is part of the SCTP kernel Implementation
 *
 * This is a functional test to verify the implementation of
 * IG Section  2.35 Port number verification in the COOKIE-ECHO:
 *    The State Cookie sent by a listening SCTP endpoint may not contain
 *    the original port numbers or the local verification tag.  It is then
 *    possible that the endpoint on reception of the COOKIE-ECHO will not
 *    be able to verify that these values match the original values found
 *    in the INIT and INIT-ACK that began the association setup.
 *
 *    ---------
 *    New text: (Section 5.1.5)
 *    ---------
 *
 *    3) Compare the port numbers and the verification tag contained
 *       within the COOKIE ECHO chunk to the actual port numbers and the
 *       verification tag within the SCTP common header of the received
 *       packet. If these values do not match the packet MUST be silently
 *       discarded,
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
 * 	Vladislav Yasevich <vlad@hp.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *
 * TEST CASES:
 *
 * Case 1: Modify my_vtag in the cookie sent as part of the INIT_ACK to
 * be different.  Subsequent COOKIE_ECHO must be dropped.
 *
 * Case 2: Modify my_port in the cookie sent as part of the INIT_ACK to
 * be different.  Subsequent COOKIE_ECHO must be dropped.
 *
 * Case 3: Modify peers port in the cookie sent as part of the INIT_ACK
 * to be different.  Subsequent COOKIE_ECHO must be dropped.
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
	uint8_t *message = "Forgetaboutit!\n";
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	sctp_init_chunk_t *initchk;
	uint8_t *p, *chkend;
	uint16_t clen;
	struct sctphdr *sh;
	uint32_t val, num_packets;
	sctp_paramhdr_t *pahdr;
	struct sctp_signed_cookie *c;

	/* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
	sctp_init();

	/* Case 1:  Modify my_vtag in the state cookie parameter of
	 * the INIT ACK chunk
	 */

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

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

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Steal the INIT-ACK and remove the STATE_COOKIE. */
	skb = test_peek_packet(TEST_NETWORK0);
	if (!skb)
		DUMP_CORE;

	packet = test_get_sctp(skb->data);
	initchk = (sctp_init_chunk_t *)&packet->ch;
	/* Is this an INIT-ACK chunk? */
	if (SCTP_CID_INIT_ACK != initchk->chunk_hdr.type) {
		DUMP_CORE;
	}

	clen = ntohs(initchk->chunk_hdr.length);

	p = &initchk->init_hdr.params[0];
	chkend = (char *)initchk + clen;
	pahdr = (sctp_paramhdr_t *)p;

	while (pahdr) {
		if (SCTP_PARAM_STATE_COOKIE == pahdr->type) {
			break;
		} else {
			printk("Looking for state cookie, but found %d\n",
			       ntohs(pahdr->type));
		}
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		if (p == chkend)
			pahdr = NULL;
		else if (p > chkend - sizeof(sctp_paramhdr_t))
			DUMP_CORE;
	}

	c = (struct sctp_signed_cookie *)(((sctp_cookie_param_t *)pahdr)->body);

	/* modify vtag */
	c->c.my_vtag = 25;

	/* Re-run the checksum. */
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
			       skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = htonl(val);

	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		printk("Case 1 Failed.\n");
		DUMP_CORE;
	}

	/* We expect the packet to be dropped.  Check the next
	 * 5 packets to be sure.  There really shouldn't be any.
	 */
	for (num_packets = 5; num_packets; num_packets--) {
		/* if we see a COOKIE-ACK, test failed */
		if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK0)) {
			printk("Case 1 Failed.\n");
			DUMP_CORE;
		}
	}
	
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	if (0 == error) {
		printk("\n\nCase 1 passed\n\n\n");
	}

	/* Case 2: Modify my_port in the state cookie parameter of
	 * the INIT ACK chunk.  The subsequent COOKIE ECHO must
	 * be dropped.
	 */

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

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

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Steal the INIT-ACK and remove the STATE_COOKIE. */
	skb = test_peek_packet(TEST_NETWORK0);
	if (!skb)
		DUMP_CORE;

	packet = test_get_sctp(skb->data);
	initchk = (sctp_init_chunk_t *)&packet->ch;
	/* Is this an INIT-ACK chunk? */
	if (SCTP_CID_INIT_ACK != initchk->chunk_hdr.type) {
		DUMP_CORE;
	}

	clen = ntohs(initchk->chunk_hdr.length);
	printk("clen = %d\n", clen);

	p = &initchk->init_hdr.params[0];
	chkend = (char *)initchk + clen;
	pahdr = (sctp_paramhdr_t *)p;

	while (pahdr) {
		if (SCTP_PARAM_STATE_COOKIE == pahdr->type) {
			break;
		} else {
			printk("Looking for state cookie, but found %d\n",
			       ntohs(pahdr->type));
		}
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		if (p == chkend)
			pahdr = NULL;
		else if (p > chkend - sizeof(sctp_paramhdr_t))
			DUMP_CORE;
	}

	c = (struct sctp_signed_cookie *)(((sctp_cookie_param_t *)pahdr)->body);

	/* modify vtag */
	c->c.my_port = 100;

	/* Re-run the checksum. */
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
			       skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = htonl(val);

	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		printk("Case 2 Failed\n");
		DUMP_CORE;
	}

	/* We expect the packet to be dropped.  Check the next
	 * 5 packets to be sure.  There really shouldn't be any.
	 */
	for (num_packets = 5; num_packets; num_packets--) {
		/* if we see a COOKIE-ACK, test failed */
		if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK0)) {
			printk("Case 2 Failed\n");
			DUMP_CORE;
		}
	}
	
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }


	if (0 == error) {
		printk("\n\nCase 2 passed\n\n\n");
	}


	/* Case 3: Modify peer' port in the state cookie parameter of
	 * the INIT ACK chunk.  The subsequent COOKIE ECHO must
	 * be dropped.
	 */

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

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

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* Steal the INIT-ACK and remove the STATE_COOKIE. */
	skb = test_peek_packet(TEST_NETWORK0);
	if (!skb)
		DUMP_CORE;

	packet = test_get_sctp(skb->data);
	initchk = (sctp_init_chunk_t *)&packet->ch;
	/* Is this an INIT-ACK chunk? */
	if (SCTP_CID_INIT_ACK != initchk->chunk_hdr.type) {
		DUMP_CORE;
	}

	clen = ntohs(initchk->chunk_hdr.length);
	printk("clen = %d\n", clen);

	p = &initchk->init_hdr.params[0];
	chkend = (char *)initchk + clen;
	pahdr = (sctp_paramhdr_t *)p;

	while (pahdr) {
		if (SCTP_PARAM_STATE_COOKIE == pahdr->type) {
			break;
		} else {
			printk("Looking for state cookie, but found %d\n",
			       ntohs(pahdr->type));
		}
		p += WORD_ROUND(ntohs(pahdr->length));
		pahdr = (sctp_paramhdr_t *)p;
		if (p == chkend)
			pahdr = NULL;
		else if (p > chkend - sizeof(sctp_paramhdr_t))
			DUMP_CORE;
	}

	c = (struct sctp_signed_cookie *)(((sctp_cookie_param_t *)pahdr)->body);

	/* modify vtag */
	c->c.peer_addr.v4.sin_port = 100;

	/* Re-run the checksum. */
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
			       skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = htonl(val);

	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		printk("Case 3 Failed.\n");
		DUMP_CORE;
	}

	/* We expect the packet to be dropped.  Check the next
	 * 5 packets to be sure.  There really shouldn't be any.
	 */
	for (num_packets = 5; num_packets; num_packets--) {
		/* if we see a COOKIE-ACK, test failed */
		if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK0)) {
			printk("Case 3 Failed.\n");
			DUMP_CORE;
		}
	}
	
	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	if (0 == error) {
		printk("\n\nCase 3 passed\n\n\n");
	}
	/* Indicate successful completion.  */
	exit(error);
}
