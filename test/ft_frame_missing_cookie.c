/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2003
 *
 * This file is part of the SCTP kernel Implementation
 *
 * This is a functional test to verify the reaction to an INIT-ACK with
 * no STATE_COOKIE.   We should ABORT.  In our implementation we will also
 * include a Missing Manadatory Parameter Error.
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
 * 	Jon Grimm  <jgrimm@us.ibm.com>
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
#include <net/sctp/checksum.h>

int
main(int argc, char *argv[])
{
	struct sock *sk1, *sk2;
	struct sockaddr_in loop1, loop2;
	int error;
	uint8_t *message = "Shrubbery!\n";
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	sctp_init_chunk_t *initchk;
	uint8_t *p, *chkend;
	uint16_t plen, clen, left;
	struct sctphdr *sh;
	uint32_t val;
	sctp_paramhdr_t *pahdr;

	/* Do all that random stuff needed to make a sensible universe. */
	init_Internet();
	sctp_init();

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

	/* At this point we have hold of the state cookie parameter. */
	plen = ntohs(pahdr->length);
	printk("plen = %d\n", plen);

	left = chkend - p - plen;
	printk("left = %d\n", left);
	memmove(p, p + plen, left);


	/* Now fix up the chunk length. */
	initchk->chunk_hdr.length = htons(clen - plen);
	skb_trim(skb, skb->len - plen);

	/* Re-run the checksum. */
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
			       skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = val;

	/* We expect an ABORT with invalid mandatory parameters. */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}


	if ( test_run_network() ) DUMP_CORE;

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);
}
