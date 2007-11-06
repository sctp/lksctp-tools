/* SCTP kernel reference Implementation
 * Copyright (c) 2003 Intel Corp.
 *
 * This is the Test for "Kamikaze" packet
 * 
 * A "Kamikaze" packet (AKA nastygram, christma tree packet,
 * lanmp test segement, et al.). That is, correctly handle a
 * segment with the maximum combination of features at once
 * (e.g., a COOKIE-ECHO, SACK, ASCONF, UNKNOWN-CHUNK, SHUTDOWN).
 * <http://www.ietf.org/internet-drafts/draft-stewart-tsvwg-sctpscore-01.txt> 
 *
 * Ardelle Fan <ardelle.fan@intel.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h>
#include <funtest.h>

/* Change total length field of ip header, also update checksum field. */
void
ip_change_totlen(struct iphdr *iph, __u16 totlen)
{
	__u32 check = ntohs(iph->check);

	check += iph->tot_len;
	if ((check+1)>>16)
		check = (check + 1) & 0xffff;
	check -= totlen;
	check += check >> 16; /* adjust carry */
	iph->check = htons(check);
	iph->tot_len = totlen;
}

void
replace_packet(int net, struct sctp_association *asoc)
{
	struct sk_buff_head *network = get_Internet(net);
	struct bare_sctp_packet *packet;
	sctp_chunkhdr_t *chunk, *next_chunk;
	struct sk_buff *skb;
	struct sctp_chunk *sack, *asconf, *unknown_chunk, *shutdown;
	void *target;
	int len, packet_len = sizeof(struct sctphdr);
	__u32 crc32;
	struct iphdr *iph;
	struct sctp_bind_addr *bp;
	struct sctp_sockaddr_entry *addr;
	struct list_head *pos;

	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;
	if (SCTP_CID_COOKIE_ECHO != chunk->type) DUMP_CORE;

	next_chunk = (struct sctp_chunkhdr *)((uint8_t *)chunk + WORD_ROUND(ntohs(chunk->length)));
	packet_len += WORD_ROUND(ntohs(chunk->length));

	skb_trim(skb, skb->len - WORD_ROUND(ntohs(next_chunk->length)));
	if (skb->len != test_hdr_size(skb->data) + sizeof(packet->sh) +
		WORD_ROUND(ntohs(chunk->length))) {
		DUMP_CORE;
	}

	sack = sctp_make_sack(asoc);
	len = ntohs(sack->chunk_hdr->length);
	target = skb_put(skb, WORD_ROUND(len));
	memcpy(target, sack->chunk_hdr, len);
	memset(target+len, 0, WORD_ROUND(len)-len);
	packet_len += WORD_ROUND(len);

	bp = (struct sctp_bind_addr *) &asoc->base.bind_addr;
	pos = bp->address_list.next;
	addr = list_entry(pos, struct sctp_sockaddr_entry, list);
	asconf = sctp_make_asconf_set_prim(asoc, &addr->a);
	len = ntohs(asconf->chunk_hdr->length);
	target = skb_put(skb, WORD_ROUND(len));
	memcpy(target, asconf->chunk_hdr, len);
	memset(target+len, 0, WORD_ROUND(len)-len);
	packet_len += WORD_ROUND(len);

	unknown_chunk = sctp_make_op_error(asoc, NULL, SCTP_ERROR_UNKNOWN_CHUNK,
					   NULL, 0);
	len = ntohs(unknown_chunk->chunk_hdr->length);
	target = skb_put(skb, WORD_ROUND(len));
	memcpy(target, unknown_chunk->chunk_hdr, len);
	memset(target+len, 0, WORD_ROUND(len)-len);
	packet_len += WORD_ROUND(len);

	shutdown = sctp_make_shutdown(asoc, NULL);
	len = ntohs(shutdown->chunk_hdr->length);
	target = skb_put(skb, WORD_ROUND(len));
	memcpy(target, shutdown->chunk_hdr, len);
	memset(target+len, 0, WORD_ROUND(len)-len);
	packet_len += WORD_ROUND(len);

	packet->sh.checksum = 0;
	crc32 = sctp_start_cksum((__u8 *)&packet->sh, packet_len);
	crc32 = sctp_end_cksum(crc32);
	packet->sh.checksum = htonl(crc32);

	iph = (struct iphdr *)skb->data;
	ip_change_totlen(iph, htons(skb->len));
}

void
check_feedback(int net)
{
	struct sk_buff_head *network = get_Internet(net);
	struct bare_sctp_packet *packet;
	sctp_chunkhdr_t *chunk;
	struct sk_buff *skb;
	sctp_errhdr_t *err;

	skb = network->next;
	packet = test_get_sctp(skb->data);
	chunk = &packet->ch;

	if (chunk->type != SCTP_CID_COOKIE_ACK) {
		DUMP_CORE;
	}
	printf("\n\nTarget feedback COOKIE_ACK to COOKIE_ECHO chunk!\n\n");

	chunk = (struct sctp_chunkhdr *)((uint8_t *)chunk + WORD_ROUND(ntohs(chunk->length)));
	if (chunk >= (sctp_chunkhdr_t *) skb->tail 
	    || chunk->type == SCTP_CID_DATA) {
		printf("Kamikaze chunk is not bundled.\n");
		skb = skb->next;
		if ((void *)skb == (void *)network) DUMP_CORE;
		packet = test_get_sctp(skb->data);
		chunk = &packet->ch;
	} else 
		printf("Kamikazee chunk was bundled!\n");

	if (chunk->type != SCTP_CID_ASCONF_ACK) {
		printf("\n\nTarget doesn't feedback ASCONF_ACK to ASCONF chunk!\n\n");
		/* Maybe the peer hasn't support ASCONF handling. */
		if (chunk->type != SCTP_CID_ERROR) {
			DUMP_CORE;
		} else {
			err = (sctp_errhdr_t *)((void *)chunk + sizeof(sctp_chunkhdr_t));
			if (err->cause != SCTP_ERROR_UNKNOWN_CHUNK) {
				printf("\n\nTarget doesn't feedback Unknown Chunk Error to ASCONF chunk!\n\n");
				DUMP_CORE;
			}
			printf("\n\nTarget feedback Unknown Chunk Error to ASCONF chunk!\n\n");
		}
	} else
		printf("\n\nTarget feedback ASCONF_ACK to ASCONF chunk!\n\n");

	chunk = (struct sctp_chunkhdr *)((uint8_t *)chunk + WORD_ROUND(ntohs(chunk->length)));
	if (chunk >= (sctp_chunkhdr_t *) skb->tail 
	    || chunk->type == SCTP_CID_DATA) {
		printf("Kamikaze chunk is not bundled.\n");
		skb = skb->next;
		if ((void *)skb == (void *)network) DUMP_CORE;
		packet = test_get_sctp(skb->data);
		chunk = &packet->ch;
	}

	if (chunk->type != SCTP_CID_SHUTDOWN_ACK) {
		printf("chunk->type is %d \n",chunk->type);
		DUMP_CORE;
	}
	printf("\n\nTarget feedback SHUTDOWN_ACK to SHUTDOWN chunk!\n\n");
}

int
main(int argc, char *argv[])
{
	int pf_class, af_family;
	struct sctp_endpoint *ep1;
        int error, bytes_sent;
        union sctp_addr loop1;
        union sctp_addr loop2;
        struct sctp_association *asoc1;
        struct iovec out_iov;
        struct msghdr outmsg;
        struct sock *sk1;
        struct sock *sk2;
        uint8_t *message = "hello, world! This is a never usded message. This DATA chunk will be replaced with SACK, ASCONF, UNKNOWN-CHUNK, SHUTDOWN chunk. And hope this message is long enough so that new chunks needn't allocate buffer again. \n";

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();
	sctp_addip_enable = 1;
	sctp_addip_noauth = 1;

	/* Set some basic values which depend on the address family. */

	pf_class = PF_INET;
	af_family = AF_INET;
        loop1.v4.sin_family = AF_INET;
        loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.v4.sin_port = htons(SCTP_TESTPORT_1);
        loop2.v4.sin_family = AF_INET;
        loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.v4.sin_port = htons(SCTP_TESTPORT_2);

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Send the first message.  This will create the association.  */
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	/* We expect DATA bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Replace the COOKIE_ECHO bundled with DATA packet with
	 * a Kamikaze packet with bundled COOKIE_ECHO, SACK, ASCONF,
	 * UNKNOWN-CHUNK, SHUTDOWN chunks
	 */ 

	/* Grub around to find our association.  */
	ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1);
	if (NULL == asoc1) DUMP_CORE;

	replace_packet(TEST_NETWORK0, asoc1);
       
	if (!test_for_chunk(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	/* We expect SACK bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	/* We expect ASCONF bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_ASCONF, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	/* We expect ERROR bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_ERROR, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	/* We expect SHUTDOWN bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	if (test_run_network_once(TEST_NETWORK0) < 0) DUMP_CORE;

	check_feedback(TEST_NETWORK0);
	
	error = 0;
        sctp_close(sk1, /* timeout */ 0);
        sctp_close(sk2, /* timeout */ 0);
	test_run_network();

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */

