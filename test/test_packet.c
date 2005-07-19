/* SCTP kernel reference Implementation
 * Copyright (c) 1999, Cisco
 * Copyright (c) 1999, Motorola
 * Copyright (c) 2002, International Business Machines, Corp.
 * 
 * This file is part of the SCTP kernel reference Implementation.
 *  
 * This is a standalone program to test struct sctp_packet.
 *
 * More specifically, this test will create a dummy association and
 * endpoint, as well as properly formed chunks for output to the "wire".
 *
 *
 * The SCTP reference implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * The SCTP reference implementation  is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied 
 *                    ***********************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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
 *   Karl Knutson          <karl@athena.chicago.il.us>
 *   La Monte H.P. Yarroll <piggy@acm.org>
 */
#include <linux/config.h>
#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <net/sock.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <funtest.h>

#define REASONABLE_PMTU 1500
/* This PMTU is 1 word longer than all the headers put together.  */
#define EPSILON 4
#define MINUSCULE_PMTU (sizeof(struct iphdr) + sizeof(struct sctphdr) \
                        + sizeof(sctp_chunkhdr_t) \
                        + WORD_ROUND(msg2_len) \
                        + EPSILON)

static struct sk_buff_head Aether;
static int empty_called = 0;

int test_xmitter(struct sk_buff *skb, struct sctp_transport *t, int ipfragok);
int test_empty(struct sctp_outq *q);
struct sctp_af test_specific;
int empty_aether(void);
int packet_went_through(struct sctp_chunk **chunk, uint32_t *, int);

static int 
verify_packet(struct sctp_packet *p, int n) 
{
	struct list_head *tmp;

	int i = 0;
	list_for_each(tmp, &p->chunk_list)
		i++;

	return (i == n);
}

int
main(void)
{
/*** Generate chunk(s), association(s), transport(s), outqueue(s)? */

        struct sctp_packet packet;
        uint16_t sport;
        uint16_t dport;
        uint32_t vTag;
	struct sctp_datamsg *datamsg;
        struct sctp_endpoint *ep;
        struct sctp_association *asoc;
        struct sctp_transport *transport;
        struct sctp_chunk *data_chunks[2];
	struct sctp_sndrcvinfo sinfo;
        uint32_t TSNs[3];
        struct sctp_chunk *control_chunk;
        struct sctp_chunk *big_chunk;
        sctp_sackhdr_t sack;
        struct sock *sk;
        union sctp_addr loop1;
        union sctp_addr loop2;
        sctp_xmit_t transmitted;

        char *message1 = "Elea jacta est.\n";
        char *message2 = "Vini, vidi, vici.\n";
        char *big_message = "We reject kings, presidents, and voting.\n"
		"We believe in rough consensus and running code.\n";
        uint8_t payload_type1, payload_type2, payload_type_big;
        int msg1_len, msg2_len, big_len;
	struct sctp_bind_addr *bp;
	struct sctp_bind_addr bind_addr_buf;
	sctp_scope_t scope;
	int error;
	int flags;

        skb_queue_head_init(&Aether);

        /* Build an endpoint. */
        sctp_init();
        sk = sctp_socket(PF_INET, SOCK_SEQPACKET);
	ep = sctp_sk(sk)->ep;
        
        /* Bind this endpoint.  */
        loop1.v4.sin_family = AF_INET;
        loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.v4.sin_port = htons(SCTP_TESTPORT_1);
        sctp_bind(sk, (struct sockaddr *)&loop1, sizeof(loop1));
	
        /* Build an association on this endpoint. */
        asoc = sctp_association_new(ep, sk, 0 /* global scope */, GFP_KERNEL);

        /* Prime the peer's transport structures.  */
        loop2.v4.sin_family = AF_INET;
        loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.v4.sin_port = htons(SCTP_TESTPORT_2);
        transport = sctp_assoc_add_peer(asoc, &loop2, GFP_KERNEL, SCTP_ACTIVE);
        transport->asoc->pmtu = REASONABLE_PMTU;

	/* Register the association with the endpoint.  */        
	sctp_endpoint_add_asoc(ep, asoc);
        
        /* Force the TSN's to a known value.  This makes the test more
         * reproducible.
         *
         * This number has the property that htonl(n) > n.  We
         * actually caught a bug because a random number had this property...
         */
        asoc->next_tsn = 7;
        TSNs[0] = asoc->next_tsn;
        TSNs[1] = TSNs[0] + 1;
        TSNs[2] = TSNs[1] + 1;
	asoc->ssnmap = sctp_ssnmap_new(10, 10, GFP_ATOMIC);

	/* We're mucking with next_tsn so we now have responsibility
	 * for making everything in the asoc congruent.
	 *
	 * If ctsn_ack_point is broken we fail to empty
	 * asoc->outqueue->transmitted.  c.initial_tsn is a dead chicken.
	 */
        asoc->c.initial_tsn = asoc->next_tsn;
	asoc->ctsn_ack_point = asoc->next_tsn - 1;

        /* Build a SACK for the two data packets.  */
        sack.cum_tsn_ack = TSNs[1];
        sack.a_rwnd = 32768;
        sack.num_gap_ack_blocks = 0;
        sack.num_dup_tsns  = 0;

	/* Build up the bind address list for the association based on
	 * info from the local endpoint and the remote peer.
	 */
	sctp_bind_addr_init(&bind_addr_buf, 0);
	bp = &bind_addr_buf;
	if (NULL == bp) { DUMP_CORE; }
	scope = sctp_scope(&asoc->peer.active_path->ipaddr);
	flags = (PF_INET6 == asoc->base.sk->sk_family) ? 
		SCTP_ADDR6_ALLOWED : 0;
	if (asoc->peer.ipv4_address) {
		flags |= SCTP_ADDR4_PEERSUPP;
	}
	if (asoc->peer.ipv6_address) {
		flags |= SCTP_ADDR6_PEERSUPP;
	}
	error = sctp_bind_addr_copy(bp, &asoc->ep->base.bind_addr,
				    scope, GFP_ATOMIC, flags);
	if (0 != error) { DUMP_CORE; }

        /* Build a control chunk (INIT). */
        control_chunk = sctp_make_init(asoc, bp, GFP_ATOMIC, 0);

	/* Save the bind address list in the association and free the 
	 * temporary holder. */
	asoc->base.bind_addr = *bp;


        /* Build three data chunks  */
        msg1_len = strlen(message1) + 1;
        payload_type1 = (uint8_t) rand();
	memset(&sinfo, 0x00, sizeof(sinfo));
	sinfo.sinfo_ppid = payload_type1;
        data_chunks[0] = sctp_make_data(asoc, &sinfo, msg1_len, (u8 *)message1);
	datamsg = sctp_datamsg_new(GFP_KERNEL);
	data_chunks[0]->msg = datamsg;

        msg2_len = strlen(message2) + 1;
        payload_type2 = (uint8_t) rand();
	sinfo.sinfo_ppid = payload_type2;
        data_chunks[1] = sctp_make_data(asoc, &sinfo, msg2_len, (u8 *)message2);
	datamsg = sctp_datamsg_new(GFP_KERNEL);
	data_chunks[1]->msg = datamsg;

        big_len = strlen(big_message) + 1;
        payload_type_big = (uint8_t) rand();
	sinfo.sinfo_ppid = payload_type_big;
        big_chunk = sctp_make_data(asoc, &sinfo, msg2_len, (u8 *)message2);
	datamsg = sctp_datamsg_new(GFP_KERNEL);
	big_chunk->msg = datamsg;

        /* ABOVE HERE SHOULD BE INDEPENDENT OF SCTP_packet.  */

/*** Create the unmodified environment and commit. */

        /* Overwrite the sctp xmit handler with the test xmit handler. */
        asoc->peer.primary_path->af_specific->sctp_xmit = &test_xmitter;

        /* Initialize the packet. */
	sport = asoc->base.bind_addr.port;
	dport = asoc->peer.port; 
	vTag = asoc->peer.i.init_tag; 
        sctp_packet_init(&packet, transport, sport, dport);
	sctp_packet_config(&packet, vTag, 0);

        /* Commit the first chunk to the network. */
        transmitted = sctp_packet_transmit_chunk(&packet, data_chunks[0]);

        if (SCTP_XMIT_OK != transmitted) { DUMP_CORE; }
        /* Verify that it only contains one chunk. */
        if (!verify_packet(&packet, 1)) { DUMP_CORE; }

        /* Commit the second chunk to the network? */
        transmitted = sctp_packet_transmit_chunk(&packet, data_chunks[1]);

        if (SCTP_XMIT_OK != transmitted) { DUMP_CORE; }
/*** Check that an appropriate packet was created but not sent. */

        /* Verify that it contains both chunks. */
        if (!verify_packet(&packet, 2)) { DUMP_CORE; }
        
        /* Transmit the resultant packet, */
        transmitted = sctp_packet_transmit(&packet);

        if (SCTP_XMIT_OK != transmitted) { DUMP_CORE; }

        /* and see what gets passed to the Aether. */
        if (!packet_went_through(data_chunks, TSNs, 2)) { DUMP_CORE; }

        /* Check that the Aether is empty. */
        if (!empty_aether()){
                DUMP_CORE;
        }

	/* Create the packet-would-fill-up environment and commit. */
        
        /* Reinitialize the packet */
        sctp_packet_init(&packet, transport, sport, dport);
	sctp_packet_config(&packet, vTag, 0);

        /* Set the Path MTU to a minuscule amount. */
        transport->asoc->pmtu = MINUSCULE_PMTU;

        /* Commit the first chunk to the network. */
        transmitted = sctp_packet_transmit_chunk(&packet, data_chunks[0]);

        if (SCTP_XMIT_OK != transmitted) { DUMP_CORE; }
        /* Verify that it only contains one chunk. */
        if (!verify_packet(&packet, 1)) { 
                DUMP_CORE; 
        }

        /* Commit the second chunk to the network. */
        transmitted = sctp_packet_transmit_chunk(&packet, data_chunks[1]);
        
        if (SCTP_XMIT_OK != transmitted) { DUMP_CORE; }

	/* Check that only the first chunk was sent and the second
         * was queued.
         */
        if (!packet_went_through(&data_chunks[0], &TSNs[0], 1)) {
                DUMP_CORE;
        }
        if (!verify_packet(&packet, 1)){
                DUMP_CORE;
        }

	/* Create the need-to-fragment environment and commit. */
        
        /* Note that the PMTU is still MINUSCULE */

        /* Commit the first chunk to the network. */
        transmitted = sctp_packet_transmit_chunk(&packet, big_chunk);
        
	

        if (SCTP_XMIT_OK == transmitted) {
		if (!packet.ipfragok) 
			DUMP_CORE;
	
	} else if (!verify_packet(&packet, 0)) { DUMP_CORE; }

        /* Check that the chunk sitting in packet went through.  */
        if (!packet_went_through(&data_chunks[1], &TSNs[1], 1)) {
                DUMP_CORE;
        }

        if (big_chunk->has_tsn) {
                DUMP_CORE;
        }

        if (!empty_aether()){ DUMP_CORE; }
        
/*** Create the congested environment and commit. */
/*** Check that an appropriate packet was not sent. */
        
        /* NO-OP */
        
        
        exit(0);
} /* main() */

int
test_xmitter(struct sk_buff *skb, struct sctp_transport *t, int ipfragok) {
        skb_queue_tail(&Aether, skb);
        return(0);
} /* test_xmitter() */

int
test_empty(struct sctp_outq *q) {
        empty_called = 1;
        return(0);
}

int
empty_aether()
{
        return(skb_queue_empty(&Aether));
} /* empty_aether() */

/* Get one packet off of the Aether and confirm that it contains the
 * listed chunks.
 */
int
packet_went_through(struct sctp_chunk **chunks, uint32_t *TSNs, int num_chunks)
{
        int retval;
	int i;
        struct sk_buff *skb;
        sctp_chunkhdr_t *ch;
        sctp_datahdr_t *dp;
	void *next_header;
        size_t len;

        skb = skb_dequeue(&Aether);
        if (NULL == skb) {
                DUMP_CORE;
        }
        
	next_header = skb_pull(skb, sizeof(struct sctphdr));

	for (i=0; i < num_chunks; i++) {
		/* Now look to see if that was the chunk we queued.  */
		if (NULL == next_header) {
			DUMP_CORE; /* The last pull failed.  */
		}

		ch = (sctp_chunkhdr_t *)next_header;
		len = (uint8_t *)chunks[i]->chunk_end -
			(uint8_t *)chunks[i]->chunk_hdr;
		retval = memcmp(ch, chunks[i]->chunk_hdr, len);
		if (len != ntohs(ch->length)) {
			DUMP_CORE; /* The chunk header is broken.  */
		}
		next_header = skb_pull(skb, sizeof(sctp_chunkhdr_t));
		len -= sizeof(sctp_chunkhdr_t);
	
		switch (ch->type) {
		case SCTP_CID_DATA:
			dp = (sctp_datahdr_t *)next_header;
			next_header = skb_pull(skb, sizeof(sctp_datahdr_t));
			len -= sizeof(sctp_datahdr_t);
			
			dp->tsn		= ntohl(dp->tsn);
			dp->stream	= ntohs(dp->stream);
			dp->ssn 	= ntohs(dp->ssn);
			dp->ppid        = ntohl(dp->ppid);
			
			/* Did we get the expected TSN?  */
			if (TSNs[i] != dp->tsn) {
				DUMP_CORE;
			}
			break;
		default:
			/* Do nothing.  */
			break;
		} /* switch(type) */
		next_header = skb_pull(skb, WORD_ROUND(len));
		if (retval != 0) {
			DUMP_CORE;
		}
	} /* for (all chunks we are expecting) */

        return(0 == retval);
} /* packet_went_through() */
