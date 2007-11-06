/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999 Motorola, Inc.
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * test_inqueue.c
 * 
 * This is a standalone program to test struct sctp_inq. 
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
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Jon "Taz" Mischo <taz@refcode.org>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <funtest.h>

void validate_chunk(struct sctp_chunk *chunk, char *msg, int flag);
void th_callback(void *);
static int th_callback_hit = 0;

int
main(void)
{
	struct sctp_association asoc;
        struct sctp_inq q;
        struct sctp_chunk *packet;
        struct sctp_chunk *chunk1;
        struct sctp_chunk *chunk2;
        unsigned char *tmp;
        struct sctp_chunk *chunk;
        struct sctphdr *sh;
        char *message1 = "Elea jacta est.\n";
        char *message2 = "Vini, vidi, vici.\n";
        char foo;
	struct sctp_sndrcvinfo sinfo;
        uint8_t ppid1, ppid2;
        int msg1_len, msg2_len;
        int size1, size2, size;

	init_Internet();
        sctp_init();
        printk("Expect three \"chunkifying w/o an sk\" messages.\n");

	/* This has the necessary side effect of making asoc.ssn[0] = 0.  */
	memset(&asoc, 0, sizeof(asoc));

        /* Build a bundled packet.  */
        msg1_len = strlen(message1) + 1;
        size1 = sizeof(sctp_chunkhdr_t)
                + sizeof(sctp_datahdr_t)
                + msg1_len;
        msg2_len = strlen(message2) + 1;
        size2 = sizeof(sctp_chunkhdr_t)
                + sizeof(sctp_datahdr_t)
                + msg2_len;

        size = WORD_ROUND(size1) + WORD_ROUND(size2);

        /* Build the first chunk.  */
        ppid1 = (uint8_t) rand();
	bzero(&sinfo, sizeof(sinfo));
	sinfo.sinfo_stream = 0;
	sinfo.sinfo_ppid = ppid1;
        chunk1 = sctp_make_data(&asoc, &sinfo, msg1_len, message1);

        if (size1 != chunk1->skb->len) {
                DUMP_CORE;
        }
        if (size1 != ntohs(chunk1->chunk_hdr->length)) {
                DUMP_CORE;
        }

        /* Build the second chunk.  */
        ppid2 = (uint8_t) rand();
	bzero(&sinfo, sizeof(sinfo));
	sinfo.sinfo_stream = 0;
	sinfo.sinfo_ppid = ppid2;
        chunk2 = sctp_make_data(&asoc, &sinfo, msg2_len, message2);

        if (size2 != chunk2->skb->len) {
                DUMP_CORE;
        }
        if (size2 != ntohs(chunk2->chunk_hdr->length)) {
                DUMP_CORE;
        }

        /* Make a chunk-shaped piece of memory.  */
        packet = sctp_make_chunk(ZERO, SCTP_CID_DATA, 0, size);
        /* Undo all that internal chunk structure... */
        packet->skb->data = packet->skb->tail = packet->skb->head;
        packet->skb->len = 0;
        packet->sctp_hdr = (struct sctphdr *)packet->skb->head;

        /* Put a host byte order SCTP header on it.  */
        sh = (struct sctphdr *)packet->skb->data;
        skb_reserve(packet->skb, sizeof(struct sctphdr));
        sh->source		= 42;
        sh->dest		= 56;
        sh->vtag        	= 0x12345678;
        sh->checksum		= 0x0;

        packet->sctp_hdr	= sh;

        /* Put in those chunks.  */
        tmp = skb_put(packet->skb, WORD_ROUND(size1));
        memcpy(tmp, chunk1->chunk_hdr, size1);
        tmp = skb_put(packet->skb, WORD_ROUND(size2));
        memcpy(tmp, chunk2->chunk_hdr, size2);

        /* Clear out these headers which should NOT be set on
         * a packet fresh from the network.
         */
        packet->chunk_hdr = NULL;
        packet->chunk_end = NULL;
        packet->subh.data_hdr = NULL;
        packet->param_hdr.v = NULL;
        packet->asoc = NULL;
	packet->rcvr = &asoc;
        
        /* At this point we have a packet with a valid SCTP header in
         * host byte order.
         */

        /* ABOVE HERE SHOULD BE INDEPENDENT OF sctp_inq.  */
        
        /* Create an sctp_inq.  */
        sctp_inq_init(&q);
        sctp_inq_set_th_handler(&q, th_callback); 
        /* Cause a SEGV if we have a bogus address.  */
        foo = *((char *)&q) ;

        /* Stuff the packet into the queue.  */
        sctp_inq_push(&q, packet);

        if (1 != th_callback_hit) {
                DUMP_CORE;
        }

        /* Pull out the first chunk and test it.  */
        chunk = sctp_inq_pop(&q);
        validate_chunk(chunk, message1, ppid1);

        /* Pull out the second chunk and test it.  */
        chunk = sctp_inq_pop(&q);
        validate_chunk(chunk, message2, ppid2);

        if (!chunk->end_of_packet) {
                DUMP_CORE;
        }

        /* Make sure we are empty.  */
        chunk = sctp_inq_pop(&q);
        if (ZERO != chunk) {
                DUMP_CORE;
        }

        /* For the moment, we just assume this works.  Run it anyway
         * in case it dumps core.
         */
        sctp_inq_free(&q);
        exit(0);

} /* main() */

void
validate_chunk(struct sctp_chunk *chunk, char *msg, int ppid)
{
        int chunk_value_len;
        int chunk_len;
        sctp_datahdr_t *dp;
        
        chunk_value_len = strlen(msg) + 1 + sizeof(sctp_datahdr_t);
        chunk_len = chunk_value_len + sizeof(sctp_chunkhdr_t);
        
        if (ZERO == chunk) {
#if 0
                fprintf(stderr, "test_inqueue:  chunk is NULL\n",
                        chunk);
#endif /* 0 */
                DUMP_CORE;
        }

        if (chunk->singleton) {
#if 0
                fprintf(stderr, "test_inqueue:  %x chunk is a singleton\n",
                        chunk);
#endif /* 0 */
                DUMP_CORE;
        }

        if (chunk->chunk_hdr->type != SCTP_CID_DATA) {
#if 0
                fprintf(stderr,"test_inqueue: %x chunk is %d, not DATA.\n",
                        chunk, chunk->chunk_hdr->type);
#endif /* 0 */
                DUMP_CORE;
        }

        if (chunk->chunk_hdr->flags != SCTP_DATA_NOT_FRAG) {
#if 0
                fprintf(stderr,"test_inqueue:  %x chunk flag is %x not 0x3\n",
                        chunk, chunk->chunk_hdr->flags);
#endif /* 0 */
                DUMP_CORE;
        }

        if (ntohs(chunk->chunk_hdr->length) != chunk_len) {
#if 0
                fprintf(stderr, "test_inqueue:  %x chunk len is %d not %d.\n"
                        chunk, ntohs(chunk->chunk_hdr->length), chunk_len);
#endif /* 0 */
                DUMP_CORE;
        }
	
        dp = (sctp_datahdr_t *)
		((uint8_t *) chunk->chunk_hdr + sizeof(sctp_chunkhdr_t));
	/* Is skb->data set correctly? */
	if ((void *)dp != chunk->skb->data) {
		DUMP_CORE;
	}
        /* BUG:  We do not check TSN, streamId, or sequence (SSN) */

        if (dp->ppid != ppid) {
                DUMP_CORE;
        }

        if (0 != strcmp((char *)dp->payload, msg)){
                DUMP_CORE;
        }
} /* void validate_chunk() */

void
th_callback(void *arg) {
        th_callback_hit++;
} /* th_callback() */
