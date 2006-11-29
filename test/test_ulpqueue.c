/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2001 Motorola, Inc.
 *
 * This file is part of the SCTP kernel reference Implementation
 *
 * This program unit tests the sctp_ulpq type.
 *
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
 * Jon Grimm <jgrimm@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/ulpqueue.h>

#include <funtest.h>


static void test_ulpqueue(void);
static char * msg1 = "Association 1";

char *msgs[3][4] = {
	{"Stream 0 SSN 0", "Stream 0 SSN 1", "Stream 0 SSN 2", "Stream 0 X",},
	{"Stream 1 SSN 0", "Stream 1 SSN 1", "Stream 1 SSN 2", "Stream 1 X",},
	{"Stream 2 SSN 0", "Stream 2 SSN 1", "Stream 2 SSN 2", "Stream 2 X",},
};

struct sctp_chunk * chunks[3][4];

enum { TEST_NUM_STREAMS=10 };

/* Test the ulpqueue abstraction. */
int
main(int argc, char * const argv[])
{
	/* Test normally. */
	test_ulpqueue();
	printk("%s passes...\n", argv[0]);

	return 0;

} /* main( ) */

/* Internal helper to create a recvchunk. */
static struct sctp_chunk *
_test_make_recvchunk(struct sctp_association *asoc,
		    char *testdata,
		    uint16_t stream,
		    uint32_t ppid,
		    uint16_t flags,
		    uint32_t tsn)
{
	struct sctp_chunk *chunk;
	struct sctp_chunk *rcvchunk;
	struct sctp_sndrcvinfo sinfo = {0};
	sctp_chunkhdr_t *ch;

	sinfo.sinfo_stream = stream;
	sinfo.sinfo_ppid = ppid;
	sinfo.sinfo_flags = flags;

	chunk = sctp_make_data(asoc,
			       &sinfo,
			       strlen(testdata) + 1,
			       testdata);

	if (NULL == chunk) { DUMP_CORE;	}

	/* Pretend that we have recieved this skb. */

	rcvchunk = sctp_chunkify(chunk->skb, asoc, asoc->base.sk);

	if (NULL == rcvchunk) { DUMP_CORE; }
	sctp_chunk_assign_ssn(chunk);

	/* Fix up the recvchunk like it has been dequeued from
	 * the inqueue.
	 */

	/* Unit tests don't have the code to fix up the network
	 * headers, so lets at least initialize it to something
	 * interesting.
	 */
	rcvchunk->skb->nh.iph =
		(struct iphdr *)skb_push(rcvchunk->skb, sizeof(struct iphdr));
	rcvchunk->skb->nh.iph->version = 4;
	rcvchunk->skb->dst = (struct dst_entry *)rcvchunk->skb->cb;
	skb_pull(rcvchunk->skb, sizeof(struct iphdr));

	ch = (sctp_chunkhdr_t *) chunk->skb->data;

	rcvchunk->chunk_hdr = ch;
        rcvchunk->chunk_end = ((uint8_t *)ch) +
		WORD_ROUND(ntohs(ch->length));
        (void) skb_pull(rcvchunk->skb, sizeof(sctp_chunkhdr_t));

	rcvchunk->subh.data_hdr = (sctp_datahdr_t *)rcvchunk->skb->data;
	skb_pull(rcvchunk->skb, sizeof(sctp_datahdr_t));
	rcvchunk->subh.data_hdr->tsn = tsn;

	return rcvchunk;

} /* _test_make_recvchunk() */


/* Internal helper to create a recieved message notification. */
static struct sctp_ulpevent *
_test_make_recvmsg(struct sctp_association *asoc,
		   char *testdata,
		   uint16_t stream,
		   uint32_t ppid,
		   uint16_t flags,
		   uint32_t tsn)
{
	struct sctp_ulpevent *event;
	struct sctp_chunk *rcvchunk;

	rcvchunk = _test_make_recvchunk(asoc,
					testdata,
					stream,
					ppid,
					flags,
					tsn);

	if (NULL == rcvchunk) { DUMP_CORE; }

	event = sctp_ulpevent_make_rcvmsg(asoc,
					  rcvchunk,
					  GFP_KERNEL);

	if (NULL == event) { DUMP_CORE; }

	return (event);

} /* _test_make_recvmsg() */

/* Test that we can send just basic notifications up the ulpqueue. */
static int
_test_basic_events(struct sctp_association *asoc, struct sctp_ulpq *ulpq)
{
	struct sctp_ulpevent *event;
	struct sk_buff *skb;

	/* Build a data event and add this event to the ulpq. */
	event = _test_make_recvmsg(asoc, msg1, 0, 10, 0, 0);

	if (NULL == event) {
		DUMP_CORE;
	}

	if (0 == sctp_ulpq_tail_event(ulpq, event)) {
		DUMP_CORE;
	}

	/* Check to make sure the event was delivered. */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (skb != sctp_event2skb(event)) {
		sctp_ulpevent_free(event);
		DUMP_CORE;
	}

	/* Check to see that there are no other events. */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL != skb) {
		DUMP_CORE;
	}

	return 0;

} /* _test_basic_events() */

/* Test multistream and ordering. */
static int
_test_multistream(struct sctp_association *asoc, struct sctp_ulpq *ulpq)
{
	int i,j;
	struct sk_buff *skb;


	/* Set up the world so we know how ssns get assigned and
	 * expected.
	 */
	sctp_ssnmap_clear(asoc->ssnmap);
	for (i=0; i<3; i++) {

		/* Create some events to start testing with. */
		for (j=0; j<3; j++) {
			printk("i:%d  j:%d\n", i, j);
			chunks[i][j] =
				_test_make_recvchunk(asoc, msgs[i][j], i,
						     0xdead, 0, 0);

			if (NULL == chunks[i][j]) { DUMP_CORE; }
		}


		chunks[i][3] = _test_make_recvchunk(asoc, msgs[i][3], i,
						    0xdead, SCTP_UNORDERED, 0);

		if (NULL == chunks[i][3]) { DUMP_CORE; }

	}

	/* Deliver stream 0, ssn 2.  This should not be delivered to the ULP
	 * as it is out of order.
	 */
	printk("Test that we don't deliver out of order chunks.\n");
	sctp_ulpq_tail_data(ulpq, chunks[0][2], GFP_KERNEL);

	/* Check to see that we did not deliver this to the ULP. */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL != skb) { DUMP_CORE; }

        /* Recieve stream 0, ssn 1.  This should not be delivered to the ULP
	 * as it is out of order.
	 */

	sctp_ulpq_tail_data(ulpq, chunks[0][1], GFP_KERNEL);

	/* Check to see that we did not deliver this to the ULP. */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL != skb) { DUMP_CORE; }


	/* Deliver stream 1, ssn 0.  This _should_ be delivered to the ULP
	 * as it is out of order.
	 */
	printk("Test that we do deliver in order chunks\n");
	sctp_ulpq_tail_data(ulpq, chunks[1][0], GFP_KERNEL);

	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL == skb) { DUMP_CORE; }
	kfree_skb(skb);

        /* Receive stream 0, UNORDERED.  This should be delivered to the ULP.
	 */
	printk("Test that we do deliver UNORDERED messages.\n");
	sctp_ulpq_tail_data(ulpq, chunks[0][3], GFP_KERNEL);

	/* Check to see that we did not deliver this to the ULP. */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL == skb) { DUMP_CORE; }
	kfree(skb);

	/* Make sure there is nothing else left on the recieve queue. */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL != skb) { DUMP_CORE; }


	/* Finally, let's fill in the chunk we've been waiting for. */
	printk("Testing harvesting of (waiting) ordered messages.\n");
	sctp_ulpq_tail_data(ulpq, chunks[0][0], GFP_KERNEL);

        /* Pull out three messages and check to see that they came back in
	 * order by comparing the message strings.
	 */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL == skb) { DUMP_CORE; }
	if (memcmp(skb->data, msgs[0][0], strlen(msgs[0][0]))) { DUMP_CORE; }
	printk("Msg: %s\n", skb->data);
	kfree_skb(skb);


	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL == skb) { DUMP_CORE; }
	if (memcmp(skb->data, msgs[0][1], strlen(msgs[0][1]))) { DUMP_CORE; }
	printk("Msg: %s\n", skb->data);
	kfree_skb(skb);

	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL == skb) { DUMP_CORE; }
	if (memcmp(skb->data, msgs[0][2], strlen(msgs[0][2]))) { DUMP_CORE; }
	printk("Msg: %s\n", skb->data);
	kfree_skb(skb);

	/* Now check that the queue is again empty. */
	skb = skb_dequeue(&asoc->base.sk->sk_receive_queue);
	if (NULL != skb) {
		DUMP_CORE;
	}

	/* Free all the memory we have allocated. */
	for (i=0; i<3; i++) {
  		for (j=0; j<4; j++) {
			sctp_chunk_free(chunks[i][j]);
			chunks[i][j] = NULL;
		}
	}

	return(0);

} /* _test_multistream() */

/* Test reassembly. */
static int
_test_reassembly(struct sctp_association *asoc, struct sctp_ulpq *ulpq)
{
	/* FIXME: Write me. */
	return(0);
}

/* Setup some common data structures for the tests and run the tests
 * sequentially.
 */
static void
test_ulpqueue()
{
	struct sctp_endpoint *ep1;
	struct sctp_association *asoc1;
	struct sctp_ulpq ulpq_buf;
	struct sctp_ulpq *ulpq;
	struct sock *sk1;
	union sctp_addr loop1, loop2;


	/* Build up some associations to test with. */
	sctp_init();
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	if (NULL == sk1 ) {
		DUMP_CORE;
	}

	ep1 = sctp_sk(sk1)->ep;

	/* Bind socket sk1.   */
	loop1.v4.sin_family = AF_INET;
	loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.v4.sin_port = htons(SCTP_TESTPORT_1);

	sctp_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));

	/* Build an association. */
	asoc1 = sctp_association_new(ep1, sk1, 0, GFP_KERNEL);

	loop2.v4.sin_family = AF_INET;
	loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.v4.sin_port = htons(SCTP_TESTPORT_2);
	sctp_assoc_add_peer(asoc1, &loop2, GFP_KERNEL, SCTP_ACTIVE);

	/* Build the new ulpqueue with an aribitrary number
	 * of inbound streams assumed.
	 */
	ulpq = sctp_ulpq_init(&ulpq_buf, asoc1);

	if (!ulpq)
		DUMP_CORE;
	asoc1->ssnmap = sctp_ssnmap_new(TEST_NUM_STREAMS, TEST_NUM_STREAMS,
				       GFP_ATOMIC);

	if (skb_dequeue(&asoc1->base.sk->sk_receive_queue)) {
		DUMP_CORE;
	}

	_test_basic_events(asoc1, ulpq);
	_test_multistream(asoc1, ulpq);
	_test_reassembly(asoc1, ulpq);

	sctp_ulpq_free(ulpq);

} /* test_ulpqueue() */


