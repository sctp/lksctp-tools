/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2001 Motorola, Inc.
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * This program unit tests the sctp_ulpevent type.
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
 * La Monte H.P. Yarroll <piggy@acm.org>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/ulpevent.h>

#include <funtest.h>


static void test_ulpevent(void);

int
main(int argc, char * const argv[])
{
	/* Test normally. */
	test_ulpevent();
	printk("%s passes...\n", argv[0]);

	return 0;

} /* main( ) */

static void 
test_assoc_change(const struct sctp_association *asoc)
{
	struct sctp_ulpevent *event;
	struct sctp_assoc_change *sac;
	struct sk_buff *skb;

	event = sctp_ulpevent_make_assoc_change(asoc,
						1, /* flags */
						SCTP_COMM_UP,
						3,  /* error */
						4,  /* outbound */
						5,  /* inbound */
						GFP_KERNEL);
						
	if (NULL == event) { DUMP_CORE; }
	skb = sctp_event2skb(event);

	
	if (sizeof(struct sctp_assoc_change) != skb->len) { DUMP_CORE; }
	if (!sctp_ulpevent_is_notification(event)) { DUMP_CORE; }

	sac = (struct sctp_assoc_change *)skb->data;
	if (SCTP_ASSOC_CHANGE != sac->sac_type) { DUMP_CORE; }
	if (SCTP_COMM_UP != sac->sac_state ) { DUMP_CORE; }

	/* Check fields that are just pure copy-ins. */
	/* Make sure unused flags field is zero'd out. */
	if (0 != sac->sac_flags) { DUMP_CORE; }
	if (3 != sac->sac_error) { DUMP_CORE; }
	if (4 != sac->sac_outbound_streams) { DUMP_CORE; }
	if (5 != sac->sac_inbound_streams) { DUMP_CORE; }
	if (sctp_assoc2id(asoc) != sac->sac_assoc_id) { DUMP_CORE; }

	sctp_ulpevent_free(event);

} /* test_assoc_change() */

static void 
test_paddr_change(const struct sctp_association *asoc)
{
	struct sctp_ulpevent *event;
	struct sctp_paddr_change *spc;
	struct sk_buff *skb;
	struct sockaddr_storage aaddr;

	event = sctp_ulpevent_make_peer_addr_change(asoc,
						    &aaddr,
						    1, /* flags */
						    SCTP_ADDR_AVAILABLE,
						    3, /* error */
						    GFP_KERNEL);
		 				
	if (NULL == event) { DUMP_CORE; }
	skb = sctp_event2skb(event);
	
	if (sizeof(struct sctp_paddr_change) != skb->len) { DUMP_CORE; }
	if (!sctp_ulpevent_is_notification(event)) { DUMP_CORE; }

	spc = (struct sctp_paddr_change *)skb->data;

	if (SCTP_PEER_ADDR_CHANGE != spc->spc_type) { DUMP_CORE; }
	if (SCTP_ADDR_AVAILABLE != spc->spc_state ) { DUMP_CORE; }

	/* Check fields that are just pure copy-ins. */
	/* Make sure unused flags field is zero'd out. */
	if (0 != spc->spc_flags) { DUMP_CORE; }
	if (3 != spc->spc_error) { DUMP_CORE; }
	if (sctp_assoc2id(asoc) != spc->spc_assoc_id) { DUMP_CORE; }

	sctp_ulpevent_free(event);

} /* test_paddr_change() */


static void 
test_remote_error(const struct sctp_association *asoc)
{
	struct sctp_ulpevent *event;
	struct sctp_remote_error *sre;
	struct sk_buff *skb;
	struct sctp_chunk *chunk;

	/* Build an error chunk. */
	chunk = sctp_make_op_error(asoc,
				   NULL,
				   SCTP_ERROR_RSRC_LOW,
				   NULL,
				   0);
				          

	skb_pull(chunk->skb, sizeof(sctp_chunkhdr_t));

	event = sctp_ulpevent_make_remote_error(asoc,
						chunk,
						1, /* flags */
						GFP_KERNEL);

	if (NULL == event) { DUMP_CORE; }

	skb = sctp_event2skb(event);
	
	if (sizeof(struct sctp_remote_error) != skb->len) { DUMP_CORE; }
	if (!sctp_ulpevent_is_notification(event)) { DUMP_CORE; }

	sre = (struct sctp_remote_error *)skb->data;
       
	if (SCTP_REMOTE_ERROR != sre->sre_type) { DUMP_CORE; }

	/* Check fields that are just pure copy-ins. */
	/* Make sure unused flags field is zero'd out. */
	if (0 != sre->sre_flags) { DUMP_CORE; }

	/* The 'sre_error' field is in network endian and now
	 * so are our constants. 
	 */
	if (SCTP_ERROR_RSRC_LOW != sre->sre_error) { DUMP_CORE; }
	if (sctp_assoc2id(asoc) != sre->sre_assoc_id) { DUMP_CORE; }

	sctp_ulpevent_free(event);

} /* test_remote_error() */

static void 
test_send_failed(struct sctp_association *asoc)
{
	struct sctp_ulpevent *event;
	struct sctp_send_failed *ssf;
	struct sk_buff *skb;
	struct sctp_chunk *chunk;
	struct sctp_sndrcvinfo sinfo = {0};
	char *testdata = "Test data.";
	int len;

	sinfo.sinfo_stream = 1000;
	chunk = sctp_make_data(asoc, 
			       &sinfo,
			       strlen(testdata),
			       testdata);			       
			       
	if (NULL == chunk) { DUMP_CORE;	}
	
			       
	event = sctp_ulpevent_make_send_failed(asoc,
					       chunk,
					       SCTP_DATA_UNSENT,
					       SCTP_ERROR_INV_STRM,
					       GFP_KERNEL);
					       
					       
	if (NULL == event) { DUMP_CORE; }
	skb = sctp_event2skb(event);					       
	
	len = sizeof(struct sctp_send_failed);
	len += strlen(testdata);
	if (len != skb->len) { DUMP_CORE; }
	if (!sctp_ulpevent_is_notification(event)) { DUMP_CORE; }

	ssf = (struct sctp_send_failed *)skb->data;
	if (SCTP_SEND_FAILED!= ssf->ssf_type) { DUMP_CORE; }

	if (sinfo.sinfo_stream != ssf->ssf_info.sinfo_stream) {
		DUMP_CORE;
	}

	if (sinfo.sinfo_ppid != ssf->ssf_info.sinfo_ppid) {
		DUMP_CORE;
	}
	
	if (sinfo.sinfo_context != ssf->ssf_info.sinfo_context) {
		DUMP_CORE;
	}


	if (0 != strncmp(ssf->ssf_data,
			testdata,
			strlen(testdata))) { DUMP_CORE; }

	if (SCTP_DATA_UNSENT != ssf->ssf_flags) { DUMP_CORE; }
	if (SCTP_ERROR_INV_STRM != ssf->ssf_error) { DUMP_CORE; }
	if (sctp_assoc2id(asoc) != ssf->ssf_assoc_id) { DUMP_CORE; }

	sctp_ulpevent_free(event);

} /* test_send_failed() */

static void 
test_shutdown_event(const struct sctp_association *asoc)
{
	struct sctp_ulpevent *event;
	struct sctp_shutdown_event *sse;
	struct sk_buff *skb;

	event = sctp_ulpevent_make_shutdown_event(asoc,
						  1, /* flags */
						  GFP_KERNEL);
						
	if (NULL == event) { DUMP_CORE; }
	skb = sctp_event2skb(event);
	
	if (sizeof(struct sctp_shutdown_event) != skb->len) { DUMP_CORE; }
	if (!sctp_ulpevent_is_notification(event)) { DUMP_CORE; }

	sse = (struct sctp_shutdown_event *)skb->data;
	if (SCTP_SHUTDOWN_EVENT != sse->sse_type) { DUMP_CORE; }


	/* Check fields that are just pure copy-ins. */
	/* Make sure unused flags field is zero'd out. */
	if (0 != sse->sse_flags) { DUMP_CORE; }
	if (sctp_assoc2id(asoc) != sse->sse_assoc_id) { DUMP_CORE; }

	sctp_ulpevent_free(event);

} /* test_shutdown_event() */


static void
test_recvmsg(struct sctp_association *asoc)
{

	struct sctp_ulpevent *event;
	struct sk_buff *skb;
	struct sctp_chunk *chunk;
	struct sctp_chunk *rcvchunk;
	struct sctp_sndrcvinfo sinfo = {0};
	struct sctp_sndrcvinfo * rcvsinfo;
	sctp_chunkhdr_t *ch;
	char *testdata = "Test data.";
	char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	int rwnd1, rwnd2;

	sinfo.sinfo_stream = 10;
	sinfo.sinfo_ppid = 5000;
	sinfo.sinfo_flags = SCTP_UNORDERED;


	chunk = sctp_make_data(asoc, 
			       &sinfo,
			       strlen(testdata),
			       testdata);
			       
	if (NULL == chunk) { DUMP_CORE;	}

	/* Pretend that we have recieved this skb. */

	rcvchunk = sctp_chunkify(chunk->skb, 
				 asoc,
				 NULL);

	
				 
	if (rcvchunk == NULL) { DUMP_CORE; }

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
        rcvchunk->chunk_end = ((uint8_t *)ch) 
		+ WORD_ROUND(ntohs(ch->length));
        (void) skb_pull(rcvchunk->skb, sizeof(sctp_chunkhdr_t)); 

	rcvchunk->subh.data_hdr = (sctp_datahdr_t *)rcvchunk->skb->data;
	skb_pull(rcvchunk->skb, sizeof(sctp_datahdr_t));

	/* Save away the current rwnd. */
	rwnd1 = asoc->rwnd;

	event = sctp_ulpevent_make_rcvmsg(asoc, rcvchunk, GFP_KERNEL);
					  
	if (NULL == event) { DUMP_CORE; }

	/* Verify this is _not_ a MSG_NOTIFICATION. */
	if (sctp_ulpevent_is_notification(event)) { DUMP_CORE; }

	skb = sctp_event2skb(event);
	if (NULL == skb) { DUMP_CORE; }
	
		 
	/* Verify the payload. */
	if (0 != memcmp(skb->data, testdata, strlen(testdata))) {
		DUMP_CORE;
	}
	
	/* Verify that we've done rwnd accounting for the payload. */
	rwnd2 = asoc->rwnd;
	if (rwnd2 != rwnd1-strlen(testdata)) { DUMP_CORE; }

	/* Pull out SNDRCVINFO, similar to what the ULP will do. */
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	sctp_ulpevent_read_sndrcvinfo(event, &msg);
	
	/* Fixup msg.control/controllen since we are 
	 * running in the testframe. 
	 */
	test_frame_fixup_msg_control(&msg, sizeof(cmsgbuf));

	cmsg = CMSG_FIRSTHDR(&msg);
	if (NULL == cmsg) { DUMP_CORE; }
	

        /* Verify that we've recovered the needed SNDRCVINFO ancillary
	 * data.
	 */
	if (IPPROTO_SCTP != cmsg->cmsg_level) { DUMP_CORE; }
	if (SCTP_SNDRCV != cmsg->cmsg_type) { DUMP_CORE; }
		
	rcvsinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	if (NULL == rcvsinfo) { DUMP_CORE; }
	if (rcvsinfo->sinfo_stream != sinfo.sinfo_stream ) { DUMP_CORE; }
	if (rcvsinfo->sinfo_ppid != sinfo.sinfo_ppid ) { DUMP_CORE; }
	if (rcvsinfo->sinfo_flags != sinfo.sinfo_flags ) { DUMP_CORE; }
	if (rcvsinfo->sinfo_assoc_id != sctp_assoc2id(asoc)) { DUMP_CORE; }
	
	sctp_ulpevent_free(event);

        /* Check whether rwnd has been freed up. */	
	rwnd2 = asoc->rwnd;
	if (rwnd1 != rwnd2 ) { DUMP_CORE; }
}


/* This is the main test function.   
 */  
static void test_ulpevent()
{
	struct sctp_ulpevent *event;
	struct sk_buff *skb;
	struct sctp_endpoint *ep;
	struct sctp_association *asoc;
	union sctp_addr loop1;
	union sctp_addr loop2;
	struct sock *sk;
	

	/* Test generic event creation. */
	event = sctp_ulpevent_new(0, /* size */
				  0, /* MSG flags */
				  GFP_KERNEL);

	if (NULL == event ) { DUMP_CORE; }
	if (sctp_ulpevent_is_notification(event)) { DUMP_CORE; }

	/* sctp_ulpevent_free() cannot be used to free a generic ulpevent
	 * as it does more that freeing the skb.
	 */
	kfree_skb(sctp_event2skb(event));

	
	/* Test generic event, built from passed in skb. */
	skb = alloc_skb(0, GFP_KERNEL);
	event = sctp_skb2event(skb);

	sctp_ulpevent_init(event, MSG_NOTIFICATION);
	if (!sctp_ulpevent_is_notification(event)) {
		DUMP_CORE;
	}

	/* sctp_ulpevent_free() cannot be used to free a generic ulpevent
	 * as it does more that freeing the skb.
	 */
	kfree_skb(sctp_event2skb(event));

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
	sctp_assoc_add_peer(asoc, &loop2, GFP_KERNEL, SCTP_ACTIVE);

	/* Test building SCTP_ASSOC_CHANGE. */
	test_assoc_change(asoc);

	/* Test building SCTP_PEER_ADDR_CHANGE. */
	test_paddr_change(asoc);
	
	/* Test building SCTP_REMOTE_ERROR. */
	test_remote_error(asoc);

	/* Test building SCTP_SEND_FAILED. */
	test_send_failed(asoc);

	/* Test building SCTP_SHUTDOWN_EVENT. */
	test_shutdown_event(asoc);

	/* Test building a received message. */
	test_recvmsg(asoc);
	
} /* test_ulpevent() */


