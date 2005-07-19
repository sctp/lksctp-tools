/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (C) 1999 Cisco
 * Copyright (C) 1999-2000 Motorola
 # Copyright (C) 2001 Nokia
 * Copyright (C) 2001 La Monte H.P. Yarroll
 * Copyright (C) 2003 Intel Corp.
 *
 * This file is part of the SCTP Linux kernel reference implementation
 *
 * These functions populate the sctp protocol structure for sockets.
 *
 * The SCTP reference implementation  is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * The SCTP reference implementation is distributed in the hope that it
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
 * Please send any bug reports or fixes you make to one of the following
 * email addresses:
 *
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Narasimha Budihal <narsi@refcode.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Jon Grimm <jgrimm@us.ibm.com>
 * Daisy Chang <daisyc@us.ibm.com>
 * Sridhar Samudrala <sri@us.ibm.com>
 * Ardelle Fan <ardelle.fan@intel.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporealated into the next SCTP release.
 */

#ifndef TEST_FRAME
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h> /* for sockaddr_in */
#include <sys/errno.h>
#include <errno.h>
#include <netinet/sctp.h>
#else
#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#endif /* TEST_FRAME */

#include <errno.h>
#include <funtest.h>

int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);

extern unsigned long volatile jiffies;
extern int network_up[];
extern struct notifier_block *inetaddr_notifier_on;

extern void test_update_rtables(void);

/* These two variables are for killing chunks.  If slaughter is true,
 * we kill the next packet where the first chunk has a chunk type of
 * scapegoat.
 */
#ifdef TEST_FRAME
int slaughter = 0;
int num_slaughter = 0;
int congest = 0;
sctp_cid_t scapegoat;
void *replacement;
int replacement_len;
int ip_mtu = SCTP_DEFAULT_MAXSEGMENT;

LIST_HEAD(test_timers);
#endif /* TEST_FRAME */
/* This function prints the cmsg data. */
int
test_print_cmsg(sctp_cmsg_t type, sctp_cmsg_data_t *data)
{
	switch(type) {
	case SCTP_INIT:
		printf("INIT\n");
		printf("sinit_num_ostreams %d\n",
		       data->init.sinit_num_ostreams);
		printf("sinit_max_instreams %d\n",
		       data->init.sinit_max_instreams);
		printf("sinit_max_attempts %d\n",
		       data->init.sinit_max_attempts);
		printf("sinit_max_init_timeo %d\n",
		       data->init.sinit_max_init_timeo);

		break;
	case SCTP_SNDRCV:
		printf("SNDRCV\n");
		printf("sinfo_stream %u\n",	data->sndrcv.sinfo_stream);
		printf("sinfo_ssn %u\n",	data->sndrcv.sinfo_ssn);
		printf("sinfo_flags 0x%x\n",	data->sndrcv.sinfo_flags);
		printf("sinfo_ppid %u\n",	data->sndrcv.sinfo_ppid);
		printf("sinfo_context %x\n",	data->sndrcv.sinfo_context);
		printf("sinfo_tsn %u\n",        data->sndrcv.sinfo_tsn);
		printf("sinfo_cumtsn %u\n",     data->sndrcv.sinfo_cumtsn);
		break;

	default:
		printf("Unknown type: %d\n", type);
		break;
	}

	return 0;

} /* test_print_cmsg() */

/* This function prints the message. */
int
test_print_message(int sk, struct msghdr *msg, size_t msg_len) {
	struct msghdr *smsg = msg;
	sctp_cmsg_data_t *data;
	struct cmsghdr *scmsg;
	int i;
	int done = 0;
	char save;

	printf("\n\n****TEST PRINT MESSAGE****\n\n");
	for (scmsg = CMSG_FIRSTHDR(msg);
	     scmsg != NULL;
	     scmsg = CMSG_NXTHDR(msg, scmsg)) {
		     data = (sctp_cmsg_data_t *)CMSG_DATA(scmsg);
		     test_print_cmsg(scmsg->cmsg_type, data);
	}

	if (!(MSG_NOTIFICATION & smsg->msg_flags)) {
		int index = 0;
		/* Make sure that everything is printable and that we
		 * are NUL terminated...
		 */
		printf("Body:  ");
		while ( msg_len > 0 ) {
			char *text;
			int len;

			text = smsg->msg_iov[index].iov_base;
			len = smsg->msg_iov[index].iov_len;

                        save = text[msg_len-1];
			if ( len > msg_len ) {
                                text[(len = msg_len) - 1] = '\0';
                        }

			if ( (msg_len -= len) > 0 ) { index++; }

			for (i = 0; i < len - 1; ++i) {
                                if (!isprint(text[i])) text[i] = '.';
                        }

			printf("%s", text);
			text[msg_len-1] = save;

			if ( (done = !strcmp(text, "exit")) ) { break; }
		}

		printf("\n");
	} /* if (we have DATA) */

	printf("\n\n****END TEST PRINT MESSAGE****\n\n");
	return done;

} /* test_print_message() */

/* A helper function of common function checking data from notifcations. */
static inline int
test_common_check_notification(union sctp_notification *sn,
			       uint16_t sn_type,
			       uint32_t additional)
{
	if (sn->sn_header.sn_type != sn_type) { return 1; }

	switch(sn->sn_header.sn_type){
	case SCTP_ASSOC_CHANGE:
		if (sn->sn_assoc_change.sac_state != additional) {
			return 1;
		}
		break;
	default:
		break;
	}

	return 0;

} /* test_common_check_notification () */

/* Verify a message as a notification, its type, and possibly an
 * additional field.
 */
int
test_check_notification(struct msghdr *msg,
			int datalen,
			int expected_datalen,
			uint16_t sn_type,
			uint32_t additional)
{
	char *data;
	union sctp_notification *sn;
	int check_failed = 0;

	if (!(msg->msg_flags & MSG_NOTIFICATION)) {
		check_failed = 1;
		goto out;
	}


	/* Fixup for testframe. */
	data = (char *)msg->msg_iov[0].iov_base;

	if (expected_datalen > 0) {

		if (datalen != expected_datalen) {
			check_failed = 2;
		}

		sn = (union sctp_notification *)data;
		if (test_common_check_notification(sn,
						   sn_type,
						   additional)) {
			check_failed = 3;
			DUMP_CORE;
		}
	}

out:
	if (check_failed) {
		DUMP_CORE;
	}

	return check_failed;

} /* test_check_notification() */

/* This function checks messages to see if they are of type 'event'
 * and if they are well-formed.
 */
int
test_check_message(struct msghdr *msg, int controllen,
		   sctp_cmsg_t event)
{


        if (msg->msg_controllen != controllen) {
                printf("Got control structure of length %d, not %d\n",
                       msg->msg_controllen, controllen);
                DUMP_CORE;
        }
        if (controllen > 0 && event != CMSG_FIRSTHDR(msg)->cmsg_type) {
                printf("Wrong kind of event: %d, not %d\n",
                       CMSG_FIRSTHDR(msg)->cmsg_type, event);
                DUMP_CORE;
        }

	return 1;

} /* test_check_message() */

/* This function checks to see if there is SCTP_SNDRCV ancillary data
 * and that it matches the expected results.
 *
 * WARNING: Make sure that the msg_control/controllen have been fixed up before
 * calling this function.   The CMSG macros need this value to work correctly.
 *
 */
int
test_check_sndrcvinfo(struct msghdr *msg,
			    uint16_t flags,
			    uint16_t stream,
			    uint32_t ppid)
{
	struct cmsghdr *cmsg = NULL;
	struct sctp_sndrcvinfo *sinfo = NULL;
	int passed = 0;

	/* Receive auxiliary data in msgh. */
	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)){

		if (IPPROTO_SCTP == cmsg->cmsg_level
		    && SCTP_SNDRCV == cmsg->cmsg_type) {
			break;
		}
	} /* for( all cmsgs) */


	if (cmsg) {
		if (cmsg->cmsg_len
		    < CMSG_LEN(sizeof(struct sctp_sndrcvinfo))) {
			SCTP_DEBUG_PRINTK("cmsg len too small\n");
		}
		else {
			sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
		}
	}


	if (sinfo) {
		if (sinfo->sinfo_stream != stream) {
			SCTP_DEBUG_PRINTK("stream mismatch: "
					  "expected:%x got:%x\n",
					  stream,
					  sinfo->sinfo_stream);
		}
		else if (sinfo->sinfo_ppid != ppid) {
			SCTP_DEBUG_PRINTK("ppid mismatch: "
					  "expected:%x got:%x\n",
					  ppid,
					  sinfo->sinfo_ppid);
		}
		else if (sinfo->sinfo_flags != flags) {
			SCTP_DEBUG_PRINTK("flags mismatch: "
					  "expected:%x got:%x\n",
					  flags,
					  sinfo->sinfo_flags);
		}
		else {
			passed = 1;
		}
	}


	return passed;

} /* test_check_sndrcvinfo() */

#ifndef TEST_FRAME
int
test_getsockopt(int sk, sctp_assoc_t assoc_id, int optname)
{
	int error = 0;
        int family;

	switch(optname) {
	case SCTP_STATUS:
	{
		struct sctp_status status;
		struct sctp_paddrinfo paddrinfo;
		int status_len;

		memset(&status, 0, sizeof(status));
		if (assoc_id)
			status.sstat_assoc_id = assoc_id;
		status_len = sizeof(struct sctp_status);
		error = getsockopt(sk, SOL_SCTP, SCTP_STATUS,
                		(char *)&status, &status_len);
		if (error != 0) { break; }

		printf("\nSock FD: %d SCTP_STATUS\n", sk);
		printf("\tAssociation ID: %p\n", status.sstat_assoc_id);
		printf("\tState: %d\n", status.sstat_state);
		printf("\tReceiver Window Size: %d\n", status.sstat_rwnd);
		printf("\tUnacknowledged Data: %d\n", status.sstat_unackdata);
		printf("\tPending data: %d\n", status.sstat_penddata);
		printf("\tInbound Streams: %d\n", status.sstat_instrms);
		printf("\tOutbound Streams: %d\n", status.sstat_outstrms);
		printf("\tFragmentation Point: %d\n",
				status.sstat_fragmentation_point);
		paddrinfo = status.sstat_primary;
		family = ((struct sockaddr *)
			  &paddrinfo.spinfo_address)->sa_family;
		switch (family) {
		case AF_INET:
		{
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)&paddrinfo.spinfo_address;
			printf("\tPrimary Peer Address: (0x%x, %d)\n",
				sin->sin_addr.s_addr, sin->sin_port);
			break;
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)&paddrinfo.spinfo_address;
			printf("\tPrimary Peer Address: (0x%x.0x%x.0x%x.0x%x,"
				" %d)\n",
				sin6->sin6_addr.s6_addr32[0],
				sin6->sin6_addr.s6_addr32[1],
				sin6->sin6_addr.s6_addr32[2],
				sin6->sin6_addr.s6_addr32[3], sin6->sin6_port);
			break;
		}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
		default:
			printf("\tPrimary Peer Address"
			       ":Unexpected Family(%d)\n", family);
			break;
		}

		printf("\tPrimary Peer State: %d\n", paddrinfo.spinfo_state);
		printf("\tPrimary Peer Congestion Window: %d\n",
						paddrinfo.spinfo_cwnd);
		printf("\tPrimary Peer Smoothed Round trip time: %d\n",
						paddrinfo.spinfo_srtt);
		printf("\tPrimary Peer Retransmission Timeout: %d\n",
						paddrinfo.spinfo_rto);
		printf("\tPrimary Peer Path MTU: %d\n\n", paddrinfo.spinfo_mtu);
		break;
	}
	case SCTP_EVENTS:
	{
		struct sctp_event_subscribe subscribe;
		int len = sizeof(struct sctp_event_subscribe);

		error = getsockopt(sk, SOL_SCTP, SCTP_EVENTS,
                			(char *)&subscribe, &len);
		if (error != 0) { break; }

		printf("SCTP_EVENTS: Enabled events on socket fd: %d\n",
		       sk);
		if (subscribe.sctp_data_io_event) {
			printf("\tData io events\n");
		}
		if (subscribe.sctp_association_event) {
			printf("\tAssociation change events\n");
		}
		if (subscribe.sctp_address_event) {
			printf("\tAddress events\n");
		}
		if (subscribe.sctp_send_failure_event) {
			printf("\tSend failure events\n");
		}
		if (subscribe.sctp_peer_error_event) {
			printf("\tPeer error events\n");
		}
		if (subscribe.sctp_shutdown_event) {
			printf("\tShutdown events\n");
		}
		if (subscribe.sctp_partial_delivery_event) {
			printf("\tPartial delivery events\n");
		}
		if (subscribe.sctp_adaption_layer_event) {
			printf("\tAdaptation layer events\n");
		}
		break;
	}
	default:
		printf("getsockopt(%d) not yet implemented\n", optname);
		error = -1;
		break;
	}

	return (error);
}
int
test_setsockopt(int sk, sctp_assoc_t assoc_id, int optname, char *optval)
{
	int error = 0;

	switch(optname) {
	case SCTP_EVENTS:
	{
		error = setsockopt(sk, SOL_SCTP, optname, optval,
				   sizeof(struct sctp_event_subscribe));
		break;
	}
	default:
		printf("setsockopt(%d) not yet implemented\n", optname);
		error = -ENOPROTOOPT;
		break;
	}

	return (error);

} /* test_setsockopt() */
#endif

#ifdef TEST_FRAME
/* This function prints the message. */
void test_frame_print_message(struct sock *sk, struct msghdr *msg)
{
	int len = msg->msg_iov[0].iov_len;
	char *text = msg->msg_iov[0].iov_base;
	struct sctp_cmsghdr *cmsg = (struct sctp_cmsghdr *)msg->msg_control;
	sctp_cmsg_t type = cmsg->cmsg_type;
	sctp_cmsg_data_t *data = &cmsg->cmsg_data;
	int i;

	printf("\n\n****TEST PRINT MESSAGE****\n\n");
	/* Print header info.  */
	switch(type) {
	case SCTP_INIT:
		printf("INIT\n");
		printf("sinit_num_ostreams %d\n",
		       data->init.sinit_num_ostreams);
		printf("sinit_max_instreams %d\n",
		       data->init.sinit_max_instreams);
		printf("sinit_max_attempts %d\n",
		       data->init.sinit_max_attempts);
		printf("sinit_max_init_timeo %d\n",
		       data->init.sinit_max_init_timeo);

		break;
	case SCTP_SNDRCV:
		printf("SNDRCV\n");
		printf("sinfo_stream %u\n",	data->sndrcv.sinfo_stream);
		printf("sinfo_ssn %u\n",	data->sndrcv.sinfo_ssn);
		printf("sinfo_flags 0x%x\n",	data->sndrcv.sinfo_flags);
		printf("sinfo_ppid %u\n",	data->sndrcv.sinfo_ppid);
		printf("sinfo_context %x\n",	data->sndrcv.sinfo_context);
		printf("sinfo_tsn %u\n",        data->sndrcv.sinfo_tsn);
		printf("sinfo_cumtsn %u\n",      data->sndrcv.sinfo_cumtsn);
		break;
	default:
		printf("Unknown type: %d\n", type);
		break;
	}


	if (!(MSG_NOTIFICATION & msg->msg_flags)) {
		/* Make sure that everything is printable and that we
		 * are NUL terminated...
		 */
		text[len-1] = '\0';
		for (i = 0; i < len; ++i) {
			if (!isprint(text[i])) {
				text[i] = '.';
			}
		}

		printf("Body:  %s\n", text);
	} /* if (we have DATA) */

	printf("\n\n****END TEST PRINT MESSAGE****\n\n");
	return;
} /* test_frame_print_message() */


/* This is a version of sendto(2) which takes a sock rather than a
 * file descriptor.  In real life, sendto() is a wrapper for
 * sendmsg().
 */
int
test_sendto(struct sock *sk,
            void *message, size_t msg_len,
            int flags, uint16_t streamID,
            struct sockaddr_in *to, int tolen)
{

        uint16_t payloadID = 0; /* BUG? */
        struct sctp_endpoint *ep;
        struct sctp_association *asoc;
	struct sctp_transport *transport;
        struct sctp_chunk *chunk;
	struct sctp_sndrcvinfo sinfo;
        int error = msg_len;
	sctp_scope_t scope;

        ep = sctp_sk(sk)->ep;

        asoc = sctp_endpoint_lookup_assoc(ep, (union sctp_addr *)to,
					  &transport);

        /* Do we need to create the association?  */
        if (NULL == asoc) {
		scope = sctp_scope((union sctp_addr *)to);
                asoc = sctp_association_new(ep, sk, scope, GFP_KERNEL);
                if (NULL == asoc) {
                        error = -ENOMEM;
                        return(error);
                }
                /* Prime the peer's transport structures.  */
                sctp_assoc_add_peer(asoc, (union sctp_addr *)to,
				    GFP_KERNEL, SCTP_ACTIVE);
                /* Register the association with the endpoint.  */
		sctp_endpoint_add_asoc(ep, asoc);
        } /* if (we need an association) */

        /* ASSERT: we have a valid association at this point.  */

	memset(&sinfo, 0x00, sizeof(sinfo));
	sinfo.sinfo_ppid = payloadID;
	sinfo.sinfo_stream = streamID;

        /* These next two lines REALLY SHOULD be sctp_primitive_SEND(). */
        chunk = sctp_make_data(asoc, &sinfo, msg_len, message);

        error = sctp_outq_tail(&asoc->outqueue, chunk);
        if (error < 0) {
                return(error);
        }
	else {
                error = msg_len;
        }

        if (SCTP_STATE_CLOSED == asoc->state) {
                sctp_primitive_ASSOCIATE(asoc, NULL);
        }

        return(error);
} /* test_sendto() */



int
test_frame_check_notification(struct msghdr *msg,
			      int orig_datalen,
			      int expected_datalen,
			      uint16_t sn_type,
			      uint32_t additional)
{
	int datalen;
	char *data;
	union sctp_notification *sn;
	int check_failed = 0;

	if (!(msg->msg_flags & MSG_NOTIFICATION)) {
		check_failed = 1;
		goto out;
	}


	datalen = orig_datalen - msg->msg_iov[0].iov_len;
	SCTP_DEBUG_PRINTK("orig: %d, got:%d, expected %d\n",
			  orig_datalen, datalen, expected_datalen);

	/* Fixup for testframe. */
	data = ((char *)msg->msg_iov[0].iov_base) - datalen;

	if (expected_datalen > 0) {

		if (datalen != expected_datalen) {
			check_failed = 2;
		}

		sn = (union sctp_notification *)data;
		if (test_common_check_notification(sn,
						  sn_type,
						  additional)){
			check_failed = 3;
			goto out;
		}


	}

out:
	if (check_failed) {
		DUMP_CORE;
	}

	return check_failed;

} /* test_frame_check_notification() */


/* This function checks messages to see if they are of type 'event'
 * and if they are well-formed.
 */
int
test_frame_check_message(struct msghdr *msg,
			 int orig_controllen,
			 int orig_datalen,
			 void *orig_data,
			 int expected_controllen,
			 size_t expected_datalen,
			 void *expected_data,
			 sctp_cmsg_t expected_event)
{
	struct sctp_cmsghdr *got_control;
	int got_controllen = orig_controllen - msg->msg_controllen;
	int got_datalen = orig_datalen - msg->msg_iov[0].iov_len;
	char *got_data;

	int check_failed = 0;

	expected_controllen = CMSG_SPACE(expected_controllen);

	got_data = ((char *)msg->msg_iov[0].iov_base) - got_datalen;
	got_control = (struct sctp_cmsghdr *)
		(((uint8_t *)msg->msg_control) - got_controllen);

	printk("\nChecking message...\n");

	/* Check the control structure.  */
	if (expected_event) { 
	if (got_controllen != expected_controllen) {
                printk("Got control structure length %d, not %d.\n",
                       got_controllen, expected_controllen);
		check_failed = 1;
        } else {
		printk("Controllen of %d passes.\n", expected_controllen);
	}

        if (expected_event != got_control->cmsg_type) {
		printk("Wrong kind of event: %d, not %d\n",
                       got_control->cmsg_type, expected_event);
		check_failed = 2;
        }
	else {
		printk("Event %d passes.\n", expected_event);
	}
	}

	/* Now check the data we got back.  */
	if (expected_datalen > 0) {
                if (got_datalen != expected_datalen) {
                        printk("Got %d bytes data, not %d.\n",
                               got_datalen, expected_datalen);
			printk("iovlen:%d\n",msg->msg_iov[0].iov_len);
                        check_failed = 3;
                }
		else {
                        printk("Datalen of %d passes.\n", got_datalen);
                }
                if (0 != strncmp(got_data, expected_data, expected_datalen)) {
                        printk("Data \"%s\" does not match \"%s\".\n",
                               got_data, (char *) expected_data);
                        check_failed = 4;
                }
		else {
                        printk("Data \"%s\" passes.\n", got_data);
                }
        }

	if (check_failed){
		DUMP_CORE;
	}

	return 1;
} /* test_frame_check_message() */

/* Fixup msg_control/msg_controllen.  _When_ executing in the
 * testframe these fields are not left in a valid state after recvmsg().
 * This function puts them into the expected state so consequent CMSG
 * macro calls will work.
 */
void
test_frame_fixup_msg_control(struct msghdr *msg,
			     int original_len)
{
	int cmlen=0;

	if (original_len >= msg->msg_controllen) {
		cmlen = original_len - msg->msg_controllen;
	}
	else {
		printk(KERN_ERR "%s: original:%x, controllen:%x\n",
			__FUNCTION__, original_len, msg->msg_controllen);
		DUMP_CORE;
	}

	msg->msg_controllen += cmlen;
	msg->msg_control -= cmlen;

	return;

} /* test_frame_fixup_msg_control() */



/* Run the network for one packet in both directions, and then confirm
 * that we see the specified chunk.
 *
 * Return a positive number if we see the specified chunk, 0 if the
 * chunk is not present, and a negative number if something goes
 * wrong.
 */
int
test_step(sctp_cid_t cid, int net)
{
	int error;

	error = test_run_network_once(net);
	if (error < 0) { return error; }

	return(test_for_chunk(cid, net));
} /* test_step() */

/* This function simulates the specified network for one packet.
 * Return 0 if the network is empty, a positive number if there are
 * packets remaining on the network, and a negative number if
 * something goes wrong.
 */
int
test_run_network_once(int net)
{
	struct sctp_ep_common *ep;
	struct sctp_hashbucket *head;
        int error = 0;
	int i;

	/* The transmission part of the simulated network
	 * happens in test_kernel.c.
	 */
	simulate_network_once(net);


        /* Find errors... */

	for (i = 0; i < sctp_ep_hashsize; i++) {
		head = &sctp_ep_hashtable[i];
		for (ep = head->chain; ep; ep = ep->next) {
			if (ep->sk->sk_err) {

				error = ep->sk->sk_err;
				printk(KERN_DEBUG
				       "\nERROR: socket %p (of %p):  %d=%s\n",
				       ep->sk, ep, error,
				       (error > 0) ? "POSITIVE?" :
				       ((0 == error) ? "ZERO?" :
					((error > -SCTP_IERROR_BASE) ?
					 strerror(-error) :"IERROR")));

				/* Reset for next time... */
				ep->sk->sk_err = 0;
				goto out;
			    }
		}
	}


out:
	if (error < 0) {
		return error;
	}  else if (is_empty_network(net)) {
		return 0;
	} else {
		return 1;
	}

} /* test_run_network_once() */

/* Test for the presence of a given chunk on the Internet.  */
int
test_for_chunk(sctp_cid_t cid, int net)
{
	struct sk_buff_head *network = get_Internet(net);
	struct bare_sctp_packet *packet;
	sctp_chunkhdr_t *chunk;
	struct sk_buff *skb;

	/* We loop through the network for the packets. */
	SK_FOR(struct sk_buff *, skb, *network, {

		/* We loop through each packet for the chunks. */
		packet = test_get_sctp(skb->data);
		for (chunk = &packet->ch;
		     chunk < (sctp_chunkhdr_t *) skb->tail;
			chunk = (struct sctp_chunkhdr *)((__u8 *)chunk + WORD_ROUND(ntohs(chunk->length)))) {

			if (cid == chunk->type) { return 1; }

		} /* for(each chunk in the packet) */

	}); /* SK_FOR(network) */

	return 0;

} /* test_for_chunk() */

static sctp_chunkhdr_t *test_find_chunk_inner_loop(struct sk_buff *skb,
							sctp_cid_t cid,
							test_chunk_fn_t test,
							void *arg);

/* Find a specific chunk on the Internet.  */
sctp_chunkhdr_t *
test_find_chunk(int net, sctp_cid_t cid,
		test_chunk_fn_t test, void *arg)
{
	struct sk_buff_head *network = get_Internet(net);
	sctp_chunkhdr_t *chunk;
	struct sk_buff *skb;

	/* We loop through the network for the packets. */
	SK_FOR(struct sk_buff *, skb, *network, {

		chunk = test_find_chunk_inner_loop(skb, cid, test, arg);
		if (chunk) { return chunk; }

	}); /* SK_FOR(network) */

	return NULL;

} /* test_find_chunk() */

static sctp_chunkhdr_t *
test_find_chunk_inner_loop(struct sk_buff *skb,
			   sctp_cid_t cid,
			   test_chunk_fn_t test, void *arg)
{
	struct bare_sctp_packet *packet;
	sctp_chunkhdr_t *chunk;
	/* We loop through each packet for the chunks. */
	packet = test_get_sctp(skb->data);
	for (chunk = &packet->ch;
	     chunk < (sctp_chunkhdr_t *) skb->tail;
		chunk = (struct sctp_chunkhdr *)((__u8 *)chunk + WORD_ROUND(ntohs(chunk->length)))) {

		if (cid == chunk->type && (test ? (*test)(arg, chunk) : 1)) {
			return chunk;
		}

	} /* for(each chunk in the packet) */

	return NULL;
} /* test_find_chunk_inner_loop() */

/* This function simulates the Internet. */
int
test_run_network(void)
{
        int error = 0;
        int i;

        /* Make time progress.  */
        test_run_timeout();

	do {
		/* Go through all the networks. */
        	for (i = 0; i < NUM_NETWORKS; ++i) {

			/* Process all the packets on this network. */
			do {
				error = test_run_network_once(i);
			} while (0 < error);
		}

	/* It is possible that the processing of packets on one network, can
	 * cause new packets to be put on another network. So check for any
	 * new packets that are on the Internet and if so, go through the loop
	 * again.
	 */
	} while (!is_empty_Internet());

        return(error);
} /* test_run_network() */


/**
 * This implements Internet fast-forward.
 * We return 0 if nothing goes wrong.
 */
int test_run_timeout(void)
{
	struct list_head *pos;
	struct list_head *tmp;
	struct timer_list *tl;

	/* Walk the queue, deleting and running timers.  */
start_over:
	list_for_each_safe(pos, tmp, &test_timers) {
	
		tl = list_entry(pos, struct timer_list, entry);
		if (tl->expires < jiffies) {

			list_del(pos);
			init_timer(tl);

			/* BUG?:  We probably want to see if this fails.  */
			(*tl->function)(tl->data);
		}
		/* The testframe has no locking so the timer may have
		 * been deleted under us.  Grrr...
		 */
		if (!tmp)
			break;
		if (!tmp->next || tmp->next == LIST_POISON1) 
			goto start_over;
	}

	/* Cleanup any expired routing table entries. */
	test_update_rtables();

	return 0;

} /* test_run_timeout() */


/**
 * Replace the next packet of type chunk_type with the packet in raw.
 */
int
test_replace_packet(void *raw, int raw_len,
		    sctp_cid_t chunk_type)
{
	replacement = raw;
	replacement_len = raw_len;
	scapegoat = chunk_type;

	return 0;
} /* test_replace_packet() */

/**
 * Simulated impairment function.  We specify that the next chunk of a
 * specified type should experience 100% packet loss (as it were).
 */
int test_kill_next_packet(sctp_cid_t chunk_type)
{
	slaughter = 1;
	scapegoat = chunk_type;

	return 0;
} /* test_kill_next_packet() */

void test_kill_next_packets(int num)
{
	slaughter = 1;
	num_slaughter = num;
}

/**
 * Simulated impairment function.  We specify that the next chunk of a
 * specified type should experience congestion.
 */
int
test_congest_next_packet(sctp_cid_t chunk_type)
{
	congest = 1;
	scapegoat = chunk_type;

	return 0;

} /* test_congest_next_packet() */


/* Break one of the simulated networks.  */
int
test_break_network(int i)
{
	int old = network_up[i];
        network_up[i] = 0;
	return old;

} /* test_break_network(int i) */

/* Restore a network to health.  */
int
test_fix_network(int i)
{
	int old = network_up[i];
        network_up[i] = 1;
	return old;

} /* test_fix_network(int i) */

int
test_set_ip_mtu(int mtu)
{
	if (mtu <= (sizeof(struct ipv6hdr) + sizeof(struct sctphdr)))
		return 1;

	ip_mtu = mtu;
	return 0;
}

int
test_bind(struct sock *sk, struct sockaddr *addr, size_t addr_size)
{
        switch (addr->sa_family) {
	case AF_INET:
		inet_sk(sk)->saddr =
			((struct sockaddr_in *)addr) ->sin_addr.s_addr;
		break;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)

	case AF_INET6:
		inet6_sk(sk)->saddr =
			((struct sockaddr_in6 *)addr)->sin6_addr;
		break;

#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */


	default:
		DUMP_CORE;
	}

        return(sctp_bind(sk, addr, addr_size));
} /* test_bind() */


int
test_bindx(struct sock *sk, struct sockaddr *addrs, int addrs_size, int flags)
{
	int setsock_option;

	switch(flags) {
	case SCTP_BINDX_ADD_ADDR:
		setsock_option = SCTP_SOCKOPT_BINDX_ADD;
		break;
	case SCTP_BINDX_REM_ADDR:
		setsock_option = SCTP_SOCKOPT_BINDX_REM;
		break;
	default:
		return -EINVAL;
	}

	return sctp_setsockopt(sk, SOL_SCTP, setsock_option, (char *)addrs,
			       addrs_size);

} /* test_bindx() */


int
test_connectx(struct sock *sk, struct sockaddr *addrs, int addrs_size)
{
	return sctp_setsockopt(sk, SOL_SCTP, SCTP_SOCKOPT_CONNECTX,
			       (char *)addrs, addrs_size);

} /* test_connectx() */


int
test_listen(struct sock *sk, int backlog)
{
	int err;

	/* FIXME: Once we have TCP-style sockets we should call
	 * style specific function.
	 */
	err = sctp_seqpacket_listen(sk, backlog);

	return err;

} /* test_listen() */

/* Send a test message on a socket.
 * Die horribly if something goes awry.
 */
void
test_frame_send_message2(struct sock *sk, struct sockaddr *addr, uint8_t *buff,
			 sctp_assoc_t associd, uint16_t stream,
			 uint32_t ppid, uint16_t flags)
{
        struct msghdr msg;
	struct cmsghdr *cmsg;
        struct iovec iov;
	char infobuf[CMSG_SPACE_SNDRCV] = {0};
	struct sctp_sndrcvinfo *sinfo;
        int len = strlen(buff) + 1;
        size_t bytes_sent;

        msg.msg_name = addr;
	switch (addr->sa_family) {
	case AF_INET:
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;
	default:
		DUMP_CORE;
		break;
	}

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_iov->iov_base = buff;
	msg.msg_iov->iov_len = len;

        /* Build up a SCTP_SNDRCV CMSG. */
	msg.msg_control = infobuf;
	msg.msg_controllen = sizeof(infobuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	/* Initialize the payload. */
	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo->sinfo_ppid = ppid;
	sinfo->sinfo_stream = stream;
	sinfo->sinfo_flags = flags;
	sinfo->sinfo_assoc_id = associd;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));

	bytes_sent = sctp_sendmsg(NULL, sk, &msg, len);
	if (bytes_sent != len) { DUMP_CORE; }
}


/* Send a test message on a socket on stream 0, ppid 0, and no flags.
 * Die horribly if something goes awry.
 */
void
test_frame_send_message(struct sock *sk, struct sockaddr *addr, uint8_t *buff)
{
	struct msghdr msg;
	struct iovec iov;
	int len = strlen(buff) + 1;
	size_t bytes_sent;

	msg.msg_name = addr;
	switch (addr->sa_family) {
	case AF_INET:
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;
	default:
		DUMP_CORE;
		break;
	}

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_iov->iov_base = buff;
	msg.msg_iov->iov_len = len;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

        bytes_sent = sctp_sendmsg(NULL, sk, &msg, len);
        if (bytes_sent != len) { DUMP_CORE; }
}

/* Receive a message from the socket. It should match the contents of buff.
 * Die horribly if something unexpected happens.
 */
void test_frame_get_message(struct sock *sk, uint8_t *buff)
{
	uint8_t big_buffer[REALLY_BIG];
        struct msghdr msg;
        struct iovec iov;
        int len = (NULL == buff)?0:strlen(buff) + 1;
        int cmsghdr[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
        int addr_len;
        int error;

        memset(&msg, 0, sizeof(struct msghdr));
        iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsghdr;
        msg.msg_controllen = sizeof(cmsghdr);
        error = sctp_recvmsg(NULL, sk, &msg, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);

	if (NULL != buff){
		if (error < 0) { DUMP_CORE; }
	} else {
		if (error != -EAGAIN) { DUMP_CORE; }
		return;
	}
	printk("%s %d %d\n", big_buffer, REALLY_BIG, len);
	test_frame_check_message(&msg,
				 /* orig */
				 sizeof(cmsghdr),
				 REALLY_BIG,
				 big_buffer,
				 /* expected */
				 sizeof(struct sctp_sndrcvinfo),
				 len,
				 buff,
				 (SOCK_SEQPACKET == sk->sk_family)?SCTP_SNDRCV:0);

} /* test_frame_get_message() */

/* Receive a message from the socket. It should match the contents of buff.
 * The in_flags are passed to recvmsg() call. The out_flags should match
 * the msg_flags field returned in the msghdr.
 * Die horribly if something unexpected happens.
 */
void test_frame_get_message2(struct sock *sk, uint8_t *buff, int len, uint32_t in_flags, uint32_t out_flags)
{
	uint8_t big_buffer[REALLY_BIG];
        struct msghdr msg;
        struct iovec iov;
        int cmsghdr[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
        int addr_len;
        int error;

        memset(&msg, 0, sizeof(struct msghdr));
        iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsghdr;
        msg.msg_controllen = sizeof(cmsghdr);
        error = sctp_recvmsg(NULL, sk, &msg, len,
                             /* noblock */ 1, /* flags */ in_flags,
                             &addr_len);

	if (NULL != buff){
		if (error < 0) { DUMP_CORE; }
	} else {
		if (error != -EAGAIN) { DUMP_CORE; }
		return;
	}
	printk("%s %d %d\n", big_buffer, REALLY_BIG, len);
	test_frame_check_message(&msg,
				 /* orig */
				 sizeof(cmsghdr),
				 REALLY_BIG,
				 big_buffer,
				 /* expected */
				 sizeof(struct sctp_sndrcvinfo),
				 len,
				 buff,
				 (SOCK_SEQPACKET == sk->sk_family)?SCTP_SNDRCV:0);

	if ((msg.msg_flags & out_flags) != out_flags)
		DUMP_CORE;

} /* test_frame_get_message2() */

void *test_frame_get_cmsg_data(struct msghdr *msgh, int level, int type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msgh);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msgh, cmsg)) {

		if ((cmsg->cmsg_level == level) &&
		    (cmsg->cmsg_type == type)) {
			return CMSG_DATA(cmsg);
		}
		printf("cmsg now %p\n", cmsg);
		printf("cmsg->cmsg_level = %d\n", cmsg->cmsg_level);
		printf("wanted %d\n", level);
		exit(0);
	}

	return NULL;
}

/* Receive a message from the socket.  Lets receive it in piece parts;
 * good for testing MSG_EOR and for partial data delivery.
 * Die horribly if something unexpected happens.
 */
#define NOT_SO_BIG 100
void test_frame_get_message_pd(struct sock *sk, uint8_t *buff, int aborted)
{
	uint8_t big_buffer[NOT_SO_BIG];
	struct sctp_association *asoc;
        struct msghdr msg;
        struct iovec iov;
        int len = (NULL == buff)?0:strlen(buff) + 1;
        int cmsghdr[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct sctp_sndrcvinfo *sinfo;
	struct sctp_pdapi_event *pdapi;
        int addr_len;
        int error, sack_tx=0;
	int offset = 0;

	asoc = test_ep_first_asoc(sctp_sk(sk)->ep);

	while (len) {

		memset(&msg, 0, sizeof(struct msghdr));
		iov.iov_base = big_buffer;
		iov.iov_len = NOT_SO_BIG;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsghdr;
		msg.msg_controllen = sizeof(cmsghdr);
		error = sctp_recvmsg(NULL, sk, &msg, NOT_SO_BIG,
				     /* noblock */ 1, /* flags */ 0,
				     &addr_len);

		if (buff){
			if ((-EAGAIN == error) && (!sack_tx)) {
				jiffies += asoc->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
				test_run_timeout();
				test_run_network();
				sack_tx = 1;
				continue;
			} else if (error > 0) {
				sack_tx = 0;
			}

			if (error < 0)
				DUMP_CORE;
		} else {
			if (error != -EAGAIN) { DUMP_CORE; }
			return;
		}

		if (msg.msg_flags & MSG_NOTIFICATION) {
			if (!aborted)
				DUMP_CORE;
			pdapi = (struct sctp_pdapi_event *)big_buffer;
			if (pdapi->pdapi_type != SCTP_PARTIAL_DELIVERY_EVENT)
				DUMP_CORE;
			return;
		} else if (memcmp(big_buffer, buff+offset, error)) {
			printk("Didn't get a match on partial\n");
			DUMP_CORE;
		}


		offset += error;
		len -= error;

		/* Fixup to account for testframe not having sock glue. */
		test_frame_fixup_msg_control(&msg, sizeof(cmsghdr));
		msg.msg_iov[0].iov_len  = NOT_SO_BIG - msg.msg_iov[0].iov_len;

		/* Verify the value of the MSG_EOR flag.  MSG_EOR
		 * should only be set if this is the last part of
		 * the message.
		 */
		sinfo = (struct sctp_sndrcvinfo *)
			test_frame_get_cmsg_data(&msg, SOL_SCTP, SCTP_SNDRCV);

		/* Verify the partial delivery. */
		if (len) {
			if (msg.msg_flags & MSG_EOR)
				 DUMP_CORE;

		} else {
			if (!(msg.msg_flags & MSG_EOR))
				DUMP_CORE;
		}

		test_run_network();
	}


} /* test_frame_get_message_all() */

void test_frame_get_message_all(struct sock *sk, uint8_t *buff)
{
	return test_frame_get_message_pd(sk, buff, 0);
}

/* Receive a notification from a socket.  It should match the notification
 * type and (if appropriate) the event type corresponding to the notification.
 * Die horribly if something unexpected happens.
 */
void
test_frame_get_event(struct sock *sk, uint16_t ntype, uint16_t etype)
{
	uint8_t big_buffer[REALLY_BIG];
        struct msghdr msg;
        struct iovec iov;
	int cmsghdr[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
        int addr_len;
        int error;
	union sctp_notification *sn;

        memset(&msg, 0, sizeof(struct msghdr));
        iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsghdr;
        msg.msg_controllen = sizeof(cmsghdr);
        error = sctp_recvmsg(NULL, sk, &msg, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);

	if (msg.msg_flags & MSG_NOTIFICATION) {
		sn = (union sctp_notification *)big_buffer;
		if (ntype == sn->sn_header.sn_type) {
			switch(ntype) {
			case SCTP_ASSOC_CHANGE:
				if (etype != sn->sn_assoc_change.sac_state) {
					DUMP_CORE;
				}
				break;
			default:
				break;
			}
		} else {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

} /* test_frame_get_event() */

int
test_frame_getsockopt(struct sock *sk, sctp_assoc_t assoc_id, int optname)
{
	int error = 0;
	int family;

	switch(optname) {
	case SCTP_STATUS:
	{
		struct sctp_status status;
		struct sctp_paddrinfo paddrinfo;
		int status_len;

		memset(&status, 0, sizeof(status));
		if (assoc_id)
			status.sstat_assoc_id = assoc_id;
		status_len = sizeof(struct sctp_status);
		error = sctp_getsockopt(sk, SOL_SCTP, SCTP_STATUS,
                		(char *)&status, &status_len);
		if (error != 0) { break; }

		printf("\nSock: %p SCTP_STATUS\n", sk);
		printf("\tAssociation ID: %d\n", status.sstat_assoc_id);
		printf("\tState: %s\n", sctp_state_tbl[status.sstat_state]);
		printf("\tReceiver Window Size: %d\n", status.sstat_rwnd);
		printf("\tUnacknowledged Data: %d\n", status.sstat_unackdata);
		printf("\tPending data: %d\n", status.sstat_penddata);
		printf("\tInbound Streams: %d\n", status.sstat_instrms);
		printf("\tOutbound Streams: %d\n", status.sstat_outstrms);
		printf("\tFragmentation Point: %d\n",
				status.sstat_fragmentation_point);
		paddrinfo = status.sstat_primary;

		family = ((struct sockaddr *)
			  &paddrinfo.spinfo_address)->sa_family;
		switch (family) {
		case AF_INET:
		{
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)&paddrinfo.spinfo_address;
			printf("\tPrimary Peer Address: (0x%x, %d)\n",
				sin->sin_addr.s_addr, sin->sin_port);
			break;
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)
				&paddrinfo.spinfo_address;
			printf("\tPrimary Peer Address: (0x%x.0x%x.0x%x.0x%x, "
				"%d)\n",
				sin6->sin6_addr.s6_addr32[0],
				sin6->sin6_addr.s6_addr32[1],
				sin6->sin6_addr.s6_addr32[2],
				sin6->sin6_addr.s6_addr32[3],sin6->sin6_port);
			break;
		}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
		default:
			printf("\tPrimary Peer Address"
			       ":Unexpected Family(%d)\n", family);
		}

		printf("\tPrimary Peer State: %d\n", paddrinfo.spinfo_state);
		printf("\tPrimary Peer Congestion Window: %d\n",
						paddrinfo.spinfo_cwnd);
		printf("\tPrimary Peer Smoothed Round trip time: %d\n",
						paddrinfo.spinfo_srtt);
		printf("\tPrimary Peer Retransmission Timeout: %d\n",
						paddrinfo.spinfo_rto);
		printf("\tPrimary Peer Path MTU: %d\n\n",
						paddrinfo.spinfo_mtu);
		break;
	}
	case SCTP_EVENTS:
	{
		struct sctp_event_subscribe subscribe;
		int len = sizeof(struct sctp_event_subscribe);

		error = sctp_getsockopt(sk, SOL_SCTP, SCTP_EVENTS,
                			(char *)&subscribe, &len);
		if (error != 0) { break; }

		printf("SCTP_EVENTS: Enabled events on sk: %p\n", sk);
		if (subscribe.sctp_data_io_event) {
			printf("\tData io events\n");
		}
		if (subscribe.sctp_association_event) {
			printf("\tAssociation change events\n");
		}
		if (subscribe.sctp_address_event) {
			printf("\tAddress events\n");
		}
		if (subscribe.sctp_send_failure_event) {
			printf("\tSend failure events\n");
		}
		if (subscribe.sctp_peer_error_event) {
			printf("\tPeer error events\n");
		}
		if (subscribe.sctp_shutdown_event) {
			printf("\tShutdown events\n");
		}
		if (subscribe.sctp_partial_delivery_event) {
			printf("\tPartial delivery events\n");
		}
		if (subscribe.sctp_adaption_layer_event) {
			printf("\tAdaptation layer events\n");
		}
		break;
	}
	case SCTP_INITMSG:
	{
		struct sctp_initmsg initmsg;
		int len = sizeof(struct sctp_initmsg);

		error = sctp_getsockopt(sk, SOL_SCTP, SCTP_INITMSG,
					(char *)&initmsg, &len);
		if (error != 0) { break; }

		printf("SCTP_INITMSG - sk: %p\n", sk);
		printf("out streams: %d\n", initmsg.sinit_num_ostreams);
		printf("max in streams: %d\n", initmsg.sinit_max_instreams);
		printf("max init attempts: %d\n", initmsg.sinit_max_attempts);
		printf("max init timeout: %d secs\n",
		       initmsg.sinit_max_init_timeo);
		break;
	}
	default:
		printf("getsockopt(%d) not yet implemented\n", optname);
		error = -ENOPROTOOPT;
		break;
	}

	return (error);

} /* test_frame_getsockopt() */

int
test_frame_setsockopt(struct sock *sk, sctp_assoc_t assoc_id, int optname,
		      char *optval)
{
	int error = 0;

	switch(optname) {
	case SCTP_EVENTS:
	{
		error = sctp_setsockopt(sk, SOL_SCTP, optname, optval,
					sizeof(struct sctp_event_subscribe));
		if (error != 0) { break; }

		if (0 != memcmp(optval, &sctp_sk(sk)->subscribe,
				sizeof(struct sctp_event_subscribe))) {
			error = -1;
		}
		break;
	}
	case SCTP_INITMSG:
	{
		error = sctp_setsockopt(sk, SOL_SCTP, optname, optval,
					sizeof(struct sctp_initmsg));
		if (error != 0) { break; }

		if (0 != memcmp(optval, &sctp_sk(sk)->initmsg,
				sizeof(struct sctp_initmsg))) {
			error = -1;
		}
		break;
	}
	default:
		printf("setsockopt(%d) not yet implemented\n", optname);
		error = -ENOPROTOOPT;
		break;
	}

	return (error);

} /* test_frame_setsockopt() */

void
test_frame_enable_data_assoc_events(struct sock *sk)
{
	struct sctp_event_subscribe subscribe;

	memset(&subscribe, 0, sizeof(struct sctp_event_subscribe));
	subscribe.sctp_data_io_event = 1;
	subscribe.sctp_association_event = 1;
	if (0 !=  sctp_setsockopt(sk, SOL_SCTP, SCTP_EVENTS, 
				  (char *)&subscribe,
				  sizeof(struct sctp_event_subscribe))) {
		DUMP_CORE;
	}
}

/*
 * This function simulates taking a device down and notifying the SCTP
 * component with the event.
 */
void
test_remove_dev(struct net_device *dev)
{
	struct net_device *tmp, **prev;

	for (tmp = dev_base, prev = &dev_base; tmp; tmp = tmp->next) {
		if (tmp == dev) {
			*prev = dev->next;
			break;
		}
	}

	if (inetaddr_notifier_on) {
		(*inetaddr_notifier_on->notifier_call)
                        (inetaddr_notifier_on, NETDEV_DOWN, dev);
	}

} /* test_remove_dev() */

/*
 * This function simulates adding a device, hence inserting all the
 * corresponding interface addresses, and notifying the SCTP component
 * with the event.
 */
void
test_add_dev(struct net_device *dev)
{

	dev->next = dev_base;
	dev_base = dev;

	if (inetaddr_notifier_on) {
		(*inetaddr_notifier_on->notifier_call)
                        (inetaddr_notifier_on, NETDEV_UP, dev);
	}

} /* test_add_dev() */


/* This routine determines one of the running interface addresses
 * based on the given destination address.
 */
uint32_t
test_get_source_from_route(uint32_t daddr)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	uint32_t addr = SCTP_ADDR_LO;
	uint32_t mask = SCTP_MASK_LO;


	for (dev = dev_base; dev; dev = dev->next) {
		if ((in_dev = __in_dev_get(dev)) == NULL) {
			continue;
		}

		for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {

			addr = ifa->ifa_local;
                        mask = ifa->ifa_mask;
                        /* Did we find the correct address?  */
			if ((daddr & mask) == (addr & mask)) {
                                goto out;
			}

		} /* for (each address on that device) */

	} /* for (each device) */

 out:
        return addr;

} /* test_get_source_from_route() */


/* Extract the SCTP part of an arbitrary IPv4/IPv6 SCTP packet.  */
struct bare_sctp_packet *
test_get_sctp(void *hdr)
{
	uint8_t *ptr = (uint8_t *) hdr;

	ptr += test_hdr_size(hdr);

	return (struct bare_sctp_packet *)ptr;
} /* test_get_sctp() */

/* How big is the network (usually IP) header?  */
int
test_hdr_size(void *hdr)
{
	struct iphdr *ih = (struct iphdr *) hdr;
	int size = 0;

	switch (ih->version) {
	case 4:
		size = sizeof(struct iphdr);
		break;
	case 6:
		size = sizeof(struct ipv6hdr);
		break;
	default:
		DUMP_CORE;
	}

	return size;
} /* test_hdr_size() */

/* Test frame helper to return the first association. */
struct sctp_association *test_ep_first_asoc(struct sctp_endpoint *ep)
{
	struct sctp_association *asoc = NULL;

	if (!list_empty(&ep->asocs)) {
		asoc = list_entry(ep->asocs.next, struct sctp_association, asocs);
	}

	return asoc;

} /* test_ep_first_asoc(ep) */


/* Get to the first outstanding packet on the specified network.  */
struct sk_buff *
test_peek_packet(int net)
{
	struct sk_buff_head *network = get_Internet(net);

	return (skb_peek(network));

} /* test_peek_packet() */


void sk_common_release(struct sock *sk);

/* This function is simply copied from sctp_close.
 * Use sctp_association_free() instead of sctp_primitive_SHUTDOWN().
 */
void
sctp_remove_sk(struct sock *sk)
{
        struct sctp_endpoint *ep;
        struct sctp_association *asoc;
	struct list_head *pos, *temp;

	SCTP_DEBUG_PRINTK("sctp_close(sk: 0x%x...)\n",
			  (unsigned int)sk);

	sctp_lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	ep = sctp_sk(sk)->ep;

	/* Walk all associations on a socket, not on an endpoint. */
	list_for_each_safe(pos, temp, &ep->asocs) {
		asoc = list_entry(pos, struct sctp_association, asocs);
		sctp_association_free(asoc);
        }

	/* Clean up any skbs sitting on the receive queue.
	 */
	skb_queue_purge(&sk->sk_receive_queue);

	/* This will run the backlog queue. */
	sctp_release_sock(sk);

	/* Supposedly, no process has access to the socket, but
	 * the net layers still may.
	 */

	sctp_local_bh_disable();
	sctp_bh_lock_sock(sk);

	/* Hold the sock, since sk_common_release() will put sock_put()
	 * and we have just a little more cleanup.
	 */
	sock_hold(sk);
	sk_common_release(sk);

	sctp_bh_unlock_sock(sk);
	sctp_local_bh_enable();

	sock_put(sk);

	SCTP_DBG_OBJCNT_DEC(sock);

} /* sctp_remove_sk() */


/* Remove a packet from network. */
struct sk_buff *
test_steal_packet(int net)
{
	return skb_dequeue(get_Internet(net));
} /* test_steal_packet() */


/* Add a packet to the network.  */
void
test_inject_packet(int net, struct sk_buff *p)
{
	struct sk_buff_head *network = get_Internet(net);

	skb_queue_tail(network, p);

} /* test_inject_packet() */


void *
test_build_msg(int len)
{
	int i = len - 1;
	int n;
	unsigned char msg[] =
		"012345678901234567890123456789012345678901234567890";
	char *msg_buf, *p;

	msg_buf = malloc(len);
	p = msg_buf;

	do {
		n = ((i > 50)?50:i);
		memcpy(p, msg, ((i > 50)?50:i));
		p += n;
		i -= n;
	} while (i > 0);

	msg_buf[len-1] = '\0';

	return(msg_buf);
}

/* Verify that congestion parameters are what the test program thinks 
 * they are. 
 */
void test_verify_congestion_parameters(struct sctp_transport *t, uint32_t cwnd,
			     uint32_t ssthresh, uint32_t pba,
			     uint32_t flight_size)
{
	if ((t->cwnd != cwnd)
	    || (t->ssthresh != ssthresh)
	    || (t->partial_bytes_acked != pba)
	    || (t->flight_size != flight_size)) {
		printk("cwnd expected: %d  was: %d\n", 
		       cwnd, t->cwnd);
		printk("ssthresh expected: %d  was: %d\n", 
		       ssthresh, t->ssthresh);
		printk("pba expected: %d  was: %d\n", 
		       pba, t->partial_bytes_acked);
		printk("ssthresh expected: %d  was: %d\n", 
		       flight_size, t->flight_size);
		DUMP_CORE;
	}
}

/* Get the specfied chunk from a list of transmitted chunks. */
struct sctp_chunk *test_get_chunk(struct list_head *tlist, int n)
{
	struct sctp_chunk *chunk;
	struct list_head *lchunk;
	int i = 0;

	list_for_each(lchunk, tlist) {
		i++;
		chunk = list_entry(lchunk, struct sctp_chunk, transmitted_list);
		if (i == n)
			return chunk;
	}

	return NULL;
}

/* Receive a notification from a socket.  It should match the notification
 * type and (if appropriate) the event type as well as its error corresponding to the notification.
 * Die horribly if something unexpected happens.
 */
void
test_frame_get_event_error(struct sock *sk, uint16_t ntype, uint16_t etype,
			__u16 cause_code)
{
	uint8_t big_buffer[REALLY_BIG];
	struct msghdr msg;
	struct iovec iov;
	int cmsghdr[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	int addr_len;
	int error;
	union sctp_notification *sn;

	memset(&msg, 0, sizeof(struct msghdr));
	iov.iov_base = big_buffer;
	iov.iov_len = REALLY_BIG;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsghdr;
	msg.msg_controllen = sizeof(cmsghdr);
	error = sctp_recvmsg(NULL, sk, &msg, REALLY_BIG,
				/* noblock */ 1, /* flags */ 0,
				&addr_len);

	if (msg.msg_flags & MSG_NOTIFICATION) {
		sn = (union sctp_notification *)big_buffer;
		if (ntype == sn->sn_header.sn_type) {
			switch(ntype) {
			case SCTP_ASSOC_CHANGE:
				if (etype != sn->sn_assoc_change.sac_state)
					DUMP_CORE;
				if (cause_code !=
				    sn->sn_assoc_change.sac_error) {
					DUMP_CORE;
				}
				break;
			case SCTP_SEND_FAILED:
				if (etype != sn->sn_send_failed.ssf_flags)
					DUMP_CORE;
				if(cause_code !=
				   sn->sn_send_failed.ssf_error)
					DUMP_CORE;
			default:
				break;
			}
		} else {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

} /* test_frame_get_event_error() */

/* Receive a send failed notification from a socket.  
 * It should match the notification
 * type and (if appropriate) the event type as well as its ssf_error 
 * corresponding to the notification.
 * Also check the ssf_info field for the message that fail to send
 * Die horribly if something unexpected happens.
 */
void
test_frame_send_failed_check(struct sock *sk, uint16_t etype,
			__u32 cause_code, struct sctp_sndrcvinfo *info,
			char *data, int datalen, int* offset)
{
	uint8_t big_buffer[REALLY_BIG];
	struct msghdr msg;
	struct iovec iov;
	int cmsghdr[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	int addr_len;
	int error;
	union sctp_notification *sn;
	int len;

	memset(&msg, 0, sizeof(struct msghdr));
	iov.iov_base = big_buffer;
	iov.iov_len = REALLY_BIG;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsghdr;
	msg.msg_controllen = sizeof(cmsghdr);
	error = sctp_recvmsg(NULL, sk, &msg, REALLY_BIG,
				/* noblock */ 1, /* flags */ 0,
				&addr_len);

	if (msg.msg_flags & MSG_NOTIFICATION) {
		sn = (union sctp_notification *)big_buffer;
		if (SCTP_SEND_FAILED == sn->sn_header.sn_type) {
			if (etype != sn->sn_send_failed.ssf_flags)
				DUMP_CORE;
			if(cause_code !=
			   sn->sn_send_failed.ssf_error)
				DUMP_CORE;


			/* Need to do a field by field comparison as
			 * flags may include fragmentation flags.
			 */
			if (info->sinfo_stream != 
			    sn->sn_send_failed.ssf_info.sinfo_stream)
				DUMP_CORE;

			if (info->sinfo_ppid != 
			    sn->sn_send_failed.ssf_info.sinfo_ppid)
				DUMP_CORE;

			if (info->sinfo_context != 
			    sn->sn_send_failed.ssf_info.sinfo_context)
				DUMP_CORE;


			if (datalen - *offset > sn->sn_send_failed.ssf_length - 
						sizeof(struct sctp_send_failed)) 
				len = sn->sn_send_failed.ssf_length - 
					  sizeof(struct sctp_send_failed);
			else
				len = datalen - *offset;
			if(memcmp(data + *offset, &sn->sn_send_failed.ssf_data, len))
				DUMP_CORE;
			printf("Send failed event for chunk, ssf_length %d, size %d, datalen %d, offset %d, len %d\n",
				sn->sn_send_failed.ssf_length,
				sizeof(struct sctp_send_failed), datalen, *offset, len);
			*offset += len;
		} else {
			DUMP_CORE;
		}
	} else {
		DUMP_CORE;
	}

} /* test_frame_send_failed_check() */

void print_address(const char *label, union sctp_addr *addr)
{
	if (addr->sa.sa_family == AF_INET6) {
		SCTP_DEBUG_PRINTK("%s addr: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
				  " port: %d\n",
				  label,
				  NIP6(addr->v6.sin6_addr),
	        		  addr->v6.sin6_port);
	} else {
		SCTP_DEBUG_PRINTK("%s addr: %u.%u.%u.%u port: %d\n",
				  label,
				  NIPQUAD(addr->v4.sin_addr.s_addr),
	        		  addr->v4.sin_port);
	}
}


void print_assoc_peer_transports(struct sctp_association *asoc)
{
	struct sctp_transport *tp;
	struct list_head *pos;

	list_for_each(pos, &asoc->peer.transport_addr_list) {
		tp = list_entry(pos, struct sctp_transport, transports);
		switch (tp->state)
		{
			case SCTP_UNKNOWN:
			print_address("UKNOWN:  ", &tp->ipaddr);
			break;

			case SCTP_INACTIVE:
			print_address("INACTIVE:", &tp->ipaddr);
			break;

			case SCTP_ACTIVE:
			print_address("ACTIVE:  ", &tp->ipaddr);
			break;
		}
	}
}


void test_assoc_peer_transports(struct sctp_association *asoc,
				union sctp_addr *peers, int num_peers)
{
	struct sctp_transport *tp;
	struct list_head *pos;
	int i, addr_found;
	int bufsize = num_peers * sizeof(union sctp_addr);
	char *peer_found = (char *)malloc(num_peers);
	union sctp_addr *tmppeers;

	tmppeers = (union sctp_addr *)malloc(bufsize);
	memcpy(tmppeers, peers, bufsize);
	for (i = 0; i < num_peers; i++) {
		tmppeers[i].v4.sin_port = ntohs(peers[i].v4.sin_port);
	}
	memset(peer_found, 0, num_peers);

	list_for_each(pos, &asoc->peer.transport_addr_list) {
		tp = list_entry(pos, struct sctp_transport, transports);
		addr_found = 0;
		for (i = 0; i < num_peers; i++) {
			if (sctp_cmp_addr_exact(&tp->ipaddr, &tmppeers[i])) {
				addr_found = 1;
				peer_found[i] = 1;
				break;
			}
		}
		if (!addr_found) {
			print_address("assoc has invalid peer transport",
				      &tp->ipaddr);
			DUMP_CORE;
		}
	}
	for (i = 0; i < num_peers; i++ ) {
		if (!peer_found[i]) {
			print_address("assoc is missing a peer transport",
				      &tmppeers[i]);
			DUMP_CORE;
		}
	}
}

int fill_addr_buf(void *buf, union sctp_addr *addrs, int first, int last)
{
	int bufsize = 0, i;
	for ( i = first; i <= last; i++ ) {
		memcpy(buf + bufsize, &addrs[i], ADDR_LEN(addrs[i]));
		bufsize += ADDR_LEN(addrs[i]);
	}
	return bufsize;
}

#endif /* TEST_FRAME */
