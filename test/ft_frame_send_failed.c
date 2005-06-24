/* SCTP kernel reference Implementation
 * Copyright (c) 2003 Intel Corp.
 *
 * This is the Functional frame test to verify the ungraceful abort of an
 * association for a UDP-style socket.
 *
 * Ardelle Fan <ardelle.fan@intel.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>
#include <errno.h>

int main(int argc, char *argv[])
{
        struct sock *sk1, *sk2;
        struct sctp_endpoint *ep1, *ep2;
        struct sctp_association *asoc1, *asoc2;
        struct sockaddr_in loop1, loop2;
	uint8_t *message = "Hello, World!!!\n";
	uint8_t long_message[6001];
        struct msghdr outmsg1, outmsg2;
	struct cmsghdr *outcmsg1, *outcmsg2;
	char infobuf1[CMSG_SPACE_SNDRCV] = {0};
	char infobuf2[CMSG_SPACE_SNDRCV] = {0};
	struct sctp_sndrcvinfo *sinfo1, *sinfo2;
	int error;
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	struct sctp_errhdr *errhdr;
	sctp_chunkhdr_t *hdr;
        int bytes_sent;
	struct iovec out_iov1, out_iov2;
        struct sctp_event_subscribe subscribe;
	int i;
	int offset;

        /* Do all that random stuff needed to make a sensible universe.  */
        sctp_init();

        /* Create and bind the socket sk1. */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        loop1.sin_family = AF_INET;
        loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.sin_port = htons(SCTP_TESTPORT_1);

        if (0 != test_bind(sk1, (struct sockaddr *)&loop1,
			   sizeof(loop1))) {
        	DUMP_CORE;
	}

        /* Create and bind the sockets sk2. */
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

       	loop2.sin_family = AF_INET;
       	loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
       	loop2.sin_port = htons(SCTP_TESTPORT_2 + i);

	if (0 != test_bind(sk2, (struct sockaddr *)&loop2,
			   sizeof(loop2))) {
       		DUMP_CORE;
	}

        /* Enable SCTP_SEND_FAILED notifications which is not on by default.
         */
        memset(&subscribe, 0, sizeof(struct sctp_event_subscribe));
        subscribe.sctp_data_io_event = 1;
        subscribe.sctp_association_event = 1;
        subscribe.sctp_send_failure_event = 1;
        subscribe.sctp_peer_error_event = 0;
        if (0 !=  sctp_setsockopt(sk1, SOL_SCTP, SCTP_EVENTS,
                                  (char *)&subscribe,
                                  sizeof(struct sctp_event_subscribe))) {
                DUMP_CORE;
        }
        if (0 !=  sctp_setsockopt(sk2, SOL_SCTP, SCTP_EVENTS,
                                  (char *)&subscribe,
                                  sizeof(struct sctp_event_subscribe))) {
                DUMP_CORE;
        }

	/* Mark server socket as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk1, 1)) { DUMP_CORE; }

	/* Test Case: user abort caused send fail. */
	/* Send a message from sk2 to sk1.  */
        test_frame_send_message(sk2,
				(struct sockaddr *)&loop1,
				message);

	if (0 != test_run_network()) {
		DUMP_CORE;
	}

	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1);

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

        /* Get the communication up message on sockets sk2. */
       	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        /* Get the communication up message and the data message on the
	 * socket sk1 for all the clients.
	 */
       	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
       	test_frame_get_message(sk1, message);

	/* Build up a msghdr structure for the abort message.  */
	outmsg1.msg_name = NULL;
	outmsg1.msg_namelen = 0;
 	outmsg1.msg_flags = 0;
	outmsg1.msg_iov = &out_iov1;
	outmsg1.msg_iovlen = 1;
	outmsg1.msg_iov->iov_base = message;
	outmsg1.msg_iov->iov_len = strlen(message) + 1;


        /* Build up a SCTP_SNDRCV CMSG. */
	outmsg1.msg_control = infobuf1;
	outmsg1.msg_controllen = sizeof(infobuf1);
	outcmsg1 = CMSG_FIRSTHDR(&outmsg1);
	outcmsg1->cmsg_level = IPPROTO_SCTP;
	outcmsg1->cmsg_type = SCTP_SNDRCV;
	outcmsg1->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	/* Set MSG_ABORT flag in the sndrcvinfo.  */
	sinfo1 = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg1);
	memset(sinfo1, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo1->sinfo_context = 100;
	sinfo1->sinfo_flags |= MSG_ABORT;

	/* Abort the associations of the socket sk1 in a loop.  */
	sinfo1->sinfo_assoc_id = sctp_assoc2id(asoc1);

	for (i = 0; i < (sizeof(long_message)) / 30; i++)
		strcpy(long_message + i * 30,
		       "This should be a long string!\n");
	/* Build up a msghdr structure for the send failed message.  */
	outmsg2.msg_name = NULL;
	outmsg2.msg_namelen = 0;
 	outmsg2.msg_flags = 0;
	outmsg2.msg_iov = &out_iov2;
	outmsg2.msg_iovlen = 1;
	outmsg2.msg_iov->iov_base = long_message;
	outmsg2.msg_iov->iov_len = strlen(long_message) + 1;

        /* Build up a SCTP_SNDRCV CMSG. */
	outmsg2.msg_control = infobuf2;
	outmsg2.msg_controllen = sizeof(infobuf2);
	outcmsg2 = CMSG_FIRSTHDR(&outmsg2);
	outcmsg2->cmsg_level = IPPROTO_SCTP;
	outcmsg2->cmsg_type = SCTP_SNDRCV;
	outcmsg2->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	sinfo2 = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg2);
	memset(sinfo2, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo2->sinfo_context = 200;
	sinfo2->sinfo_assoc_id = sctp_assoc2id(asoc2);

	/* Verify that the association is present. */
	error = test_frame_getsockopt(sk1, sinfo1->sinfo_assoc_id,
				      SCTP_STATUS);
	if (0 != error) {
       		printf("getsockopt(SCTP_STATUS) on association %p "
		       "failed with error: %d\n", asoc1, error);
       		DUMP_CORE;
	}

	/* Call sendmsg() to abort the association.  */
	bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg1,
				  strlen(message)+1);
        if (bytes_sent != 0) { DUMP_CORE; }

	/* We should have an ABORT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_ABORT, TEST_NETWORK0))
		DUMP_CORE;

	/* Send a message from sk2 to sk1 meanwhile.  */
	bytes_sent = sctp_sendmsg(NULL, sk2, &outmsg2,
				  strlen(long_message)+1);
        if (bytes_sent != strlen(long_message)+1) { DUMP_CORE; }

	/* Test the SCTP_ERROR_USER_ABORT the abort chunk should
	 * contain
	 */
	skb = test_peek_packet(TEST_NETWORK0);

	if (skb) {
		packet = test_get_sctp(skb->data);
			hdr = &packet->ch;
		errhdr = (struct sctp_errhdr *)((uint8_t *)hdr +
			sizeof(sctp_chunkhdr_t));
		printf("cause: %d\n",errhdr->cause);
		if (errhdr->cause != SCTP_ERROR_USER_ABORT)
			DUMP_CORE;
		if (strncmp(errhdr->variable,message,
				strlen(message)+1))
			DUMP_CORE;
	} else
		DUMP_CORE;

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the communication lost message on the sockets sk2. */
       	test_frame_get_event_error(sk2, SCTP_ASSOC_CHANGE,
			     SCTP_COMM_LOST,SCTP_ERROR_USER_ABORT);

        /* Get the communication lost message on the sockets sk1. */
       	test_frame_get_event_error(sk1, SCTP_ASSOC_CHANGE,
			     SCTP_COMM_LOST,SCTP_ERROR_USER_ABORT);

	/* Verify that the association is no longer present.  */
	error = test_frame_getsockopt(sk1, sinfo1->sinfo_assoc_id,
				      SCTP_STATUS);
	if (-EINVAL != error) {
       		printf("getsockopt(SCTP_STATUS) successful even after "
		       "the association %p is abort\n", asoc1);
       		DUMP_CORE;
	}

	offset = 0;
	while (offset < (strlen(long_message)+1)) {
		int sent;
		if (offset < 4380) 
			sent = SCTP_DATA_SENT;
		else
			sent = SCTP_DATA_UNSENT;
		
		/* Get the send_failed message on the sockets sk2. */
		test_frame_send_failed_check(sk2, sent,
					     SCTP_ERROR_USER_ABORT, sinfo2,
					     long_message, 
					     strlen(long_message)+1,
					     &offset);
	}

	error = 0;
	sctp_close(sk1, 0);

	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
