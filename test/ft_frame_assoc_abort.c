/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 2002 Intel Corp.
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

#define MAX_CLIENTS	10

int
main(int argc, char *argv[])
{
        struct sock *svr_sk, *clt_sk[MAX_CLIENTS];
        struct sctp_endpoint *svr_ep, *clt_ep[MAX_CLIENTS]; 
        struct sctp_association *svr_asoc[MAX_CLIENTS], *clt_asoc[MAX_CLIENTS];
        struct sockaddr_in svr_loop, clt_loop[MAX_CLIENTS];
	uint8_t *message = "Hello, World!!!\n";
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
	struct list_head *pos;
	struct iovec out_iov;
	int i;

        /* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
        sctp_init();
	
        /* Create and bind the server socket. */ 
        svr_sk = sctp_socket(PF_INET, SOCK_SEQPACKET);

        svr_loop.sin_family = AF_INET;
        svr_loop.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        svr_loop.sin_port = htons(SCTP_TESTPORT_1);

        if (0 != test_bind(svr_sk, (struct sockaddr *)&svr_loop, 
			   sizeof(svr_loop))) {
        	DUMP_CORE; 
	}
        
        /* Create and bind the client sockets. */ 
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	clt_sk[i] = sctp_socket(PF_INET, SOCK_SEQPACKET);

        	clt_loop[i].sin_family = AF_INET;
        	clt_loop[i].sin_addr.s_addr = SCTP_IP_LOOPBACK;
        	clt_loop[i].sin_port = htons(SCTP_TESTPORT_2 + i);

		if (0 != test_bind(clt_sk[i], (struct sockaddr *)&clt_loop[i], 
				   sizeof(clt_loop[i]))) {
        		DUMP_CORE; 
		}
	}
        
	/* Mark server socket as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(svr_sk, 1)) { DUMP_CORE; }
      
	/* Send a message from all the clients to the server.  */ 
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_send_message(clt_sk[i], 
					(struct sockaddr *)&svr_loop, 
					message);
	}

	if (0 != test_run_network()) {
		DUMP_CORE; 
	}

	svr_ep = sctp_sk(svr_sk)->ep;

	for (i = 0; i < MAX_CLIENTS; i++) { 
		clt_ep[i] = sctp_sk(clt_sk[i])->ep;
		clt_asoc[i] = test_ep_first_asoc(clt_ep[i]);
	}

	i = 0;	
	list_for_each(pos, &svr_ep->asocs) {
		svr_asoc[i++] = list_entry(pos, struct sctp_association, asocs);
	}

        /* Get the communication up message on all the client sockets. */  
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_get_event(clt_sk[i], SCTP_ASSOC_CHANGE, 
				     SCTP_COMM_UP);
	}

        /* Get the communication up message and the data message on the  server 
	 * socket for all the clients.  
	 */
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
        	test_frame_get_message(svr_sk, message);
	}

	/* Build up a msghdr structure we can use for all sending.  */
	outmsg1.msg_name = NULL;
	outmsg1.msg_namelen = 0;
 	outmsg1.msg_flags = 0;
	outmsg1.msg_iov = &out_iov;
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

	outmsg2.msg_name = NULL;
	outmsg2.msg_namelen = 0;
	outmsg2.msg_iov = NULL;
	outmsg2.msg_iovlen = 0;
	outmsg2.msg_flags = 0;

        /* Build up a SCTP_SNDRCV CMSG. */
	outmsg2.msg_control = infobuf2;
	outmsg2.msg_controllen = sizeof(infobuf2);
	outcmsg2 = CMSG_FIRSTHDR(&outmsg2);
	outcmsg2->cmsg_level = IPPROTO_SCTP;
	outcmsg2->cmsg_type = SCTP_SNDRCV;
	outcmsg2->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	/* Set SCTP_ABORT flag in the sndrcvinfo.  */
	sinfo1 = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg1);
	memset(sinfo1, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo1->sinfo_flags |= SCTP_ABORT;

	/* Set SCTP_EOF flag in the sndrcvinfo.  */
	sinfo2 = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg2);
	memset(sinfo2, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo2->sinfo_flags |= SCTP_EOF;

	/* Abort all the associations of the server socket in a loop.  */
	for (i = 0; i < MAX_CLIENTS/2; i++) {
		sinfo1->sinfo_assoc_id = sctp_assoc2id(svr_asoc[i]);

		/* Verify that the association is present. */
		error = test_frame_getsockopt(svr_sk, sinfo1->sinfo_assoc_id,
					      SCTP_STATUS);
		if (0 != error) {
        		printf("getsockopt(SCTP_STATUS) on association %p " 
			       "failed with error: %d\n", svr_asoc[i], error);
        		DUMP_CORE;
		}

		outmsg1.msg_iov->iov_base = message;
		outmsg1.msg_iov->iov_len = strlen(message) + 1;
		/* Call sendmsg() to abort the association.  */
		bytes_sent = sctp_sendmsg(NULL, svr_sk, &outmsg1,
					  strlen(message)+1);
	        if (bytes_sent != 0) { DUMP_CORE; }

		/* We should have and ABORT sitting on the Internet. */
		if (!test_for_chunk(SCTP_CID_ABORT, TEST_NETWORK0))
			DUMP_CORE;

		/* Test the SCTP_ERROR_USER_ABORT the abort chunk should
		 * contain
		 */
		skb = test_peek_packet(TEST_NETWORK0);

		if (skb) {
			packet = test_get_sctp(skb->data);
			hdr = &packet->ch;
			errhdr = (struct sctp_errhdr *)((uint8_t *)hdr +
				sizeof(sctp_chunkhdr_t));
			if (errhdr->cause != SCTP_ERROR_USER_ABORT)
				DUMP_CORE;
			if (strncmp(errhdr->variable,message,
					strlen(message)+1))
				DUMP_CORE;
		} else
			DUMP_CORE;

		error = test_run_network();
		if (0 != error) { DUMP_CORE; }

	        /* Get the communication lost message on the client sockets. */
        	test_frame_get_event_error(clt_sk[i], SCTP_ASSOC_CHANGE,
				     SCTP_COMM_LOST,SCTP_ERROR_USER_ABORT);

	        /* Get the communication lost message on the server sockets. */
        	test_frame_get_event_error(svr_sk, SCTP_ASSOC_CHANGE,
				     SCTP_COMM_LOST,SCTP_ERROR_USER_ABORT);

		/* Verify that the association is no longer present.  */
		error = test_frame_getsockopt(svr_sk, sinfo1->sinfo_assoc_id,
					      SCTP_STATUS);
		if (-EINVAL != error) {
        		printf("getsockopt(SCTP_STATUS) successful even after "
			       "the association %p is abort\n", svr_asoc[i]);
        		DUMP_CORE;
		}
	}

	/* Test the ungracefully abort during shutdown */

	for (i = MAX_CLIENTS/2; i < MAX_CLIENTS; i++) {
		sinfo2->sinfo_assoc_id = sctp_assoc2id(svr_asoc[i]);

		/* Verify that the association is present. */
		error = test_frame_getsockopt(svr_sk, sinfo2->sinfo_assoc_id,
					      SCTP_STATUS);
		if (0 != error) {
        		printf("getsockopt(SCTP_STATUS) on association %p "
			       "failed with error: %d\n", svr_asoc[i], error);
        		DUMP_CORE;
		}

		/* Call sendmsg() to abort the association.  */
		bytes_sent = sctp_sendmsg(NULL, svr_sk, &outmsg2, 0);
		if (bytes_sent != 0) { DUMP_CORE; }

		/* We should have and SHUTDOWN sitting on the Internet. */
		if (!test_for_chunk(SCTP_CID_SHUTDOWN, TEST_NETWORK0)) {
			DUMP_CORE;
		}

		error = test_run_network_once(TEST_NETWORK0);
		if (0 > error) { DUMP_CORE; }

		/* We should have and SHUTDOWN_ACK sitting on the Internet. */
		if (!test_for_chunk(SCTP_CID_SHUTDOWN_ACK, 
					TEST_NETWORK0)) {
			DUMP_CORE;
		}

		sinfo1->sinfo_assoc_id = sctp_assoc2id(clt_asoc[i]);

		/* Verify that the client association is present. */
		error = test_frame_getsockopt(clt_sk[i], sinfo1->sinfo_assoc_id,
					      SCTP_STATUS);
		if (0 != error) {
        		printf("getsockopt(SCTP_STATUS) on association %p "
			       "failed with error: %d\n", clt_asoc[i], error);
        		DUMP_CORE;
		}
		
		outmsg1.msg_iov->iov_base = message;
		outmsg1.msg_iov->iov_len = strlen(message) + 1;
		/* Call sendmsg() to abort the client's association */
		bytes_sent = sctp_sendmsg(NULL, clt_sk[i], &outmsg1, 
					  strlen(message)+1);
		if (bytes_sent != 0) {
			printf("the result of client sctp_sendmsg() is %d\n",
				bytes_sent);
			DUMP_CORE;
		}

	        /* Get the communication lost message on the client sockets. */
        	test_frame_get_event(clt_sk[i], SCTP_ASSOC_CHANGE, 
				     SCTP_COMM_LOST);

		/* Verify that the client's association is no longer present. */
		error = test_frame_getsockopt(clt_sk[i], sinfo1->sinfo_assoc_id,
					      SCTP_STATUS);
		if (-EINVAL != error) {
        		printf("client getsockopt(SCTP_STATUS) successful"
				" even after the association %p is abort\n",
				clt_asoc[i]);
        		DUMP_CORE;
		}

		/* Set SCTP_ABORT flag in the sndrcvinfo.  */
		sinfo1->sinfo_assoc_id = sctp_assoc2id(svr_asoc[i]);

		outmsg1.msg_iov->iov_base = message;
		outmsg1.msg_iov->iov_len = strlen(message) + 1;
		/* Call sendmsg() to abort the server's association */
		bytes_sent = sctp_sendmsg(NULL, svr_sk, &outmsg1, 
					  strlen(message)+1);
		if (bytes_sent != 0) { DUMP_CORE; }

	        /* Get the communication lost message on the server sockets. */
        	test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, 
				     SCTP_COMM_LOST);

		/* Verify that the server's association is no longer present.*/
		error = test_frame_getsockopt(svr_sk, sinfo1->sinfo_assoc_id,
					      SCTP_STATUS);
		if (-EINVAL != error) {
        		printf("server getsockopt(SCTP_STATUS) successful"
				" even after the association %p is abort\n",
				svr_asoc[i]);
        		DUMP_CORE;
		}

		error = test_run_network();
		if (0 != error) { DUMP_CORE; }
	}

	error = 0;
	sctp_close(svr_sk, 0);

	for (i = 0; i < MAX_CLIENTS; i++) { 
		sctp_close(clt_sk[i], 0);
	}

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
