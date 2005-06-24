/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is the Functional frame test to verify the graceful shutdown of an
 * association for a UDP-style socket.
 * 
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>


#define MAX_CLIENTS	10

int
main(int argc, char *argv[])
{
        struct sock *svr_sk, *clt_sk[MAX_CLIENTS];
        struct sctp_endpoint *svr_ep, *clt_ep[MAX_CLIENTS]; 
        struct sctp_association *svr_asoc[MAX_CLIENTS], *clt_asoc[MAX_CLIENTS];
        struct sockaddr_in svr_loop, clt_loop[MAX_CLIENTS];
	uint8_t *message = "Hello, World!!!\n";
        struct msghdr outmsg;
	struct cmsghdr *outcmsg;
	char infobuf[CMSG_SPACE_SNDRCV] = {0};
	struct sctp_sndrcvinfo *sinfo;
	int error;
        int bytes_sent;
	struct list_head *pos;
	int i;

        /* Do all that random stuff needed to make a sensible universe.  */
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
	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = NULL;
	outmsg.msg_iovlen = 0;
	outmsg.msg_flags = 0;
        
        /* Build up a SCTP_SNDRCV CMSG. */
	outmsg.msg_control = infobuf;
	outmsg.msg_controllen = sizeof(infobuf);
	outcmsg = CMSG_FIRSTHDR(&outmsg);
	outcmsg->cmsg_level = IPPROTO_SCTP;
	outcmsg->cmsg_type = SCTP_SNDRCV;
	outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	/* Set MSG_EOF flag in the sndrcvinfo.  */ 
	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg);
	memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo->sinfo_flags |= MSG_EOF;

	/* Shutdown all the associations of the server socket in a loop.  */
	for (i = 0; i < MAX_CLIENTS; i++) { 
		sinfo->sinfo_assoc_id = sctp_assoc2id(svr_asoc[i]);

		/* Verify that the association is present. */
		error = test_frame_getsockopt(svr_sk, sinfo->sinfo_assoc_id, 
					      SCTP_STATUS);
		if (0 != error) { 
        		printf("getsockopt(SCTP_STATUS) on association %p " 
			       "failed with error: %d\n", svr_asoc[i], error);
        		DUMP_CORE;
		}

		/* Call sendmsg() to shutdown the association.  */
		bytes_sent = sctp_sendmsg(NULL, svr_sk, &outmsg, 0);
		if (bytes_sent != 0) { DUMP_CORE; }

		error = test_run_network();
		if (0 != error) { DUMP_CORE; }

		/* Verify that the association is no longer present.  */
		error = test_frame_getsockopt(svr_sk, sinfo->sinfo_assoc_id, 
					      SCTP_STATUS);
		if (-EINVAL != error) {
        		printf("getsockopt(SCTP_STATUS) successful even after "
			       "the association %p is shutdown\n", svr_asoc[i]);
        		DUMP_CORE;
		}
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
