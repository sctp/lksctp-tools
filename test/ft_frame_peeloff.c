/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is the Functional frame test to verify the new SCTP interface
 * sctp_peeloff() that can be used to branch off an association into a 
 * separate socket. 
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
	struct sock *svr_sk, *clt_sk[MAX_CLIENTS], *peeloff_sk[MAX_CLIENTS];
	struct sctp_endpoint *svr_ep, *clt_ep[MAX_CLIENTS]; 
	struct sctp_association *svr_asoc[MAX_CLIENTS], *clt_asoc[MAX_CLIENTS];
	union sctp_addr svr_loop, clt_loop[MAX_CLIENTS];
	struct socket *peeloff_sock;
	uint8_t *message = "Hello, World!!!\n";
	struct msghdr outmsg;
	struct iovec out_iov;
	int bytes_sent;
	int error;
	struct list_head *pos;
	int i;
	int pf_class;

	/* Do all that random stuff needed to make a sensible universe.  */
	sctp_init();
	
#if TEST_V6
	pf_class = PF_INET6;
#else
	pf_class = PF_INET;
#endif

	/* Create and bind the server socket. */ 
	svr_sk = sctp_socket(pf_class, SOCK_SEQPACKET);

#if TEST_V6
        svr_loop.v6.sin6_family = AF_INET6;
        svr_loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        svr_loop.v6.sin6_port = htons(SCTP_TESTPORT_1);
#else
	svr_loop.v4.sin_family = AF_INET;
	svr_loop.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	svr_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
#endif

	if (0 != test_bind(svr_sk, (struct sockaddr *)&svr_loop, 
			   sizeof(svr_loop))) {
		DUMP_CORE; 
	}
        
	/* Create and bind the client sockets. */ 
	for (i = 0; i < MAX_CLIENTS; i++) { 
		clt_sk[i] = sctp_socket(pf_class, SOCK_SEQPACKET);

#if TEST_V6
        	clt_loop[i].v6.sin6_family = AF_INET6;
        	clt_loop[i].v6.sin6_addr =
				(struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
        	clt_loop[i].v6.sin6_port = htons(SCTP_TESTPORT_2 + i);
#else
		clt_loop[i].v4.sin_family = AF_INET;
		clt_loop[i].v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
		clt_loop[i].v4.sin_port = htons(SCTP_TESTPORT_2 + i);
#endif

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

        /* Get the communication up message and the data message on the  
	 * server socket for all the clients.  
	 */
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
        	test_frame_get_message(svr_sk, message);
	}

	/* Send a data message from all the client sockets so that the data
	 * gets into the server's receive queue.
	 */ 
	for (i = 0; i < MAX_CLIENTS; i++) {
		test_frame_send_message(clt_sk[i], (struct sockaddr *)&svr_loop,
					message);
	}
	if (0 != test_run_network())
		DUMP_CORE;

	/* Branch off all the associations on the server socket to separate
	 * individual sockets.
	 */ 
	for (i = 0; i < MAX_CLIENTS; i++) {
		error = sctp_do_peeloff(svr_asoc[i], &peeloff_sock);
		if (error < 0) {
			printf("\tpeeloff failed\n");
			DUMP_CORE;
		}
		peeloff_sk[i] = peeloff_sock->sk;
	}

	/* Verify that the data that was waiting on the server's receive queue
	 * is moved and can be read from the peeled off sockets.
	 */
	for (i = 0; i < MAX_CLIENTS; i++)
		test_frame_get_message(peeloff_sk[i], message);

	outmsg.msg_name = &clt_loop[0];
	outmsg.msg_namelen = sizeof(clt_loop[0]);
	outmsg.msg_iov = &out_iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = NULL;
	outmsg.msg_controllen = 0;
	outmsg.msg_flags = 0;
        
	outmsg.msg_iov->iov_base = message;
	outmsg.msg_iov->iov_len = strlen(message) + 1;

	/* Verify that data cannot be sent to a peer that is already on an
	 * association that is peeled off from the parent socket.
	 */
	bytes_sent = sctp_sendmsg(NULL, svr_sk, &outmsg, strlen(message)+1);
	if (-EADDRNOTAVAIL != bytes_sent)
		DUMP_CORE;

	/* Verify that a peeled off socket is not allowed to do listen().  */
	if (-EINVAL != sctp_seqpacket_listen(peeloff_sk[0], 1)) { 
		DUMP_CORE; 
	}

	/* Verify that an association cannot be branched off an already
	 * peeled-off socket.
	 */
	if (!sctp_do_peeloff(svr_asoc[0], &peeloff_sock)) {
		DUMP_CORE; 
	}

	/* Send a message from all the client sockets to the server socket. */
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_send_message(clt_sk[i], 
					(struct sockaddr *)&svr_loop, 
					message);
	}

	if (0 != test_run_network()) {
		DUMP_CORE; 
	}

	/* Receive the sent messages on the peeled off server sockets.  */    
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_get_message(peeloff_sk[i], message);
	}

	/* Send a message from all the peeled off server sockets to the client 
	 * sockets. 
	 */
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_send_message(peeloff_sk[i], 
					(struct sockaddr *)&clt_loop[i], 
					message);
	}

	if (0 != test_run_network()) {
		DUMP_CORE; 
	}

	/* Receive the messages sent from the peeled of server sockets on 
	 * the client sockets.
	 */
	for (i = 0; i < MAX_CLIENTS; i++) { 
        	test_frame_get_message(clt_sk[i], message);
	}

	error = 0;
	sctp_close(svr_sk, 0);

	/* Close all the peeled off server sockets.  */
	for (i = 0; i < MAX_CLIENTS; i++) { 
		sctp_close(peeloff_sk[i], 0);
	}

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* Get the shutdown complete notification from all the client 
	 * sockets.  
	 */
	for (i = 0; i < MAX_CLIENTS; i++) {
        	test_frame_get_event(clt_sk[i], SCTP_ASSOC_CHANGE, 
				     SCTP_SHUTDOWN_COMP);

		sctp_close(clt_sk[i], 0);
	}

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
