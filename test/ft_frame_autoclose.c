/*
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is a Functional Test to verify autoclose functionality and the
 * socket option SCTP_AUTOCLOSE that can be used to specify the duration in
 * which an idle association is automatically closed. 
 * 
 * Sridhar Samudrala <samudrala@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sock *sk1, *sk2;
	struct sockaddr_in loop1, loop2;
	uint8_t *message = "Hello, World!!!\n";
	int error;
	uint32_t autoclose;

	/* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();
	
	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind this sockets to the test ports.  */
	loop1.sin_family = AF_INET;
	loop1.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.sin_port = htons(SCTP_TESTPORT_1);

	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }
        
	loop2.sin_family = AF_INET;
	loop2.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.sin_port = htons(SCTP_TESTPORT_2);
        
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) { DUMP_CORE; }
        
	/* Set the autoclose duration for the associations created on sk1 
	 * and sk2 to be 10 seconds.  
	 */ 
	autoclose = 10;
	error = sctp_setsockopt(sk1, IPPROTO_SCTP, SCTP_AUTOCLOSE, 
				(void *)&autoclose, sizeof(autoclose));
	if (error != 0) { DUMP_CORE; }

	error = sctp_setsockopt(sk2, IPPROTO_SCTP, SCTP_AUTOCLOSE, 
				(void *)&autoclose, sizeof(autoclose));
	if (error != 0) { DUMP_CORE; }

	/* Send the first message. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	/* Get the communication up message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	test_frame_get_message(sk2, message);

	/* Send and receive a couple of messages. */
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
	test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }
	test_frame_get_message(sk2, message);
	test_frame_get_message(sk2, message);

	/* Move time forward by the autoclose duration to trigger the
	 * autoclose timer and close the associations.
	 */
	jiffies += asoc1->timeouts[SCTP_EVENT_TIMEOUT_AUTOCLOSE] + 1;

	error = test_run_network();
	if (error != 0) { DUMP_CORE; }

	/* Get the shutdown complete message from sk2.  */
	test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	/* Get the shutdown complete message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

	/* Indicate successful completion.  */
	exit(error);

} /* main() */
