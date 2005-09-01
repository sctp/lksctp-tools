/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This is a Functional Test for verifying the sockopt SCTP_RTOINFO for 
 * the rto_max and * rto_min values.
 * On one socket rto_max is set to a very low value, which should force
 * the rto of that endpoint to equal the rto_max.
 * On the other socket rto_min is set to a very high value, which should
 * force the rto of that endpoint to equal the rto_min.
 * 
 * Ryan Layer <rmlayer@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <errno.h> /* for sys_errlist[] */
#include <funtest.h>

int main(int argc, char *argv[]) {

        struct sctp_endpoint *ep;
        struct sctp_association *asoc;
        struct sock *sk1, *sk2;
        struct sockaddr_in loop1, loop2;
	uint8_t *message = "Hello, World!!!\n";
	struct sctp_transport *t;
	int error;
	struct sctp_rtoinfo rtoinfo1, rtoinfo2;

	memset(&rtoinfo1, 0, sizeof (struct sctp_rtoinfo));
	memset(&rtoinfo2, 0, sizeof (struct sctp_rtoinfo));

        /* Do all that random stuff needed to make a sensible universe. */
        sctp_init();

        /* Create the two endpoints which will talk to each other. */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Set the rto_max to a very low number for sk1*/
	rtoinfo1.srto_max = 2;
	rtoinfo1.srto_initial = 0;
	rtoinfo1.srto_min = 1;
	error = sctp_setsockopt(sk1, SOL_SCTP, SCTP_RTOINFO, (char *)&rtoinfo1,
				sizeof (struct sctp_rtoinfo));

	/* Set the rto_min to a very high number for sk2*/
	rtoinfo2.srto_max = 10000;
	rtoinfo2.srto_initial = 0;
	rtoinfo2.srto_min = 9000;
	error = sctp_setsockopt(sk2, SOL_SCTP, SCTP_RTOINFO, (char *)&rtoinfo2,
				sizeof (struct sctp_rtoinfo));

	/* Bind this sockets to the test ports. */
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

        /* Send messages */
        test_frame_send_message(sk1, (struct sockaddr *)&loop2, message);
        test_frame_send_message(sk2, (struct sockaddr *)&loop1, message);

	if ( test_run_network() ) {
		DUMP_CORE;
	} 

	ep = sctp_sk(sk1)->ep;
	asoc = test_ep_first_asoc(ep);

	t = asoc->peer.primary_path;

	printf("t->rto: %d,  rtoinfo1.srto_max: %d asoc->rto_max: %d\n", t->rto,  
	       rtoinfo1.srto_max, asoc->rto_max);
	if (t->rto != msecs_to_jiffies(rtoinfo1.srto_max))
		DUMP_CORE;

	printf("\n\n\trto_max Test Passed\n\n\n");

	ep = sctp_sk(sk2)->ep;
	asoc = test_ep_first_asoc(ep);

	t = asoc->peer.primary_path;

	if (t->rto != msecs_to_jiffies(rtoinfo2.srto_min))
		DUMP_CORE;

	printf("\n\n\trto_min Test Passed\n\n\n");

	sctp_close(sk1, 0);
	if ( 0 != test_run_network()) { DUMP_CORE; }

	sctp_close(sk2, 0);

	if (0 == error) {
		printf("\n\n%s passed\n\n\n", argv[0]);
	}
	return 0;
} /* main() */

