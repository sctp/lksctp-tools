/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 * Copyright (c) 2001 La Monte H.P. Yarroll
 *
 * This is the Functional Test for testing SET_DEFAULT_SEND_PARAM sockopt and
 * use of the SCTP_SNDRCV ancillary data.
 *
 * Just test payload protocol id and stream. This is mostly just a simple
 * wiring test.
 *
 * Send/receive two messages.  Each with different stream & ppid.
 *
 * Ardelle Fan <ardelle.fan@intel.com>
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
#include <net/sctp/sm.h>
#include <errno.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	int pf_class, af_family;
	struct sctp_endpoint *ep1;
	struct sctp_endpoint *ep2;
	uint8_t *big_buffer;
	int addr_len;
	int error, bytes_sent;
	union sctp_addr loop1;
	union sctp_addr loop2;
	struct sctp_association *asoc1;
	struct sctp_association *asoc2;
	struct iovec iov;
	struct iovec out_iov;
	struct msghdr inmessage;
	char cmsghdr[CMSG_SPACE_SNDRCV] = {0};
	char buf[CMSG_SPACE_INITMSG] = {0};
        struct cmsghdr *outcmsg;
	struct sctp_initmsg *initmsg;
	struct sctp_sndrcvinfo info;
	struct sctp_assoc_change *sac;
	sctp_assoc_t associd1;
	sctp_assoc_t associd2;
        struct msghdr outmsg;
        struct sock *sk1;
        struct sock *sk2;
        uint16_t stream;
	uint32_t ppid;
        uint8_t *message = "hello, world!\n";
        uint8_t *telephone = "Watson, come here!  I need you!\n";

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

	/* Set some basic values which depend on the address family. */

	pf_class = PF_INET;
	af_family = AF_INET;
        loop1.v4.sin_family = AF_INET;
        loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.v4.sin_port = htons(SCTP_TESTPORT_1);
        loop2.v4.sin_family = AF_INET;
        loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.v4.sin_port = htons(SCTP_TESTPORT_2);


        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}

        /* Make sure that duplicate binding fails.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != -EINVAL) { DUMP_CORE; }


        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_flags = 0;

        outmsg.msg_control = buf;
        outmsg.msg_controllen = CMSG_SPACE_INITMSG;
        outcmsg = CMSG_FIRSTHDR(&outmsg);
        outcmsg->cmsg_level = IPPROTO_SCTP;
        outcmsg->cmsg_type = SCTP_INIT;
        outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_initmsg));

        initmsg = (struct sctp_initmsg *)CMSG_DATA(outcmsg);
        initmsg->sinit_num_ostreams = 20;
        initmsg->sinit_max_instreams = 5;
        initmsg->sinit_max_attempts = 0;
        initmsg->sinit_max_init_timeo = 0;

	/* Send the first message.  This will create the association.  */
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	/* Walk through the startup sequence.  */

        /* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	/* Next we expect an INIT ACK. */
	if (test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	/* We expect a COOKIE ECHO.  */
	if (test_step(SCTP_CID_COOKIE_ECHO, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

#ifndef NO_COOKIE_ECHO_BUNDLE
	/* We expect DATA bundled with that COOKIE ECHO.  */
	if (!test_for_chunk(SCTP_CID_DATA, TEST_NETWORK0)) {
		DUMP_CORE;
	}
#endif /* !NO_COOKIE_ECHO_BUNDLE */

	/* We expect a COOKIE ACK.  */
	if (test_step(SCTP_CID_COOKIE_ACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

#ifdef NO_COOKIE_ECHO_BUNDLE
	if (test_step(SCTP_CID_DATA, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	if (test_step(SCTP_CID_SACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
#else
       /* We should see a SACK next.
	 * We ARE truly clever and bundle the SACK with the COOKIE ACK.
	 */
	if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}
#endif /* NO_COOKIE_ECHO_BUNDLE */

	/* Process the COOKIE ACK and the SACK.  */
	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* We have two established associations.  Let's extract some
	 * useful details.
	 */

	ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1);
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

        if (!sctp_outq_is_empty(&asoc1->outqueue)) {
                DUMP_CORE;
        }

	memset(&inmessage, 0x00, sizeof(inmessage));

        /* NOW initialize inmessage with enough space for DATA... */
	big_buffer = kmalloc(REALLY_BIG, GFP_KERNEL);
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        /* or a control message.  */
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = CMSG_SPACE_SNDRCV;

        /* Get the communication up message from sk2.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) {
                printk("recvmsg:  Something went wrong, error: %d\n",
		       error);
                DUMP_CORE;
        }
	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);

	sac = (struct sctp_assoc_change *)big_buffer;
	associd2 = sac->sac_assoc_id;
	printk("sk2 associd = %x\n", (unsigned int)associd2);
	if (associd2 != (sctp_assoc_t)asoc2) {
		DUMP_CORE;
	}


        /* Restore the altered values for the next call... */
	iov.iov_base = big_buffer;
	iov.iov_len = REALLY_BIG;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);


        /* Get the communication up message from sk1.  */
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) {
                printk("recvmsg:  Something went wrong, error: %d\n",
		       error);
                DUMP_CORE;
        }
	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);

	sac = (struct sctp_assoc_change *)big_buffer;
	associd1 = sac->sac_assoc_id;
	printk("sk1 associd = %x\n", (unsigned int)associd1);
	if (associd1 != (sctp_assoc_t)asoc1) {
		DUMP_CORE;
	}

        /* Restore the altered values for the next call... */
	iov.iov_len = REALLY_BIG;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);


        /* Get the first message which was sent.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }


        test_frame_check_message(&inmessage,
                                 /* orig */
				 sizeof(struct sctp_cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
                                 sizeof(struct sctp_sndrcvinfo),
                                 strlen(message) + 1,
                                 message,
                                 SCTP_SNDRCV);

        /* Fixup msg_control, as testframe leaves it in a goofy state. */
	test_frame_fixup_msg_control(&inmessage,
				     sizeof(struct sctp_cmsghdr));

	/* SET_DEFAULT_SEND_PARAM */
	memset(&info, 0x00, sizeof(struct sctp_sndrcvinfo));
	ppid = (uint32_t)rand();
	info.sinfo_ppid = ppid;
	stream = 2;
	info.sinfo_stream = stream;
	info.sinfo_assoc_id = associd1;
        error = sctp_setsockopt(sk1, IPPROTO_SCTP,
				SCTP_DEFAULT_SEND_PARAM, (char *)&info,
                               sizeof(struct sctp_sndrcvinfo));
        if (error != 0) { DUMP_CORE; }

	/* Send a second message */

	outmsg.msg_control = NULL;
	outmsg.msg_controllen = 0;
        outmsg.msg_iov->iov_base = telephone;
        outmsg.msg_iov->iov_len = strlen(telephone) + 1;

        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(telephone)+1);
        if (bytes_sent != strlen(telephone) + 1) { DUMP_CORE; }

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Get that message.  */
        /* Restore the altered values for the next call.  */
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = cmsghdr;
        inmessage.msg_controllen = CMSG_SPACE_SNDRCV;

        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }
        test_frame_check_message(&inmessage,
                                 /* orig */
                                 CMSG_SPACE_SNDRCV,
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
                                 sizeof(struct sctp_sndrcvinfo),
                                 strlen(telephone) + 1,
                                 telephone,
                                 SCTP_SNDRCV);

        /* Fixup msg_control, as testframe leaves it in a goofy state. */
	test_frame_fixup_msg_control(&inmessage,
				     sizeof(struct sctp_cmsghdr));

	/* Make sure that the stream and ppid were preserved. */
	if (!test_check_sndrcvinfo(&inmessage, 0, stream, ppid)) {
		printf("stream: %d, ppid: %d\n",stream, ppid);
		DUMP_CORE;
	}

        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        error = 0;
        sctp_close(sk2, /* timeout */ 0);


	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);

} /* main() */
