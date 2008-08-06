/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 *
 * This file is part of the SCTP kernel Implementation
 *
 * This is a standalone program to test stream negotiation.
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ^^^^^^^^^^^^^^^^^^^^^^^^
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.  
 * 
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 * 
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by: 
 *   Jon Grimm <jgrimm@us.ibm.com>
 *   Daisy Chang <daisyc@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *
 * This test will test the negotiation of the number of inbound/outbound 
 * streams in the association initialization.
 * Case 1 - Open 2 sockets. Do sendmsg() from sk1 to sk2 with a SCTP_INIT 
 *   cmsg without any data. This should result into an EINVAL error.
 * Case 2 - Do sendmsg() from sk1 to sk2 with a SCTP_INIT cmsg along with
 *   a message. This should result in an association between sk1 and sk2.
 *   Since the SCTP_INIT cmsg specifies outbound/inbound streams to be 20/5 
 *   for sk1, and the default values on sk2 is 10/10 for now, the result of 
 *   the negotiation should be 10/20 on sk1, 5/10 on sk2. FIXME - Note that 
 *   this testcase is not perfect because it depends on the default number of 
 *   streams value. Once the setsockopt(SCTP_INITMSG) is implemented, this
 *   testcase should be modified to set the init parms on sk2 to be some
 *   specific numbers, such as 10/10, in order to eliminate any dependencies 
 *   on the default values. 
 * Case 3 - Do sendmsg() from sk1 to sk2 with a SCTP_SNDRCVINFO cmsg. 
 *   The stream id in the SCTP_SNDRCVINFO is invalid - a number which is 
 *   bigger than 10, say 128. This should result in an EINVAL error.
 * Case 4 - Close and reopen sk1 and sk2. Do sendmsg() from sk1 to sk2 with 
 *   a SCTP_INIT as well as a SCTP_SNDRCVINFO cmsg. The stream id in the 
 *   SCTP_SNDRCVINFO is valid before the negotiation but invalid after the 
 *   negotiation. This will result in a SCTP_SEND_FAILED event on sk1. No
 *   data should be sent out.
 * Case 5 - Force to send a message with invalid streams id out from sk1
 *   to sk2. This will result in sk2 receiving a bad data chunk, and 
 *   sk2 should generate an ERROR chunk to sk1 reporting the "Invalid Stream 
 *   Identifier".
 * Case 6 - Hack an INIT to request invalid output stream of 0.  This should
 *   result in an ABORT (Inv. Mandatory Param).
 * Case 7 - Hack an INIT-ACK to request input stream of 0.  This should 
 *   result in an ABORT (Inv. Mandatory Param). 
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/checksum.h>
#include <funtest.h>

int
main(int argc, char **argv)
{
	union sctp_addr loop1, loop2;
	struct sock *sk1, *sk2;
	struct cmsghdr *outcmsg;
	struct cmsghdr *incmsg;
	struct msghdr outmsg;
	struct msghdr inmsg;
	char buf[CMSG_SPACE_INITMSG + CMSG_SPACE_SNDRCV];
	char inbuf[80];
	struct iovec out_iov;
	struct iovec in_iov;
	struct sctp_initmsg *initmsg;
	uint8_t *message = "Hello, World!!!\n";
	int error, bytes_sent;
	struct sctp_endpoint *ep1, *ep2;
	struct sctp_association *asoc1, *asoc2;
	struct sctp_sndrcvinfo *sinfo;
	union sctp_notification *sno;
	int addr_len;
	struct sctp_event_subscribe subscribe;
	struct sk_buff *skb;
	struct bare_sctp_packet *packet;
	sctp_init_chunk_t *initchk;
	struct sctphdr *sh;
	uint32_t val;

        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
        sctp_init();

	/* Set some basic values which depend on the address family. */

        loop1.v4.sin_family = AF_INET;
        loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop1.v4.sin_port = htons(SCTP_TESTPORT_1);
        loop2.v4.sin_family = AF_INET;
        loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop2.v4.sin_port = htons(SCTP_TESTPORT_2);


        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = NULL;
        outmsg.msg_iovlen = 0;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Build up a SCTP_INIT CMSG. */
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

	/* Case 1 - Send it with a 0-length message. This should result
	 * in a EINVAL error. 
	 * Note: Returning EINVAL for this case is currently 
	 * an implementation choice and not defined by the API I-D.
	 */
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, 0);
        if (bytes_sent != -EINVAL) { 
		printk("\n\n %s case 1 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n %s case 1 passed.\n\n\n", argv[0]);

        /* Case 2 - Send it with a message. This will create an association
	 * with outbound/inbound streams to be 5/5. 
	 */
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	if ( test_run_network() ) DUMP_CORE;

	/* Verify the outbound/inbound streams value in the established
	 * association. 
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 
        ep2 = sctp_sk(sk2)->ep;
	asoc2 = test_ep_first_asoc(ep2);

	if (asoc1->c.sinit_num_ostreams != 20 || 
	    asoc2->c.sinit_num_ostreams != 5) {
		printk("asoc1 ostreams=%d instreams=%d, "
		       "asoc2 ostreams=%d instreams=%d\n", 
		       asoc1->c.sinit_num_ostreams, 
		       asoc1->c.sinit_max_instreams, 
		       asoc2->c.sinit_num_ostreams,
		       asoc2->c.sinit_max_instreams); 
		printk("\n\n %s case 2 failed.\n\n\n", argv[0]);
		DUMP_CORE;
	}
	printk("\n\n %s case 2 passed.\n\n\n", argv[0]);

        /* Case 3 - Send a message with an invalid stream id. This will 
	 * cause an EINVAL error. 
	 */

        /* Build up a SCTP_SNDRCVINFO CMSG. */
	outmsg.msg_control = buf;
	outmsg.msg_controllen = CMSG_SPACE_SNDRCV;
	outcmsg = CMSG_FIRSTHDR(&outmsg);
	outcmsg->cmsg_level = IPPROTO_SCTP;
	outcmsg->cmsg_type = SCTP_SNDRCV;
	outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg);
	sinfo->sinfo_stream = 128;
	sinfo->sinfo_ssn = 0;
	sinfo->sinfo_flags = 0;
	sinfo->sinfo_ppid = 0;
	sinfo->sinfo_context = 0;
	sinfo->sinfo_assoc_id = 0;

        /* Send it with a message. This should result in an EINVAL error. */
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != -EINVAL) { 
		printk("\n\n %s case 3 failed.\n\n\n", argv[0]);
		DUMP_CORE; 
	}
	printk("\n\n %s case 3 passed.\n\n\n", argv[0]);

	sctp_close(sk1, 0);

	if ( test_run_network() ) DUMP_CORE;

 	/* Case 4 - Close and reopen sk1 and sk2. Do sendmsg() from sk1 
	 * to sk2 with a SCTP_INIT as well as a SCTP_SNDRCVINFO cmsg. The 
	 * stream id in the SCTP_SNDRCVINFO is valid before the negotiation 
	 * but invalid after the negotiation. This will result in a 
	 * SCTP_SEND_FAILED event on sk1. No data should be sent out.
	 */

	sctp_close(sk2, 0);

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }
       
	/* Enable SCTP_SEND_FAILED and SCTP_REMOTE_ERROR notifications which 
	 * are not on by default. 
	 */
	memset(&subscribe, 0, sizeof(struct sctp_event_subscribe));
	subscribe.sctp_data_io_event = 1;
	subscribe.sctp_association_event = 1;
	subscribe.sctp_send_failure_event = 1;
	subscribe.sctp_peer_error_event = 1;
	if (0 !=  sctp_setsockopt(sk1, SOL_SCTP, SCTP_EVENTS, 
				  (char *)&subscribe,
				  sizeof(struct sctp_event_subscribe))) {
		DUMP_CORE;
	}

	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = NULL;
        outmsg.msg_iovlen = 0;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;

        /* Build up a SCTP_INIT CMSG. */
	outmsg.msg_control = buf;
	outmsg.msg_controllen = CMSG_SPACE_INITMSG + CMSG_SPACE_SNDRCV;
	outcmsg = CMSG_FIRSTHDR(&outmsg);
	outcmsg->cmsg_level = IPPROTO_SCTP;
	outcmsg->cmsg_type = SCTP_INIT;
	outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_initmsg));

	/* Assert that this is even a valid test. */
	if (SCTP_MAX_STREAM < 2) {
		printk("This test needs SCTP_MAX_STREAM > 2, but "
		       "SCTP_MAX_STREAM is %d.\n", SCTP_MAX_STREAM);
		DUMP_CORE;
	}
	initmsg = (struct sctp_initmsg *)CMSG_DATA(outcmsg);
	initmsg->sinit_num_ostreams = SCTP_MAX_STREAM;
	initmsg->sinit_max_instreams = SCTP_MAX_STREAM-1;
	initmsg->sinit_max_attempts = 0;
	initmsg->sinit_max_init_timeo = 0;

	outcmsg = CMSG_NXTHDR(&outmsg, outcmsg);
	outcmsg->cmsg_level = IPPROTO_SCTP;
	outcmsg->cmsg_type = SCTP_SNDRCV;
	outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg);
        /* Set to an invalid number after negotiation */
	sctp_sk(sk2)->initmsg.sinit_max_instreams = SCTP_MAX_STREAM-1;
	sinfo->sinfo_stream = SCTP_MAX_STREAM-1;	
	sinfo->sinfo_ssn = 0;
	sinfo->sinfo_flags = 0;
	sinfo->sinfo_ppid = 0;
	sinfo->sinfo_context = 0;
	sinfo->sinfo_assoc_id = 0;

        /* Send it with a message. */
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	if ( test_run_network() ) DUMP_CORE;

        memset(&inmsg, 0, sizeof(struct msghdr));
        in_iov.iov_base = inbuf;
        in_iov.iov_len = sizeof(inbuf);
        inmsg.msg_iov = &in_iov;
        inmsg.msg_iovlen = 1;
        inmsg.msg_control = &incmsg;
        inmsg.msg_controllen = sizeof(struct sctp_cmsghdr);

	/* Get the communication up message from sk1.  */

        bytes_sent = sctp_recvmsg(NULL, sk1, &inmsg, sizeof(inbuf),
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
	        

	if (inmsg.msg_flags & MSG_NOTIFICATION) {
		sno = (union sctp_notification *)inbuf;
		if (SCTP_SEND_FAILED != sno->sn_header.sn_type) {
			printk("We expect %x but we get %x notification\n",
				SCTP_SEND_FAILED, sno->sn_header.sn_type);
			DUMP_CORE;
		}
		if (SCTP_DATA_UNSENT != sno->sn_send_failed.ssf_flags) {
			printk("We expect %x but we get %x ssf_flags\n",
			  SCTP_DATA_UNSENT, sno->sn_send_failed.ssf_flags);
			DUMP_CORE;
		}
		if (SCTP_ERROR_INV_STRM != sno->sn_send_failed.ssf_error) {
			printk("We expect %x but we get %x ssf_error\n",
			  SCTP_ERROR_INV_STRM, sno->sn_send_failed.ssf_error);
			DUMP_CORE;
		}
	}
	else {
		printk("We expect notification, nothing else!!\n");
		DUMP_CORE;
	}


	/* Get the communication up message from sk1.  */
	test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	printk("\n\n %s case 4 passed.\n\n\n", argv[0]);
	
	/* Case 5 - Force to send a message with invalid streams id out 
	 * from sk1 to sk2. This will result in sk2 receiving a bad data 
	 * chunk, and sk2 should generate an ERROR chunk to sk1 reporting 
	 * the "Invalid Stream Identifier". 
 	 */

	/* Fake the outbound streams value in the established
	 * association on the sk1 side to allow a bad stream id to be
	 * sent.
	 * Note: the previous test negotitated the outbound stream down
	 * from the maximum.  
	 */
	ep1 = sctp_sk(sk1)->ep;
	asoc1 = test_ep_first_asoc(ep1); 

	if (asoc1->c.sinit_num_ostreams != (SCTP_MAX_STREAM-1)) { 
		printk("asoc1 ostreams=%x instreams=%x\n", 
			asoc1->c.sinit_num_ostreams, 
			asoc1->c.sinit_max_instreams);
		printk("\n\n %s case 5 failed.\n\n\n", argv[0]);
		DUMP_CORE;
	}

	/* Bump up to the maximum allowed by our data structures. 
	 */
	asoc1->c.sinit_num_ostreams = SCTP_MAX_STREAM;  /* Fake it! */

        /* Build up a SCTP_INIT CMSG. */
	outmsg.msg_control = buf;
	outmsg.msg_controllen = CMSG_SPACE_SNDRCV;
	outcmsg = CMSG_FIRSTHDR(&outmsg);
	outcmsg->cmsg_level = IPPROTO_SCTP;
	outcmsg->cmsg_type = SCTP_SNDRCV;
	outcmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(outcmsg);
	sinfo->sinfo_stream = SCTP_MAX_STREAM-1;   /* invalid number */
	sinfo->sinfo_ssn = 0;
	sinfo->sinfo_flags = 0;
	sinfo->sinfo_ppid = 0;
	sinfo->sinfo_context = 0;
	sinfo->sinfo_assoc_id = 0;

        /* Send it with a message. */
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	if ( test_run_network() ) DUMP_CORE;

	/* Get the remote error event from sk1.  */
        memset(&inmsg, 0, sizeof(struct msghdr));
        in_iov.iov_base = inbuf;
        in_iov.iov_len = sizeof(inbuf);
        inmsg.msg_iov = &in_iov;
        inmsg.msg_iovlen = 1;
        inmsg.msg_control = &incmsg;
        inmsg.msg_controllen = sizeof(struct sctp_cmsghdr);
        bytes_sent = sctp_recvmsg(NULL, sk1, &inmsg, sizeof(inbuf),
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
	        
	if (inmsg.msg_flags & MSG_NOTIFICATION) {
		sno = (union sctp_notification *)inbuf;
		if (SCTP_REMOTE_ERROR != sno->sn_header.sn_type) {
			printk("We expect %x but we get %x notification\n",
			       SCTP_REMOTE_ERROR, sno->sn_header.sn_type);
			DUMP_CORE;
		}
		if (SCTP_ERROR_INV_STRM != 
				sno->sn_remote_error.sre_error) {
			printk("We expect %x but we get %x sre_error\n",
			       SCTP_ERROR_INV_STRM, 
			       sno->sn_remote_error.sre_error);
			DUMP_CORE;
		}
		if (SCTP_MAX_STREAM-1 != ntohs(*((uint16_t *)
			(sno->sn_remote_error.sre_data)))) {
			printk("We expect %d but we get %d invalid stream #\n",
			       SCTP_MAX_STREAM-1,
			       ntohs(*((uint16_t *)
				       (sno->sn_remote_error.sre_data))));
			DUMP_CORE;
		}
	}
	else {
		printk("We expect notification, nothing else!!\n");
		DUMP_CORE;
	}

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if ( test_run_network() ) DUMP_CORE;

	printk("\n\n %s case 5 passed.\n\n\n", argv[0]);


	/* Hack up an INIT with output stream 0.   This should
	 * be ABORTed. 
	 */

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = NULL;
        outmsg.msg_iovlen = 0;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Build up a SCTP_INIT CMSG. */
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


        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	/* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (!skb) 
		DUMP_CORE;


	packet = test_get_sctp(skb->data);
	initchk = (sctp_init_chunk_t *)&packet->ch;
	/* Is this an INIT chunk? */
	if (SCTP_CID_INIT != initchk->chunk_hdr.type) {
		DUMP_CORE;
	}

	initchk->init_hdr.num_outbound_streams = 0;
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
			       skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = val;

	/* We expect an ABORT with invalid mandatory parameters. */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (!skb) 
		DUMP_CORE;

	if ( test_run_network() ) DUMP_CORE;

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if ( test_run_network() ) DUMP_CORE;

	printk("\n\n %s case 6 passed.\n\n\n", argv[0]);

	/* Hack up an INIT with output stream 0.   This should
	 * be ABORTed. 
	 */

        /* Create the two endpoints which will talk to each other.  */
        sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
        sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        /* Bind these sockets to the test ports.  */
        error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
        if (error != 0) { DUMP_CORE; }

        error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = NULL;
        outmsg.msg_iovlen = 0;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Build up a SCTP_INIT CMSG. */
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


        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }

	/* We should have an INIT sitting on the Internet. */
	if (!test_for_chunk(SCTP_CID_INIT, TEST_NETWORK0)) {
		DUMP_CORE;
	}
	/* Next we expect an INIT ACK, since there is no peer.  */
	if (!test_step(SCTP_CID_INIT_ACK, TEST_NETWORK0)) {
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (!skb) 
		DUMP_CORE;

	packet = test_get_sctp(skb->data);
	initchk = (sctp_init_chunk_t *)&packet->ch;
	/* Is this an INIT-ACK chunk? */
	if (SCTP_CID_INIT_ACK != initchk->chunk_hdr.type) {
		DUMP_CORE;
	}

	/* INIT and INIT-ACK have same header. */
	/* Hack the inbound streams this time. */
	initchk->init_hdr.num_inbound_streams = 0;
	sh = &packet->sh;
	val = sctp_start_cksum((uint8_t *)sh,
			       skb->len - sizeof(struct iphdr));
	val = sctp_end_cksum(val);
	sh->checksum = val;

	/* We expect an ABORT with invalid mandatory parameters. */
	if (test_step(SCTP_CID_ABORT, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	skb = test_peek_packet(TEST_NETWORK0);
	if (!skb) 
		DUMP_CORE;

	if ( test_run_network() ) DUMP_CORE;

	sctp_close(sk1, 0);
	sctp_close(sk2, 0);

	if ( test_run_network() ) DUMP_CORE;

	printk("\n\n %s case 7 passed.\n\n\n", argv[0]);

	exit(0);

} /* main() */



