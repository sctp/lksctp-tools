/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
 *
 * This file is part of the SCTP Linux kernel reference implementation
 * 
 * This is a functional test for the SCTP kernel reference
 * implementation state machine.
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
 * Please send any bug reports or fixes you make to one of the following
 * email addresses:
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
        struct sock *sk1, *sk2;
	union sctp_addr loop1;
	union sctp_addr loop2;
        struct msghdr outmsg;
        struct iovec out_iov;
        uint8_t message[15] = "Hello world!";
        int error, bytes_sent;
	int mapped, len;
        uint8_t big_buffer[REALLY_BIG];
        struct msghdr msg;
        struct iovec iov;
        int cmsghdr[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
        int addr_len;

        /* Do all that random stuff needed to make a sensible universe.  */
	init_Internet();
	sctp_init();

	memset(&loop1, 0, sizeof(union sctp_addr));
	memset(&loop2, 0, sizeof(union sctp_addr));

	/* Create the two endpoints which will talk to each other.  */
	sk1 = sctp_socket(PF_INET6, SOCK_SEQPACKET);
	sk2 = sctp_socket(PF_INET6, SOCK_SEQPACKET);

	len = sizeof(mapped);
	/* By default v4 addresses are mapped to v6 representation. Verify
	 * that this option is turned on.
	 */ 
	error = sctp_getsockopt(sk2, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR,
				(char *)&mapped, &len);
	if (error != 0) DUMP_CORE;
	if (mapped != 1) DUMP_CORE;

	/* Turn off mapped v4 addresses. */
	mapped = 0;
	error = sctp_setsockopt(sk2, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR,
				(char *)&mapped, sizeof(int));

	error = sctp_getsockopt(sk2, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR,
				(char *)&mapped, &len);
	if (error != 0) DUMP_CORE;
	if (mapped != 0) DUMP_CORE;

	/* Initialize a v4 address. */
	loop1.v4.sin_family = AF_INET;
	loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.v4.sin_port = htons(SCTP_TESTPORT_1);

	/* Initialize a v4-mapped-v6 address. */
        loop2.v6.sin6_family = AF_INET6;
	loop2.v6.sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
        loop2.v6.sin6_addr.s6_addr32[3] = SCTP_IP_LOOPBACK;
        loop2.v6.sin6_port = htons(SCTP_TESTPORT_2);

	/* Bind a v4 address to sk1. */
	error = test_bind(sk1, (struct sockaddr *)&loop1, sizeof(loop1));
	if (error != 0) { DUMP_CORE; }
       
	/* Bind a v4 mapped v6 address to sk2. It should fail. */
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error == 0) { DUMP_CORE; }

	/* Enable v4 mapped v6 addresseson sk2. */
	mapped = 1;
	error = sctp_setsockopt(sk2, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR,
				(char *)&mapped, sizeof(int));

	error = sctp_getsockopt(sk2, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR,
				(char *)&mapped, &len);
	if (error != 0) DUMP_CORE;
	if (mapped != 1) DUMP_CORE;

	/* Since the frame test uses a faked ipv6_setsockopt, set ipv6only
	 * manually.
	 */
	inet6_sk(sk2)->ipv6only = 1;

	/* Try to bind a v4-mapped-v6 address to a v6only socket. It should
	 * fail.
	 */	
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error == 0) { DUMP_CORE; }

	loop2.v4.sin_family = AF_INET;
	loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.v4.sin_port = htons(SCTP_TESTPORT_2);
	/* Try to bind a v4 address to a v6only socket. It should fail.  */	
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error == 0) { DUMP_CORE; }

        loop2.v6.sin6_family = AF_INET6;
	loop2.v6.sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
        loop2.v6.sin6_addr.s6_addr32[3] = SCTP_IP_LOOPBACK;
        loop2.v6.sin6_port = htons(SCTP_TESTPORT_2);

	/* Disable v6only socket option. */
	inet6_sk(sk2)->ipv6only = 0;

	/* Bind a v4 mapped v6 address to sk2. It should succeed now as
	 * I_WANT_MAPPED_V4_ADDR is turned on and v6only is turned off.
	 */
	error = test_bind(sk2, (struct sockaddr *)&loop2, sizeof(loop2));
	if (error != 0) { DUMP_CORE; }

	/* Mark sk2 as being able to accept new associations. */
	if (0 != test_listen(sk2, 1)) {
		DUMP_CORE;
	}
        
	loop2.v4.sin_family = AF_INET;
	loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.v4.sin_port = htons(SCTP_TESTPORT_2);

        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop2;
        outmsg.msg_namelen = sizeof(loop2);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
	/* Send the first message.  This will create the association.  */
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }
        
        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        test_frame_get_event(sk2, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
        test_frame_get_event(sk1, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        len = strlen(message) + 1;
        memset(&msg, 0, sizeof(struct msghdr));
        iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        msg.msg_name = &loop2;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsghdr;
        msg.msg_controllen = sizeof(cmsghdr);
        error = sctp_recvmsg(NULL, sk2, &msg, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }
        printk("%s %d %d\n", big_buffer, REALLY_BIG, len);

        test_frame_check_message(&msg,
                                 /* orig */
                                 sizeof(cmsghdr),
                                 REALLY_BIG,
                                 big_buffer,
                                 /* expected */
                                 sizeof(struct sctp_sndrcvinfo),
                                 len,
                                 message,
                                 (SOCK_SEQPACKET == sk2->sk_family)?SCTP_SNDRCV:0);

	/* Verify that the returned address is a v4-mapped-v6 address. */
	if (!msg.msg_name)
		DUMP_CORE;
	if (((union sctp_addr *)msg.msg_name)->v6.sin6_family != AF_INET6) {
		DUMP_CORE;
	}
	if (((union sctp_addr *)msg.msg_name)->v6.sin6_addr.s6_addr32[3] !=
	    SCTP_IP_LOOPBACK)
		DUMP_CORE;
	if (((union sctp_addr *)msg.msg_name)->v6.sin6_port !=
	    htons(SCTP_TESTPORT_1))
		DUMP_CORE;

	sctp_close(sk1, /* timeout */ 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        sctp_close(sk2, /* timeout */ 0);

	if (0 == error) {
		printk("\n\n%s passed\n\n\n", argv[0]);
	}

        /* Indicate successful completion.  */
        exit(error);
} /* main() */
