/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999 Cisco and Motorola
 *
 * This file is part of the SCTP Linux kernel implementation
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
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Jon Grimm <jgrimm@us.ibm.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */


/*
 * ft_frame_ecn_negotiate.c
 * This is the Functional Test for the negotiation of ECN capability.
 * ECN is an optional feature of SCTP, however an implementation may choose
 * to implement it along the lines of RFC 2481.  As SCTP was developed 
 * post-ECN, SCTP had the luxury of incorporating ECN considerations and 
 * consequently, has specific data structures used for both ECN negotiation, 
 * as well as, ECN ECHO & CWR.
 *
 * 
 * Originally this testcase set up 4 links to test the following scenarios:
 * 1) neither sender nor reciever supports ECN
 * 2) both sender and receiver supports ECN
 * 3) only sender supports ECN
 * 4) only receiver supports ECN
 * 
 * However, we are removing the ability to even make ECN negotiation
 * configurable, thus removing the ability to test (within the framework)
 * #1, #3, and #4.  We'll comment those tests out.  
 * 
 *
 *
 * To test this we'll reach directly into the association data structure to
 * determine if an established association negotiationed for ECN capabilities
 *
 * Jon Grimm <jgrimm@us.ibm.com>
 *
 * We use functions which approximate the user level API defined in
 * draft-ietf-tsvwg-sctpsocket-07.txt.
 */

#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/cache.h> /* For SMP_CACHE_BYTES */
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h>
#include <funtest.h>

static void _test_ecn_both_on(void);
static void _get_sockets(struct sock**, struct sock**);
static void _initiate_connection(struct sock*, struct sock*);
static void _teardown_connection(struct sock*, struct sock*);

int
main(int argc, char *argv[])
{
        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
	sctp_init();
	
	/* Scenario #1 */
	/* _test_ecn_both_off(); */

	/* Scenario #2 */
	_test_ecn_both_on();

	/* Scenario #3 */
	/* _test_ecn_snd_on(); */

	/* Scenario #4 */
	/* _test_ecn_rcv_on(); */

	printk("\n\n%s passed\n\n\n", argv[0]);


        /* Indicate successful completion.  */
        exit(0);
} /* main() */

static void
_get_sockets(struct sock **sk1, struct sock **sk2)
{
        
        struct sock *_sk1;
	struct sock *_sk2;
	struct sockaddr_in loop;
        int error = 0;
	
      /* Create the two endpoints which will talk to each other.  */
        _sk1 = sctp_socket(PF_INET, SOCK_SEQPACKET);
	_sk2 = sctp_socket(PF_INET, SOCK_SEQPACKET);

        loop.sin_family = AF_INET;
        loop.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        /* Bind these sockets to the test ports.  */
        loop.sin_port = htons(SCTP_TESTPORT_1);
        error = test_bind(_sk1, (struct sockaddr *)&loop, sizeof(loop));
        if (error != 0) { DUMP_CORE; }
        
        loop.sin_port = htons(SCTP_TESTPORT_2);
        error = test_bind(_sk2, (struct sockaddr *)&loop, sizeof(loop));
        if (error != 0) { DUMP_CORE; }
        
	/* Mark _sk2 as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(_sk2, 1)) {
		DUMP_CORE;
	}
	

	*sk1 = _sk1;
	*sk2 = _sk2;

} /* _get_sockets() */

static void
_initiate_connection(struct sock *sk1, struct sock *sk2)
{
	struct sockaddr_in loop;  
        struct msghdr outmsg;
        struct sctp_cmsghdr cmsghdr;
        struct iovec iov;
        struct iovec out_iov;
        struct msghdr inmessage;
	uint8_t *big_buffer;
        uint8_t *message = "hello, world!\n";
        int error = 0;
        int bytes_sent;
        int addr_len; 

        
        loop.sin_family = AF_INET;
        loop.sin_addr.s_addr = SCTP_IP_LOOPBACK;
        loop.sin_port = htons(SCTP_TESTPORT_2);
        
        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop;
        outmsg.msg_namelen = sizeof(loop);
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
        /* DO NOT PASS THIS LINE WITHOUT SEEING COOKIE ACK AND THE
         * FIRST SACK!!!!
         */

        /* NOW initialize inmessage with enough space for DATA... */
        memset(&inmessage, 0, sizeof(inmessage));
	big_buffer = kmalloc(REALLY_BIG, GFP_KERNEL);
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        /* or a control message.  */
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        /* Get the communication up message from sk2.  */
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }
	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);


        /* Restore the altered values for the next call... */
	iov.iov_len = REALLY_BIG;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);

        /* Get the communication up message from sk1.  */
        error = sctp_recvmsg(NULL, sk1, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) {
                printk("recvmsg:  Something went wrong, error: %d\n", error);
                DUMP_CORE;
        }

	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_COMM_UP);


        /* Get the first message which was sent.  */
	iov.iov_len = REALLY_BIG;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
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
	
	kfree(big_buffer);

}; /* _initiate_connection() */


static void
_teardown_connection(struct sock* sk1, struct sock* sk2)
{
        struct sctp_cmsghdr cmsghdr;
        struct iovec iov;
        struct msghdr inmessage;
	uint8_t *big_buffer;
        int error = 0;
        int addr_len; 

        /* NOW initialize inmessage with enough space for DATA... */
        memset(&inmessage, 0, sizeof(inmessage));
	big_buffer = kmalloc(REALLY_BIG, GFP_KERNEL);
	iov.iov_base = big_buffer;
        iov.iov_len = REALLY_BIG;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        /* or a control message.  */
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);


        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);

        error = test_run_network();
        if (error != 0) { DUMP_CORE; }

        /* Get the shutdown complete notification. */
        /* Restore the altered values for the next call.  */
        iov.iov_len = REALLY_BIG;
	iov.iov_base = big_buffer;
        inmessage.msg_iov = &iov;
        inmessage.msg_iovlen = 1;
        inmessage.msg_control = &cmsghdr;
        inmessage.msg_controllen = sizeof(struct sctp_cmsghdr);
        error = sctp_recvmsg(NULL, sk2, &inmessage, REALLY_BIG,
                             /* noblock */ 1, /* flags */ 0,
                             &addr_len);
        if (error < 0) { DUMP_CORE; }

	test_frame_check_notification(&inmessage,
				      REALLY_BIG,
				      sizeof(struct sctp_assoc_change),
				      SCTP_ASSOC_CHANGE,
				      SCTP_SHUTDOWN_COMP);
	  
        sctp_close(sk2, /* timeout */ 0);

	kfree(big_buffer);

} /* _teardown_connection() */

static int
_test_ecn_capable(int scap, int rcap)
{
	struct sock *sk1;
	struct sock *sk2;
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;
        struct sctp_endpoint *ep2;
        struct sctp_association *asoc2;
	int capable;

	_get_sockets(&sk1, &sk2);

	printk("test ecn capable\n");
	ep1 = sctp_sk(sk1)->ep;
	ep2 = sctp_sk(sk2)->ep;

	_initiate_connection(sk1, sk2);
        asoc1 = test_ep_first_asoc(ep1);
        asoc2 = test_ep_first_asoc(ep2);

	printk("ecn_capable 1:%d 2:%d\n", asoc1->peer.ecn_capable, 
	       asoc2->peer.ecn_capable);

	capable = asoc1->peer.ecn_capable && asoc2->peer.ecn_capable;
 
	_teardown_connection(sk1, sk2);   

	
	return capable;	
} /* _test_ecn_capable() */


void
_test_ecn_both_on(void)
{
	int capable;

	capable = _test_ecn_capable(1, 1);

	if (!capable){
		printk("both_on: failed\n");
		DUMP_CORE;
	}	

} /* _test_ecn_both_on() */

void
_test_ecn_both_off(void)
{
	int capable;

	capable = _test_ecn_capable(0, 0);

	if (capable){
		printk("both_off: failed\n");
		DUMP_CORE;
	}	
	
} /* _test_ecn_both_off() */

void
_test_ecn_snd_on(void)
{
	int capable;

	capable = _test_ecn_capable(1, 0);

	if (capable){
		printk("snd_on: failed\n");
		DUMP_CORE;
	}	
} /* _test_ecn_snd_on() */

void
_test_ecn_rcv_on(void)
{
	int capable;
	
	capable = _test_ecn_capable(0, 1);

	if (capable){
		printk("rcv on: failed\n");
		DUMP_CORE;
	}	

} /* _test_ecn_rcv_on() */
