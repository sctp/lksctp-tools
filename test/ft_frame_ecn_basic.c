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
 * warranty of
 *                 ************************
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.  
 * 
 * Please send any bug reports or fixes you make to one of the following email
 * addresses:
 * 
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Jon Grimm <jgrimm@us.ibm.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* ft_frame_ecn_basic.c
 * This is the Functional Test for to test the ecn capabilities-o!
 * ECN is an optional feature of SCTP, however an implementation may choose
 * to implement it along the lines of RFC 2481.  As SCTP was developed 
 * post-ECN, SCTP had the luxury of incorporating ECN considerations and 
 * consequently, has specific data structures used for both ECN negotiation, 
 * as well as, ECN ECHO & CWR.
 *
 * The following steps will occur:
 * 1) Setup succesful association between to sockets on loopback
 * 2) Check that ECN has been negotiated
 * 3) Store rcvr ssthresh
 * 4) Send uncongested packet
 * 5) Check that rcvr ssthresh has not changed
 * 6) Send congested packet
 * 7) Check that rcvr ssthresh has changed 
 *
 * To test this we'll reach directly into the association data structure to
 * determine if an established association negotiationed for ECN capabilities.
 * Additionally, I will use the same hack to check the rcvr ssthresh.  
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
#include <net/sock.h>
#include <linux/wait.h> /* For wait_queue_head_t */
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <errno.h>
#include <funtest.h>

static int _is_ecn(struct sock*);
static void _test_congestion(struct sock*, 
			     struct sock*, int congest);
static int _get_cwnd(struct sock*);


static int _get_ssthresh(struct sock *sk1);
static void _get_sockets(struct sock**, struct sock**);
static  void _initiate_connection(struct sock*, struct sock*);
static void _teardown_connection(struct sock*, struct sock*);

int main(int argc, char *argv[])
{
	struct sock *sk1;
	struct sock *sk2;
        
        /* Do all that random stuff needed to make a sensible
         * universe.
         */
	init_Internet();
	sctp_init();

	_get_sockets(&sk1, &sk2);
	_initiate_connection(sk1, sk2);


	if ( !_is_ecn(sk1) ||
	    !_is_ecn(sk2)){
		printk("ECN not negotiated !\n");
		DUMP_CORE;
	}
        
	
	_test_congestion(sk1, sk2, 0);
	_test_congestion(sk1, sk2, 1);
	_test_congestion(sk1, sk2, 0);

	_teardown_connection(sk1, sk2);
       
	
	printk("\n\n%s passed\n\n\n", argv[0]);


        /* Indicate successful completion.  */
        exit(0);
} /* main() */

static void
_get_sockets(struct sock **sk1, struct sock **sk2)
{
        struct sock *_sk1;
	struct sock *_sk2;
	union sctp_addr loop;
	int pf_class;
        int error = 0;

#if TEST_V6    
	pf_class = PF_INET6;
        loop.v6.sin6_family = AF_INET6;
        loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
#else    
	pf_class = PF_INET;
        loop.v4.sin_family = AF_INET;
        loop.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
#endif

      /* Create the two endpoints which will talk to each other.  */
        _sk1 = sctp_socket(pf_class, SOCK_SEQPACKET);
        _sk2 = sctp_socket(pf_class, SOCK_SEQPACKET);
        
        /* Bind these sockets to the test ports.  */
        loop.v4.sin_port = htons(SCTP_TESTPORT_1);
        error = test_bind(_sk1, (struct sockaddr *)&loop, sizeof(loop));
        if (error != 0) { DUMP_CORE; }
        
        loop.v4.sin_port = htons(SCTP_TESTPORT_2);
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
	union sctp_addr loop;  
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

#if TEST_V6    
        loop.v6.sin6_family = AF_INET6;
        loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
#else    
        loop.v4.sin_family = AF_INET;
        loop.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
#endif       
        loop.v4.sin_port = htons(SCTP_TESTPORT_2);
        
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
	iov.iov_base = big_buffer;
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
	iov.iov_base = big_buffer;
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
       
        /* Shut down the link.  */
	sctp_close(sk1, /* timeout */ 0);
	sctp_close(sk2, /* timeout */ 0);
       
} /* _teardown_connection() */


static int
_is_ecn(struct sock *sk1)
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;

	ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1); 

	return(asoc1->peer.ecn_capable);

} /* _is_ecn() */


static void
_test_congestion(struct sock* sk1, struct sock* sk2, int congest)
{
	union sctp_addr loop;
        struct msghdr outmsg;
        struct iovec out_iov;
        uint8_t *message = "hello, world!\n";
        int error = 0;
        int bytes_sent;
	int cwnd, ssthresh;

	ssthresh = _get_ssthresh(sk1);
	cwnd = _get_cwnd(sk1);
	congest = (congest != 0); /* Normalize to boolean.  */

	printk("ssthresh = %d\n", ssthresh);

#if TEST_V6    
        loop.v6.sin6_family = AF_INET6;
        loop.v6.sin6_addr = (struct in6_addr)SCTP_IN6ADDR_LOOPBACK_INIT;
#else    
        loop.v4.sin_family = AF_INET;
        loop.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
#endif
        loop.v4.sin_port = htons(SCTP_TESTPORT_2);	

        /* Build up a msghdr structure we can use for all sending.  */
        outmsg.msg_name = &loop;
        outmsg.msg_namelen = sizeof(loop);
        outmsg.msg_iov = &out_iov;
        outmsg.msg_iovlen = 1;
        outmsg.msg_control = NULL;
        outmsg.msg_controllen = 0;
        outmsg.msg_flags = 0;
        
        /* Send a single message. */
        outmsg.msg_iov->iov_base = message;
        outmsg.msg_iov->iov_len = strlen(message) + 1;
        bytes_sent = sctp_sendmsg(NULL, sk1, &outmsg, strlen(message)+1);
        if (bytes_sent != strlen(message) + 1) { DUMP_CORE; }
        
	if (congest) {
		test_congest_next_packet(SCTP_CID_DATA);
		/* Increment jiffies so that ECNE chunk is sent after a
		 * round trip time. 
		 */
		jiffies += 1;
	}

        error = test_run_network();

        if (error != 0) { DUMP_CORE; }

	/* Check whether cwnd changed vs congestion sent */

	printk("congestion = %s\n", congest?"yes":"no");
	printk("before send, rcvr ssthresh = 0x%x\n", ssthresh);
	printk("after send, rcvr ssthresh= 0x%x\n", _get_ssthresh(sk1));
	if (congest == (ssthresh == _get_ssthresh(sk1))){	
 		DUMP_CORE;
 	}

} /* _test_congestion() */


static int
_get_cwnd(struct sock *sk1)
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;

	ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1); 

	return(asoc1->peer.active_path->cwnd);	
	
} /* _get_cwnd() */


static int
_get_ssthresh(struct sock *sk1)
{
        struct sctp_endpoint *ep1;
        struct sctp_association *asoc1;

	ep1 = sctp_sk(sk1)->ep;
	asoc1= test_ep_first_asoc(ep1); 

	return(asoc1->peer.active_path->ssthresh);	
	
} /* _get_ssthresh() */

