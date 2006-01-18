/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 * Copyright (c) 2001 La Monte H.P. Yarroll
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * The SCTP reference implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * the SCTP reference implementation  is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.  
 * 
 * Please send any bug reports or fixes you make to one of the
 * following email addresses:
 * 
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Randall Stewart <randall@stewart.chicago.il.us>
 * Ken Morneau <kmorneau@cisco.com>
 * Qiaobing Xie <qxie1@motorola.com>
 * Daisy Chang <daisyc@us.ibm.com>
 * Jon Grimm <jgrimm@us.ibm.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * Hui Huang <hui.huang@nokia.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 * 
 */

#ifndef __funtest_h__


/* FIXME:  This is a temporary workaround to get the code compiling again.  
 * The header files really need a refactoring.
 */
#ifdef TEST_FRAME

#include <linux/ip.h> /* Dang struct bare_ipv4_sctp_packet... */
#include <linux/ipv6.h> /* ibid bare_ipv6_... */
#include <net/sctp/sctp.h> 
#include <net/sctp/sm.h> 
#include <stdio.h> /* pick up fflush. */


/* FIXME: This should go away as it encourages improper CMSG handling.
 * --jgrimm
 */
struct sctp_cmsghdr {
        size_t		 cmsg_len;   /* #bytes, including this header */
        int     	 cmsg_level; /* originating protocol */
        sctp_cmsg_t	 cmsg_type;  /* protocol-specific type */
        sctp_cmsg_data_t cmsg_data;
}; /* struct sctp_cmsghdr */



#else 

#include <sys/time.h>		/* for struct timezone */

#endif /* TEST_FRAME */

#define CMSG_SPACE_INITMSG (CMSG_SPACE(sizeof(struct sctp_initmsg)))
#define CMSG_LEN_INITMSG CMSG_LEN(sizeof(struct sctp_initmsg))
#define CMSG_SPACE_SNDRCV CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))
#define CMSG_LEN_SNDRCV CMSG_LEN(sizeof(struct sctp_sndrcvinfo))
#define CMSG_SPACE_SNDRCVINFO (CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)))

/* Loop through an sk_buff_head list.
 * Now SK_FOR can tolerate 'todo' removing 'var' from 'thelist'
 *						--xguo
 */
#define SK_FOR(type, var, thelist, todo)			\
{								\
	type __tmp;						\
	type __list = (type) &(thelist);			\
	for (var = __list->next; var != __list; var = __tmp) {	\
		/* Make safe for deleted elements.  */		\
		__tmp = var->next;				\
		todo;						\
	}							\
} /* SK_FOR() */


#define SK_FOR2(t1, v1, l1, t2, v2, l2, todo) \
	SK_FOR(t1, v1, l1, SK_FOR(t2, v2, l2, todo));

#define SK_FOR3(t1, v1, l1, t2, v2, l2, t3, v3, l3, todo) \
	SK_FOR(t1, v1, l1, SK_FOR(t2, v2, l2, SK_FOR(t3, v3, l3, todo)));



#define REALLY_BIG 70000


/* Literal defines.  */
#ifdef PROT_SOCK
#define SCTP_TESTPORT_1 PROT_SOCK
#else
#define SCTP_TESTPORT_1 1024 
#endif
#define SCTP_TESTPORT_2 (SCTP_TESTPORT_1+1)
/* We use this port when we need a port that doesn't matter.  */
#define SCTP_TESTPORT_FOO (SCTP_TESTPORT_1+0xFF)

#define SCTP_IP_BCAST  	htonl(0xffffffff)
#define SCTP_IP_LOOPBACK  htonl(0x7f000001)

/* These are stolen from <netinet/in.h> because it is a pain to incle
 * that file in the test frame.
 */
#define SCTP_IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define SCTP_IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

#define SCTP_NETMASK htonl(0xff000000)                /* netmask */T

/* The number of links/networks defined for the testframe kernel.  Note that
 * the number of networks would need to correspond to the number of 
 * interfaces/addresses defined below.  The network number for each 
 * link/network is set by masking address SCTP_ADDR_ETHx with the 
 * SCTP_MASK_LO.  The output will be routed to different networks based
 * on network numbers. 
 */
#define NUM_NETWORKS 4
#define TEST_NETWORK0 0
#define TEST_NETWORK_ETH0 1
#define TEST_NETWORK_ETH1 2
#define TEST_NETWORK_ETH2 3

#define SCTP_ADDR_LO	htonl(0x7f000001)	/* 127.0.0.1/8 */
#define SCTP_MASK_LO	htonl(0xff000000)

/* These are all RFC1918 addresses.
 * 10.0.0.0/8 
 * 172.16.0.0/12 
 * 192.168.0.0/16
 */
#define SCTP_ADDR_ETH0	htonl(0x0a000001)	/* 10.0.0.1/8 */
#define SCTP_MASK_ETH0	htonl(0xff000000)
#define SCTP_ADDR_ETH1	htonl(0xac100001)       /* 172.16.0.1/16 */
#define SCTP_MASK_ETH1	htonl(0xffff0000)
#define SCTP_ADDR_ETH2  htonl(0xc0a82a01)	/* 192.168.42.1/24 */
#define SCTP_MASK_ETH2	htonl(0xffffff00)
#define SCTP_B_ETH0     htonl(0x0a000002)       /* 10.0.0.2/8 */
#define SCTP_C_ETH0     htonl(0x0a000003)       /* 10.0.0.3/8 */
#define SCTP_D_ETH0     htonl(0x0a000004)       /* 10.0.0.4/8 */
#define SCTP_GLOBAL_ETH0 htonl(0x0411a806)      /* 4.17.168.6 */

/* define three types of IPv6 address for eth0, eth1 and eth2 */
#define SCTP_ADDR6_LINKLOCAL_ETH0 { { { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } } /* fe80::1*/
#define SCTP_ADDR6_SITELOCAL_ETH0 { { { 0xfe,0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } } /* fec0::1*/
#define SCTP_ADDR6_GLOBAL_ETH0 { { { 0x3f,0xfe,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } } /* 3ffe::1*/
#define SCTP_ADDR6_LINKLOCAL_ETH1 { { { 0xfe,0x80,0,0,0,1,0,0,0,0,0,0,0,0,0,1 } } } /* fe80:0:1::1*/
#define SCTP_ADDR6_SITELOCAL_ETH1 { { { 0xfe,0xc0,0,0,0,1,0,0,0,0,0,0,0,0,0,1 } } } /* fec0:0:1::1*/
#define SCTP_ADDR6_GLOBAL_ETH1 { { { 0x3f,0xfe,0,0,0,1,0,0,0,0,0,0,0,0,0,1 } } } /* 3ffe:0:1:::1*/
#define SCTP_ADDR6_LINKLOCAL_ETH2 { { { 0xfe,0x80,0,0,0,2,0,0,0,0,0,0,0,0,0,1 } } } /* fe80:0:2::1*/
#define SCTP_ADDR6_SITELOCAL_ETH2 { { { 0xfe,0xc0,0,0,0,2,0,0,0,0,0,0,0,0,0,1 } } } /* fec0:0:2::1*/
#define SCTP_ADDR6_GLOBAL_ETH2 { { { 0x3f,0xfe,0,0,0,2,0,0,0,0,0,0,0,0,0,1 } } } /* 3ffe:0:2::1*/

/* define three types of IPv6 address for another host */
#define SCTP_B_ADDR6_GLOBAL_ETH0 { { { 0x3f,0xfe,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }      /* 3ffe::2*/
#define SCTP_B_ADDR6_SITELOCAL_ETH0 { { { 0xfe,0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }      /* fec0::2*/
#define SCTP_B_ADDR6_LINKLOCAL_ETH0 { { { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }      /* fe80::2*/
#define SCTP_C_ADDR6_LINKLOCAL_ETH0 { { { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,3 } } }      /* fe80::3*/
#define SCTP_C_ADDR6_SITELOCAL_ETH0 { { { 0xfe,0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,3 } } }      /* fec0::3*/
#define SCTP_D_ADDR6_LINKLOCAL_ETH0 { { { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,4 } } }      /* fe80::4*/
#define SCTP_D_ADDR6_SITELOCAL_ETH0 { { { 0xfe,0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,4 } } }      /* fec0::4*/

/* Macros for various fun-and-games.  */
#define ZERO 0

#ifndef DUMP_CORE
/* This has the advantage of giving us something to look at with the
 * debugger.
 */
#ifdef __KERNEL__
#define DUMP_CORE { 					 \
	char *diediedie = 0;				 \
	printk("DUMP_CORE %s: %d\n", __FILE__, __LINE__);\
	fflush(NULL);\
	*diediedie = 0;					 \
}
#else
#define DUMP_CORE { 					 \
	char *diediedie = 0;				 \
	printf("DUMP_CORE %s: %d\n", __FILE__, __LINE__);\
	fflush(NULL);\
	*diediedie = 0;					 \
}
#endif /* __KERNEL__ */
#endif /* DUMP_CORE */

#if 0
/* Here is an alternative DUMP_CORE you can put in a Makefile if you
 * want to see more than one test fail.
 */
#define DUMP_CORE { label: printk("Failure at %x\n", &label); exit(0)}
#endif


#ifdef TEST_FRAME
#include <linux/ipv6.h> /* ibid bare_ipv6_... */

/* These are convenience types for packet dissection.  */
struct bare_sctp_packet {
        struct sctphdr sh;
        sctp_chunkhdr_t ch;
        uint8_t data[0];
} __attribute__((packed));

struct bare_ipv4_sctp_packet {
        struct iphdr iph;
        struct bare_sctp_packet s;
} __attribute__((packed));

struct bare_ipv6_sctp_packet {
        struct ipv6hdr iph;
        struct bare_sctp_packet s;
} __attribute__((packed));

typedef struct sctp_asconf_param {
	sctp_paramhdr_t param_hdr;
	__u32 cor_id;           // Correlation ID
	union sctp_addr_param addr; // For Add IP, Delete IP and Set Primary
} __attribute__((packed)) sctp_asconf_param_t; 

typedef struct sctp_asconfhdr {
	__u32 serial;
	union sctp_addr_param addr;
	sctp_asconf_param_t param[0];
} __attribute__((packed)) sctp_asconfhdr_t;

typedef int (test_chunk_fn_t)(void *, sctp_chunkhdr_t *);

/* Prototypes for test frame.  */
struct sctp_chunk *test_get_chunk(struct list_head *tlist, int n);

/* Macros for test frame.  */
void *kalloc(int);
void *krealloc(void *, int);
void free(void *);

void simulate_internet(void);
void simulate_network_once(int net);

int test_sendto(struct sock *, void *, size_t msg_len,
                int flags, uint16_t streamID,
                struct sockaddr_in *to, int tolen);
int test_bind(struct sock *sk, struct sockaddr *addr, size_t addr_size);
int test_bindx(struct sock *sk, struct sockaddr *addrs, int addrs_size,
               int flags);
int test_connectx(struct sock *sk, struct sockaddr *addrs, int addrs_size);
int test_listen(struct sock *sk, int backlog);
int test_replace_packet(void *raw, int raw_len, sctp_cid_t chunk_type);
int test_break_network(int i);
int test_fix_network(int i);

int test_congest_next_packet(sctp_cid_t chunk_type);
void test_frame_send_message(struct sock *sk,
			     struct sockaddr *addr, uint8_t *buff);
void test_frame_send_message2(struct sock *sk, struct sockaddr *addr, 
			      uint8_t *buff, sctp_assoc_t associd,
			      uint16_t stream, uint32_t ppid, uint16_t flags);
void test_frame_get_message(struct sock *sk, uint8_t *buff);
void test_frame_get_message_all(struct sock *sk, uint8_t *buff);
void test_frame_get_message_pd(struct sock *, uint8_t *buff, int aborted);
void test_frame_get_message2(struct sock *sk, uint8_t *buff, int len, uint32_t in_flags, uint32_t out_flags);
void test_frame_get_event(struct sock *sk, uint16_t ntype, uint16_t etype);
void test_frame_get_event_error(struct sock *sk, uint16_t ntype, 
				uint16_t etype, __u16 cause_code);
void test_frame_send_failed_check(struct sock *sk, uint16_t etype,
                        __u32 cause_code, struct sctp_sndrcvinfo *info,
			char *data, int datalen, int* offset);
int test_frame_getsockopt(struct sock *sk, sctp_assoc_t assoc_id, int optname);
int test_frame_setsockopt(struct sock *sk, sctp_assoc_t assoc_id, int optname,
			  char *optval);
int test_frame_check_notification(struct msghdr *msg,
				  int original_len,
				  int expected_len,
				  uint16_t expected_type,
				  uint32_t additional);
int test_frame_check_message(struct msghdr *msg,
                             int orig_controllen,
                             int orig_datalen,
                             void *orig_data,
                             int expected_controllen,
                             size_t expected_datalen,
                             void *expected_data, 
                             sctp_cmsg_t expected_event);
void test_frame_print_message(struct sock *sk, struct msghdr *msg);
void test_frame_fixup_msg_control(struct msghdr *msg,
				  int original_controllen);
void test_frame_enable_data_assoc_events(struct sock *sk);
int test_run_network(void);
int test_run_network_once(int net);
int test_step(sctp_cid_t, int net);
int test_for_chunk(sctp_cid_t, int net);
sctp_chunkhdr_t * test_find_chunk(int net, sctp_cid_t cid,
				  test_chunk_fn_t test, void *arg);
int test_run_timeout(void);
int test_kill_next_packet(sctp_cid_t chunk_type);
void test_kill_next_packets(int);
int test_get_network_ip_addr(void *, unsigned short);
int test_get_network_sctp_addr(union sctp_addr *);
void debug_halt(void);
void init_Internet(void);
struct sk_buff_head *get_Internet(int net);
int is_empty_Internet(void);
int is_empty_network(int net);
void test_remove_dev(struct net_device *);
void test_add_dev(struct net_device *);
uint32_t test_get_source_from_route(uint32_t);
struct bare_sctp_packet *test_get_sctp(void *hdr);
struct sk_buff *test_peek_packet(int net);
void sctp_remove_sk(struct sock *);
void change_chunk_sequence(int net);
void test_steal_network(int net);
void test_restore_network(int net);
struct sk_buff *test_steal_packet(int net);
void test_inject_packet(int net, struct sk_buff *p);
void *test_build_msg(int len);
void test_verify_congestion_parameters(struct sctp_transport *t, uint32_t cwnd,
				       uint32_t ssthresh, uint32_t pba,
				       uint32_t flight_size);
int test_set_ip_mtu(int mtu);

/* These are internel kernel functions which are normally scattered
 * all over the place, but we simulate them all in test_kernel.c.
 */
int ip_setsockopt(struct sock *sk, int level, int optname, char
		  *optval, int optlen);
int memcpy_toiovec(struct iovec *iov, unsigned char *kdata, int len);

struct sock * sctp_socket(int class, int type);
struct sctp_association *test_ep_first_asoc(struct sctp_endpoint *ep);
struct sctp_endpoint *sctp_lookup_endpoint(const union sctp_addr *);
struct sctp_endpoint *sctp_lookup_endpoint_ntohs(const union sctp_addr *);
int sctp_msghdr_parse(const struct msghdr *, sctp_cmsgs_t *);
struct sctp_chunk *sctp_copy_chunk(struct sctp_chunk *chunk, const int priority);
void print_address(const char *label, union sctp_addr *addr);
void print_assoc_peer_transports(struct sctp_association *assoc);
void test_assoc_peer_transports(struct sctp_association *assoc,
				union sctp_addr *peers, int num_peers);
void get_assoc_peer_transports(struct sctp_association *asoc,
			       struct sctp_transport **t1, int num_peers);

#endif /* TEST_FRAME */

#ifndef __KERNEL__
#ifndef SCTP_DEBUG_PRINTK
#ifdef SCTP_DEBUG
#define SCTP_DEBUG_PRINTK(whatever...) printf(whatever)
#else  
#define SCTP_DEBUG_PRINTK(whatever...)
#endif /* SCTP_DEBUG */
#endif /* !SCTP_DEBUG_PRINTK */
#endif /* !_KERNEL */

int test_print_message(int sk, struct msghdr *, size_t msg_len);
int test_hdr_size(void *hdr);
int test_check_message(struct msghdr *msg, int controllen, sctp_cmsg_t event);
int test_check_sndrcvinfo(struct msghdr *msg,
			  uint16_t expected_flags,
			  uint16_t expected_stream,
			  uint32_t expected_ppid);
int test_check_notification(struct msghdr *msg,
			    int datalen,
			    int expected_len,
			    uint16_t expected_type,
			    uint32_t additional);
int test_getsockopt(int sk, sctp_assoc_t assoc_id, int optname);
int test_setsockopt(int sk, sctp_assoc_t assoc_id, int optname, 
		    char *optval);


/* These are items normally defined in <stdio.h> and <stdlib.h> an
 * assortment of other standard include files.
 *
 * We can't use those include files because they conflict deeply with
 * many of the kernel include files we need.
 */

extern int rand(void);
void exit(int status);
void *calloc(size_t nmemb, size_t size);
void *malloc(size_t size);
void free(void *ptr);
void *realloc(void *ptr, size_t size);
int gettimeofday(struct timeval *tv, struct timezone *tz);
int printf(const char *format, ...);
int isprint (int c);
size_t strlen(const char *s);
void *memset(void *s, int c, size_t n);
unsigned int sleep(unsigned int seconds);
int close(int fd);

/* These are handy-dandy pseudo-kernel calls for test frame functions
 * which want to pull shenanigans, but can't get at <stdio.h> and
 * friends.
 */
void freopenk(char *file, char *mode, int fd);
int fprintk(int fd, const char *fmt, ...);

struct sctp_chunk *sctp_make_data(struct sctp_association *asoc,
				  const struct sctp_sndrcvinfo *sinfo,
				  int data_len, const __u8 *data);
struct sctp_chunk *sctp_make_data_empty(struct sctp_association *,
					const struct sctp_sndrcvinfo *,
					int len);
struct sctp_chunk *sctp_make_chunk(const struct sctp_association *asoc,
				   __u8 type, __u8 flags, int paylen);
struct sctp_datamsg *sctp_datamsg_new(int gfp);
int sctp_rewind_sequence(sctp_cmd_seq_t *seq);
void sctp_tsnmap_iter_init(const struct sctp_tsnmap *,
			   struct sctp_tsnmap_iter *);
int sctp_tsnmap_next_gap_ack(const struct sctp_tsnmap *,
			     struct sctp_tsnmap_iter *,__u16 *start,
			     __u16 *end);
struct sctp_ulpevent *sctp_ulpevent_new(int size, int flags, int gfp);
void sctp_ulpevent_init(struct sctp_ulpevent *, int flags);
struct sctp_association *sctp_lookup_association(const union sctp_addr *laddr,
                                                 const union sctp_addr *paddr,
                                            struct sctp_transport **transportp);
void sctp_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt, int type,
		 int code, int offset, __u32 info);

#define ADDR_LEN(VAR) sctp_get_af_specific(VAR.v4.sin_family)->sockaddr_len

void setup_paddrparams(struct sctp_paddrparams *params,
		       struct sctp_association *asoc,
		       union  sctp_addr        *loop);
void change_paddrparams(struct sctp_paddrparams *params,
		        struct sctp_association *asoc,
		        union  sctp_addr        *loop);
int test_paddrparams(struct sock             *sk,
		     struct sctp_paddrparams *params,
		     struct sctp_association *asoc,
		     union  sctp_addr        *loop,
		     __u32                    flags_mask);
int fill_addr_buf(void *buf, union sctp_addr *addrs, int first, int last);

#endif /* __funtest_h__ */
