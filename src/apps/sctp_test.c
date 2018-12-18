/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999 Cisco
 * Copyright (c) 1999, 2000, 2001 Motorola
 * Copyright (c) 2001-2002 Nokia
 * Copyright (c) 2001 La Monte H.P. Yarroll
 *
 * This is a userspace test application for the SCTP kernel 
 * implementation.
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
 *   Hui Huang         <hui.huang@nokia.com>
 *   Sridhar Samudrala <samudrala@us.ibm.com>
 *   Jon Grimm         <jgrimm@us.ibm.com>
 *   Daisy Chang       <daisyc@us.ibm.com>
 *   Ryan Layer	       <rmlayer@us.ibm.com>
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <errno.h>
#include <netinet/sctp.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <fcntl.h>
#include <netdb.h>
#include <net/if.h>

#include <sys/resource.h>


#define REALLY_BIG 65536

#define SERVER 		0
#define CLIENT 		1
#define MIXED 		2
#define NOT_DEFINED	666

#define REPEAT 		10
#define BIG_REPEAT	1000000
#define MAX_BIND_RETRYS 10
#define BODYSIZE	10
#define MSG_CNT		10	/* If this is changed the msg_sizes array
				   needs to be modified accordingly.  */

#define DEFAULT_MAX_WINDOW 32768
#define DEFAULT_MIN_WINDOW 1500

#define DEBUG_NONE	0
#define DEBUG_MIN	1
#define DEBUG_MAX	2

#define STREAM_PATTERN_SEQUENTIAL 0
#define STREAM_PATTERN_RANDOM     1

#define ORDER_PATTERN_UNORDERED   0
#define ORDER_PATTERN_ORDERED     1
#define ORDER_PATTERN_ALTERNATE   2
#define ORDER_PATTERN_RANDOM      3

#define ASSOC_PATTERN_SEQUENTIAL 0
#define ASSOC_PATTERN_RANDOM     1

#define NCASES 6
#define MAX_POLL_SKS 256

#define DEBUG_PRINT(level, print_this...)	\
{						\
	if (debug_level >= level) { 		\
		fprintf(stdout, print_this); 	\
		fflush(stdout); 		\
	}					\
} /* DEBUG_PRINT */

/* Convenience structure to determine space needed for cmsg. */
typedef union {
        struct sctp_initmsg init;
        struct sctp_sndrcvinfo sndrcvinfo;
} _sctp_cmsg_data_t;

#ifdef __FreeBSD__
typedef union {
        int                    raw;
        struct sctp_initmsg     init;
        struct sctp_sndrcvinfo  sndrcv;
} sctp_cmsg_data_t;
#endif

#define CMSG_SPACE_INITMSG (CMSG_SPACE(sizeof(struct sctp_initmsg)))
#define CMSG_SPACE_SNDRCV (CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)))

typedef struct {
	int rem_port;
        int order_state;
        int stream_state;
	int msg_cnt;
	int msg_sent;
	int cycle;
} _assoc_state;

typedef struct {
        int sk;
        int assoc_i;
	_assoc_state *assoc_state;
} _poll_sks;

char *local_host = NULL;
int local_port = 0;
char *remote_host = NULL;
int remote_port = 0;
/* struct sockaddr_in s_rem, s_loc; */
struct sockaddr_storage s_rem, s_loc;
int r_len, l_len;
int test_case = 0;
int size_arg = 0;
int xflag = 0;
int debug_level = DEBUG_MAX;
int do_exit = 1;
int stream_pattern = STREAM_PATTERN_SEQUENTIAL;
int stream_state = 0;
int order_pattern = ORDER_PATTERN_UNORDERED;
int order_state = 0;
int max_stream = 0;
int seed = 0;
int max_msgsize = DEFAULT_MAX_WINDOW;
int timetolive = 0;
int assoc_pattern = ASSOC_PATTERN_SEQUENTIAL;
int socket_type = SOCK_SEQPACKET;
int repeat_count = 0;
int listeners = 0;
int tosend = 0;
_poll_sks poll_sks[MAX_POLL_SKS];
int repeat = REPEAT;
int msg_cnt = MSG_CNT;
int drain = 0;
int role = NOT_DEFINED;
struct sockaddr *bindx_add_addrs = NULL;
int bindx_add_count = 0;
struct sockaddr *connectx_addrs = NULL;
int connectx_count = 0;
int if_index = 0;

unsigned char msg[] = "012345678901234567890123456789012345678901234567890";

static int msg_sizes[NCASES][MSG_CNT] =
	{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	 {1452, 2904, 4356, 1452, 2904, 4356, 1452, 2904, 4356, 1452},
	 {1453, 1453, 1453, 1453, 1453, 1453, 1453, 1453, 1453, 1453},
	 {1, 1453, 32768, 1, 1453, 32768, 1, 1453, 32768, 1},
	 {1, 1000, 2000, 3000, 5000, 10000, 15000, 20000, 25000, 32768},
	 {32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768},
	};

static const char *sac_state_tbl[] = {
	"COMMUNICATION_UP",
	"COMMUNICATION_LOST",
	"RESTART",
	"SHUTDOWN_COMPLETE",
	"CANT_START_ASSOCICATION"
};

void usage(char *argv0)
{
	fprintf(stderr, "\nusage:\n");
	fprintf(stderr, "  server:\n");
	fprintf(stderr, "  %8s -H local-addr -P local-port -l [-d level] [-x]\n"
			"\t      [-L num-ports] [-S num-ports]\n"
			"\t      [-a assoc-pattern]\n"
			"\t      [-i interface]\n",
		argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "  client:\n");
	fprintf(stderr, "  %8s -H local-addr -P local-port -h remote-addr\n"
		"\t      -p remote-port -s [-c case ] [-d level]\n"
		"\t      [-x repeat] [-o order-pattern] [-t stream-pattern]\n"
		"\t      [-M max-stream] [-r rand-seed]\n"
		"\t      [-m max-msgsize]\n"
		"\t      [-L num-ports] [-S num-ports]\n"
		"\t      [-a assoc-pattern]\n"
		"\t      [-i interface]\n",
		argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "\t-a assoc_pattern in the mixed mode\n");
	fprintf(stderr, "\t   0 = sequential ascending(default)\n");
	fprintf(stderr, "\t   1 = random\n");
	fprintf(stderr, "\t-d debug\n");
	fprintf(stderr, "\t   0 = none\n");
	fprintf(stderr, "\t   1 = min(default)\n");
	fprintf(stderr, "\t   2 = max\n");
	fprintf(stderr, "\t-c testcase\n");
	fprintf(stderr, "\t   0 = 1 byte packets.\n");
	fprintf(stderr, "\t   1 = Sequence of multiples of 1452 byte packets.\n");
	fprintf(stderr, "\t       (1452 is fragmentation point for an i/f with ");
	fprintf(stderr, "1500 as mtu.)\n");
	fprintf(stderr, "\t   2 = 1453 byte packets.\n");
	fprintf(stderr, "\t       (min. size at which fragmentation occurs\n");
	fprintf(stderr, "\t        for an i/f with 1500 as mtu.)\n");
	fprintf(stderr, "\t   3 = Sequence of 1, 1453, 32768 byte packets.\n");
	fprintf(stderr, "\t   4 = Sequence of following size packets.\n");
	fprintf(stderr, "\t       (1, 1000, 2000, 3000, 5000, 10000,");
	fprintf(stderr, "15000, 20000, 25000, 32768)\n");
	fprintf(stderr, "\t   5 = 32768 byte packets.\n");
	fprintf(stderr, "\t       (default max receive window size.)\n");
	fprintf(stderr, "\t   6 = random size packets.\n");
	fprintf(stderr, "\t   -ve value = Packets of specifed size.\n");
	fprintf(stderr, "\t-m max msgsize for option -c 6 (1500-65515, default value 32768)\n");
	fprintf(stderr, "\t-x number of repeats\n");
	fprintf(stderr, "\t-o order-pattern\n");
	fprintf(stderr, "\t   0 = all unordered(default) \n");
	fprintf(stderr, "\t   1 = all ordered \n");
	fprintf(stderr, "\t   2 = alternating \n");
        fprintf(stderr, "\t   3 = random\n");
	fprintf(stderr, "\t-t stream-pattern\n");
	fprintf(stderr, "\t   0 = sequential ascending(default)\n");
	fprintf(stderr, "\t   1 = random\n");
	fprintf(stderr, "\t-M max-stream (default value 0)\n");
	fprintf(stderr, "\t-r seed (default 0, use time())\n");
	fprintf(stderr, "\t-L num-ports (default value 0). Run the mixed mode\n");
	fprintf(stderr, "\t-S num-ports (default value 0). Run the mixed mode\n");
	fprintf(stderr, "\t-D drain. If in client mode do a read following send.\n");
	fprintf(stderr, "\t-T use SOCK_STREAM tcp-style sockets.\n");
	fprintf(stderr, "\t-B add the specified address(es) as additional bind\n");
	fprintf(stderr, "\t   addresses of the local socket. Multiple addresses can\n");
	fprintf(stderr, "\t   be specified by using this argument multiple times.\n");
	fprintf(stderr, "\t   For example, '-B 10.0.0.1 -B 20.0.0.2'.\n");
	fprintf(stderr, "\t   In case of IPv6 linklocal address, interface name can be set in following way \n");
	fprintf(stderr, "\t   For example, '-B fe80::f8c3:b77f:698e:4506%%eth2'.\n");
	fprintf(stderr, "\t-C use the specified address(es) for connection to the\n");
	fprintf(stderr, "\t   peer socket. Multiple addresses can be specified by\n");
	fprintf(stderr, "\t   using this argument multiple times.\n");
	fprintf(stderr, "\t   For example, '-C 10.0.0.1 -C 20.0.0.2'.\n");
	fprintf(stderr, "\t   This option is incompatible with the -h option.\n");
	fprintf(stderr, "\t-O time to live (default value 0)\n");
	fprintf(stderr, "\n");
	fflush(stderr);

} /* usage() */

void *
build_msg(int len)
{
	int i = len - 1;
	int n;
	char *msg_buf, *p;

	msg_buf = malloc(len);
	if (NULL == msg_buf) {
		fprintf(stderr, "\n\t\t*** malloc not enough memory!!! ***\n");
		exit(1);
	}
	p = msg_buf;

	do {
		n = ((i > 50)?50:i);
		memcpy(p, msg, ((i > 50)?50:i));
		p += n;
		i -= n;
	} while (i > 0);

	msg_buf[len-1] = '\0';

	return(msg_buf);

} /* build_msg() */

static int
print_cmsg(int type, sctp_cmsg_data_t *data)
{
        switch(type) {
        case SCTP_INIT:
		DEBUG_PRINT(DEBUG_MAX, "\tINIT\n");
		if (DEBUG_MAX == debug_level) {
			printf("\t\tsinit_num_ostreams=%d ",
			       data->init.sinit_num_ostreams);
                	printf("sinit_max_instreams=%d ",
			       data->init.sinit_max_instreams);
	                printf("sinit_max_attempts=%d ",
			       data->init.sinit_max_attempts);
        	        printf("sinit_max_init_timeo=%d\n",
			       data->init.sinit_max_init_timeo);
		}
		break;
        case SCTP_SNDRCV:
		DEBUG_PRINT(DEBUG_MAX, "\t  SNDRCV");
		if (DEBUG_MAX == debug_level) {
        	        printf("(stream=%u ", 	data->sndrcv.sinfo_stream);
                	printf("ssn=%u ", 	data->sndrcv.sinfo_ssn);
			printf("tsn=%u ", 	data->sndrcv.sinfo_tsn);
	                printf("flags=0x%x ",	data->sndrcv.sinfo_flags);
        	        printf("ppid=%u\n",	data->sndrcv.sinfo_ppid);
			printf("cumtsn=%u\n",   data->sndrcv.sinfo_cumtsn);
                }
		break;
         default:
		DEBUG_PRINT(DEBUG_MIN, "\tUnknown type: %d\n", type);
                break;
        }
	fflush(stdout);
        return 0;

} /* print_cmsg() */

/* This function prints the message. */
static int
print_message(const int sk, struct msghdr *msg, size_t msg_len) {
	struct cmsghdr *scmsg;
	sctp_cmsg_data_t *data;
        int i;

        if (!(MSG_NOTIFICATION & msg->msg_flags)) {
                int index = 0;

		DEBUG_PRINT(DEBUG_MIN, "Data %zu bytes.", msg_len);
		DEBUG_PRINT(DEBUG_MAX, " First %zu bytes: ",
				    (msg_len < BODYSIZE)?msg_len:BODYSIZE);
                /* Make sure that everything is printable and that we
                 * are NUL terminated...
                 */
		while ( msg_len > 0 ) {
			char *text, tmptext[BODYSIZE];
			int len;

			memset(tmptext, 0x0, BODYSIZE);

			text = msg->msg_iov[index].iov_base;
			len = msg->msg_iov[index].iov_len;

			if (msg_len == 1 && text[0] == 0) {
				DEBUG_PRINT(DEBUG_MIN, "<empty> text[0]=%d",
					    text[0]);
				break;
			}

			if ( len > msg_len ) {
				/* text[(len = msg_len) - 1] = '\0'; */
				text[(len = msg_len)] = '\0';
			}

			if ( (msg_len -= len) > 0 ) { index++; }

			for (i = 0; i < len - 1; ++i) {
				if (!isprint(text[i])) text[i] = '.';
			}

 			strncpy(tmptext, text, BODYSIZE);
 			tmptext[BODYSIZE-1] = '\0';

			DEBUG_PRINT(DEBUG_MAX, "%s", tmptext);
                }

                DEBUG_PRINT(DEBUG_MIN, "\n");
                fflush(stdout);
        }  else { /* if(we have notification) */
		struct sctp_assoc_change *sac;
		struct sctp_send_failed *ssf;
		struct sctp_paddr_change *spc;
		struct sctp_remote_error *sre;
		union sctp_notification *snp;
		char addrbuf[INET6_ADDRSTRLEN];
		const char *ap;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		int index = 0;

		snp = (union sctp_notification *)msg->msg_iov[index].iov_base;

		DEBUG_PRINT(DEBUG_MIN, "Notification:");
        	
		switch (snp->sn_header.sn_type) {
			case SCTP_ASSOC_CHANGE:
				sac = &snp->sn_assoc_change;
				DEBUG_PRINT(DEBUG_MIN,
					    " SCTP_ASSOC_CHANGE(%s)\n",
					    sac_state_tbl[sac->sac_state]);
				DEBUG_PRINT(DEBUG_MAX,
					    "\t\t(assoc_change: state=%hu, "
					    "error=%hu, instr=%hu "
					    "outstr=%hu)\n",
					    sac->sac_state, sac->sac_error,
					    sac->sac_inbound_streams,
					    sac->sac_outbound_streams);
				break;
			case SCTP_PEER_ADDR_CHANGE:
				spc = &snp->sn_paddr_change;
				DEBUG_PRINT(DEBUG_MIN,
					    " SCTP_PEER_ADDR_CHANGE\n");
				if (spc->spc_aaddr.ss_family == AF_INET) {
					sin = (struct sockaddr_in *)
					       &spc->spc_aaddr;
					ap = inet_ntop(AF_INET, &sin->sin_addr,
						       addrbuf,
						       INET6_ADDRSTRLEN);
				} else {
					sin6 = (struct sockaddr_in6 *)
						&spc->spc_aaddr;
					ap = inet_ntop(AF_INET6,
						       &sin6->sin6_addr,
						       addrbuf,
						       INET6_ADDRSTRLEN);
				}
				DEBUG_PRINT(DEBUG_MAX,
					    "\t\t(peer_addr_change: %s "
					    "state=%d, error=%d)\n",
					    ap, spc->spc_state,
					    spc->spc_error);
				break;
			case SCTP_SEND_FAILED:
				ssf = &snp->sn_send_failed;
				DEBUG_PRINT(DEBUG_MIN,
					    " SCTP_SEND_FAILED\n");
				DEBUG_PRINT(DEBUG_MAX,
					    "\t\t(sendfailed: len=%hu "
					    "err=%d)\n",
					    ssf->ssf_length, ssf->ssf_error);
				break;
			case SCTP_REMOTE_ERROR:
				sre = &snp->sn_remote_error;
				DEBUG_PRINT(DEBUG_MIN,
					    " SCTP_REMOTE_ERROR\n");
				DEBUG_PRINT(DEBUG_MAX,
					    "\t\t(remote_error: err=%hu)\n",
					     ntohs(sre->sre_error));
				break;
			case SCTP_SHUTDOWN_EVENT:
				DEBUG_PRINT(DEBUG_MIN,
					    " SCTP_SHUTDOWN_EVENT\n");
				break;
			default:
				DEBUG_PRINT(DEBUG_MIN,
					    " Unknown type: %hu\n",
					    snp->sn_header.sn_type);
				break;
		}

		fflush(stdout);
		return 1;

        } /* notification received */

        for (scmsg = CMSG_FIRSTHDR(msg);
             scmsg != NULL;
             scmsg = CMSG_NXTHDR(msg, scmsg)) {

		data = (sctp_cmsg_data_t *)CMSG_DATA(scmsg);
		if (debug_level) print_cmsg(scmsg->cmsg_type, data);
	}


	fflush(stdout);
        return 0;

} /* print_message() */

struct sockaddr *
append_addr(const char *parm, struct sockaddr *addrs, int *ret_count)
{
	struct sockaddr *new_addrs = NULL;
	void *aptr;
	struct sockaddr *sa_addr;
	struct sockaddr_in *b4ap;
	struct sockaddr_in6 *b6ap;
	struct hostent *hst4 = NULL;
	struct hostent *hst6 = NULL;
	int i4 = 0;
	int i6 = 0;
	int j;
	int orig_count = *ret_count;
	int count = orig_count;
	char *ipaddr = strdup(parm);
	char *ifname;
	int ifindex = 0;

	/* check the interface. */
	ifname = strchr(ipaddr,'%');
	if (ifname) {
		*ifname=0;
		ifname++;
		ifindex = if_nametoindex(ifname);
		if (!ifindex) {
			fprintf(stderr, "bad interface name: %s\n", ifname);
			goto finally;
		}
	}

	/* Get the entries for this host.  */
	hst4 = gethostbyname(ipaddr);
	hst6 = gethostbyname2(ipaddr, AF_INET6);

	if ((NULL == hst4 || hst4->h_length < 1)
	    && (NULL == hst6 || hst6->h_length < 1)) {
		fprintf(stderr, "bad hostname: %s\n", ipaddr);
		goto finally;
	}

	/* Figure out the number of addresses.  */
	if (NULL != hst4) {
		for (i4 = 0; NULL != hst4->h_addr_list[i4]; ++i4) {
			count++;
		}
	}
	if (NULL != hst6) {
		for (i6 = 0; NULL != hst6->h_addr_list[i6]; ++i6) {
			count++;
		}
	}

	/* Expand memory for the new addresses.  Assume all the addresses
	 * are v6 addresses.
	 */
	new_addrs = (struct sockaddr *)
		realloc(addrs, sizeof(struct sockaddr_in6) * count);

	if (NULL == new_addrs) {
		count = *ret_count;
		goto finally;
	}

	/* Skip the existing addresses. */
	aptr = new_addrs;
	for (j = 0; j < orig_count; j++) {
		sa_addr = (struct sockaddr *)aptr;
		switch(sa_addr->sa_family) {
		case AF_INET:
			aptr += sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			aptr += sizeof(struct sockaddr_in6);
			break;
		default:
			count = orig_count;
			goto finally;
		}
	}

	/* Put the new addresses away.  */
	if (NULL != hst4) {
		for (j = 0; j < i4; ++j) {
			b4ap = (struct sockaddr_in *)aptr;
			memset(b4ap, 0x00, sizeof(*b4ap));
			b4ap->sin_family = AF_INET;
			b4ap->sin_port = htons(local_port);
			bcopy(hst4->h_addr_list[j], &b4ap->sin_addr,
			      hst4->h_length);

			aptr += sizeof(struct sockaddr_in);
		} /* for (loop through the new v4 addresses) */
	}

	if (NULL != hst6) {
		for (j = 0; j < i6; ++j) {
			b6ap = (struct sockaddr_in6 *)aptr;
			memset(b6ap, 0x00, sizeof(*b6ap));
			b6ap->sin6_family = AF_INET6;
			b6ap->sin6_port =  htons(local_port);
			b6ap->sin6_scope_id = if_index;
			bcopy(hst6->h_addr_list[j], &b6ap->sin6_addr,
			      hst6->h_length);
			if (!ifindex) {
				b6ap->sin6_scope_id = ifindex;
			}

			aptr += sizeof(struct sockaddr_in6);
		} /* for (loop through the new v6 addresses) */
	}

 finally:
	free(ipaddr);
	*ret_count = count;

	return new_addrs;

} /* append_addr() */

int socket_r(void)
{
	struct sctp_event_subscribe subscribe;
	int sk, error;

	DEBUG_PRINT(DEBUG_MIN, "\tsocket(%s, IPPROTO_SCTP)",
		(socket_type == SOCK_SEQPACKET) ? "SOCK_SEQPACKET" : "SOCK_STREAM");

	if ((sk = socket(s_loc.ss_family, socket_type, IPPROTO_SCTP)) < 0 ) {
		if (do_exit) {
			fprintf(stderr, "\n\n\t\t*** socket: failed to create"
				" socket:  %s ***\n",
        	       	        strerror(errno));
			exit(1);
		} else {
			return -1;
		}
	}
	DEBUG_PRINT(DEBUG_MIN, "  ->  sk=%d\n", sk);

	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.sctp_data_io_event = 1;
	subscribe.sctp_association_event = 1;
	error = setsockopt(sk, SOL_SCTP, SCTP_EVENTS, (char *)&subscribe,
			   sizeof(subscribe));
	if (error) {
		fprintf(stderr, "SCTP_EVENTS: error: %d\n", error);
		exit(1);
	}
        if (max_stream > 0) {
        	struct sctp_initmsg initmsg;
        	memset(&initmsg, 0, sizeof(struct sctp_initmsg));
        	initmsg.sinit_num_ostreams = max_stream;
        	error = setsockopt(sk, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg));
        	if (error) {
        		fprintf(stderr, "SCTP_INITMSG: error: %d\n", error);
        		exit(1);
        	}
        }
	return sk;

} /* socket_r() */

int bind_r(int sk, struct sockaddr_storage *saddr)
{
        int error = 0, i = 0;
	char *host_s, *serv_s;

	if ((host_s = malloc(NI_MAXHOST)) == NULL) {
		fprintf(stderr, "\n\t\t*** host_s malloc failed!!! ***\n");
		exit(1);
	}
	if ((serv_s = malloc(NI_MAXSERV)) == NULL) {
		fprintf(stderr, "\n\t\t*** serv_s malloc failed!!! ***\n");
		exit(1);
	}

	do {
		if (i > 0) sleep(1); /* sleep a while before new try... */

		error = getnameinfo((struct sockaddr *)saddr, l_len, host_s,
				    NI_MAXHOST, serv_s, NI_MAXSERV,
				    NI_NUMERICHOST);

		if (error)
			printf("%s\n", gai_strerror(error));

       		DEBUG_PRINT(DEBUG_MIN,
			    "\tbind(sk=%d, [a:%s,p:%s])  --  attempt %d/%d\n",
       			    sk, host_s, serv_s, i+1, MAX_BIND_RETRYS);

       		error = bind(sk, (struct sockaddr *)saddr, l_len);

	        if (error != 0) {
	        	if( errno != EADDRINUSE ) {
	        		if (do_exit) {
	        		        fprintf(stderr, "\n\n\t\t***bind: can "
						"not bind to %s:%s: %s ****\n",
						host_s, serv_s,
						strerror(errno));
					exit(1);
				} else {
					return -1;
				}
			}
		}
		i++;
		if (i >= MAX_BIND_RETRYS) {
			fprintf(stderr, "Maximum bind() attempts. "
				"Die now...\n\n");
			exit(1);
		}
        } while (error < 0 && i < MAX_BIND_RETRYS);

	free(host_s);
	free(serv_s);
	return 0;

} /* bind_r() */

int
bindx_r(int sk, struct sockaddr *addrs, int count, int flag)
{
	int error;
	int i;
	struct sockaddr *sa_addr;
	void *aptr;

	/* Set the port in every address.  */
	aptr = addrs;
	for (i = 0; i < count; i++) {
		sa_addr = (struct sockaddr *)aptr;

		switch(sa_addr->sa_family) {
		case AF_INET:
			((struct sockaddr_in *)sa_addr)->sin_port =
				htons(local_port);
			aptr += sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)sa_addr)->sin6_port =
				htons(local_port);
			aptr += sizeof(struct sockaddr_in6);
			break;
		default:
			fprintf(stderr, "Invalid address family\n");
			exit(1);
		}
	}

	error = sctp_bindx(sk, addrs, count, flag);
	if (error != 0) {
		fprintf(stderr, "\n\n\t\t***bindx_r: error adding addrs:"
			" %s. ***\n", strerror(errno));
		exit(1);
	}

	return 0;

} /* bindx_r() */

int listen_r(int sk, int listen_count)
{
	int error = 0;
	
        DEBUG_PRINT(DEBUG_MIN, "\tlisten(sk=%d,backlog=%d)\n",
		    sk, listen_count);

 	/* Mark sk as being able to accept new associations */
        error = listen(sk, listen_count);
        if (error != 0) {
        	if (do_exit) {
                	fprintf(stderr, "\n\n\t\t*** listen:  %s ***\n\n\n",
                       		strerror(errno));
			exit(1);
		}
		else return -1;
        }
        return 0;

} /* listen_r() */

int accept_r(int sk){
	socklen_t len = 0;
	int subsk;

	DEBUG_PRINT(DEBUG_MIN, "\taccept(sk=%d)\n", sk);

	subsk = accept(sk, NULL, &len);
	if (subsk < 0) {
		fprintf(stderr, "\n\n\t\t*** accept:  %s ***\n\n\n", strerror(errno));
		exit(1);
	}

	return subsk;
} /* accept_r() */

int connect_r(int sk, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	int error = 0;

	DEBUG_PRINT(DEBUG_MIN, "\tconnect(sk=%d)\n", sk);

	/* Mark sk as being able to accept new associations */
	error = connect(sk, serv_addr, addrlen);
	if (error != 0) {
		if (do_exit) {
			fprintf(stderr, "\n\n\t\t*** connect:  %s ***\n\n\n",
				strerror(errno));
			exit(1);
		}
		else return -1;
	}
	return 0;

} /* connect_r() */

int connectx_r(int sk, struct sockaddr *addrs, int count)
{
	int error;
	int i;
	struct sockaddr *sa_addr;
	void *aptr;

	/* Set the port in every address.  */
	aptr = addrs;
	for (i = 0; i < count; i++) {
		sa_addr = (struct sockaddr *)aptr;

		switch(sa_addr->sa_family) {
		case AF_INET:
			((struct sockaddr_in *)sa_addr)->sin_port =
				htons(remote_port);
			aptr += sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)sa_addr)->sin6_port =
				htons(remote_port);
			aptr += sizeof(struct sockaddr_in6);
			break;
		default:
			fprintf(stderr, "Invalid address family\n");
			exit(1);
		}
	}

	error = sctp_connectx(sk, addrs, count, NULL);
	if (error != 0) {
		fprintf(stderr, "\n\n\t\t*** connectx_r: error connecting"
			" to addrs: %s ***\n", strerror(errno));
		exit(1);
	}

	return 0;

} /* connectx_r() */

int receive_r(int sk, int once)
{
	int recvsk = sk, i = 0, error = 0;
        char incmsg[CMSG_SPACE(sizeof(_sctp_cmsg_data_t))];
        struct iovec iov;
        struct msghdr inmessage;

        /* Initialize inmessage with enough space for DATA... */
        memset(&inmessage, 0, sizeof(inmessage));
        if ((iov.iov_base = malloc(REALLY_BIG)) == NULL) {
		fprintf(stderr, "\n\t\t*** malloc not enough memory!!! ***\n");
		exit(1);
	}
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	/* or a control message.  */
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);

	/* Get the messages sent */
	while (1) {

		if (recvsk == sk && socket_type == SOCK_STREAM &&
		    role == SERVER)
			recvsk = accept_r(sk);

		DEBUG_PRINT(DEBUG_MIN, "\trecvmsg(sk=%d) ", sk);

		error = recvmsg(recvsk, &inmessage, MSG_WAITALL);
		if (error < 0 && errno != EAGAIN) {
			if (errno == ENOTCONN && socket_type == SOCK_STREAM &&
			    role == SERVER) {
				printf("No association is present now!!\n");
				close(recvsk);
				recvsk = sk;
				continue;
			}

			fprintf(stderr, "\n\t\t*** recvmsg: %s ***\n\n",
					strerror(errno));
			fflush(stdout);
			if (do_exit) exit(1);
			else goto error_out;
		}
		else if (error == 0) {
			if (socket_type == SOCK_STREAM && role == SERVER) {
				printf("No association is present now!!\n");
				close(recvsk);
				recvsk = sk;
				continue;
			}
			printf("\n\t\trecvmsg() returned 0 !!!!\n");
			fflush(stdout);
		}

		if (print_message(recvsk, &inmessage, error) > 0)
			continue; /* got a notification... */

		inmessage.msg_control = incmsg;
		inmessage.msg_controllen = sizeof(incmsg);
		iov.iov_len = REALLY_BIG;
		i++;
		if (once)
			break;
	}

	if (recvsk != sk)
		close(recvsk);

	free(iov.iov_base);
	return 0;
error_out:
	close(sk);
	free(iov.iov_base);
	return -1;

} /* receive_r () */

int next_order(int state, int pattern)
{
	switch (pattern){
	case ORDER_PATTERN_UNORDERED:
		state = 0;
		break;
	case ORDER_PATTERN_ORDERED:
		state = 1;
		break;
	case ORDER_PATTERN_ALTERNATE:
		state = state ? 0 : 1;
		break;
	case ORDER_PATTERN_RANDOM:
		state = rand() % 2;
		break;
	}

	return state;
}

int next_stream(int state, int pattern)
{
	switch (pattern){
	case STREAM_PATTERN_RANDOM:
		state = rand() % (max_stream == 0 ? 1 : max_stream);
		break;
	case STREAM_PATTERN_SEQUENTIAL:
		state = state + 1;
		if (state >= max_stream)
			state = 0;
		break;
	}

	return state;
}

int next_msg_size(int msg_cnt)
{
	int msg_size;

	if (size_arg) {
		msg_size = size_arg;
	} else if (test_case < NCASES) {
		msg_size = msg_sizes[test_case][msg_cnt];
	} else {
		msg_size = (rand() % max_msgsize) + 1;
	}

	return msg_size;

} /* next_msg_size() */

int next_assoc(int i, int state, int pattern)
{
	int j;
	int found = 0;
	_assoc_state *as;


	switch (pattern){
	case ASSOC_PATTERN_RANDOM:
		state = rand() % tosend;
		break;
	case ASSOC_PATTERN_SEQUENTIAL:
		state = state + 1;
		if (state >= tosend)
			state = 0;
		break;
	}

	as = poll_sks[i].assoc_state;
	j = state;
	do {
		if (as[j].msg_sent < repeat_count) {
			found = 1;
			break;
		}
		if (++j >= tosend) {
			j = 0;
		}
	} while (j != state);

	if (found) {
		return j;
	} else {
		return -1;
	}
	
} /* next_assoc() */

int send_r(int sk, int stream, int order, int send_size, int assoc_i)
{
	int error = 0;
	struct msghdr outmsg;
	struct iovec iov;
	char *message = NULL;
	int msglen = 0;
	char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;

	if (send_size > 0) {
		message = build_msg(send_size);
		msglen = strlen(message) + 1;
		iov.iov_base = message;
		iov.iov_len = msglen;
	}
	else {
		if (do_exit) {
			exit(1);
		} else {
			goto error_out;
		}
	}

	outmsg.msg_name = &s_rem;
       	outmsg.msg_namelen = sizeof(struct sockaddr_storage);
	outmsg.msg_iov = &iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo->sinfo_ppid = rand();
	sinfo->sinfo_stream = stream;
	sinfo->sinfo_flags = 0;
	if (!order)
		sinfo->sinfo_flags = SCTP_UNORDERED;
	if (timetolive)
		sinfo->sinfo_timetolive = timetolive;

	DEBUG_PRINT(DEBUG_MIN, "\tsendmsg(sk=%d, assoc=%d) %4d bytes.\n",
		    sk, assoc_i, send_size);
	DEBUG_PRINT(DEBUG_MAX, "\t  SNDRCV");
	if (DEBUG_MAX == debug_level) {
        	printf("(stream=%u ", 	sinfo->sinfo_stream);
		printf("flags=0x%x ",	sinfo->sinfo_flags);
		printf("ppid=%u\n",	sinfo->sinfo_ppid);
	}

	/* Send to our neighbor.  */
	error = sendmsg(sk, &outmsg, MSG_WAITALL);
	if (error != msglen) {
		fprintf(stderr, "\n\t\t*** sendmsg: %s ***\n\n",
			strerror(errno));
		fflush(stdout);
	
		if (do_exit) {
			exit(1);
		} else {
			if (!drain)
				goto error_out;
		}
	}

	if (send_size > 0) free(message);
	return 0;
error_out:
	if (send_size > 0) free(message);
	return -1;

} /* send_r() */

int close_r(int sk)
{
	int error = 0;
	
	DEBUG_PRINT(DEBUG_MIN, "\tclose(sk=%d)\n",sk);

	error = close(sk);
	if (error != 0) {
		if (do_exit) {
			fprintf(stderr, "\n\n\t\t*** close: %s ***\n\n",
				strerror(errno));
			exit(1);
		} else {
			return -1;
		}
	}
	fflush(stdout);
	return 0;

} /* close_r() */

void
server(int sk)
{
	if (max_msgsize > DEFAULT_MAX_WINDOW) {
		if (setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &max_msgsize,
			       sizeof(max_msgsize)) < 0) {
			perror("setsockopt(SO_RCVBUF)");
			exit(1);
		} 	
	}

	receive_r(sk, 0);

} /* server() */

void
client(int sk)
{
	int msg_size;
	int i;

	for (i = 0; i < msg_cnt; i++) {

		msg_size = next_msg_size(i);
		order_state = next_order(order_state, order_pattern);
		stream_state = next_stream(stream_state, stream_pattern);

		if (send_r(sk, stream_state, order_state, msg_size, 0) < 0)
			break;
		/* The sender is echoing so do discard the echoed data. */
		if (drain) {
			receive_r(sk, 1);
		}
	}
} /* client() */

void
mixed_mode_test(void)
{
	int error, i, j, max_fd, sks, size;
	int assoc_i, n_msg_size, n_order, n_stream;
	int done = 0;
	fd_set *ibitsp = NULL, *obitsp = NULL, *xbitsp = NULL;
        char incmsg[CMSG_SPACE(sizeof(_sctp_cmsg_data_t))];
        struct iovec iov;
        struct msghdr inmessage;
	_assoc_state *as;

	
	/* Set up the listeners.  If listeners is 0, set up one socket for
	 * transmitting only.
	 */
	iov.iov_base = NULL;
	max_fd = -1;
	sks = (0 == listeners) ? 1 : listeners;
	memset(poll_sks, 0, sks * sizeof(_poll_sks));

	for (i = 0; i < sks; i++) {
		poll_sks[i].sk = socket_r();

		if (s_loc.ss_family == AF_INET6)
			( (struct sockaddr_in6 *)&s_loc)->sin6_port =
				htons(local_port + i);
		else
			( (struct sockaddr_in *)&s_loc)->sin_port =
				htons(local_port + i);

		bind_r(poll_sks[i].sk, &s_loc);
		if (listeners) {
			listen_r(poll_sks[i].sk, 100);
		}
		if (max_msgsize > DEFAULT_MAX_WINDOW) {
			if (setsockopt(poll_sks[i].sk, SOL_SOCKET, SO_RCVBUF,
				&max_msgsize, sizeof(max_msgsize)) < 0) {
				perror("setsockopt(SO_RCVBUF)");
				exit(1);
			}
		} 	

		if (tosend) {
			if ((poll_sks[i].assoc_state = (_assoc_state *)malloc(
				sizeof(_assoc_state) * tosend)) == NULL) {
				printf("Can't allocate memory.\n");
				goto clean_up;
			}
			memset(poll_sks[i].assoc_state, 0,
				sizeof(_assoc_state) * tosend);
		}

		if (poll_sks[i].sk > max_fd) {
			max_fd = poll_sks[i].sk;
		}
	}

	size = howmany(max_fd + 1, NFDBITS) * sizeof(fd_mask);
	if ((ibitsp = (fd_set *)malloc(size)) == NULL) {
		printf("Can't allocate memory.\n");
		goto clean_up;
	}
	if ((obitsp = (fd_set *)malloc(size)) == NULL) {
		printf("Can't allocate memory.\n");
		goto clean_up;
	}
	if ((xbitsp = (fd_set *)malloc(size)) == NULL) {
		printf("Can't allocate memory.\n");
		goto clean_up;
	}

	memset(ibitsp, 0, size);
	memset(obitsp, 0, size);
	memset(xbitsp, 0, size);


        /* Initialize inmessage with enough space for DATA... */
        memset(&inmessage, 0, sizeof(inmessage));
        if ((iov.iov_base = malloc(REALLY_BIG)) == NULL) {
		fprintf(stderr, "\n\t\t*** malloc not enough memory!!! ***\n");
		goto clean_up;
	}
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	/* or a control message.  */
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);

	/* Set up the remote port number per association for output.  */
	for (i = 0; i < sks; i++) {
		as = poll_sks[i].assoc_state;
		for (j = 0; j < tosend; j++) {
			as[j].rem_port = remote_port + j;
		}
	}

	while (!done) {

		for (i = 0; i < sks; i++) {
			FD_SET(poll_sks[i].sk, ibitsp);
			FD_SET(poll_sks[i].sk, obitsp);
			FD_SET(poll_sks[i].sk, xbitsp);
		}
		if ((error = select(max_fd + 1, ibitsp, obitsp, xbitsp,
			(struct timeval *)0)) < 0) {
			fprintf(stderr, "\n\t\t*** select() failed ");
			fprintf(stderr, "with error: %s\n\n",
				strerror(errno));
			fflush(stdout);
			goto clean_up;
		}
		
		for (i = 0; i < sks; i++) {
			/* Is there anything to read from the socket?  */
			if (listeners && FD_ISSET(poll_sks[i].sk, ibitsp)) {

				FD_CLR(poll_sks[i].sk, ibitsp);
				error = recvmsg(poll_sks[i].sk, &inmessage,
					MSG_WAITALL);
				if (error < 0) {
					fprintf(stderr,
						"\n\t\t*** recvmsg: %s ***\n\n",
						strerror(errno));
					fflush(stdout);
					goto clean_up;
				}
				else if (error == 0) {
					printf("\n\t\trecvmsg() returned ");
				       	printf("0 !!!!\n");
					fflush(stdout);
				}

				print_message(poll_sks[i].sk, &inmessage,
					error);

				inmessage.msg_control = incmsg;
				inmessage.msg_controllen = sizeof(incmsg);
				iov.iov_len = REALLY_BIG;
			}
			
			/* Is this socket writeable?  */
			if (tosend && FD_ISSET(poll_sks[i].sk, obitsp)) {

				FD_CLR(poll_sks[i].sk, obitsp);

				/* Pick an association.  */
				assoc_i = next_assoc(i, poll_sks[i].assoc_i,
						assoc_pattern);
				if (assoc_i < 0) {
					/* No work to do on any associations.
					 * We are probably done. */
					if (!listeners) {
						done = 1;
					}
					continue;
				}
				poll_sks[i].assoc_i = assoc_i;

				as = poll_sks[i].assoc_state;
				n_msg_size = next_msg_size(as[assoc_i].msg_cnt);
				n_order = as[assoc_i].order_state =
					next_order(as[assoc_i].order_state,
					order_pattern);
				n_stream = as[assoc_i].stream_state =
					next_stream(as[assoc_i].stream_state,
					stream_pattern);

				/* Set the destination port.  */
				if (s_rem.ss_family == AF_INET6)
					( (struct sockaddr_in6 *)&s_rem)->
						sin6_port =
						htons(as[assoc_i].rem_port);
				else
					( (struct sockaddr_in *)&s_rem)->
						sin_port =
						htons(as[assoc_i].rem_port);

				/* Send a message thru the association.  */
				if (send_r(poll_sks[i].sk, n_stream, n_order,
					n_msg_size, assoc_i) < 0) {
					/* Don't increment counter if there
					 * is a problem of sending.
					 */
					continue;
				}

				/* Increment counters. */
				if (++as[assoc_i].msg_cnt >= MSG_CNT) {
					as[assoc_i].msg_cnt = 0;
				}
				if (++as[assoc_i].msg_sent >=
					repeat_count) {
					fprintf(stderr, "Association #%d in ",
						assoc_i);
					fprintf(stderr, "sk=%d has ",
						poll_sks[i].sk);
					fprintf(stderr, "completed %d msg as ",
						as[assoc_i].msg_sent);
					fprintf(stderr, "cycle %d.\n",
						++as[assoc_i].cycle);

					/* In the mixed mode, -x not only
					 * specify the longer repeat cycle,
					 * but it also mean to run the test
					 * forever.
					 */
					if (xflag) {
						as[assoc_i].msg_sent = 0;
					}

				}

			}
		}
	}

clean_up:
	for (i = 0; i < sks; i++) {
		close(poll_sks[i].sk);
		if (poll_sks[i].assoc_state) {
			free(poll_sks[i].assoc_state);
		}
	}

	if (ibitsp) free(ibitsp);
	if (obitsp) free(obitsp);
	if (xbitsp) free(xbitsp);

	if (iov.iov_base) free(iov.iov_base);

} /* mixed_mode_test() */

void start_test(int role)
{
	int sk;
	int i = 0;
	
	DEBUG_PRINT(DEBUG_NONE, "\nStarting tests...\n");

	repeat_count = repeat;


	if (MIXED == role) {
		repeat_count = repeat_count * msg_cnt;  /* Repeat per assoc. */
		mixed_mode_test();
		return;
	}

	sk = socket_r();
	if (sk < 0) {
		DEBUG_PRINT(DEBUG_NONE, "\nSocket create err %d\n", errno);
		return;
	}

	if (bind_r(sk, &s_loc) == -1) {
		DEBUG_PRINT(DEBUG_NONE, "\nSocket bind err %d\n", errno);
		return;
	}

	/* Do we need to do bindx() to add any additional addresses? */
	if (bindx_add_addrs)
		bindx_r(sk, bindx_add_addrs, bindx_add_count,
			   SCTP_BINDX_ADD_ADDR);

	if (role == SERVER) {
		listen_r(sk, 100);
	} else {
		if (socket_type == SOCK_STREAM && connectx_count == 0)
			connect_r(sk, (struct sockaddr *)&s_rem, r_len);

		if (connectx_count != 0)
			connectx_r(sk, connectx_addrs, connectx_count);
	}

	if (!debug_level) {
		printf("     ");
	}

	for(i = 0; i < repeat_count; i++) {
		
		if (role == SERVER) {
			DEBUG_PRINT(DEBUG_NONE,
				    "Server: Receiving packets.\n");
			server(sk);
		} else {
			DEBUG_PRINT(DEBUG_NONE,
				    "Client: Sending packets.(%d/%d)\n",
		    		    i+1, repeat_count);
			client(sk);
		}

		fflush(stdout);
	}

	close_r(sk);

} /* start_test() */

int
main(int argc, char *argv[])
{
	int c;
	char *interface = NULL;
	struct sockaddr_in *t_addr;
	struct sockaddr_in6 *t_addr6;
	struct sockaddr *tmp_addrs = NULL;
	
        /* Parse the arguments.  */
        while ((c = getopt(argc, argv, ":H:L:P:S:a:h:p:c:d:lm:sx:X:o:t:M:r:w:Di:TB:C:O:")) >= 0 ) {

                switch (c) {
		case 'H':
			local_host = optarg;
			break;
		case 'L':
			role = MIXED;
			listeners = atoi(optarg);
			if (listeners > MAX_POLL_SKS) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'P':
			local_port = atoi(optarg);
			break;
		case 'S':
			role = MIXED;
			tosend = atoi(optarg);
			if (tosend > MAX_POLL_SKS) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'a':
			assoc_pattern = atoi(optarg);
			if (assoc_pattern <  ASSOC_PATTERN_SEQUENTIAL
			    || assoc_pattern > ASSOC_PATTERN_RANDOM ) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'h':
			remote_host = optarg;
			break;
		case 'D':
			drain = 1;
			do_exit = 0;
			break;
		case 'p':
			remote_port = atoi(optarg);
			break;
		case 's':
			if (role != NOT_DEFINED) {
				printf("%s: only -s or -l\n", argv[0]);
				usage(argv[0]);
				exit(1);
			}
			role = CLIENT;
			break;
		case 'l':
			if (role != NOT_DEFINED) {
				printf("%s: only -s or -l\n", argv[0]);
				usage(argv[0]);
				exit(1);
			}
			role = SERVER;
			break;
		case 'd':
			debug_level = atoi(optarg);
			if (debug_level < DEBUG_NONE
			    || debug_level > DEBUG_MAX) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'x':
			repeat = atoi(optarg);
			if (!repeat) {
				xflag = 1;
				repeat = BIG_REPEAT;
			}
			break;
		case 'X':
			msg_cnt = atoi(optarg);
			if ((msg_cnt <= 0) || (msg_cnt > MSG_CNT)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'c':
			test_case = atoi(optarg);
			if (test_case > NCASES) {
				usage(argv[0]);
				exit(1);
			}
			if (test_case < 0) {
				size_arg = -test_case;
			}
			
			break;
		case 'o':
			order_pattern = atoi(optarg);
			if (order_pattern <  ORDER_PATTERN_UNORDERED
			    || order_pattern  > ORDER_PATTERN_RANDOM ) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'O':
			timetolive = atoi(optarg);
			if (timetolive < 0) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 't':
			stream_pattern = atoi(optarg);
			if (stream_pattern <  STREAM_PATTERN_SEQUENTIAL
			    || stream_pattern > STREAM_PATTERN_RANDOM ) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'M':
			max_stream = atoi(optarg);
			if (max_stream <  0
			    || max_stream >= (1<<16)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'r':
			seed = atoi(optarg);
			break;
		case 'm':
			max_msgsize = atoi(optarg);
#if 0
			if ((max_msgsize < DEFAULT_MIN_WINDOW) ||
			    (max_msgsize > 65515)) {
				usage(argv[0]);
				exit(1);
			}
#endif
			break;
		case 'i':
			interface = optarg;
			if_index = if_nametoindex(interface);
			if (!if_index) {
				printf("Interface %s unknown\n", interface);
				exit(1);
			}
			break;
		case 'T':
			socket_type = SOCK_STREAM;
			break;
		case 'B':
			tmp_addrs = append_addr(optarg, bindx_add_addrs,
						&bindx_add_count);
			if (NULL == tmp_addrs) {
				fprintf(stderr, "No memory to add ");
				fprintf(stderr, "%s\n", optarg);
				exit(1);
			}
			bindx_add_addrs = tmp_addrs;
			break;
		case 'C':
			tmp_addrs = append_addr(optarg, connectx_addrs,
						&connectx_count);
			if (NULL == tmp_addrs) {
				fprintf(stderr, "No memory to add ");
				fprintf(stderr, "%s\n", optarg);
				exit(1);
			}
			connectx_addrs = tmp_addrs;
			break;
		case '?':
		default:
			usage(argv[0]);
			exit(0);
		}
	} /* while() */

	if (NOT_DEFINED == role) {
		usage(argv[0]);
		exit(1);
	}


	if (SERVER == role && NULL == local_host && remote_host != NULL) {
		fprintf (stderr, "%s: Server needs local address, "
			 "not remote address\n", argv[0]);
		usage(argv[0]);
		exit(1);
	}
	if (CLIENT == role && NULL == remote_host && connectx_count == 0) {
		fprintf (stderr, "%s: Client needs at least remote address "
			 "& port\n", argv[0]);
		usage(argv[0]);
		exit(1);
	}
	if (MIXED == role) {
		if (listeners && NULL == local_host) {
			fprintf (stderr, "%s: Servers need local address\n",
				argv[0]);
			usage(argv[0]);
			exit(1);
		}
		if (tosend && NULL == remote_host) {
			fprintf (stderr, "%s: Clients need remote address ",
				argv[0]);
			fprintf (stderr, "& port\n");
			usage(argv[0]);
			exit(1);
		}
	}

	if (optind < argc) {
                fprintf(stderr, "%s: non-option arguments are illegal: ",
                        argv[0]);
                while (optind < argc)
                        fprintf(stderr, "%s ", argv[optind++]);
                fprintf (stderr, "\n");
                usage(argv[0]);
                exit(1);
	}

	if (remote_host != NULL && connectx_count != 0) {
		fprintf(stderr, "%s: You can not provide both -h and -C options.\n",
			argv[0]);
		usage(argv[0]);
		exit(1);
	}

	if (remote_host != NULL && remote_port != 0) {
		struct addrinfo *res;
		int error;
		char *host_s, *serv_s;

		if ((host_s = malloc(NI_MAXHOST)) == NULL) {
			fprintf(stderr, "\n*** host_s malloc failed!!! ***\n");
			exit(1);
		}
		if ((serv_s = malloc(NI_MAXSERV)) == NULL) {
			fprintf(stderr, "\n*** serv_s malloc failed!!! ***\n");
			exit(1);
		}

		error = getaddrinfo(remote_host, 0, NULL, &res);
		if (error) {
			printf("%s.\n", gai_strerror(error));
			usage(argv[0]);
			exit(1);
		}

		switch (res->ai_family) {
			case AF_INET:
				t_addr = (struct sockaddr_in *)&s_rem;

				memcpy(t_addr, res->ai_addr,
				       res->ai_addrlen);
				t_addr->sin_family = res->ai_family;
				t_addr->sin_port = htons(remote_port);

				r_len = res->ai_addrlen;

#ifdef __FreeBSD__
				t_addr->sin_len = r_len;
#endif
				break;
			case AF_INET6:

				t_addr6 = (struct sockaddr_in6 *)&s_rem;
				
				memcpy(t_addr6, res->ai_addr,
				       res->ai_addrlen);
				t_addr6->sin6_family = res->ai_family;
				t_addr6->sin6_port = htons(remote_port);
				if (interface)
					t_addr6->sin6_scope_id =
						if_nametoindex(interface);

				r_len = res->ai_addrlen;

#ifdef __FreeBSD__
				t_addr6->sin6_len = r_len;
#endif
				break;
		}

		getnameinfo((struct sockaddr *)&s_rem, r_len, host_s,
			    NI_MAXHOST, serv_s, NI_MAXSERV, NI_NUMERICHOST);
			
		DEBUG_PRINT(DEBUG_MAX, "remote:addr=%s, port=%s, family=%d\n",
			    host_s, serv_s, res->ai_family);

		freeaddrinfo(res);
        }

	if (connectx_count != 0) {
		switch (connectx_addrs->sa_family) {
		case AF_INET:
			t_addr = (struct sockaddr_in *)&s_rem;
			r_len = sizeof(struct sockaddr_in);
			memcpy(t_addr, connectx_addrs, r_len);
			t_addr->sin_port = htons(remote_port);
			break;
		case AF_INET6:
			t_addr6 = (struct sockaddr_in6 *)&s_rem;
			r_len = sizeof(struct sockaddr_in6);
			memcpy(t_addr6, connectx_addrs, r_len);
			t_addr6->sin6_port = htons(remote_port);
			break;
		}
	}

	if (local_host != NULL) {
		struct addrinfo *res;
		int error;
		char *host_s, *serv_s;
		struct sockaddr_in *t_addr;
		struct sockaddr_in6 *t_addr6;

		if ((host_s = malloc(NI_MAXHOST)) == NULL) {
			fprintf(stderr, "\n*** host_s malloc failed!!! ***\n");
			exit(1);
		}
		if ((serv_s = malloc(NI_MAXSERV)) == NULL) {
			fprintf(stderr, "\n*** serv_s malloc failed!!! ***\n");
			exit(1);
		}

		if (strcmp(local_host, "0") == 0)
			local_host = "0.0.0.0";

		error = getaddrinfo(local_host, 0, NULL, &res);
		if (error) {
			printf("%s.\n", gai_strerror(error));
			usage(argv[0]);
			exit(1);
		}

		switch (res->ai_family) {
			case AF_INET:
				t_addr = (struct sockaddr_in *)&s_loc;
				memcpy(t_addr, res->ai_addr,
				       res->ai_addrlen);
				t_addr->sin_family = res->ai_family;
				t_addr->sin_port = htons(local_port);

				l_len = res->ai_addrlen;

#ifdef __FreeBSD__
				t_addr->sin_len = l_len;
#endif
				break;
			case AF_INET6:
				t_addr6 = (struct sockaddr_in6 *)&s_loc;

				memcpy(t_addr6, res->ai_addr,
				       res->ai_addrlen);
				t_addr6->sin6_family = res->ai_family;
				t_addr6->sin6_port = htons(local_port);
				if (interface)
					t_addr6->sin6_scope_id =
						if_nametoindex(interface);

				l_len = res->ai_addrlen;

#ifdef __FreeBSD__
				t_addr6->sin6_len = l_len;
#endif
				break;
		}

		error = getnameinfo((struct sockaddr *)&s_loc, l_len, host_s,
			    NI_MAXHOST, serv_s, NI_MAXSERV, NI_NUMERICHOST);

		if (error)
			printf("%s..\n", gai_strerror(error));

		DEBUG_PRINT(DEBUG_MAX, "local:addr=%s, port=%s, family=%d\n",
			    host_s, serv_s, res->ai_family);

		freeaddrinfo(res);
        }


	/* A half-hearted attempt to seed rand() */
	if (seed == 0 ) {
		seed = time(0);
		DEBUG_PRINT(DEBUG_NONE, "seed = %d\n", seed);	
	}
	
	srand(seed);

	/* Let the testing begin. */
	start_test(role);

	return 0;

} /*  main() */
