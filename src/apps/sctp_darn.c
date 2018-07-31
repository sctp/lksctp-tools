/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999 Cisco
 * Copyright (c) 1999, 2000, 2001 Motorola
 * Copyright (c) 2001 Nokia
 * Copyright (c) 2001 La Monte H.P. Yarroll
 *
 * The SCTP implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * The SCTP implementation is distributed in the hope that it
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
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 *
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Any bugs reported to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *
 * Written or modified by:
 *    La Monte H.P. Yarroll <piggy@acm.org>
 *    Karl Knutson <karl@athena.chicago.il.us>
 *    Hui Huang <hui.huang@nokia.com>
 *    Daisy Chang <daisyc@us.ibm.com>
 *    Sridhar Samudrala <sri@us.ibm.com>
 */

/* This is a userspace test application for the SCTP kernel 
 * implementation state machine.  It is vaguely inspired by Stevens'
 * program "sock".
 *
 * It has the limited ability to send messages and to listen for messages
 * sent via SCTP.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
//#define _GNU_SOURCE
#include <getopt.h>
#include <netdb.h>
#include <inttypes.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/sctp.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "sctp_darn.h"

char *TCID = __FILE__;
int TST_TOTAL = 1;
int TST_CNT = 0;

#define GEN_DATA_FIRST	0x21
#define GEN_DATA_LAST	0x7e

/* Display an IPv4 address in readable format.  */
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

/* Display an IPv6 address in readable format.  */
#define NIP6(addr) \
        ntohs((addr).s6_addr16[0]), \
        ntohs((addr).s6_addr16[1]), \
        ntohs((addr).s6_addr16[2]), \
        ntohs((addr).s6_addr16[3]), \
        ntohs((addr).s6_addr16[4]), \
        ntohs((addr).s6_addr16[5]), \
        ntohs((addr).s6_addr16[6]), \
        ntohs((addr).s6_addr16[7])

/* These are the global options.  */
char *local_host = NULL;
int local_port = 0;
char *remote_host = NULL;
int remote_port = 0;
command_t command = COMMAND_NONE;
struct sockaddr *bindx_add_addrs = NULL;
int bindx_add_count = 0;
struct sockaddr *bindx_rem_addrs = NULL;
int bindx_rem_count = 0;
struct sockaddr *connectx_addrs = NULL;
int connectx_count = 0;
int interactive_mode = 0;
int poll_skn = 0;
int nonblocking = 0;
int opt_space = 0;
char gen_data = GEN_DATA_FIRST;
char *inter_outbuf = NULL;
int inter_outlen = 0;
int inter_sk = 0;
int poll_snd_size = 0;
int use_poll = 0;
int socket_type = SOCK_SEQPACKET;
sctp_assoc_t associd = 0;
int echo = 0;
char *interface = "eth0";
int if_index = 0;
sockaddr_storage_t remote_addr;
sa_family_t ra_family;	/* What family is remote_addr? */
int ra_len = 0;		/* How long is remote_addr? */
void *ra_raw;		/* This is the addr part of remote_addr. */
int new_connection = 1;

enum inter_cmd_num {
	INTER_SND = 0,
	INTER_RCV,
	INTER_SNDBUF,
	INTER_RCVBUF,
	INTER_BINDX_ADD,
	INTER_BINDX_REM,
	INTER_SET_PRIM,
	INTER_SET_PEER_PRIM,
	INTER_SHUTDOWN,
	INTER_ABORT,
	INTER_NODELAY,
	INTER_MAXSEG,
	INTER_HEARTBEAT,
	INTER_GET_STATS
};

enum shutdown_type {
	SHUTDOWN_ABORT = 0,
	SHUTDOWN_SHUTDOWN
};

struct inter_entry {
	char *cmd;
	int cmd_num;
};

struct inter_entry inter_commands[] = {
	{"snd", INTER_SND},
	{"rcv",	INTER_RCV},
	{"sndbuf", INTER_SNDBUF},
	{"rcvbuf", INTER_RCVBUF},
	{"bindx-add", INTER_BINDX_ADD},
	{"bindx-rem", INTER_BINDX_REM},
	{"primary", INTER_SET_PRIM},
	{"peer_primary", INTER_SET_PEER_PRIM},
	{"shutdown", INTER_SHUTDOWN},
	{"abort", INTER_ABORT},
	{"nodelay", INTER_NODELAY},
	{"maxseg", INTER_MAXSEG},
	{"heartbeat", INTER_HEARTBEAT},
	{"stats", INTER_GET_STATS},
	{NULL, -1},
};

#define POLL_SK_MAX 	256	/* The max number of sockets to select/poll. */
int poll_sks[POLL_SK_MAX];		/* The array for using select(). */
struct pollfd poll_fds[POLL_SK_MAX];	/* The array for using poll().  */
#define POLL_SND_SIZE	16384	/* Default message size in the poll mode. */


struct sockaddr *append_addr(const char *parm, struct sockaddr *addrs,
			     int *ret_count) ;
int build_endpoint(char *argv0, int portnum);
static int parse_inter_commands(char *, char *, int);
static void snd_func(char *);
static void sndbuf_func(char *, int, int, int);
static void rcvbuf_func(char *, int, int, int);
static struct sockaddr *get_bindx_addr(char *, int *);
static int bindx_func(char *, int, struct sockaddr *, int, int, int);
static int connectx_func(char *, int, struct sockaddr *, int);
static void  primary_func(char *, int, char *, int);
static void  peer_primary_func(char *, int, char *, int);
static void  spp_hb_demand_func(char *, int, char *, int);
static int nodelay_func(char *, int, int val, int set);
static int maxseg_func(char *, int, int val, int set);
static int shutdown_func(char *argv0, int *skp, int shutdown_type);
static int get_assocstats_func(int, sctp_assoc_t);
static int test_sk_for_assoc(int sk, sctp_assoc_t assoc_id);
static char * gen_message(int);
static sctp_assoc_t test_recv_assoc_change(int);
static sctp_assoc_t test_verify_assoc_change(struct msghdr *);
void print_addr_buf(void * laddrs, int n_laddrs);
int print_sockaddr(struct sockaddr *sa_addr);

int
main(int argc, char *argv[]) {
	int sk = -1;
	int error = 0;
	int i;

	signal(SIGPIPE, SIG_IGN);

	parse_arguments(argc, argv);

	switch(command) {
	case COMMAND_NONE:
		fprintf(stderr, "%s: Please specify a command.\n",
			argv[0]);
		exit(1);
		break;
	case COMMAND_LISTEN:
		sk = build_endpoint(argv[0], local_port);
		error = command_listen(argv[0], sk);
		break;
	case COMMAND_SEND:
		sk = build_endpoint(argv[0], local_port);
		error = command_send(argv[0], &sk);
		break;
	case COMMAND_POLL:
		if (use_poll) {
			for (i = 0; i < poll_skn; i++) {
				poll_fds[i].fd = build_endpoint(argv[0],
					local_port + i);
			}
		} else {
			for (i = 0; i < poll_skn; i++) {
				poll_sks[i] = build_endpoint(argv[0],
					local_port + i);
			}
		}
		error = command_poll(argv[0]);
		break;
	default:
		fprintf(stderr, "%s: illegal command %d\n",
			argv[0], command);
		exit(1);
	}

	/* Shut down the link.  */
	if (COMMAND_POLL != command) {
		close(sk);
	} else {
		/* Shutdown all links.  */
		if (use_poll) {
			for (i = 0; i < poll_skn; i++) {
				close(poll_fds[i].fd);
			}
		} else {
			for (i = 0; i < poll_skn; i++) {
				close(poll_sks[i]);
			}
		}
	}

	exit(error);
}

/********************************************************************
 * 2nd Level Abstractions
 ********************************************************************/

void
parse_arguments(int argc, char *argv[]) {
	int option_index = 0;
	int c;
	struct sockaddr *tmp_addrs = NULL;

	static struct option long_options[] = {
		{"local",	1, 0, 1},
		{"local-port",	1, 0, 2},
		{"remote",	1, 0, 3},
		{"remote-port",	1, 0, 4},
		{"listen",	0, 0, 10},
		{"send",	0, 0, 11},
		{"bindx-add",	1, 0, 15},
		{"bindx-rem",	1, 0, 16},
		{"use-poll",	0, 0, 20},
		{"echo",        0, 0, 'e'},
		{"interface",   optional_argument, 0, 5,},
		{"connectx",    1, 0, 17},
		{0,		0, 0, 0}
	};

	/* Parse the arguments.  */
	while (1) {
		c = getopt_long (argc, argv, "B:H:IP:b:h:i:p:lm:nstz:ec:",
				 long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			printf("option %s", long_options[option_index].name);
			if (optarg) {
				printf(" with arg %s", optarg);
			}
			printf("\n");
			break;
		case 1:		/* local host */
		case 'H':
			local_host = optarg;
			break;
		case 2:		/* local port */
		case 'P':
			local_port = atoi(optarg);
			break;
		case 3:		/* remote host */
		case 'h':
			remote_host = optarg;
			break;
		case 4:		/* remote port */
		case 'p':
			remote_port = atoi(optarg);
			break;
		case 5:  /* interface for sin6_scope_id */
			if (optarg)
				interface = optarg;
			if_index = if_nametoindex(interface);
			if (!if_index) {
				printf("Interface %s unknown\n", interface);
				exit(1);
			}
			break;
			/* COMMANDS */
		case 10:	/* listen */
		case 'l':
			if (command) {
				fprintf(stderr,
					"%s: pick ONE of listen or send\n",
					argv[0]);
				exit(1);
			} else {
				command = COMMAND_LISTEN;
			}
			break;

		case 11:	/* send */
		case 's':
			if (command) {
				fprintf(stderr,
					"%s: pick ONE of listen or send\n",
					argv[0]);
				exit(1);
			} else {
				command = COMMAND_SEND;
			}
			break;

		case 15:		/* bindx_add */
		case 'B':
			tmp_addrs =
				append_addr(optarg, bindx_add_addrs,
					    &bindx_add_count);
			if (NULL == tmp_addrs) {
				/* We have no memory, so keep fprintf()
				 * from trying to allocate more.
				 */
				fprintf(stderr, "No memory to add ");
				fprintf(stderr, "%s\n", optarg);
				exit(2);
			}
			bindx_add_addrs = tmp_addrs;

			break;

		case 16:		/* bindx_rem */
		case 'b':
			tmp_addrs =
				append_addr(optarg, bindx_rem_addrs,
					    &bindx_rem_count);
			if (NULL == tmp_addrs) {
				/* We have no memory, so keep fprintf()
				 * from trying to allocate more.
				 */
				fprintf(stderr, "No memory to add ");
				fprintf(stderr, "%s\n", optarg);
				exit(2);
			}
			bindx_rem_addrs = tmp_addrs;
			break;
		case 17:		/* connectx */
		case 'c':
			tmp_addrs =
				append_addr(optarg, connectx_addrs,
					    &connectx_count);
			if (NULL == tmp_addrs) {
				/* We have no memory, so keep fprintf()
				 * from trying to allocate more.
				 */
				fprintf(stderr, "No memory to add ");
				fprintf(stderr, "%s\n", optarg);
				exit(2);
			}
			connectx_addrs = tmp_addrs;
			break;
		case 20:		/* use-poll */
			use_poll = 1;
			break;
		case 'I':
			interactive_mode = 1;
			break;
		case 'i':
			command = COMMAND_POLL;
			poll_skn = atoi(optarg);
			if (poll_skn <= 0 || poll_skn > POLL_SK_MAX) {
				fprintf(stderr, "Too many sockets for ");
				fprintf(stderr, "for polling\n");
				exit(2);
			}
			break;
		case 'm':
			opt_space = atoi(optarg);
			break;
		case 'n':
			nonblocking = 1;
			break;
		case 't':
			socket_type = SOCK_STREAM;
			break;
		case 'z':
			poll_snd_size = atoi(optarg);
			if (poll_snd_size <= 0) {
				fprintf(stderr, "Bad message size.\n");
				exit(2);
			}
			break;
		case 'e':
			echo = 1;
			break;
		case '?':
			usage(argv[0]);
			exit(1);

		default:
			printf ("%s: unrecognized option 0%c\n",
				argv[0], c);
			usage(argv[0]);
			exit(1);
		}
	}

	if (optind < argc)
	{
		fprintf(stderr, "%s: non-option arguments are illegal: ",
			argv[0]);
		while (optind < argc)
			fprintf(stderr, "%s ", argv[optind++]);
		fprintf (stderr, "\n");
		usage(argv[0]);
		exit(1);
	}


	if (NULL == local_host) {
		fprintf(stderr, "%s: You MUST provide a local host.\n",
			argv[0]);
		usage(argv[0]);
		exit(1);
	}

	if (command == COMMAND_SEND && NULL == remote_host
	    && connectx_count == 0) {
		fprintf(stderr, "%s: You MUST provide a remote host for sending.\n",
			argv[0]);
		usage(argv[0]);
		exit(1);
	}

	if (remote_host != NULL && connectx_count != 0) {
		fprintf(stderr, "%s: You can not provide both -h and -c options.\n",
			argv[0]);
		usage(argv[0]);
		exit(1);
	}
} /* parse_arguments() */

/* Set up the local endpoint.  */
int
build_endpoint(char *argv0, int portnum)
{
	int retval;
	struct hostent *hst;
	sockaddr_storage_t local_addr;
	sa_family_t la_family;	/* What family is local_addr? */
	int la_len;		/* How long is local_addr? */
	void *la_raw;		/* This is the addr part of local_addr. */
	int error;
	struct sctp_event_subscribe subscribe;

	/* Get the transport address for the local host name.  */
	hst = gethostbyname(local_host);
	if (hst == NULL) {
		hst = gethostbyname2(local_host, AF_INET6);
	}

	if (hst == NULL || hst->h_length < 1) {
		fprintf(stderr, "%s: bad hostname: %s\n", argv0, local_host);
		exit(1);
	}

	la_family = hst->h_addrtype;
	switch (la_family) {
	case AF_INET:
		la_len = sizeof(local_addr.v4);
		la_raw = &local_addr.v4.sin_addr;
		local_addr.v4.sin_port = htons(portnum);
		local_addr.v4.sin_family = AF_INET;
		break;
	case AF_INET6:
		la_len = sizeof(local_addr.v6);
		la_raw = &local_addr.v6.sin6_addr;
		local_addr.v6.sin6_port = htons(portnum);
		local_addr.v6.sin6_family = AF_INET6;
		local_addr.v6.sin6_scope_id = if_index;
		break;
	default:
		fprintf(stderr, "Invalid address type.\n");
		exit(1);
		break;
	}
	memcpy(la_raw, hst->h_addr_list[0], hst->h_length);

	/* Create the local endpoint.  */
	retval = socket(la_family, socket_type, IPPROTO_SCTP);
	if (retval < 0) {
		fprintf(stderr, "%s: failed to create socket:  %s.\n",
			argv0, strerror(errno));
		exit(1);
	}

	if (SOCK_SEQPACKET == socket_type) {
		memset(&subscribe, 0, sizeof(subscribe));
		subscribe.sctp_data_io_event = 1;
		subscribe.sctp_association_event = 1;
		error = setsockopt(retval, SOL_SCTP, SCTP_EVENTS,
				   (char *)&subscribe, sizeof(subscribe));
		if (error) {
			fprintf(stderr, "SCTP_EVENTS: error: %d\n", error);
			exit(1);
		}
	}

	/* Bind this socket to the test port.  */
	error = bind(retval, &local_addr.sa, la_len);
	if (error != 0) {
		fprintf(stderr, "%s: can not bind to %s:%d: %s.\n",
			argv0, local_host, portnum,
			strerror(errno));
		exit(1);
	}

	/* Do we need to do bindx() to add any additional addresses? */
	if (bindx_add_addrs) {
		if (0 != bindx_func(argv0, retval, bindx_add_addrs,
			bindx_add_count, SCTP_BINDX_ADD_ADDR, portnum)) {
			fprintf(stderr, "bindx_func (add) failed.\n");
			exit(1);
		}
	} /* if (bindx_add_addrs) */

	/* Do we need to do bindx() to remove any bound addresses? */
	if (bindx_rem_addrs) {
		if (0 != bindx_func(argv0, retval, bindx_rem_addrs,
			bindx_rem_count, SCTP_BINDX_REM_ADDR, portnum)) {
			fprintf(stderr, "bindx_func (remove) failed.\n");
			exit(1);
		}
	} /* if (bindx_rem_addrs) */

	/* Do we want to run in the non-blocking mode? */
	if (nonblocking) {
		error = fcntl(retval, F_SETFL, O_NONBLOCK);
		if (error != 0) {
			fprintf(stderr, "%s: error fcntl: %s.\n",
				argv0, strerror(errno));
			exit(1);
		}
	}

	if (opt_space) {
		sndbuf_func(argv0, retval, opt_space, 1);
		rcvbuf_func(argv0, retval, opt_space, 1);
	}

	return retval;

} /* build_endpoint() */

/* Convenience structure to determine space needed for cmsg. */
typedef union {
	struct sctp_initmsg init;
	struct sctp_sndrcvinfo sndrcvinfo;
} _sctp_cmsg_data_t;


/* Listen on the socket, printing out anything that arrives.  */
int
command_listen(char *argv0, int sk)
{
	char incmsg[CMSG_SPACE(sizeof(_sctp_cmsg_data_t))];
	struct iovec iov;
	struct msghdr inmessage;
	sockaddr_storage_t msgname;
	char message[REALLY_BIG];
	int done = 0;
	int error;
	int c;
	int recvsk = 0;

 	/* Mark sk as being able to accept new associations */
	error = listen(sk, 5);
	if (error != 0) {
		printf("\n\n\t\tlisten Failure:  %s.\n\n\n",
		       strerror(errno));
		exit(1);
	}

	if (nonblocking) {
		if (!interactive_mode) {
			printf("Use -I for interactive mode with");
		       printf("	-n nonblocking\n");
		       exit(1);
		 }
	}

	/* Initialize the global value for interactive mode functions.  */
	if (interactive_mode) {
		inter_sk = sk;
	}

	/* Initialize inmessage with enough space for DATA... */
	memset(&inmessage, 0, sizeof(inmessage));
	if ((iov.iov_base = malloc(REALLY_BIG)) == NULL) {
		printf("%s: Can't allocate memory.\n", argv0);
		exit(1);
	}
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	/* or a control message.  */
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);
	inmessage.msg_name = &msgname;
	inmessage.msg_namelen = sizeof(msgname);

	printf("%s listening...\n", argv0);
	/* Get the messages sent */
	done = 0;
	while (!done) {
		if (interactive_mode) {
			/* Read from the user.  */
			if (remote_host) {
				printf("%s:%d-%s:%d Interactive mode> ",
					local_host, local_port, remote_host,
					remote_port);
			} else {
				printf("%s:%d-", local_host, local_port);
				if (associd) {
					print_sockaddr(&remote_addr.sa);
				} else {
					printf("?:%d", remote_port);
				}
				printf(" Interactive mode> ");
			}
			fflush(stdout);
			if (NULL == fgets(message, REALLY_BIG, stdin)) {
				done = 1;
				continue;
			}

			if (0 <= (c = parse_inter_commands(argv0, message,
				0))) {
				if (INTER_RCV != c) {
					continue;
				}
			} else {
				continue;
			}
		}

		if (socket_type == SOCK_STREAM) {
			socklen_t len = 0;

			if (!recvsk) {
				if ((recvsk = accept(sk, NULL, &len)) < 0) {
					fprintf(stderr, "%s: error: %s.\n",
						argv0, strerror(errno));
					exit(1);
				}
			}

		} else {
			recvsk = sk;
		}

		error = recvmsg(recvsk, &inmessage, MSG_WAITALL);
		if (error < 0) {
			if (nonblocking && (EAGAIN == errno)) {
				error = 0;
				continue;
			}

			if (socket_type == SOCK_STREAM) {
				if (ENOTCONN != errno)
					break;
				printf("No association is present now!!\n");
				close(recvsk);
				recvsk = 0;
				continue;
			}
			break;
		}

		/* Update the associd when a notification is received on a
		 * UDP-style socket.
		 */
		if (inmessage.msg_flags & MSG_NOTIFICATION)
			associd = test_verify_assoc_change(&inmessage);

		if (echo) {
			if( !(MSG_NOTIFICATION & inmessage.msg_flags)) {
				if (sendto(recvsk, inmessage.msg_iov->iov_base,
					   error, 0,
					   (struct sockaddr *)&msgname,
					   sizeof(msgname)) == -1) {
					fprintf(stderr, "%s: error: %s.\n",
						argv0, strerror(errno));
					exit(1);
				}
			}
		}

		test_print_message(sk, &inmessage, error);

		inmessage.msg_control = incmsg;
		inmessage.msg_controllen = sizeof(incmsg);
		inmessage.msg_name = &msgname;
		inmessage.msg_namelen = sizeof(msgname);
		iov.iov_len = REALLY_BIG;

		/* Verify that the association is no longer present.  */
		if (0 != test_sk_for_assoc(recvsk, associd)) {
			printf("No association is present now!!\n");
			if (socket_type == SOCK_STREAM) {
				close(recvsk);
				recvsk = 0;
			}
		}
	}

	if (error < 0) {
		fprintf(stderr, "%s: error: %s.\n",
			argv0, strerror(errno));
		exit(1);
	}

	return error;

} /* command_listen() */

/* Read lines from stdin and send them to the socket.  */
int
command_send(char *argv0, int *skp)
{
	struct msghdr outmsg;
	struct iovec iov;
	int done = 0;
	char message[REALLY_BIG];
	struct hostent *hst;
	int c;
	struct sockaddr *addrs;
	int msglen;
	int error = 0;
	int sk = *skp;

	/* Set up the destination.  */
	if (remote_host != NULL) {
		hst = gethostbyname(remote_host);
		if (hst == NULL) {
			hst = gethostbyname2(remote_host, AF_INET6);
		}

		if (hst == NULL || hst->h_length < 1) {
			fprintf(stderr, "%s: bad hostname: %s\n",
				argv0, remote_host);
			exit(1);
		}

		ra_family = hst->h_addrtype;
		switch (ra_family) {
		case AF_INET:
			ra_len = sizeof(remote_addr.v4);
			ra_raw = &remote_addr.v4.sin_addr;
			remote_addr.v4.sin_port = htons(remote_port);
			remote_addr.v4.sin_family = AF_INET;
			break;
		case AF_INET6:
			ra_len = sizeof(remote_addr.v6);
			ra_raw = &remote_addr.v6.sin6_addr;
			remote_addr.v6.sin6_port = htons(remote_port);
			remote_addr.v6.sin6_family = AF_INET6;
			remote_addr.v6.sin6_scope_id = if_index;
			break;
		default:
			fprintf(stderr, "Invalid address type.\n");
			exit(1);
			break;
		}
		memcpy(ra_raw, hst->h_addr_list[0], hst->h_length);
	}

	/* Initialize the global value for interactive mode functions.  */
	if (interactive_mode) {
		inter_sk = sk;
	}

	printf("%s ready to send...\n", argv0);
	while (!done) {
		/* Read from the user.  */
		if (remote_host) {
			if (interactive_mode) {
				printf("%s:%d-%s:%d Interactive mode> ",
					local_host, local_port, remote_host,
					remote_port);
			} else {
				printf("%s:%d-%s:%d> ",
				       local_host, local_port,
				       remote_host, remote_port);
			}
		} else {
			printf("%s:%d-", local_host, local_port);
			if (associd) {
				print_sockaddr(&remote_addr.sa);
			} else {
				printf("XXXXXX:%d", remote_port);
			}
			if (interactive_mode) {
				printf(" Interactive mode> ");
			} else {
				printf("> ");
			}
		}
		fflush(stdout);
		if (NULL == fgets(message, REALLY_BIG, stdin)) {
			done = 1;
			continue;
		}

		if (interactive_mode) {
			/* This is the send only agent.  */
			if (0 <= (c = parse_inter_commands(argv0, message,
				1))) {
				if (INTER_SND == c) {
					iov.iov_base = inter_outbuf;
					msglen = inter_outlen;
					iov.iov_len = msglen;

				} else {
					continue;
				}

			} else {
				continue;
			}
		} else {
			/* Send to our neighbor.  */
			msglen = strlen(message) + 1;
			iov.iov_len = msglen;
		}

		/* For a UDP-style socket, verify if an existing association
		 * has gone. If so, receive the pending SCTP_ASSOC_CHANGE
		 * notification.
		 */
		if ((SOCK_SEQPACKET == socket_type) && associd &&
		    (0 != test_sk_for_assoc(sk, associd))) {
			associd = test_recv_assoc_change(sk);
			printf("Old association gone, Starting a new one!\n");
			new_connection = 1;
		}

		if (new_connection && connectx_count != 0) {
			/* Do a sctp_connectx() to establish a connection. */
			error = connectx_func(argv0, sk, connectx_addrs,
					      connectx_count);
			if (0 != error) {
				if (error == -2) {
					printf("Connection refused\n");
					if (SOCK_SEQPACKET == socket_type) {
						associd = test_recv_assoc_change(sk);
					}
					continue;
				}
				fprintf(stderr, "connectx failed.\n");
				exit(1);
			}
			if (SOCK_SEQPACKET == socket_type) {
				associd = test_recv_assoc_change(sk);
			} else {
				associd = 1;
			}
			int rc = sctp_getpaddrs(sk, associd, &addrs);
			if (0 >= rc) {
				if (rc == 0) {
					fprintf(stderr, "sctp_getpaddrs failed, no peers.\n");
				} else {
					fprintf(stderr, "sctp_getpaddrs failed %s(%d).\n", strerror(errno), errno);
				}
				exit(1);
			}
			printf("New connection, peer addresses\n");
			print_addr_buf(addrs, rc);
			ra_family = addrs[0].sa_family;
			switch (ra_family) {
			case AF_INET:
				ra_len = sizeof(remote_addr.v4);
				break;
			case AF_INET6:
				ra_len = sizeof(remote_addr.v6);
				break;
			default:
				fprintf(stderr, "Invalid address type.\n");
				exit(1);
			}
			memcpy(&remote_addr, &addrs[0], ra_len);
			sctp_freepaddrs(addrs);
			new_connection = 0;
		}

		do {
			if (SOCK_SEQPACKET == socket_type ||
			    (connectx_count == 0 && new_connection)) {
				/* Initialize the message struct we use to pass
				 * messages to the remote socket.
				 */
				if (!interactive_mode) {
					iov.iov_base = message;
					iov.iov_len = msglen;
				}
				outmsg.msg_iov = &iov;
				outmsg.msg_iovlen = 1;
				outmsg.msg_control = NULL;
				outmsg.msg_controllen = 0;
				outmsg.msg_name = &remote_addr;
				outmsg.msg_namelen = ra_len;
				outmsg.msg_flags = 0;

				error = sendmsg(sk, &outmsg, 0);
			} else {
				error = send(sk, message, msglen, 0);
				if (error == -1 && errno == EPIPE) {
					error = close(sk);
					if (error != 0) {
						fprintf(stderr, "close failed %s\n", strerror(errno));
						exit(1);
					}
					*skp = sk = build_endpoint(argv0, local_port);
					break;
				}
			}

			if (error != msglen) {
				fprintf(stderr, "%s: error: %s.\n",
					argv0, strerror(errno));
				if (nonblocking && EAGAIN == errno) {
					if (interactive_mode) {
						break;
					}
					continue;
				}
				exit(1);
			} else {
				break;
			}
		} while (error != msglen);

		/* If this is the first message sent over a UDP-style socket,
		 * get the associd from the SCTP_ASSOC_CHANGE notification.
		 */
		if ((SOCK_SEQPACKET == socket_type) && (0 == associd))
			associd = test_recv_assoc_change(sk);

		/* Verify there is no association.  */
		if (0 != test_sk_for_assoc(sk, associd)) {
			printf("No association is present now!!\n");
			new_connection = 1;
		} else {
			if (new_connection) {
				int rc = sctp_getpaddrs(sk, associd, &addrs);
				if (0 >= rc) {
					if (rc == 0) {
						fprintf(stderr, "sctp_getpaddrs failed, no peers.\n");
					} else {
						fprintf(stderr, "sctp_getpaddrs failed %s(%d).\n", strerror(errno), errno);
					}
					exit(1);
				}
				printf("New connection, peer addresses\n");
				print_addr_buf(addrs, rc);
				sctp_freepaddrs(addrs);
				new_connection = 0;
			}
		}

		/* Clean up.  */
		if (interactive_mode) {
			free(inter_outbuf);
			inter_outbuf = NULL;
		}
	} /* while(!done) */

	return error;

} /* command_send() */

/* Listen on the array of sockets, printing out anything that arrives.  */
int
command_poll(char *argv0)
{
	char incmsg[CMSG_SPACE(sizeof(_sctp_cmsg_data_t))];
	struct iovec iov;
	struct msghdr inmessage;
	int done = 0;
	int error = 0;
	int max_fd, i, ret;
	int size;
	fd_set *ibitsp = NULL;
	fd_set *obitsp = NULL;
	fd_set *xbitsp = NULL;

	struct msghdr outmsg;
	struct hostent *hst;
	int msglen;
	int temp_fd, temp_set;



	/* If a remote host is specified, initialize the destination. */
	if (remote_host) {
		/* Set up the destination.  */
		hst = gethostbyname(remote_host);
		if (hst == NULL) {
			hst = gethostbyname2(remote_host, AF_INET6);
		}

		if (hst == NULL || hst->h_length < 1) {
			fprintf(stderr, "%s: bad hostname: %s\n",
				argv0, remote_host);
			exit(1);
		}

		ra_family = hst->h_addrtype;
		switch (ra_family) {
		case AF_INET:
			ra_len = sizeof(remote_addr.v4);
			ra_raw = &remote_addr.v4.sin_addr;
			remote_addr.v4.sin_port = htons(remote_port);
			remote_addr.v4.sin_family = AF_INET;
			break;
		case AF_INET6:
			ra_len = sizeof(remote_addr.v6);
			ra_raw = &remote_addr.v6.sin6_addr;
			remote_addr.v6.sin6_port = htons(remote_port);
			remote_addr.v6.sin6_family = AF_INET6;
			remote_addr.v6.sin6_scope_id = if_index;
			break;
		default:
			fprintf(stderr, "Invalid address type.\n");
			exit(1);
			break;
		}
		memcpy(ra_raw, hst->h_addr_list[0], hst->h_length);

		/* Initialize the message struct we use to pass messages to
	 	 * the remote socket.
	 	 */
		outmsg.msg_iov = &iov;
		outmsg.msg_iovlen = 1;
		outmsg.msg_control = NULL;
		outmsg.msg_controllen = 0;
		outmsg.msg_name = &remote_addr;
		outmsg.msg_namelen = ra_len;
		outmsg.msg_flags = 0;
	}


	max_fd = -1;

	/* Set all of the sockets to be ready for listening. */
	if (use_poll) {
		for (i = 0; i < poll_skn; i++) {
			error = listen(poll_fds[i].fd, 1);
			if (error != 0) {
				printf("%s: Listen failed on socket number ",
					argv0);
				printf("%d: %s.\n", i, strerror(errno));
				exit(1);
			}
		}
		printf("%s listening...\n", argv0);
	} else {
		for (i = 0; i < poll_skn; i++) {
			error = listen(poll_sks[i], 1);
			if (error != 0) {
				printf("%s: Listen failed on socket number ",
					argv0);
				printf("%d: %s.\n", i, strerror(errno));
				exit(1);
			}
			if (poll_sks[i] > max_fd) {
				max_fd = poll_sks[i];
			}
		}
		printf("%s listening...\n", argv0);

		size = howmany(max_fd + 1, NFDBITS) * sizeof(fd_mask);
		if ((ibitsp = (fd_set *)malloc(size)) == NULL) {
			printf("%s: Can't allocate memory.\n", argv0);
			exit(1);
		}
		if ((obitsp = (fd_set *)malloc(size)) == NULL) {
			printf("%s: Can't allocate memory.\n", argv0);
			exit(1);
		}
		if ((xbitsp = (fd_set *)malloc(size)) == NULL) {
			printf("%s: Can't allocate memory.\n", argv0);
			exit(1);
		}
		memset(ibitsp, 0, size);
		memset(obitsp, 0, size);
		memset(xbitsp, 0, size);
	}


	/* Initialize inmessage with enough space for DATA... */
	memset(&inmessage, 0, sizeof(inmessage));
	if ((iov.iov_base = malloc(REALLY_BIG)) == NULL) {
		printf("%s: Can't allocate memory.\n", argv0);
		exit(1);
	}
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	/* or a control message.  */
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);


	done = 0;
	/* Set the default send message size.  */
	if (!poll_snd_size) {
		poll_snd_size = POLL_SND_SIZE;
	}

	while (!done) {

		if (use_poll) {
			for (i = 0; i < poll_skn; i++) {
				poll_fds[i].events = POLLIN;
			}
			if (remote_host) {
				/* Poll output on the first socket.  */
				poll_fds[0].events |= POLLOUT;
			}

			if ((ret = poll(poll_fds, poll_skn, -1))) {
				if (ret == -1) {
					break;
				}
			}
		} else {
			for (i = 0; i < poll_skn; i++) {
				FD_SET(poll_sks[i], ibitsp);
				FD_SET(poll_sks[i], xbitsp);
			}
			if (remote_host) {
				/* Only select output on the first socket.  */
				FD_SET(poll_sks[0], obitsp);
			}


			if ((ret = select(max_fd + 1, ibitsp, obitsp, xbitsp,
				(struct timeval *)0)) < 0) {
				if (ret == -1) {
					break;
				}
			}

		}

		if (remote_host) {
			if (use_poll) {
				temp_set = poll_fds[0].revents & POLLOUT;
				temp_fd = poll_fds[0].fd;
			} else {
				temp_set = FD_ISSET(poll_sks[0], obitsp);
				temp_fd = poll_sks[0];
			}

			if (temp_set) {
				inter_outbuf = gen_message(poll_snd_size);
				if (!inter_outbuf) {
					fprintf(stderr,
					"Cannot allocate out message.\n");
					exit(1);
				}
				iov.iov_base = inter_outbuf;
				msglen = poll_snd_size;
				iov.iov_len = msglen;

				error = sendmsg(temp_fd, &outmsg, 0);
				fprintf(stderr,
					"sent a message, msglen = %d\n",
					msglen);

				if (error != msglen) {
					fprintf(stderr, "%s: error: %s.\n",
						argv0, strerror(errno));
					if ((!nonblocking) ||
					    (EAGAIN != errno)) {
						exit(1);
					}
				}

				/* Clean up.  */
				free(inter_outbuf);
				inter_outbuf = NULL;
			}

		} /* while(!done) */

		for (i = 0; !done && (i < poll_skn); i++) {
			if (use_poll) {
				temp_set = poll_fds[i].revents & POLLIN;
				temp_fd = poll_fds[i].fd;
			} else {
				temp_set = FD_ISSET(poll_sks[i], ibitsp);
				temp_fd = poll_sks[i];
			}
			if (temp_set) {
				error = recvmsg(temp_fd, &inmessage,
					MSG_WAITALL);
				if (error < 0) {
					if ((EAGAIN == errno)) {
						error = 0;
						continue;
					}
					else {
						fprintf(stderr,
							"%s: error: %s.\n",
							argv0,
							strerror(errno));
						exit(1);
					}
				}
				test_print_message(temp_fd, &inmessage, error);
				inmessage.msg_control = incmsg;
				inmessage.msg_controllen = sizeof(incmsg);
				iov.iov_len = REALLY_BIG;
			}

			/* Update the associd when a notification is received
			 * on a UDP-style socket.
			 */
			if (inmessage.msg_flags & MSG_NOTIFICATION)
				associd = test_verify_assoc_change(&inmessage);

			/* Verify there is no association. */
			if (0 != test_sk_for_assoc(poll_sks[i], associd)) {
				printf("No association is present in sk "
				       "No.%d now!!\n",i);
			}
		}

	}

	if (!use_poll) {
		free(ibitsp);
		free(obitsp);
		free(xbitsp);
	}

	return error;

} /* command_poll() */

/********************************************************************
 * 3rd Level Abstractions
 ********************************************************************/

#define FPS(arg) fprintf(stderr, arg)

void
usage(char *argv0)
{
	/*
	 * The bindx options, --bindx-add and --bindx-rem, are added to
	 *
	 * 1. provide first testcases for the new bindx system call
	 *
	 * 2. continue to grow sctp_darn with more functions and
	 * features so it will be equivalent to the "sock" tool for
	 * TCP as for SCTP.
	 *
	 * FIXME -
	 *
	 * It is not very effective to use these two options in the
	 * current command line mode of sctp_darn. For example, the
	 * --bindx-rem option can only be used in conjunction with the
	 * --bindx-add simply to test the function in the kernel
	 * path. Ideally, bindx needs to be tested by a tool which
	 * provides an interactive mode for users to change parameters
	 * and configuration dynamically with existing endpoints and
	 * associations.
	 */
	fprintf(stderr, "Usage: %s -H <localhost> -P <localport> "
		"[-h <remotehost>] [-p <remoteport>] -l|s\n"
		" -H, --local\t\tspecify one of the local addresses,\n"
		" -P, --local-port\tspecify the port number for local addresses,\n"
		" -h, --remote\t\tspecify the peer address,\n"
		" -p, --remote-port\tspecify the port number for the peer address,\n"
		" -l, --listen\t\tprint messages received from the peer,\n"
		" -s, --send\t\tsend messages to the peer,\n"
		" -B, --bindx-add"
		"\tadd the specified address(es) as additional bind\n"
		"\t\t\taddresses to the local socket. Multiple addresses can\n"
		"\t\t\tbe specified by using this argument multiple times.\n"
		"\t\t\tFor example, '-B 10.0.0.1 -B 20.0.0.2'.\n"
		" -b, --bindx-rem"
		"\tremove the specified address(es) from the bind\n"
		"\t\t\taddresses of the local socket. Multiple addresses can\n"
		"\t\t\tbe specified by using this argument multiple times.\n"
		"\t\t\tFor example, '-b 10.0.0.1 -b 20.0.0.2'.\n"
		" -c, --connectx"
		"\t\tuse the specified address(es) for connection to the\n"
		"\t\t\tpeer socket. Multiple addresses can be specified by\n"
		"\t\t\tusing this argument multiple times.\n"
		"\t\t\tFor example, '-c 10.0.0.1 -c 20.0.0.2'.\n"
		"\t\t\tThis option is incompatible with the -h option.\n"
		" -I\t\t\tuse the interactive mode.\n"
		" -i\t\t\tsetup the specified number of endpoints by using the\n"
		"\t\t\tspecified local host (-H) and local port (-P). The port\n"
        	"\t\t\tnumber will be incremented by one for each additional\n"
        	"\t\t\tendpoint.  All of these endpoints will be listening.\n"
		"\t\t\tIf a remote host (-h) and a remote port are also\n"
		"\t\t\tspecified, the first endpoint will start sending fixed\n"
		"\t\t\tsized messages to the remote host.\n"
		" -m\t\t\tspecify the sockopt sndbuf/rcvbuf size.\n"
		" -n\t\t\tset the socket(s) to be in the non-blocking mode.\n"
		"\t\t\tcollect messages from stdin and deliver them to the\n"
		"\t\t\tpeer,\n"
		"--use-poll\t\tuse system call poll() for polling among the\n"
		"\t\t\tnumber of endpoints specified by the -i option. Without\n"
		"\t\t\tthis option, select() would be used as default.\n"
		" -t\t\t\tuse SOCK_STREAM tcp-style sockets.\n"
		" -z\t\t\tspecify the message size to be sent.  The default\n"
		"\t\t\tmessage size generated would be 16K.\n"
		" --interface=\"ifname\"\tselect interface for sin6_scope_id.\n",
		argv0);
}


/* This function checks messages to see if they are of type 'event'
 * and if they are well-formed.
 */
int
user_test_check_message(struct msghdr *msg,
                        int controllen,
                        sctp_cmsg_t event)
{


	if (msg->msg_controllen != controllen) {
		fprintf(stderr,
			"Got control structure of length %zu, not %d\n",
			msg->msg_controllen, controllen);
		exit(1);
	}
	if (controllen > 0 && event != CMSG_FIRSTHDR(msg)->cmsg_type) {
		fprintf(stderr, "Wrong kind of event: %d, not %d\n",
			CMSG_FIRSTHDR(msg)->cmsg_type, event);
		exit(1);
	}

	return 1;

} /* user_test_check_message() */

/* Add another address represented as the string 'parm' to the list
 * addrs.  The argument count is the number of addrs on input and is
 * adjusted for output.
 */
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


	if (!parm)
		return NULL;
	/* Get the entries for this host.  */
	hst4 = gethostbyname(parm);
	hst6 = gethostbyname2(parm, AF_INET6);

	if ((NULL == hst4 || hst4->h_length < 1)
	    && (NULL == hst6 || hst6->h_length < 1)) {
		fprintf(stderr, "bad hostname: %s\n", parm);
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

			aptr += sizeof(struct sockaddr_in6);
		} /* for (loop through the new v6 addresses) */
	}

 finally:

	*ret_count = count;

	return new_addrs;

} /* append_addr() */

static int
parse_inter_commands(char *argv0, char *input, int snd_only)
{
	int i;
	char *p;
	int len;
	int set = 0;
	int val;
	struct sockaddr *tmp_addrs = NULL;


	p = input;
	if (*p == '?' || *p == '\n') {
		printf("Interactive commands:\n");
		printf("snd=<int>        - Do a sendmsg with the specified");
		printf(" length.\n");
		printf("rcv=<int>        - Do a recvmsg.");
		printf("The length is ignored for now.\n");
		printf("bindx-add=<addr> - Add a local address");
		printf(" with bindx. \n");
		printf("bindx-rem=<addr> - Remove a local address");
		printf(" with bindx. \n");
		printf("rcvbuf=<int>     - Get/Set receive buffer size\n");
		printf("sndbuf=<int>     - Get/Set send buffer size.\n");
		printf("primary=<addr>   - Get/Set association's primary\n");
		printf("peer_primary=addr- Set association's peer_primary\n");
		printf("heartbeat=<addr> - Request a user initiated heartbeat\n");
		printf("maxseg=<int>     - Get/Set Maximum fragment size.\n");
		printf("nodelay=<0|1>    - Get/Set NODELAY option.\n");
		printf("shutdown         - Shutdown the association.\n");
		printf("abort            - Abort the association.\n");
		printf("stats            - Print GET_ASSOC_STATS (if available in kernel).\n");
		printf("?                - Help. Display this message.\n");
		return -1;
	}

	for (i = 0; i < REALLY_BIG; i++) {
		if (('=' == *p) ||
		    ('?' == *p) ||
		    ('\n' == *p)) {
			if ('=' == *p) {
				set = 1;
			}
			*p++ = '\0';
			break;
		}
		p++;
	}
	if (i >= REALLY_BIG) {
		printf("Invalid input.\n");
		return -1;
	}

	i = 0;
	while (NULL != inter_commands[i].cmd) {
		if (!strcmp(input, inter_commands[i].cmd)) {
			switch (i) {
			case INTER_SND:
				if (snd_only) {
					if (*p < '0' || *p > '9') {
						goto err_input;
					}
					snd_func(p);
				} else {
					goto err_input;
				}
				break;
			case INTER_RCV:
				if (snd_only) {
					goto err_input;
				}
				break;
			case INTER_SNDBUF:
				if (set) {
					if (*p < '0' || *p > '9') {
						goto err_input;
					}
				}
				len = (set) ? atoi(p) : 0;
				sndbuf_func(argv0, inter_sk, len, set);
				break;
			case INTER_RCVBUF:
				if (set) {
					if (*p < '0' || *p > '9') {
						goto err_input;
					}
				}
				len = (set) ? atoi(p) : 0;
				rcvbuf_func(argv0, inter_sk, len, set);
				break;
			case INTER_BINDX_ADD:
				tmp_addrs = get_bindx_addr(p, &len);
				bindx_func(argv0, inter_sk, tmp_addrs, len,
					SCTP_BINDX_ADD_ADDR, local_port);
				free(tmp_addrs);
				break;
			case INTER_BINDX_REM:
				tmp_addrs = get_bindx_addr(p, &len);
				bindx_func(argv0, inter_sk, tmp_addrs, len,
					SCTP_BINDX_REM_ADDR, local_port);
				free(tmp_addrs);
				break;
			case INTER_SET_PRIM:
				primary_func(argv0, inter_sk, p, set);
				break;
			case INTER_SET_PEER_PRIM:
				peer_primary_func(argv0, inter_sk, p, set);
				break;
			case INTER_HEARTBEAT:
				spp_hb_demand_func(argv0, inter_sk, p, set);
				break;
			case INTER_SHUTDOWN:
				shutdown_func(argv0, &inter_sk, SHUTDOWN_SHUTDOWN);
				break;
			case INTER_ABORT:
				shutdown_func(argv0, &inter_sk, SHUTDOWN_ABORT);
				break;
			case INTER_NODELAY:
				if (set) {
					if (*p < '0' || *p > '9') {
						goto err_input;
					}
				}
				val = (set) ? atoi(p) : 0;
				nodelay_func(argv0, inter_sk, val, set);
				break;
			case INTER_MAXSEG:
				if (set) {
					if (*p < '0' || *p > '9') {
						goto err_input;
					}
				}
				val = (set) ? atoi(p) : 0;
				maxseg_func(argv0, inter_sk, val, set);
				break;
			case INTER_GET_STATS:
				get_assocstats_func(inter_sk, associd);
				break;
			default:
				goto err_input;
				break;
			}

			return i;
		}
		i++;
	}

err_input:
	printf("Invalid input.\n");
	return -1;

} /* parse_inter_commands() */

static char *
gen_message(int len)
{

	char *buf;
	char *p;
	int i;

	buf = malloc(len);

	if (NULL != buf) {
		for (i = 0, p = buf; i < len; i++, p++) {
			if (gen_data > GEN_DATA_LAST) {
				gen_data = GEN_DATA_FIRST;
			}
			*p = gen_data++;
		}
	}

	return(buf);

} /* gen_message() */

static void
snd_func(char *input)
{

	int len;

	len = atoi(input);
	if (!(inter_outbuf = gen_message(len))) {
		fprintf(stderr, "Cannot allocate out message.\n");
		exit(1);
	}
	inter_outlen = len;

} /* snd_func() */

static void
sndbuf_func(char *argv0, int sk, int len, int set)
{
	int error;
	socklen_t optlen;

	if (set) {
		error = setsockopt(sk, SOL_SOCKET, SO_SNDBUF,
			(char *)&len, sizeof(len));
	} else {
		optlen = sizeof(len);
		error = getsockopt(sk, SOL_SOCKET, SO_SNDBUF,
			(char *)&len, &optlen);
	}
	if (error != 0) {
		fprintf(stderr, "%s: Error setting/getting sndbuf: %s.\n",
			argv0, strerror(errno));
		exit(1);
	}

	if (!set) {
		printf("sndbuf is %d.\n", len);
	}

} /* sndbuf_func() */

static void
rcvbuf_func(char *argv0, int sk, int len, int set)
{
	int error;
	socklen_t optlen;

	if (set) {
		error = setsockopt(sk, SOL_SOCKET, SO_RCVBUF,
			(char *)&len, sizeof(len));
	} else {
		optlen = sizeof(len);
		error = getsockopt(sk, SOL_SOCKET, SO_RCVBUF,
			(char *)&len, &optlen);
	}
	if (error != 0) {
		fprintf(stderr, "%s: Error setting/getting rcvbuf: %s.\n",
			argv0, strerror(errno));
		exit(1);
	}

	if (!set) {
		printf("rcvbuf is %d.\n", len);
	}

} /* rcvbuf_func() */


static struct sockaddr *
get_bindx_addr(char *in, int *count)
{

	struct sockaddr *tmp_addrs = NULL;
	char *p = in;

	/* Set the buffer for address parsing.  */
	while ('\n' != *p) {
		p++;
	}
	*p = '\0';

	*count = 0;

	tmp_addrs = append_addr(in, tmp_addrs, count);
	if (NULL == tmp_addrs) {
		/* We have no memory, so keep fprintf()
		 * from trying to allocate more.
		 */
		fprintf(stderr, "No memory to add ");
		fprintf(stderr, "%s\n", in);
		exit(2);
	}
	return tmp_addrs;

} /* get_bindx_addr() */

static int
bindx_func(char *argv0, int sk, struct sockaddr *addrs, int count, int flag, int portnum)
{

	int error;
	int i;
	struct sockaddr *sa_addr;
	void *aptr;


	if (0 == portnum) {
		fprintf(stderr, "%s: A non-0 local port number is ", argv0);
		fprintf(stderr, "required for bindx to work!\n");
		return -1 ;
	}

	/* Set the port in every address.  */
	aptr = addrs;
	for (i = 0; i < count; i++) {
		sa_addr = (struct sockaddr *)aptr;

		switch(sa_addr->sa_family) {
		case AF_INET:
			((struct sockaddr_in *)sa_addr)->sin_port =
				htons(portnum);
			aptr += sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)sa_addr)->sin6_port =
				htons(portnum);
			aptr += sizeof(struct sockaddr_in6);
			break;
		default:
			fprintf(stderr, "Invalid address family\n");
			return -1;
		}
	}

	error = sctp_bindx(sk, addrs, count, flag);

	if (error != 0) {
		if (flag == SCTP_BINDX_ADD_ADDR) {
			fprintf(stderr, "%s: error adding addrs: %s.\n",
				argv0, strerror(errno));
			return -1;
		} else {
			fprintf(stderr, "%s: error removing addrs: %s.\n",
				argv0, strerror(errno));
			return -1;
		}
	}

	return 0;

} /* bindx_func() */

static int
connectx_func(char *argv0, int sk, struct sockaddr *addrs, int count)
{

	int error;
	int i;
	struct sockaddr *sa_addr;
	void *aptr;


	if (0 == remote_port) {
		fprintf(stderr, "%s: A non-0 remote port number is ", argv0);
		fprintf(stderr, "required for connectx to work!\n");
		return -1 ;
	}

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
			return -1;
		}
	}

	error = sctp_connectx(sk, addrs, count, NULL);

	if (error != 0) {
		if (errno == ECONNREFUSED)
			return -2;
		fprintf(stderr, "%s: error connecting to addrs: %s.\n",
			argv0, strerror(errno));
		return -1;
	}

	return 0;

} /* connectx_func() */

static void
primary_func(char *argv0, int sk, char *cp, int set)
{
	struct sctp_prim prim;
	struct sockaddr_in *in_addr;
	struct sockaddr_in6 *in6_addr;
	struct sockaddr *saddr;
	socklen_t prim_len;
	int ret;
	char *p = cp;
	char addr_buf[INET6_ADDRSTRLEN];
	const char *ap = NULL;

	prim_len = sizeof(struct sctp_prim);
	if (!set) {
		prim.ssp_assoc_id = associd;
		ret = getsockopt(sk, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
				   &prim, &prim_len); 
		if (ret < 0)
			goto err;
	
		saddr = (struct sockaddr *)&prim.ssp_addr;	
		if (AF_INET == saddr->sa_family) {
			in_addr = (struct sockaddr_in *)&prim.ssp_addr;
			ap = inet_ntop(AF_INET, &in_addr->sin_addr, addr_buf,
				       INET6_ADDRSTRLEN);
		} else if (AF_INET6 == saddr->sa_family) {
			in6_addr = (struct sockaddr_in6 *)&prim.ssp_addr;
			ap = inet_ntop(AF_INET6, &in6_addr->sin6_addr, addr_buf,
				       INET6_ADDRSTRLEN);
		}
		if (!ap)
			goto err;
		printf("%s\n", ap);
		return;
	}

	/* Set the buffer for address parsing.  */
	while ('\n' != *p)
		p++;
	*p = '\0';

	prim.ssp_assoc_id = associd;	
	if (strchr(cp, '.')) {
		in_addr = (struct sockaddr_in *)&prim.ssp_addr;
		in_addr->sin_port = htons(remote_port);
		in_addr->sin_family = AF_INET;
		ret = inet_pton (AF_INET, cp, &in_addr->sin_addr);
		if (ret <= 0)
			goto err;		
	} else if (strchr(cp, ':')) {
		in6_addr = (struct sockaddr_in6 *)&prim.ssp_addr;
		in6_addr->sin6_port = htons(remote_port);
		in6_addr->sin6_family = AF_INET6;
		ret = inet_pton(AF_INET6, cp, &in6_addr->sin6_addr);
		if (ret <= 0)
			goto err;		
	} else
		goto err;

	ret = setsockopt(sk, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
			    &prim, sizeof(struct sctp_prim)); 
	if (ret < 0)
		goto err;

	return;
err:
	if (!errno)
		errno = EINVAL;
	fprintf(stderr, "%s: error %s primary: %s.\n", argv0,
	        (set)?"setting":"getting", strerror(errno));
}

static void
peer_primary_func(char *argv0, int sk, char *cp, int set)
{
	struct sctp_setpeerprim setpeerprim;
	struct sockaddr_in *in_addr;
	struct sockaddr_in6 *in6_addr;
	int ret;
	char *p = cp;

	if (!set) {
		goto err;
	}

	/* Set the buffer for address parsing.  */
	while ('\n' != *p)
		p++;
	*p = '\0';

	setpeerprim.sspp_assoc_id = associd;	
	if (strchr(cp, '.')) {
		in_addr = (struct sockaddr_in *)&setpeerprim.sspp_addr;
		in_addr->sin_port = htons(local_port);
		in_addr->sin_family = AF_INET;
		ret = inet_pton (AF_INET, cp, &in_addr->sin_addr);
		if (ret <= 0)
			goto err;		
	} else if (strchr(cp, ':')) {
		in6_addr = (struct sockaddr_in6 *)&setpeerprim.sspp_addr;
		in6_addr->sin6_port = htons(local_port);
		in6_addr->sin6_family = AF_INET6;
		ret = inet_pton(AF_INET6, cp, &in6_addr->sin6_addr);
		if (ret <= 0)
			goto err;		
	} else
		goto err;

	ret = setsockopt(sk, IPPROTO_SCTP, SCTP_SET_PEER_PRIMARY_ADDR,
			    &setpeerprim, sizeof(struct sctp_setpeerprim)); 
	if (ret < 0)
		goto err;

	return;
err:
	if (!errno)
		errno = EINVAL;
	fprintf(stderr, "%s: error %s peer_primary: %s.\n", argv0,
	        (set)?"setting":"getting", strerror(errno));
}

static void
spp_hb_demand_func(char *argv0, int sk, char *cp, int set)
{
	struct sctp_paddrparams params;
	struct sockaddr_in *in_addr;
	struct sockaddr_in6 *in6_addr;
	int ret;
	char *p = cp;

	memset(&params, 0, sizeof(struct sctp_paddrparams));
	params.spp_assoc_id = associd;
	params.spp_flags = SPP_HB_DEMAND;

	if (set) {
		/* Set the buffer for address parsing.  */
		while ('\n' != *p)
			p++;
		*p = '\0';

		if (strchr(cp, '.')) {
			in_addr = (struct sockaddr_in *)&params.spp_address;
			in_addr->sin_port = htons(remote_port);
			in_addr->sin_family = AF_INET;
			ret = inet_pton(AF_INET, cp, &in_addr->sin_addr);
			if (ret <= 0)
				goto err;
		} else if (strchr(cp, ':')) {
			in6_addr = (struct sockaddr_in6 *)&params.spp_address;
			in6_addr->sin6_port = htons(remote_port);
			in6_addr->sin6_family = AF_INET6;
			ret = inet_pton(AF_INET6, cp, &in6_addr->sin6_addr);
			if (ret <= 0)
				goto err;
		} else
			goto err;
	}

	ret = setsockopt(sk, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
			    &params, sizeof(struct sctp_paddrparams));
	if (ret < 0)
		goto err;

	return;
err:
	if (!errno)
		errno = EINVAL;
	fprintf(stderr, "%s: error %s peer_addr_params: %s.\n", argv0,
	        (set)?"setting":"getting", strerror(errno));
}

static int
nodelay_func(char *argv0, int sk, int val, int set)
{
	socklen_t optlen;
	int error;

	if (set) {
		error = setsockopt(sk, SOL_SCTP, SCTP_NODELAY,
			(char *)&val, sizeof(val));
	} else {
		optlen = sizeof(val);
		error = getsockopt(sk, SOL_SCTP, SCTP_NODELAY,
			(char *)&val, &optlen);
	}
	if (error != 0) {
		fprintf(stderr, "%s: Error setting/getting nodelay: %s.\n",
			argv0, strerror(errno));
		exit(1);
	}

	if (!set) {
		printf("nodelay is %d.\n", val);
	}

	return error;
}

static int
maxseg_func(char *argv0, int sk, int val, int set)
{
	socklen_t optlen;
	int error;

	if (set) {
		error = setsockopt(sk, SOL_SCTP, SCTP_MAXSEG,
			(char *)&val, sizeof(val));
	} else {
		optlen = sizeof(val);
		error = getsockopt(sk, SOL_SCTP, SCTP_MAXSEG,
			(char *)&val, &optlen);
	}
	if (error != 0) {
		fprintf(stderr, "%s: Error setting/getting maxseg: %s.\n",
			argv0, strerror(errno));
		exit(1);
	}

	if (!set) {
		printf("maxseg is %d.\n", val);
	}

	return error;
}

static int
shutdown_func(char *argv0, int *skp, int shutdown_type)
{
	struct msghdr outmessage;
	char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct cmsghdr *cmsg;
        int error=0, bytes_sent;
	struct sctp_sndrcvinfo *sinfo;
	struct hostent *hst;
	char *sd_type;
	int sk = *skp;

	if (shutdown_type == SHUTDOWN_ABORT)
		sd_type = "ABORT";
	else
		sd_type = "SHUTDOWN";

	/* Verify that the association is present. */
	error = test_sk_for_assoc(sk, associd);
	if (error != 0) {
		printf("The association isn't present yet! Cannot %s!\n", sd_type);
		return -1;
	}

	if (socket_type == SOCK_SEQPACKET) {
		/* Set up the destination.  */
		if (remote_host) {
			hst = gethostbyname(remote_host);
			if (hst == NULL) {
				hst = gethostbyname2(remote_host, AF_INET6);
			}

			if (hst == NULL || hst->h_length < 1) {
				fprintf(stderr, "%s: bad hostname: %s\n",
					argv0, remote_host);
				exit(1);
			}

			ra_family = hst->h_addrtype;
			switch (ra_family) {
			case AF_INET:
				ra_len = sizeof(remote_addr.v4);
				ra_raw = &remote_addr.v4.sin_addr;
				remote_addr.v4.sin_port = htons(remote_port);
				remote_addr.v4.sin_family = AF_INET;
				break;
			case AF_INET6:
				ra_len = sizeof(remote_addr.v6);
				ra_raw = &remote_addr.v6.sin6_addr;
				remote_addr.v6.sin6_port = htons(remote_port);
				remote_addr.v6.sin6_family = AF_INET6;
				break;
			default:
				fprintf(stderr, "Invalid address type.\n");
				exit(1);
				break;
			}
			memcpy(ra_raw, hst->h_addr_list[0], hst->h_length);
		}

		/* Initialize the message struct we use to pass messages to
		 * the remote socket.
		 */
		outmessage.msg_name = &remote_addr;
		outmessage.msg_namelen = ra_len;

		outmessage.msg_iov = NULL;
		outmessage.msg_iovlen = 0;
		outmessage.msg_control = outcmsg;
		outmessage.msg_controllen = sizeof(outcmsg);
		outmessage.msg_flags = 0;

		cmsg = CMSG_FIRSTHDR(&outmessage);
		cmsg->cmsg_level = IPPROTO_SCTP;
		cmsg->cmsg_type = SCTP_SNDRCV;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
		outmessage.msg_controllen = cmsg->cmsg_len;
		sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
		memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));
		if (shutdown_type == SHUTDOWN_ABORT)
			sinfo->sinfo_flags |= SCTP_ABORT;
		else
			sinfo->sinfo_flags |= SCTP_EOF;

		sinfo->sinfo_assoc_id = associd;
	
		bytes_sent = sendmsg(sk, &outmessage, 0);
		if (bytes_sent != 0) {
			printf("Failure:  %s.\n", strerror(errno));
			return -1;
		}

		/* Receive the COMM_LOST or SHUTDOWN_COMP event. */
		test_recv_assoc_change(sk);
	} else {
		if (shutdown_type == SHUTDOWN_ABORT) {
			struct  linger {
				int  l_onoff; 
				int  l_linger;
			} data = {1, 0};
			error = setsockopt(sk, SOL_SOCKET, SO_LINGER,
					   (char *)&data, sizeof(data));
			if (error != 0) {
				printf("setsockopt failed %s\n", strerror(errno));
				exit(1);
			}
		}
		error = close(sk);
		if (error != 0) {
			printf("close failed %s\n", strerror(errno));
			exit(1);
		}
		*skp = sk = build_endpoint(argv0, local_port);
	}

	/* Verify that the association is no longer present.  */
	error = test_sk_for_assoc(sk, associd);
	if (error != 0) {
		printf("Successfully %s the original association\n", sd_type);
		associd = 0;
		new_connection = 1;
	} else {
		printf("%s failed\n", sd_type);
		exit(1);
	}

	return 0;
}

static int
get_assocstats_func(int sk, sctp_assoc_t assoc_id)
{
	int error = 0;
	struct sctp_assoc_stats stats;
	socklen_t len;

	if (assoc_id == 0) {
		printf("No association present yet\n");
		return -1;
	}

	memset(&stats, 0, sizeof(struct sctp_assoc_stats));
	stats.sas_assoc_id = assoc_id;
	len = sizeof(struct sctp_assoc_stats);
	error = getsockopt(sk, SOL_SCTP, SCTP_GET_ASSOC_STATS,
			(char *)&stats, &len);
	if (error != 0) {
		printf("get_assoc_stats() failed %s\n", strerror(errno));
		return error;
	}

	printf("Retransmitted Chunks: %" PRIu64 "\n", (uint64_t) stats.sas_rtxchunks);
	printf("Gap Acknowledgements Received: %" PRIu64 "\n", (uint64_t) stats.sas_gapcnt);
	printf("TSN received > next expected: %" PRIu64 "\n", (uint64_t) stats.sas_outofseqtsns);
	printf("SACKs sent: %" PRIu64 "\n", (uint64_t) stats.sas_osacks);
	printf("SACKs received: %" PRIu64 "\n", (uint64_t) stats.sas_isacks);
	printf("Control chunks sent: %" PRIu64 "\n", (uint64_t) stats.sas_octrlchunks);
	printf("Control chunks received: %" PRIu64 "\n", (uint64_t) stats.sas_ictrlchunks);
	printf("Ordered data chunks sent: %" PRIu64 "\n", (uint64_t) stats.sas_oodchunks);
	printf("Ordered data chunks received: %" PRIu64 "\n", (uint64_t) stats.sas_iodchunks);
	printf("Unordered data chunks sent: %" PRIu64 "\n", (uint64_t) stats.sas_ouodchunks);
	printf("Unordered data chunks received: %" PRIu64 "\n", (uint64_t) stats.sas_iuodchunks);
	printf("Dups received (ordered+unordered): %" PRIu64 "\n", (uint64_t) stats.sas_idupchunks);
	printf("Packets sent: %" PRIu64 "\n", (uint64_t) stats.sas_opackets);
	printf("Packets received: %" PRIu64 "\n", (uint64_t) stats.sas_ipackets);
	printf("Maximum Observed RTO this period: %" PRIu64 " - Transport: ", (uint64_t) stats.sas_maxrto);
	print_sockaddr((struct sockaddr *)&stats.sas_obs_rto_ipaddr);
	printf("\n");

	return 0;
}

static int
test_sk_for_assoc(int sk, sctp_assoc_t assoc_id)
{
	int error = 0;
	struct sctp_status status;
	socklen_t status_len;

	memset(&status, 0, sizeof(status));
	if (assoc_id)
		status.sstat_assoc_id = assoc_id;
	status_len = sizeof(struct sctp_status);
	error = getsockopt(sk, SOL_SCTP, SCTP_STATUS,
               		(char *)&status, &status_len);
	return error;
}

/* Receive a notification and return the corresponding associd if the event is
 * SCTP_COMM_UP. Return 0 for any other event.
 */
static sctp_assoc_t
test_recv_assoc_change(int sk)
{
	struct msghdr inmessage;
	struct iovec iov;
	char incmsg[CMSG_SPACE(sizeof(_sctp_cmsg_data_t))];
	int error;

	/* Initialize inmessage with enough space for DATA... */
	memset(&inmessage, 0, sizeof(inmessage));
	if ((iov.iov_base = malloc(REALLY_BIG)) == NULL) {
		printf("%s: Can't allocate memory.\n", __FUNCTION__);
		exit(1);
	}
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	/* or a control message.  */
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);

	error = recvmsg(sk, &inmessage, MSG_WAITALL);
	if (error < 0) {
		printf("%s: recvmsg: %s\n", __FUNCTION__, strerror(errno));
		exit(1);
	}

	return test_verify_assoc_change(&inmessage);
}

/* Verify a notification and return the corresponding associd if the event is
 * SCTP_COMM_UP. Return 0 for any other event.
 */
static sctp_assoc_t
test_verify_assoc_change(struct msghdr *msg)
{
	union sctp_notification *sn;

	if (!(msg->msg_flags & MSG_NOTIFICATION)) {
		fprintf(stderr, "%s: Received data when notification is expected\n",
		       __FUNCTION__);
		exit(1);
	}

	sn = (union sctp_notification *)msg->msg_iov->iov_base;
	if (SCTP_ASSOC_CHANGE != sn->sn_header.sn_type) {
		fprintf(stderr, "%s: Received unexpected notification: %d",
			__FUNCTION__, sn->sn_header.sn_type);
		exit(1);
	}

	switch(sn->sn_assoc_change.sac_state)
	{
	case SCTP_COMM_UP:
		printf("Received SCTP_COMM_UP\n");
		break;
	case SCTP_COMM_LOST:
		printf("Received SCTP_COMM_LOST\n");
		break;
	case SCTP_RESTART:
		printf("Received SCTP_RESTART\n");
		break;
	case SCTP_SHUTDOWN_COMP:
		printf("Received SCTP_SHUTDOWN_COMP\n");
		break;
	case SCTP_CANT_STR_ASSOC:
		printf("Received SCTP_CANT_STR_ASSOC\n");
		break;
	}

	if (SCTP_COMM_UP == sn->sn_assoc_change.sac_state)
		return sn->sn_assoc_change.sac_assoc_id;
	else
		return 0;
}

void print_addr_buf(void * laddrs, int n_laddrs)
{
	void *addr_buf = laddrs;
	int i;

	for (i = 0; i < n_laddrs; i++) {
		addr_buf += print_sockaddr((struct sockaddr *)addr_buf);
		printf("\n");
	}
}

int print_sockaddr(struct sockaddr *sa_addr)
{
	struct sockaddr_in *in_addr;
	struct sockaddr_in6 *in6_addr;

	if (AF_INET == sa_addr->sa_family) {
		in_addr = (struct sockaddr_in *)sa_addr;
		printf("%d.%d.%d.%d:%d",
		       NIPQUAD(in_addr->sin_addr),
		       ntohs(in_addr->sin_port));
		return sizeof(struct sockaddr_in);
	} else {
		in6_addr = (struct sockaddr_in6 *)sa_addr;
		printf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%d",
		       NIP6(in6_addr->sin6_addr),
		       ntohs(in6_addr->sin6_port));
		return sizeof(struct sockaddr_in6);
	}
}
