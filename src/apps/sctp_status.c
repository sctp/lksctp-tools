/* SCTP kernel reference Implementation
 * (C) Copyright Fujitsu Ltd. 2008, 2009
 *
 * The SCTP reference implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * The SCTP reference implementation is distributed in the hope that it
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
 *    Wei Yongjun <yjwei@cn.fujitsu.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/sctp.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>

#define DEFAULT_SEC	0
#define DEFAULT_USEC	5000

#define REALLY_BIG 65536

#define SERVER 		0
#define CLIENT 		1
#define NOT_DEFINED	666

#define DEBUG_NONE	0
#define DEBUG_MIN	1
#define DEBUG_MAX	2

#define ORDER_PATTERN_UNORDERED   0
#define ORDER_PATTERN_ORDERED     1
#define ORDER_PATTERN_ALTERNATE   2
#define ORDER_PATTERN_RANDOM      3

#define STREAM_PATTERN_SEQUENTIAL 0
#define STREAM_PATTERN_RANDOM     1

#define MAX_BIND_RETRYS 10
#define BIG_REPEAT	1000000
#define REPEAT 		10

#define DEFAULT_MAX_WINDOW 32768
#define DEFAULT_MIN_WINDOW 1500

#define MSG_CNT		10

#define DEBUG_PRINT(level, print_this...)	\
{						\
	if (debug_level >= level) { 		\
		fprintf(stdout, print_this); 	\
		fflush(stdout); 		\
	}					\
} /* DEBUG_PRINT */

char *local_host = NULL;
int local_port = 0;
char *remote_host = NULL;
int remote_port = 0;
struct sockaddr_storage s_rem, s_loc;
int r_len, l_len;
int size_arg = 0;
int debug_level = DEBUG_NONE;
int order_pattern = ORDER_PATTERN_UNORDERED;
int order_state = 0;
int stream_pattern = STREAM_PATTERN_SEQUENTIAL;
int stream_state = 0;
int repeat = REPEAT;
int repeat_count = 0;
int max_msgsize = DEFAULT_MAX_WINDOW;
int msg_cnt = MSG_CNT;
int drain = 0;
int max_stream = 0;
int gsk = -1;
int period = 1;
char *statusfile = NULL;

void printstatus(int sk);
void sighandler(int signo);
void settimerhandle(void);
void usage(char *argv0);
void start_test(int role);

unsigned char msg[] = "012345678901234567890123456789012345678901234567890";

/* Convenience structure to determine space needed for cmsg. */
typedef union {
	struct sctp_initmsg init;
	struct sctp_sndrcvinfo sndrcvinfo;
} _sctp_cmsg_data_t;

int main(int argc, char *argv[]) {
	int c, role = NOT_DEFINED;
	char *interface = NULL;
	struct sockaddr_in *t_addr;
	struct sockaddr_in6 *t_addr6;

	/* Parse the arguments.  */
	while ((c = getopt(argc, argv, ":H:L:P:h:p:c:d:lm:sx:X:o:M:Di:I:f:")) >= 0 ) {
		switch (c) {
		case 'H':
			local_host = optarg;
			break;
		case 'P':
			local_port = atoi(optarg);
			break;
		case 'h':
			remote_host = optarg;
			break;
		case 'p':
			remote_port = atoi(optarg);
			break;
		case 'l':
			if (role != NOT_DEFINED) {
				printf("%s: only -s or -l\n", argv[0]);
				usage(argv[0]);
				exit(1);
			}
			role = SERVER;
			break;
		case 's':
			if (role != NOT_DEFINED) {
				printf("%s: only -s or -l\n", argv[0]);
				usage(argv[0]);
				exit(1);
			}
			role = CLIENT;
			break;
		case 'D':
			drain = 1;
			break;
		case 'd':
			debug_level = atoi(optarg);
			if (debug_level < DEBUG_NONE
			    || debug_level > DEBUG_MAX) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'I':
			period = atoi(optarg);
			if (period < 0) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'x':
			repeat = atoi(optarg);
			if (!repeat) {
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
			size_arg = atoi(optarg);
			if (size_arg < 0) {
				usage(argv[0]);
				exit(1);
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
		case 'M':
			max_stream = atoi(optarg);
			if (max_stream <  0
			    || max_stream >= (1<<16)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'm':
			max_msgsize = atoi(optarg);
			break;
		case 'i':
			interface = optarg;
			break;
		case 'f':
			statusfile = optarg;
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
		fprintf(stderr, "%s: Server needs local address, "
			 "not remote address\n", argv[0]);
		usage(argv[0]);
		exit(1);
	}
	if (CLIENT == role && NULL == remote_host) {
		fprintf(stderr, "%s: Client needs at least remote address "
			 "& port\n", argv[0]);
		usage(argv[0]);
		exit(1);
	}

	if (optind < argc) {
		fprintf(stderr, "%s: non-option arguments are illegal: ", argv[0]);
		while (optind < argc)
			fprintf(stderr, "%s ", argv[optind++]);
		fprintf (stderr, "\n");
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
					t_addr6->sin6_scope_id = if_nametoindex(interface);

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
					t_addr6->sin6_scope_id = if_nametoindex(interface);

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

	/* Let the testing begin. */
	start_test(role);

	return 0;
}

int bind_r(int sk, struct sockaddr_storage *saddr) {
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
				fprintf(stderr, "\n\n\t\t***bind: can "
					"not bind to %s:%s: %s ****\n",
					host_s, serv_s, strerror(errno));
				exit(1);
			}
		}
		i++;
		if (i >= MAX_BIND_RETRYS) {
			fprintf(stderr, "Maximum bind() attempts. "
				"Die now...\n\n");
			exit(1);
		}
	} while (error < 0 && i < MAX_BIND_RETRYS);

	return 0;
} /* bind_r() */

int listen_r(int sk, int listen_count) {
	int error = 0;

	DEBUG_PRINT(DEBUG_MIN, "\tlisten(sk=%d,backlog=%d)\n",
		sk, listen_count);

	/* Mark sk as being able to accept new associations */
	error = listen(sk, 1);
	if (error != 0) {
		fprintf(stderr, "\n\n\t\t*** listen:  %s ***\n\n\n", strerror(errno));
		exit(1);
	}

	return 0;
} /* listen_r() */

int accept_r(int sk){
	socklen_t len = 0;

	DEBUG_PRINT(DEBUG_MIN, "\taccept(sk=%d)\n", sk);

	gsk = accept(sk, NULL, &len);
	if (gsk < 0) {
		fprintf(stderr, "\n\n\t\t*** accept:  %s ***\n\n\n", strerror(errno));
		exit(1);
	}

	return 0;
} /* accept_r() */

int connect_r(int sk, const struct sockaddr *serv_addr, socklen_t addrlen) {
	int error = 0;

	DEBUG_PRINT(DEBUG_MIN, "\tconnect(sk=%d)\n", sk);

	/* Mark sk as being able to accept new associations */
	error = connect(sk, serv_addr, addrlen);
	if (error != 0) {
		fprintf(stderr, "\n\n\t\t*** connect:  %s ***\n\n\n",
			strerror(errno));
		exit(1);
	}

	gsk = sk;

	return 0;
} /* connect_r() */

int close_r(int sk) {
	int error = 0;

	DEBUG_PRINT(DEBUG_MIN, "\tclose(sk=%d)\n",sk);

	error = close(sk);
	if (error != 0) {
		fprintf(stderr, "\n\n\t\t*** close: %s ***\n\n",
			strerror(errno));
		exit(1);
	}
	fflush(stdout);
	return 0;
} /* close_r() */

int receive_r(int sk)
{
	int error = 0;
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
		DEBUG_PRINT(DEBUG_MIN, "\trecvmsg(sk=%d) ", sk);

		error = recvmsg(sk, &inmessage, MSG_WAITALL);
		if (error < 0 && errno != EAGAIN) {
			fprintf(stderr, "\n\t\t*** recvmsg: %s ***\n\n",
					strerror(errno));
			fflush(stdout);
			close(sk);
			free(iov.iov_base);
			exit(1);
		} else if (error == 0) {
			printf("\n\t\trecvmsg() returned 0 !!!!\n");
			fflush(stdout);
		}

		if(MSG_NOTIFICATION & inmessage.msg_flags)
			continue; /* got a notification... */

		inmessage.msg_control = incmsg;
		inmessage.msg_controllen = sizeof(incmsg);
		iov.iov_len = REALLY_BIG;
		break;
	}

	free(iov.iov_base);
	return 0;
} /* receive_r () */

void server(int sk) {
	int i;

	if (max_msgsize > DEFAULT_MAX_WINDOW) {
		if (setsockopt(sk, IPPROTO_SCTP, SO_RCVBUF, &max_msgsize,
			       sizeof(max_msgsize)) < 0) {
			perror("setsockopt(SO_RCVBUF)");
			exit(1);
		}
	}

	for (i = 0; i < msg_cnt; i++) {
		receive_r(sk);
		DEBUG_PRINT(DEBUG_MIN, "count %d\n", i+1);
	}
} /* server() */

void * build_msg(int len) {
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

int send_r(int sk, int stream, int order, int send_size, int assoc_i) {
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
	} else {
			exit(1);
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

	DEBUG_PRINT(DEBUG_MIN, "\tsendmsg(sk=%d, assoc=%d) %4d bytes.\n",
		    sk, assoc_i, send_size);
	DEBUG_PRINT(DEBUG_MAX, "\t  SNDRCV");
	if (DEBUG_MAX == debug_level) {
		printf("(stream=%u ", 	sinfo->sinfo_stream);
		printf("flags=0x%x ",	sinfo->sinfo_flags);
		printf("ppid=%u)\n",	sinfo->sinfo_ppid);
	}

	/* Send to our neighbor.  */
	error = sendmsg(sk, &outmsg, MSG_WAITALL);
	if (error != msglen) {
		fprintf(stderr, "\n\t\t*** sendmsg: %s ***\n\n",
			strerror(errno));
		fflush(stdout);
		exit(1);
	}

	if (send_size > 0) free(message);
	return 0;
} /* send_r() */

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
		state = rand() % max_stream;
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
	} else {
		msg_size = (rand() % max_msgsize) + 1;
	}

	return msg_size;

} /* next_msg_size() */

void client(int sk) {
	int msg_size;
	int i;

	for (i = 0; i < msg_cnt; i++) {
		msg_size = next_msg_size(i);
		order_state = next_order(order_state, order_pattern);
		stream_state = next_stream(stream_state, stream_pattern);

		if (send_r(sk, stream_state, order_state, msg_size, 0) < 0) {
			close(sk);
			break;
		}

		/* The sender is echoing so do discard the echoed data. */
		if (drain && ((i + 1) % period == 0)) {
			receive_r(sk);
		}
	}
} /* client() */

void start_test(int role) {
	int sk, pid, ret;
	int i = 0;

	DEBUG_PRINT(DEBUG_NONE, "\nStarting tests...\n");

	repeat_count = repeat;

	DEBUG_PRINT(DEBUG_MIN, "\tsocket(SOCK_STREAM, IPPROTO_SCTP)");

	if ((sk = socket(s_loc.ss_family, SOCK_STREAM, IPPROTO_SCTP)) < 0 ) {
		fprintf(stderr, "\n\n\t\t*** socket: failed to create"
			" socket:  %s ***\n", strerror(errno));
		exit(1);
	}
	DEBUG_PRINT(DEBUG_MIN, "  ->  sk=%d\n", sk);

	bind_r(sk, &s_loc);

	if (role == SERVER) {
		listen_r(sk, 1);
		accept_r(sk);
	} else {
		if (max_stream > 0) {
			struct sctp_initmsg initmsg;

			memset(&initmsg, 0, sizeof(initmsg));
			initmsg.sinit_num_ostreams = max_stream;
			initmsg.sinit_max_instreams = max_stream;
			initmsg.sinit_max_attempts = 3;

			ret = setsockopt(sk, IPPROTO_SCTP, SCTP_INITMSG,
					 &initmsg, sizeof(initmsg));
			if (ret < 0) {
				perror("setsockopt(SCTP_INITMSG)");
				exit(0);
			}
		}

		connect_r(sk, (struct sockaddr *)&s_rem, r_len);
	}

	if ((pid = fork()) == 0) {
		settimerhandle();
		printstatus(gsk);
		while(1);
	} else {
		if (!debug_level) {
			printf("     ");
		}

		for(i = 0; i < repeat_count; i++) {

			if (role == SERVER) {
				DEBUG_PRINT(DEBUG_NONE, "Server: Receiving packets.(%d/%d)\n",
					i+1, repeat_count);
				server(gsk);
			} else {
				DEBUG_PRINT(DEBUG_NONE, "Client: Sending packets.(%d/%d)\n",
					i+1, repeat_count);
				client(sk);
			}

			fflush(stdout);
		}

		if (role == SERVER) close_r(gsk);
		close_r(sk);
	}
} /* start_test() */

void settimerhandle(void) {
	struct sigaction act;
	struct itimerval interval;

	act.sa_handler = sighandler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGPROF, &act, NULL);

	interval.it_value.tv_sec = DEFAULT_SEC;
	interval.it_value.tv_usec = DEFAULT_USEC;
	interval.it_interval = interval.it_value;

	setitimer(ITIMER_PROF, &interval, NULL);
}

void usage(char *argv0) {
	fprintf(stderr, "\nusage:\n");
	fprintf(stderr, "  server:\n");
	fprintf(stderr, "  %8s -H local-addr -P local-port -l [-d level] [-x]\n"
			"\t      [-L num-ports] [-S num-ports]\n"
			"\t      [-a assoc-pattern]\n"
			"\t      [-i interface]\n"
			"\t      [-f status-file]\n",
		argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "  client:\n");
	fprintf(stderr, "  %8s -H local-addr -P local-port -h remote-addr\n"
		"\t      -p remote-port -s [-c case ] [-d level]\n"
		"\t      [-x repeat] [-o order-pattern] ream-pattern]\n"
		"\t      [-M max-stream]\n"
		"\t      [-m max-msgsize]\n"
		"\t      [-L num-ports] [-S num-ports]\n"
		"\t      [-i interface]\n"
		"\t      [-f status-file]\n",
		argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "\t-c value = Packets of specifed size.\n");
	fprintf(stderr, "\t-m msgsize(1500-65515, default value 32768)\n");
	fprintf(stderr, "\t-x number of repeats\n");
	fprintf(stderr, "\t-X number of messages\n");
	fprintf(stderr, "\t-o order-pattern\n");
	fprintf(stderr, "\t   0 = all unordered(default) \n");
	fprintf(stderr, "\t   1 = all ordered \n");
	fprintf(stderr, "\t   2 = alternating \n");
	fprintf(stderr, "\t   3 = random\n");
	fprintf(stderr, "\t-M max-stream (default value 0)\n");
	fprintf(stderr, "\t-D drain. If in client mode do a read following send.\n");
	fprintf(stderr, "\t-I receive after <n> times of send, default value 1.\n");
	fprintf(stderr, "\n");
	fflush(stderr);

} /* usage() */

void sighandler(int signo) {
	DEBUG_PRINT(DEBUG_MAX, "timeout sig\n");
	printstatus(gsk);
}

char* get_sstat_state(int state) {
	switch(state) {
	case SCTP_EMPTY:
		return "EMPTY";
	case SCTP_CLOSED:
		return "CLOSED";
	case SCTP_COOKIE_WAIT:
		return "COOKIE_WAIT";
	case SCTP_COOKIE_ECHOED:
		return "COOKIE_ECHOED";
	case SCTP_ESTABLISHED:
		return "ESTABLISHED";
	case SCTP_SHUTDOWN_PENDING:
		return "SHUTDOWN_PENDING";
	case SCTP_SHUTDOWN_SENT:
		return "SHUTDOWN_SENT";
	case SCTP_SHUTDOWN_RECEIVED:
		return "SHUTDOWN_RECEIVED";
	case SCTP_SHUTDOWN_ACK_SENT:
		return "SHUTDOWN_ACK_SENT";
	default:
		return "UNKNOW";
	}
}

void printstatus(int sk) {
	static int cwnd = 0;
	static int count = 0;
	struct sctp_status status;
	socklen_t optlen;
	FILE * fp;
	const char *state_to_str[] = {
		[SCTP_INACTIVE]		=	"INACTIVE",
		[SCTP_PF]		=	"PF",
		[SCTP_ACTIVE]		=	"ACTIVE",
		[SCTP_UNCONFIRMED]	=	"UNCONFIRMED",
	};

	optlen = sizeof(struct sctp_status);
	if(getsockopt(sk, IPPROTO_SCTP, SCTP_STATUS, &status, &optlen) < 0) {
		fprintf(stderr, "Error getting status: %s.\n", strerror(errno));
		exit(1);
	}

	if (statusfile != NULL) {
		if (count == 0)
			unlink(statusfile);

		if((fp = fopen(statusfile, "a+")) == NULL) {
			perror("fopen");
			exit(1);
		}
	} else
		fp = stdout;

	if (count == 0)
		fprintf(fp, "NO. ASSOC-ID STATE             RWND     UNACKDATA PENDDATA INSTRMS OUTSTRMS "
				"FRAG-POINT SPINFO-STATE SPINFO-CWDN SPINFO-SRTT SPINFO-RTO SPINFO-MTU\n");

	if (cwnd != status.sstat_primary.spinfo_cwnd) {
		count++;

		fprintf(fp, "%-3d %-8d %-17s %-8d %-9d %-8d %-7d %-8d %-10d %-12s %-11d %-11d %-10d %d\n", count,
				status.sstat_assoc_id, get_sstat_state(status.sstat_state),
				status.sstat_rwnd, status.sstat_unackdata, status.sstat_penddata,
				status.sstat_instrms, status.sstat_outstrms, status.sstat_fragmentation_point,
				state_to_str[status.sstat_primary.spinfo_state],
				status.sstat_primary.spinfo_cwnd, status.sstat_primary.spinfo_srtt,
				status.sstat_primary.spinfo_rto, status.sstat_primary.spinfo_mtu);
	}

	cwnd = status.sstat_primary.spinfo_cwnd;

	fflush(fp);

	if (fp != stdout)
		fclose(fp);

	if (status.sstat_primary.spinfo_state != SCTP_ACTIVE) {
		close_r(sk);
		exit(1);
	}
}
