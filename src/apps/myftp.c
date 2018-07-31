/* myftp - simple file transfer over sctp testing tool. 
 * Copyright (c) 2002 Intel Corp.
 * 
 * This file is part of the LKSCTP kernel Implementation.  This
 * is a submission by Xingang Guo from the Intel Corporation while 
 * participating on the LKSCTP project.  
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
 *    lksctp developers <sctp-developers-list@cig.mot.com>
 * 
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by: 
 *    Xingang Guo           <xingang.guo@intel.com>
 *    Jon Grimm             <jgrimm@us.ibm.com> 
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h> /* for sockaddr_in */
#include <errno.h>
#include <netinet/sctp.h>

#define BUFSIZE 1024
static char buffer[BUFSIZE];
#define DUMP_CORE {  char *diediedie = 0; *diediedie = 0; }

typedef enum { COMMAND_NONE, COMMAND_RECV, COMMAND_SEND } command_t;

/* These are the global options.  */
#define MAX_NUM_HOST	5
static char *local_host[MAX_NUM_HOST];
static int num_local_host = 0;
static int local_port = 4444;

static int buffer_size = BUFSIZE;
static char *remote_host = NULL;
static int remote_port = 4444;
static command_t command = COMMAND_NONE;
static char *filename = NULL;
static int interactive = 0;
static unsigned long delay = 0;	     
static int verbose = 0;

static void
usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [options]\n",argv0);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t--local, -H <hostname>     Specify local interface\n");
	fprintf(stderr, "\t--local-port, -P <port>    Specify local port (default 4444)\n");
	fprintf(stderr, "\t--remote, -h <hostname>    Specify interface on remote host\n");
	fprintf(stderr, "\t--remote-port, -p <port>   Specify remote port (default 4444)\n");
	fprintf(stderr, "\t--listen, -l               Work in receiving mode\n");
	fprintf(stderr, "\t--send, -s                 Work in sending mode\n");
	fprintf(stderr, "\t--file, -f <filename>      File to read or write,\n");
	fprintf(stderr, "\t--buffer, -b <size>        Buffer size. (default 1024 bytes)\n");
	fprintf(stderr, "\t                           by default use standard input/output.\n");
	fprintf(stderr, "\t--quick, -q                Send packets continueously,\n");
	fprintf(stderr, "\t                           do not wait for <ENTER> key. Default wait.\n");
	fprintf(stderr, "\t--delay, -d <usec>         Delay between consecutive sends (see --quick)\n");
	fprintf(stderr, "\t--verbose, -v              In verbose mode, display the progress.\n");
	fprintf(stderr, "\n\t--help,                    Print this message.\n\n");
} /* usage() */

static int parse_arguments(int argc, char *argv[])
{
	int option_index = 0;
	int c;
	static struct option long_options[] = {
		{"local",	1, 0, 1},
		{"local-port",	1, 0, 2},
		{"remote",	1, 0, 3},
		{"remote-port",	1, 0, 4},
		{"file",	1, 0, 5},
		{"delay",	1, 0, 6},
		{"buffer",	1, 0, 7},
		{"listen",	0, 0, 10},
		{"send",	0, 0, 11},
		{"quick",	0, 0, 12},
		{"verbose",	0, 0, 13},
		{"help",	0, 0, 99},
		{0,		0, 0, 0}
	};

	/* Parse the arguments.  */
	while (1) {
		c = getopt_long(argc, argv, "H:P:h:p:f:d:b:qlsv",long_options,&option_index);
		if (c == -1) break;

		switch (c) {
		case 0:
			printf ("option %s", long_options[option_index].name);
			if (optarg) printf (" with arg %s", optarg);
			printf ("\n");
			break;
		case 1:		/* local host */
		case 'H':
			local_host[num_local_host++] = optarg;
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
		case 5:
		case 'f':
			filename = optarg;
			break;

		case 6:
		case 'd':
			delay = strtoul(optarg,NULL,10);
			printf("delay is %ld usec\n",delay);
			break;

		case 7:
		case 'b':
			buffer_size = atoi(optarg);
			if ( buffer_size > BUFSIZE ) {
				buffer_size = BUFSIZE;
				fprintf(stderr,"Warning, buffer size too large, set to %d\n",buffer_size);
			}
			break;

		case 12:
		case 'q':	interactive = 0; break;

		case 13:
		case 'v':	verbose = 1; break;
			/* COMMANDS */
		case 10:	/* listen */
		case 'l':
			if (command) {
				fprintf(stderr, "%s: pick ONE of listen or send\n", argv[0]);
				return 1;
			}
			else command = COMMAND_RECV;
			break;

		case 11:	/* send */
		case 's':
			if (command) {
				fprintf(stderr, "%s: pick ONE of listen or send\n", argv[0]);
				return 2;
			} else command = COMMAND_SEND;
			break;

		case '?':
		case 99:
			usage(argv[0]);
			return 3;
			break;

		default:
			printf ("%s: unrecognized option 0%c\n", argv[0], c);
			usage(argv[0]);
			return 4;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "%s: non-option arguments are illegal: ", argv[0]);
		while (optind < argc) fprintf(stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
		usage(argv[0]);
		return 5;
	}


	if (0 == num_local_host) {
		fprintf(stderr, "%s: You MUST provide a local host.\n", argv[0]);
		usage(argv[0]);
		return 6;
	}

	if ( filename == NULL && command == COMMAND_SEND)
		fprintf(stderr,"%s: Use standard input to send\n",argv[0]);

	if ( filename == NULL && command == COMMAND_RECV )
		fprintf(stderr,"%s: Use standard output to write\n",argv[0]);

	return 0;
} /* parse_arguments() */

static void
emsg(char *prog,char *s)
{
	if ( prog != NULL ) fprintf(stderr,"%s: ",prog);
	perror(s);
	fflush(stdout);
	//DUMP_CORE;

	exit(-1);
}

static int build_endpoint(char *argv0)
{
	int retval,i;

	/* Create the local endpoint.  */
	if ( (retval = socket(PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0 ) {
		emsg(argv0,"socket");
		exit(retval);
	}

	for ( i = 0;i < num_local_host;i++ ) {
		struct hostent *hst;
		struct sockaddr_in laddr;

		memset(&laddr, 0, sizeof(laddr));
		/* Get the transport address for the local host name.  */
		fprintf(stderr,"Hostname %d is %s\n",i+1,local_host[i]);
		if ( (hst = gethostbyname(local_host[i])) == NULL ) {
			fprintf(stderr, "%s: bad hostname: %s\n", argv0, local_host[i]);
			exit(1);
		}
		memcpy(&laddr.sin_addr, hst->h_addr_list[0],sizeof(laddr.sin_addr));
		laddr.sin_port = htons(local_port);
		laddr.sin_family = AF_INET;

		/* Bind this socket to the test port.  */
		if ( bind(retval, (struct sockaddr *)&laddr, sizeof(laddr)) ) {
			emsg(argv0,"bind");
			exit(-1);
		}
	}

	fprintf(stderr,"Endpoint built.\n");

	return retval;
} /* build_endpoint() */

/* Convenience structure to determine space needed for cmsg. */
typedef union {
	struct sctp_initmsg init;
	struct sctp_sndrcvinfo sndrcvinfo;
} _sctp_cmsg_data_t;


/* Listen on the socket, printing out anything that arrives.  */
static void
command_recv(char *argv0, int sk)
{
	struct msghdr inmessage;
	char incmsg[CMSG_SPACE(sizeof(_sctp_cmsg_data_t))];
	struct iovec iov;
	int ret;
	int fd;
	int ct;

	if (listen(sk, 1) == -1)
		emsg(argv0, "listen");
	/* Initialize inmessage with enough space for DATA... */
	memset(&inmessage, 0, sizeof(inmessage));
	iov.iov_base = buffer;
	iov.iov_len = buffer_size;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	/* or a control message.  */
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);

	/* creat a file */
	if ( filename == NULL ) fd = 1;
	else if ( (fd = open(filename,O_WRONLY|O_CREAT|O_TRUNC,S_IREAD|S_IWRITE)) == -1 )
		emsg(argv0,"open");

	fprintf(stderr,"%s Receiving...\n", argv0);
	/* Get the messages sent */
	ct = 0;
	while ( (ret = recvmsg(sk, &inmessage, MSG_WAITALL)) >= 0 ) {
		if ( verbose )
			fprintf(stderr,"%s-%d received %d bytes\n",
				argv0, ++ct, ret);
		if ( !(inmessage.msg_flags & MSG_NOTIFICATION) ) {
			//printf("%s write %d bytes\n",argv0,ret);
			if ( write(fd,buffer,ret) != ret ) emsg(argv0,"write");
		} else {
			union sctp_notification *sn;
			sn = (union sctp_notification *)iov.iov_base;
			if ((sn->sn_header.sn_type == SCTP_ASSOC_CHANGE) &&
			    (sn->sn_assoc_change.sac_state 
			     == SCTP_SHUTDOWN_COMP))
				break;
		}
			
	}

	if ( ret < 0 ) emsg(argv0,"recvmsg");

	close(fd);
	close(sk);
} /* command_recv() */

/* Read lines from stdin and send them to the socket.  */
static void
command_send(char *argv0, int sk)
{
	struct msghdr outmsg;
	struct iovec iov;
	struct hostent *hst;
	struct sockaddr_in remote_addr;
	int fd;
	int msglen;
	int ct;

	/* Set up the destination.  */
	hst = gethostbyname(remote_host);
	if (hst == NULL || hst->h_length < 1) {
		fprintf(stderr, "%s: bad hostname: %s\n", argv0, remote_host);
		exit(1);
	}
	memcpy(&remote_addr.sin_addr, hst->h_addr_list[0], sizeof(remote_addr.sin_addr));
	remote_addr.sin_port = htons(remote_port);
	remote_addr.sin_family = AF_INET;

	/* Initialize the message struct we use to pass messages to
	 * the remote socket.
	 */
	iov.iov_base = buffer;
	iov.iov_len = buffer_size;
	outmsg.msg_iov = &iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = NULL;
	outmsg.msg_controllen = 0;
	outmsg.msg_name = &remote_addr;
	outmsg.msg_namelen = sizeof(remote_addr);

	/* open the file */
	if ( filename == NULL ) fd = 0;
	else if ( (fd = open(filename,O_RDONLY)) == -1 ) emsg(argv0,"open");

	fprintf(stderr,"%s ready to send...\n", argv0);
	ct = 0;
	while ( (msglen = read(fd,buffer,buffer_size)) > 0 ) {
		/* Send to our neighbor.  */
		iov.iov_len = msglen;
		if ( sendmsg(sk, &outmsg, 0) != msglen ) emsg(argv0,"sendmsg");
		if ( verbose ) fprintf(stderr,"%s-%d send %d bytes\n",argv0,++ct,msglen);
		if ( interactive && fd != 1 ) 
			getchar();
			// no flow control? no problem, make it slow
		else if ( delay > 0 ) 
			usleep(delay);
	}

	close(fd);
	close(sk);
} /* command_send() */

int main(int argc, char *argv[])
{
	int ret;

	if (( ret = parse_arguments(argc, argv) )) return ret;

	switch(command) {
	case COMMAND_NONE:
		fprintf(stderr, "%s: Please specify a command.\n", argv[0]);
		break;
	case COMMAND_RECV:
		command_recv(argv[0],build_endpoint(argv[0]));
		break;
	case COMMAND_SEND:
		command_send(argv[0],build_endpoint(argv[0]));
		break;
	default:
		fprintf(stderr, "%s: illegal command %d\n", argv[0], command);
	} /* switch(command) */

	return 0;
}
