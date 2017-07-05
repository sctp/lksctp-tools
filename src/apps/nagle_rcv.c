/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2002, 2003
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
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
 *    Ardelle Fan <ardelle.fan@intel.com>
 *    Sridhar Samudrala <sri@us.ibm.com>
 */

/* This is a receiver for the performance test to verify Nagle's algorithm. 
 * It creates a socket, binds to a address specified as a parameter and
 * goes into a receive loop waiting for 1,000,000 packets. Then it calculates
 * the packet receive rate, i.e. packets/second.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <errno.h>
#include <netinet/sctp.h>
#include <sctputil.h>
#include <getopt.h>
#include <netdb.h>
#include <time.h>

char *TCID = __FILE__;
int TST_TOTAL = 1;
int TST_CNT = 0;

void
usage(char *progname)
{
	fprintf(stderr, "Usage: %s -H hostname [-P port]\n", progname);
	fprintf(stderr, " -H, --local\t\t local hostname,\n");
	fprintf(stderr, " -P, --local-port\t local port,\n");
}

int
main(int argc, char *argv[])
{
	int sk, i;
	struct addrinfo *hst_res;
	sockaddr_storage_t host;
	sockaddr_storage_t msgname;
	struct iovec iov;
	struct msghdr inmessage;
	char incmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
	int error, pf_class;
	char *big_buffer;
	char *local_host = NULL;
	int local_port = SCTP_TESTPORT_1; 
	char port_buffer[10];
	int option_index = 0;
	time_t from, to;
	int bytes_received = 0; 
	int c;
	static struct option long_options[] = {
		{"local",	1, 0, 1},
		{"local-port",	1, 0, 2},
		{0,		0, 0, 0}
	};

	/* Rather than fflush() throughout the code, set stdout to 
	 * be unbuffered. 
	 */
	setvbuf(stdout, NULL, _IONBF, 0); 

	/* Parse the arguments.  */
	while (1) {
		c = getopt_long (argc, argv, "H:P:",
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
		case '?':
			usage(argv[0]);
			exit(0);

		default:
			printf ("%s: unrecognized option 0%c\n", argv[0], c);
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

	if (!local_host) {
		fprintf(stderr, "%s: : option -H, --local is required\n",
			argv[0]);
		usage(argv[0]);
		exit(1);
	}

	/* Set some basic values which depend on the address family. */
	if (!strcmp(local_host, "0"))
		local_host = "0.0.0.0";

	snprintf(port_buffer, 10, "%d", local_port);
	error = getaddrinfo(local_host, port_buffer, NULL, &hst_res);
	if (error) {
		fprintf(stderr, "%s: getaddrinfo failed: %s\n", argv[0], local_host);
		exit(1);
	}

	pf_class = hst_res->ai_family;
	switch (pf_class) {
	case AF_INET:
	case AF_INET6:
		memcpy(&host.sa, hst_res->ai_addr, hst_res->ai_addrlen);
		break;
	default:
		fprintf(stderr, "Invalid address type.\n");
		exit(1);
		break;
	}

	freeaddrinfo(hst_res);

	/* Create the endpoint which will talk to nagle_snd.  */
	sk = test_socket(pf_class, SOCK_SEQPACKET, IPPROTO_SCTP);

	/* Enable ASSOC_CHANGE and SNDRCVINFO notifications. */
	test_enable_assoc_change(sk);

	/* Bind the sockets to the test port.  */
	test_bind(sk, &host.sa, sizeof(host));

	/* Mark sk as being able to accept new associations.  */
	test_listen(sk, 1);

	printf("Listening on port:%d\n", local_port);

	/* Initialize inmessage for receives. */
	memset(&inmessage, 0, sizeof(inmessage));
	big_buffer = test_malloc(REALLY_BIG);
	iov.iov_base = big_buffer;
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);
	inmessage.msg_name = &msgname;
	inmessage.msg_namelen = sizeof(msgname);
	memset(&msgname, 0, sizeof(msgname));

	/* Get the communication up message on sk.  */
	error = test_recvmsg(sk, &inmessage, MSG_WAITALL);
	test_check_msg_notification(&inmessage, error,
				    sizeof(struct sctp_assoc_change),
				    SCTP_ASSOC_CHANGE, SCTP_COMM_UP);	

	printf("Established connection with "); 
	if (AF_INET == msgname.sa.sa_family)
		printf("%d.%d.%d.%d(%d)\n", NIPQUAD(msgname.v4.sin_addr),
		       ntohs(msgname.v4.sin_port));
	if (AF_INET6 == msgname.sa.sa_family)
		printf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x(%d)\n",
		       NIP6(msgname.v6.sin6_addr), ntohs(msgname.v6.sin6_port));

	time(&from);
	for (i=0; i<1000000; i++) {
		inmessage.msg_controllen = sizeof(incmsg);
		inmessage.msg_namelen = sizeof(msgname);
		error = test_recvmsg(sk, &inmessage, MSG_WAITALL);
		if (inmessage.msg_flags & MSG_NOTIFICATION)
			break;
		printf("Received %d bytes of data\n", error);
		bytes_received += error;
	}
	time(&to);

	printf("\t%d messages(%d bytes) successfully received in %ld "
	       "seconds.\n", i, bytes_received, to - from);
	printf("The receive rate is %ld bytes/second\n",
	       bytes_received/(to - from));

	/* Shut down the link.	*/
	error = 0;
	close(sk);

	return 0;
}
