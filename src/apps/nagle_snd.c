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
 * sends 1,000,000 packets to a specified target.
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

char *TCID = __FILE__;
int TST_TOTAL = 1;
int TST_CNT = 0;

void
usage(char *argv0)
{
	fprintf(stderr, "Usage: %s -H localhost [-P localport] "
		"-h remotehost [-p remoteport]\n"
		"\t\t[-S msgsize] [-I interval] -N\n"
		" -H, --local\t\tspecify one of the local addresses,\n"
		" -P, --local-port\tspecify the port number for local addresses,\n"
		" -h, --remote\t\tspecify one of the remote addresses,\n"
		" -p, --remote-port\tspecify the port number for remote addresses,\n"
		" -S, --size\t\tspecify the size(byte) of the sending message,\n"
		" -I, --interval\t\tspecify the interval(second) that sending messages at,\n"
		" -N, --nodelay\t\tspecify whether the SCTP allows Nagle's algorithm\n",
		argv0);
}

int
main(int argc, char *argv[])
{
	int sk, i;
	struct addrinfo *hst_res, *tgt_res;
	sockaddr_storage_t host, target;
	sockaddr_storage_t msgname;
	struct iovec iov;
	struct msghdr inmessage;
	struct msghdr outmessage;
	char incmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
	char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	struct iovec out_iov;
	char *message;
	int error, pf_class;
	sctp_assoc_t associd;
	uint32_t ppid;
	uint32_t stream;
	char *remote_host = NULL;
	int remote_port = SCTP_TESTPORT_1;
	char *local_host = NULL;
	int local_port = SCTP_TESTPORT_2;
	int size = 1;
	int interval = 0;
	int nodelay = 0;
	int option_index = 0;
	char *big_buffer;
	char port_buffer[10];
	int c;
	static struct option long_options[] = {
		{"local",	 1, 0, 1},
		{"local-port",	 1, 0, 2},
		{"remote",	 1, 0, 3},
		{"remote-port",  1, 0, 4},
		{"size",	 1, 0, 5},
		{"interval",	 1, 0, 6},
		{"nodelay",	 0, 0, 10},
		{0,		 0, 0, 0}
	};

	/* Rather than fflush() throughout the code, set stdout to 
	 * be unbuffered. 
	 */
	setvbuf(stdout, NULL, _IONBF, 0); 

	/* Parse the arguments.  */
	while (1) {
		c = getopt_long (argc, argv, "H:P:h:p:S:I:N",
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
		case 5:		/* size */
		case 'S':
			size = atoi(optarg);
			break;
		case 6:		/* interval */
		case 'I':
			interval = atoi(optarg);
			break;
		case 10:	 /* nodelay */
		case 'N':
			nodelay = 1;
			break;
		case '?':
			usage(argv[0]);
			exit(0);

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

	if (!local_host || !remote_host) {
		fprintf(stderr, "%s: : option --local and --remote are required\n",
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

	snprintf(port_buffer, 10, "%d", remote_port);
	error = getaddrinfo(remote_host, port_buffer, NULL, &tgt_res);
	if (error) {
		fprintf(stderr, "%s: getaddrinfo failed: %s\n", argv[0], remote_host);
		exit(1);
	}

	if ( hst_res->ai_family != tgt_res->ai_family) {
		fprintf(stderr, "local and reomte hosts should be the " 
			"same address family\n");
		exit(1);
	}

	pf_class = hst_res->ai_family;
	switch (pf_class) {
	case AF_INET:
	case AF_INET6:
		memcpy(&host.sa, hst_res->ai_addr, hst_res->ai_addrlen);
		memcpy(&target.sa, tgt_res->ai_addr, tgt_res->ai_addrlen);
		break;
	default:
		fprintf(stderr, "Invalid address type.\n");
		exit(1);
		break;
	}

	freeaddrinfo(hst_res);
	freeaddrinfo(tgt_res);

	sk = test_socket(pf_class, SOCK_SEQPACKET, IPPROTO_SCTP);

	/* Enable ASSOC_CHANGE and SNDRCVINFO notifications. */
	test_enable_assoc_change(sk);

	test_setsockopt(sk, SCTP_NODELAY, &nodelay, sizeof(int));

	/* Bind the sockets to the test port.  */
	test_bind(sk, &host.sa, sizeof(host));

	/* Mark sk as being able to accept new associations.  */
	test_listen(sk, 1);

	/* Build up a msghdr structure we can use for all sending.  */
	outmessage.msg_name = &target;
	outmessage.msg_namelen = sizeof(target);
	outmessage.msg_iov = &out_iov;
	outmessage.msg_iovlen = 1;
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
	ppid = rand(); /* Choose an arbitrary value. */
	stream = 1; 
	sinfo->sinfo_ppid = ppid;
	sinfo->sinfo_stream = stream;

	message = test_malloc((size + 1) * sizeof(u_int8_t));

	for(i=0; i + 10 < size; i+= 10)
		memcpy(message+i, "1234567890", 10);
	strncpy(message+i, "1234567890", size-i);
	*(message+size) = 0;

	outmessage.msg_iov->iov_base = message;
	outmessage.msg_iov->iov_len = size + 1;

	printf("Initiating connection with %s:%d...\n", remote_host,
	       remote_port);

	/* Send the first message.  This will create the association.  */
	test_sendmsg(sk, &outmessage, 0, size+1);

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
	associd = ((struct sctp_assoc_change *)iov.iov_base)->sac_assoc_id;

	printf("Established connection with ");	
	if (AF_INET == msgname.sa.sa_family)
		printf("%d.%d.%d.%d(%d)\n", NIPQUAD(msgname.v4.sin_addr),
		       ntohs(msgname.v4.sin_port));
	if (AF_INET6 == msgname.sa.sa_family)
		printf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x(%d)\n",
		       NIP6(msgname.v6.sin6_addr), ntohs(msgname.v6.sin6_port));

	printf("Sending data to receiver...\n");

	for (i=1; i<1000000; i++) {

		if (interval)
			sleep(interval);

		outmessage.msg_name = &target;
		outmessage.msg_namelen = sizeof(target);
		outmessage.msg_iov = &out_iov;
		outmessage.msg_iovlen = 1;
		outmessage.msg_controllen = sizeof(outcmsg);
		outmessage.msg_flags = 0;

		cmsg = CMSG_FIRSTHDR(&outmessage);
		cmsg->cmsg_level = IPPROTO_SCTP;
		cmsg->cmsg_type = SCTP_SNDRCV;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
		outmessage.msg_controllen = cmsg->cmsg_len;
		sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
		memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));

		ppid++;

		sinfo->sinfo_ppid = ppid;
		sinfo->sinfo_stream = stream;
		sinfo->sinfo_assoc_id = associd;

		outmessage.msg_iov->iov_base = message;
		outmessage.msg_iov->iov_len = size + 1;

		test_sendmsg(sk, &outmessage, 0, size+1);
	}

	printf("\n\n\t\tComplete all the data sendings to receiver...\n\n\n");

	error = 0;
	close(sk);

	free(message);

	/* Indicate successful completion.  */
	return 0;

}
