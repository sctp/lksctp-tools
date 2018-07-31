/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2003
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
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 *
 * Written or modified by:
 *    Ryan Layer		<rmlayer@us.ibm.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <errno.h>
#include <netinet/sctp.h>
#include <sctputil.h>
#include <netdb.h>
#include <getopt.h>

char *TCID = __FILE__;
int TST_TOTAL = 1;
int TST_CNT = 0;

#define MAXHOSTNAME 64

#define MAXCLIENTNUM 10000

#define TRUE 1

#define SERVER 1
#define CLIENT 0
#define NOT_DEFINED -1

int mode = NOT_DEFINED;

int	assoc_num,
	remote_port,
	local_port;
int active = 0;

char *local_host = NULL;
char *remote_host = NULL;
sockaddr_storage_t client_loop,
		server_loop;
struct hostent *hst;
char big_buffer[REALLY_BIG];

void usage(char *argv0);
void parse_arguments(int argc, char*argv[]);
void data_received(struct msghdr *inmessage, int len, int stream,
                        int server_socket);
int event_received(struct msghdr *inmessage, int assoc_num);
void process_ready_sockets(int client_socket[], int assoc_num, fd_set *rfds);
void server_mode(void);
void client_mode(void);

/* Print the syntax/usage */
void usage(char *argv0)
{
	printf("usage: %s -H localhost -P localport -l|c [-h remotehost]\n"
	       "\t\t[-p remoteport] [-a] [-n <cnt>]\n" 
	       " -H\t\tspecify a local address.\n"
	       " -P\t\tspecify the local port number to be used\n"
	       " -l\t\trun in server mode.\n"
	       " -c\t\trun in client mode.\n"
	       " -h\t\tspecify the peer address.\n"
	       " -p\t\tspecify the port number for the peer address.\n"
	       " -a\t\tactively generate traffic with the server.\n"
	       " -n\t\tspecify the number of associations to create.\n",
	       argv0);
}

/* Parse command line options */
void parse_arguments(int argc, char*argv[]) {
	int c;

	while ((c = getopt(argc, argv, ":H:P:ach:ln:p:")) >= 0) {
		switch (c) {
			case 'H':
				local_host = optarg;
				break;
			case 'P':
				local_port = atoi(optarg);
				break;
			case 'c':
			    if (mode == NOT_DEFINED)
					mode = CLIENT;
				else {
					usage(argv[0]);
					exit(0);
				}
				break;
			case 'a':
				active = 1;
				break;
			case 'h':
				remote_host = optarg;
				break;
			case 'l':
			    if (mode == NOT_DEFINED)
					mode = SERVER;
				else {
					usage(argv[0]);
					exit(0);
				}
				break;
			case 'n':
				assoc_num = atoi(optarg);
				break;
			case 'p':
				remote_port = atoi(optarg);
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	} /* while() */

	if (mode == CLIENT) {
		if (assoc_num) {
			if (assoc_num > MAXCLIENTNUM) {
				printf("The number of associations indicated "
					"is greater than the");
				printf("max number of associations "
					"allowed(%d).", MAXCLIENTNUM);
				usage(argv[0]);
				exit(0);
			}
		} else
			assoc_num = 1;

		if (remote_host && remote_port) {
			hst = gethostbyname(remote_host);

			memcpy(&server_loop.v4.sin_addr, hst->h_addr_list[0],
				   sizeof(server_loop.v4.sin_addr));

			server_loop.v4.sin_family = AF_INET;
server_loop.v4.sin_port = htons(remote_port);
		} else {
			printf("Remote host and remote port must be defined "
				"in client mode\n");
			usage(argv[0]);
			exit(0);
		}

		if (local_host) {
			hst = gethostbyname(local_host);

			memcpy(&client_loop.v4.sin_addr, hst->h_addr_list[0],
				   sizeof(client_loop.v4.sin_addr));
		} else
			client_loop.v4.sin_addr.s_addr = INADDR_ANY;

		if (local_port)
			client_loop.v4.sin_port = htons(local_port);
		else
			client_loop.v4.sin_port = 0;

		client_loop.v4.sin_family = AF_INET;
	} else if (mode == SERVER) {
		if (active) {
			printf("This option if for client use only");
			usage(argv[0]);
			exit(0);
		}

		if (remote_host || remote_port) {
			printf("Remote values not needed in server mode.\n");
			usage(argv[0]);
			exit(0);
		}

		if (local_host) {
			hst = gethostbyname(local_host);

			memcpy(&server_loop.v4.sin_addr, hst->h_addr_list[0],
				   sizeof(server_loop.v4.sin_addr));
		} else
			server_loop.v4.sin_addr.s_addr = INADDR_ANY;

		if (local_port)
			server_loop.v4.sin_port = htons(local_port);
		else {
			printf("Specify a local port in server mode.\n");
			usage(argv[0]);
			exit(0);
		}

		server_loop.v4.sin_family = AF_INET;
	} else {
		printf("Must assisgn a client or server mode.\n");
		usage(argv[0]);
		exit(0);
	}
} /* parse_arguments() */

/* Handle data received */
void data_received(struct msghdr *inmessage, int len, int stream, int socket) {

	int ppid, error;
	char *ping = "PING";

	if (mode == SERVER) {
		ppid = rand();

		error = sctp_sendmsg(socket,
				inmessage->msg_iov->iov_base,
				len,
				(struct sockaddr *)inmessage->msg_name,
				inmessage->msg_namelen,
				ppid,
				0,
				stream,
				0, 0);

		if (error < 0) {
			printf("Send Failure: %s.\n", strerror(errno));
			DUMP_CORE;
		}
	} else {
		ppid = rand();

		printf("Data Received by socket #: %d.\n", socket);
		printf("\tMessage = %s\n",
			(char *)inmessage->msg_iov->iov_base);

		if (active) {
			error = sctp_sendmsg(socket, ping, strlen(ping) + 1,
					     (struct sockaddr *)&server_loop,
					     sizeof(server_loop), ppid, 0,
					     stream, 0, 0);
			if (error < 0) {
				printf("Send Failure: %s.\n",
				       strerror(errno));
				DUMP_CORE;
			}
		}
	}
}

/* This will print what type of SCTP_ASSOC_CHANGE state that was received */
void print_sctp_sac_state(struct msghdr *msg) {

	char *data;
	union sctp_notification *sn;

	if (msg->msg_flags & MSG_NOTIFICATION) {
		data = (char *)msg->msg_iov[0].iov_base;

		sn = (union sctp_notification *)data;

		switch (sn->sn_assoc_change.sac_state) {
				case SCTP_COMM_UP:
						printf("SCTP_COMM_UP\n");
						break;
				case SCTP_COMM_LOST:
						printf("SCTP_COMM_LOST\n");
						break;
				case SCTP_RESTART:
						printf("SCTP_RESTART");
						break;
				case SCTP_SHUTDOWN_COMP:
						printf("SCTP_SHUTDOWN_COMP\n");
						break;
				case SCTP_CANT_STR_ASSOC:
						printf("SCTP_CANT_STR_ASSOC\n");
						break;
				default:
						break;
		}
	}
} /* void print_sctp_sac_state() */

/* Tests what type of MSG_NOTIFICATION has been received.
* For now this fucntion only works with SCTP_ASSOC_CHANGE 
* types, but can be easily expanded.
*
* Will return...
* -1 if the msg_flags is not MSG_NOTIFICATION
*  0 if the MSG_NOTIFICATION type differs from the type
*       passed into the additional variable
*  1 if the MSG_NOTIFICATION type matches the type
*       passed into the additional variable
*/
int test_check_notification_type(struct msghdr *msg,
	uint16_t sn_type,
	uint32_t additional) {

	char *data;
	union sctp_notification *sn;

	if (!(msg->msg_flags & MSG_NOTIFICATION)) {
		return -1;
	} else {

		/* Fixup for testframe. */
		data = (char *)msg->msg_iov[0].iov_base;

		sn = (union sctp_notification *)data;

		if (sn->sn_header.sn_type != sn_type)
			return 0;
		else if (sn->sn_header.sn_type == SCTP_ASSOC_CHANGE)
			if (sn->sn_assoc_change.sac_state == additional)
				return 1;
		return 0;
	}
}

/* Determine the type of event and make correct adjustments to the
* association count
*/
int event_received(struct msghdr *inmessage, int assoc_num) {

	int error;

	printf("Event Received\n");

	print_sctp_sac_state(inmessage);

	if (mode == SERVER) {
		/* Test type of Event */
		error = test_check_notification_type(inmessage,
						SCTP_ASSOC_CHANGE,
						SCTP_COMM_UP);
		if (error > 0) {
			assoc_num++;
			printf("Assosiation Established: count = %d.\n",
				assoc_num);
		} else {
			error = test_check_notification_type(inmessage,
							SCTP_ASSOC_CHANGE,
							SCTP_SHUTDOWN_COMP);

			if (error > 0) {
				assoc_num--;
				printf("Assosiation Shutdown: count = %d.\n",
					assoc_num);
			}
		}
	}
	return assoc_num;
}

void server_mode() {
	sockaddr_storage_t msgname;
	int server_socket,
		error,
		stream;
	int assoc_num =0;
	struct msghdr inmessage;
	struct iovec iov;
	char incmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];


	printf("Running in Server Mode...\n");

	memset(&inmessage, 0, sizeof(inmessage));
	iov.iov_base = big_buffer;
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen =1;
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof(incmsg);
	inmessage.msg_name = &msgname;
	inmessage.msg_namelen = sizeof (msgname);

	stream = 1;

	server_socket = socket(PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
	if (server_socket < 0) {
		printf("Socket Failure:  %s.\n", strerror(errno));
		DUMP_CORE;
	}

	error = bind(server_socket, &server_loop.sa, sizeof(server_loop));
	if (error != 0 ) {
		printf("Bind Failure: %s.\n", strerror(errno));
		DUMP_CORE;
	}

	error = listen(server_socket, 1);
	if (error != 0) {
		printf("Listen Failure: %s.\n", strerror(errno));
		DUMP_CORE;
	}
	while (TRUE) {
		error = recvmsg(server_socket, &inmessage, MSG_WAITALL);
		if (error < 0) {
			printf("Receive Failure: %s\n",
			strerror(errno));
		} else {
		if (inmessage.msg_flags & MSG_NOTIFICATION)
			assoc_num = event_received(&inmessage, assoc_num);
		else
			data_received(&inmessage, error, stream, server_socket);
		}
	}
}

void client_mode() {

	int i, error, stream, max_socket = 0;
	uint32_t ppid = 0;
	int client_socket[assoc_num];
	char *message = "Awake";
	fd_set rfds;
	struct timeval tv;

        stream = 1;

	printf("Running in Client Mode...\n");

        /* Create the sockets */
	for (i = 0; i < assoc_num; i++) {
		client_socket[i] = socket(PF_INET, SOCK_SEQPACKET,
					IPPROTO_SCTP);
		if (client_socket[i] < 0 ){
			printf("Socket Failure: %s.\n", strerror(errno));
			DUMP_CORE;
		}

		if (local_port) {
			error = bind(client_socket[i], &client_loop.sa,
				sizeof(client_loop));
			if (error < 0) {
				printf("Bind Failure: %s\n", strerror(errno));
				DUMP_CORE;
			}
		}

		printf("Create Socket #: %d\n", client_socket[i]);

		/* Connect to server and send initial message */
		error = connect(client_socket[i], &server_loop.sa,
						    sizeof(server_loop));
		if (error < 0){
			printf("Connect Failure: %s.\n", strerror(errno));
			DUMP_CORE;
		}

		max_socket = client_socket[i];

                ppid++;

		/* Send initial message */
		error = sctp_sendmsg(client_socket[i],
				message,
				strlen(message) + 1,
				(struct sockaddr *)&server_loop,
				sizeof(server_loop),
				ppid,
				0,
				stream,
				0, 0);
		if (error < 0 ) {
			printf("Send Failure: %s.\n", strerror(errno));
			DUMP_CORE;
		}
	}

	while (TRUE){

		/* Clear the set for select() */
		FD_ZERO(&rfds);

		/* Set time out values for select() */
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		/* Add the sockets select() will examine */
		for (i = 0; i < assoc_num; i++) {
			FD_SET(client_socket[i], &rfds);
		}

		/* Wait until there is data to be read from one of the
		 * sockets, or until the timer expires
		 */
		error = select(max_socket + 1, &rfds, NULL, NULL, &tv);

		if (error < 0) {
			printf("Select Failure: %s.\n", strerror(errno));
			DUMP_CORE;
		} else if (error) {
			/* Loop through the array of sockets to find the ones
			 *that have information to be read
			 */
			process_ready_sockets(client_socket, assoc_num, &rfds);
		}
	}
}

void process_ready_sockets(int client_socket[], int assoc_num, fd_set *rfds) {

        int i, stream, error;
	struct msghdr inmessage;
	struct iovec iov;
	char incmsg[CMSG_SPACE(sizeof (sctp_cmsg_data_t))];
	sockaddr_storage_t msgname;

        /* Setup inmessage to be able to receive in incomming message */
	memset(&inmessage, 0, sizeof (inmessage));
	iov.iov_base = big_buffer;
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen =1;
	inmessage.msg_control = incmsg;
	inmessage.msg_controllen = sizeof (incmsg);
	inmessage.msg_name = &msgname;
	inmessage.msg_namelen = sizeof (msgname);

	stream = 1;

	for( i = 0; i < assoc_num; i++) {
		if (FD_ISSET(client_socket[i], rfds)) {
				error = recvmsg(client_socket[i], &inmessage,
						MSG_WAITALL);
				if (error < 0)
						printf("Receive Failure: %s\n",
							strerror(errno));
				else {
		/* Test to find the type of message that was read(event/data) */
					if (inmessage.msg_flags &
						MSG_NOTIFICATION)
						 event_received(&inmessage,
								0);

					else
						data_received(&inmessage, error,
							stream,
							client_socket[i]);
			}
		}
	}
}

int main(int argc, char *argv[]) {

	parse_arguments(argc, argv);

	if (mode == SERVER) {
		server_mode();
	} else if (mode == CLIENT){
		client_mode();
	}
	exit(1);
}

