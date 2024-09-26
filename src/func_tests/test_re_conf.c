/* The purpose of this test is to examine the support for RE-CONFIG chunk
 * The following tests are done in sequence:
 * - Verify the SCTP_ENABLE_STREAM_RESET option by doing a setsockopt()
 *   followed by a getsockopt()
 * - Verify the reset I/O stream functionality by setting SCTP_RESET_STREAMS
 * - Verify the reset assoc functionality by setting SCTP_RESET_ASSOC
 * - Verify the add streams functionality by setting SCTP_ADD_STREAMS
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
#include <fcntl.h>
#include <netinet/sctp.h>
#include <sctputil.h>

#define STREAM_NUM 3
#define ADD_STREAM 2

char *TCID = __FILE__;
int TST_TOTAL = 4;
int TST_CNT = 0;

int
main(int argc, char *argv[])
{
	int error;
	int sk1, sk2, acpt_sk;
	int pf_class;
	int fd;
	int msg_len;
	void *msg_buffer;
	sockaddr_storage_t loop1;
	sockaddr_storage_t loop2;
	sockaddr_storage_t acpt_addr;
	sctp_assoc_t assoc_id;
	socklen_t optlen, sock_len;
	uint32_t ppid;
	uint32_t stream;
	struct msghdr inmessage;
	struct msghdr outmessage;
	struct iovec iov;
	struct iovec out_iov;
	struct cmsghdr *cmsg;
	struct sctp_assoc_value assoc;
	struct sctp_assoc_value get_assoc;
	struct sctp_reset_streams *srs;
	struct sctp_add_streams *sas;
	struct sctp_sndrcvinfo *sinfo;
	char setting[4];
	char * buffer;
	char incmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
	char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];

	/* Rather than fflush() throughout the code, set stdout to
	 * be unbuffered.
	 */
	setvbuf(stdout, NULL, _IONBF, 0);

#if TEST_V6
	pf_class = PF_INET6;
	sock_len = sizeof(struct sockaddr_in6);

	loop1.v6.sin6_family = AF_INET6;
	loop1.v6.sin6_addr = in6addr_loopback;
	loop1.v6.sin6_port = htons(SCTP_TESTPORT_1);

	loop2.v6.sin6_family = AF_INET6;
	loop2.v6.sin6_addr = in6addr_loopback;
	loop2.v6.sin6_port = htons(SCTP_TESTPORT_2);
#else
	pf_class = PF_INET;
	sock_len = sizeof(struct sockaddr_in);

	loop1.v4.sin_family = AF_INET;
	loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.v4.sin_port = htons(SCTP_TESTPORT_1);

	loop2.v4.sin_family = AF_INET;
	loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.v4.sin_port = htons(SCTP_TESTPORT_2);
#endif /* TEST_V6 */

	/* Create the two endpoints which will talk to each other */
	sk1 = test_socket(pf_class, SOCK_STREAM, IPPROTO_SCTP);
	sk2 = test_socket(pf_class, SOCK_STREAM, IPPROTO_SCTP);

	/* Enable ASSOC_CHANGE and SNDRCVINFO notifications */
	test_enable_assoc_change(sk1);
	test_enable_assoc_change(sk2);

	/* Bind these sockets to the test ports */
	test_bind(sk1, &loop1.sa, sizeof(loop2));
	test_bind(sk2, &loop2.sa, sizeof(loop2));

	/* Let sk2 listen to new associations */
	test_listen(sk2, 1);

	/* Set up connection */
	test_connectx(sk1, &loop2.sa, 1);
	acpt_sk = test_accept(sk2, &acpt_addr.sa, &sock_len);
	test_enable_assoc_change(acpt_sk);

	/* Initialize inmessage for all receives */
	buffer = test_malloc(REALLY_BIG);
	memset(&inmessage, 0x00, sizeof(inmessage));
	iov.iov_base = buffer;
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	inmessage.msg_control = incmsg;

	/* Send the first message to create an association */
	memset(&outmessage, 0x00, sizeof(outmessage));
	outmessage.msg_name = &loop2;
	outmessage.msg_namelen = sizeof(loop2);
	outmessage.msg_iov = &out_iov;
	outmessage.msg_iovlen = 1;
	outmessage.msg_control = outcmsg;
	outmessage.msg_controllen = sizeof(outcmsg);
	outmessage.msg_flags = 0;
	cmsg = CMSG_FIRSTHDR(&outmessage);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));
	ppid = rand(); /* Choose an arbitrary value */
	stream = 1;
	sinfo->sinfo_ppid = ppid;
	sinfo->sinfo_stream = stream;
	msg_len = 10;
	msg_buffer = test_build_msg(10);
	outmessage.msg_iov->iov_base = msg_buffer;
	outmessage.msg_iov->iov_len = msg_len;
	test_sendmsg(sk1, &outmessage, 0, msg_len);

	/* Get the communication up message on sk1 */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(sk1, &inmessage, MSG_WAITALL);
	test_check_msg_notification(&inmessage, error,
					sizeof(struct sctp_assoc_change),
					SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message on acpt_sk */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(acpt_sk, &inmessage, MSG_WAITALL);
	test_check_msg_notification(&inmessage, error,
					sizeof(struct sctp_assoc_change),
					SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first data message which was sent. */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(acpt_sk, &inmessage, MSG_WAITALL);
	test_check_msg_data(&inmessage, error, 10, MSG_EOR, stream, ppid);

	/* TEST #1: verify SCTP_ENABLE_STREAM_RESET option */
	memset(&assoc, 0, sizeof(struct sctp_assoc_value));
	assoc.assoc_id = 0;
	assoc.assoc_value = (SCTP_ENABLE_RESET_STREAM_REQ
			   | SCTP_ENABLE_RESET_ASSOC_REQ
			   | SCTP_ENABLE_CHANGE_ASSOC_REQ);
	test_setsockopt(sk1, SCTP_ENABLE_STREAM_RESET, &assoc, sizeof(assoc));
	test_setsockopt(sk2, SCTP_ENABLE_STREAM_RESET, &assoc, sizeof(assoc));

	tst_resm(TPASS, "setsockopt(SCTP_ENABLE_STREAM_RESET)");

	optlen = sizeof(struct sctp_assoc_value);
	memset(&get_assoc, 0x00, optlen);
	assoc.assoc_id = 0;
	error = test_getsockopt(sk1, SCTP_ENABLE_STREAM_RESET,
				&get_assoc, &optlen);
	if (get_assoc.assoc_value != 7)
		tst_brkm(TBROK, tst_exit,
			 "getsockopt(SCTP_INTERLEAVING_SUPPORTED) "
			 "error: %d errno: %d get_result: %d",
			 error, errno, get_assoc.assoc_value);
	error = test_getsockopt(sk2, SCTP_ENABLE_STREAM_RESET,
				&get_assoc, &optlen);
	if (get_assoc.assoc_value != 7)
		tst_brkm(TBROK, tst_exit,
			 "getsockopt(SCTP_INTERLEAVING_SUPPORTED) "
			 "error: %d errno: %d get_result: %d",
			 error, errno, get_assoc.assoc_value);

	tst_resm(TPASS, "getsockopt(SCTP_ENABLE_STREAM_RESET)");

	/* TEST #2: Reset I/O streams */
	/* Check if net.sctp.reconf_enable=1, exit if not */
	fd = open("/proc/sys/net/sctp/reconf_enable", O_RDONLY);
	if (0 > fd ||
	    0 >= read(fd, &setting, 4) ||
	    strncmp("1", setting, 1) != 0) {
		fprintf(stderr, "reconf_enable is not set to 1, skip test\n");
		exit(0);
	}
	close(fd);

	optlen = sizeof(struct sctp_reset_streams)
		 + STREAM_NUM * sizeof(uint16_t);
	srs = (struct sctp_reset_streams*) test_malloc(optlen);
	srs->srs_assoc_id = 0;
	srs->srs_number_streams = STREAM_NUM;
	for (int i = 0; i < srs->srs_number_streams; ++i)
		srs->srs_stream_list[i] = i;
	srs->srs_flags = (SCTP_STREAM_RESET_INCOMING | SCTP_STREAM_RESET_OUTGOING);

	test_setsockopt(sk1, SCTP_RESET_STREAMS, srs, optlen);

	tst_resm(TPASS, "setsockopt(SCTP_RESET_STREAMS)");

	/* TEST #3: Reset assoc */
	assoc_id = 0;
	test_setsockopt(sk1, SCTP_RESET_ASSOC, &assoc_id, sizeof(socklen_t));

	tst_resm(TPASS, "setsockopt(SCTP_RESET_ASSOC)");

	/* TEST #4: Add stream */
	sas = (struct sctp_add_streams *) test_malloc(sizeof(struct sctp_add_streams));
	sas->sas_assoc_id = 0;
	sas->sas_instrms = ADD_STREAM;
	sas->sas_outstrms= ADD_STREAM;
	test_setsockopt(sk1, SCTP_ADD_STREAMS, sas, (socklen_t)sizeof(struct sctp_add_streams));

	tst_resm(TPASS, "setsockopt(SCTP_ADD_STREAMS)");

	/* Shut down the link */
	close(sk1);

	/* Get the shutdown complete notification */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(acpt_sk, &inmessage, MSG_WAITALL);
	test_check_msg_notification(&inmessage, error,
					sizeof(struct sctp_assoc_change),
					SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);
	close(acpt_sk);
	close(sk2);

	free(buffer);
	free(srs);
	free(sas);
	free(msg_buffer);
	/*Indicate successful completion*/
	exit(EXIT_SUCCESS);
}
