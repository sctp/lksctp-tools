/* This purpose of this test is to examine the
 * support of the interleaving
 * The following tests are done in sequence:
 * - Verify SCTP_FRAGMENT_INTERLEAVE and SCTP_INTERLEAVING_SUPPORTED
 *   socket option by doing a setsockopt() followed by a getsockopt()
 * - Verify the integrity of the data sent by client using a sendmsg()
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

#define MSG_SIZE 1000

char *TCID = __FILE__;
int TST_TOTAL = 2;
int TST_CNT = 0;

int
main(int argc, char *argv[])
{
	int sk1, sk2;
	int pf_class;
	int error;
	int fd;
	int msg_len, bytes_sent;
	int frag_interleave, get_result;
	sockaddr_storage_t loop1;
	sockaddr_storage_t loop2;
	struct iovec iov;
	struct iovec out_iov;
	struct msghdr inmessage;
	struct msghdr outmessage;
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	struct sctp_assoc_value assoc, get_assoc;
	uint32_t ppid;
	uint32_t stream;
	char *buffer;
	char setting[4];
	char incmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
	char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	void *msg_buffer;
	socklen_t optlen;

	/* Rather than fflush() throughout the code, set stdout to
	 * be unbuffered.
	 */
	setvbuf(stdout, NULL, _IONBF, 0);

	/* Set some basic values which depend on the address family. */
#if TEST_V6
	pf_class = PF_INET6;

	loop1.v6.sin6_family = AF_INET6;
	loop1.v6.sin6_addr = in6addr_loopback;
	loop1.v6.sin6_port = htons(SCTP_TESTPORT_1);

	loop2.v6.sin6_family = AF_INET6;
	loop2.v6.sin6_addr = in6addr_loopback;
	loop2.v6.sin6_port = htons(SCTP_TESTPORT_2);
#else
	pf_class = PF_INET;

	loop1.v4.sin_family = AF_INET;
	loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.v4.sin_port = htons(SCTP_TESTPORT_1);

	loop2.v4.sin_family = AF_INET;
	loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.v4.sin_port = htons(SCTP_TESTPORT_2);
#endif /* TEST_V6 */

	/* Create the two endpoints which will talk to each other */
	sk1 = test_socket(pf_class, SOCK_SEQPACKET, IPPROTO_SCTP);
	sk2 = test_socket(pf_class, SOCK_SEQPACKET, IPPROTO_SCTP);

	/* Enable ASSOC_CHANGE and SNDRCVINFO notifications */
	test_enable_assoc_change(sk1);
	test_enable_assoc_change(sk2);

	/* Bind these sockets to the test ports */
	test_bind(sk1, &loop1.sa, sizeof(loop1));
	test_bind(sk2, &loop2.sa, sizeof(loop2));

	/* Let sk2 listen to new associations */
	test_listen(sk2, 1);

	/* TEST #1: verify SCTP_FRAGMENT_INTERLEAVE option
	 *          followed by a getsockopt()
	 */
	frag_interleave = 1;
	test_setsockopt(sk1, SCTP_FRAGMENT_INTERLEAVE,
			&frag_interleave, sizeof(frag_interleave));
	test_setsockopt(sk2, SCTP_FRAGMENT_INTERLEAVE,
			&frag_interleave, sizeof(frag_interleave));

	tst_resm(TPASS, "setsockopt(SCTP_FRAGMENT_INTERLEAVE)");

	get_result = 0;
	optlen = sizeof(get_result);
	error = test_getsockopt(sk1, SCTP_FRAGMENT_INTERLEAVE,
				&get_result, &optlen);
	if (get_result != frag_interleave)
		tst_brkm(TBROK, tst_exit, "getsockopt(SCTP_FRAGMENT_INTERLEAVE) "
			 "error: %d errno: %d get_result: %d",
			 error, errno, get_result);
	get_result = 0;
	error = test_getsockopt(sk2, SCTP_FRAGMENT_INTERLEAVE,
				&get_result, &optlen);
	if (get_result != frag_interleave)
		tst_brkm(TBROK, tst_exit, "getsockopt(SCTP_FRAGMENT_INTERLEAVE) "
			 "error: %d errno: %d get_result: %d",
			 error, errno, get_result);

	tst_resm(TPASS, "getsockopt(SCTP_FRAGMENT_INTERLEAVE)");

	/* Check if net.sctp.intl_enable=1, exit if not */
	fd = open("/proc/sys/net/sctp/intl_enable", O_RDONLY);
	if (fd < 0 ||
	    read(fd, &setting, 4) < 0 ||
	    strncmp("1", setting, 1) != 0) {
		tst_resm(TINFO, "intl_enable is not set to 1, skip test\n");
		return 0;
	}
	close(fd);

	assoc.assoc_id = 0;
	assoc.assoc_value = 1;
	test_setsockopt(sk1, SCTP_INTERLEAVING_SUPPORTED,
			&assoc, sizeof(assoc));
	test_setsockopt(sk2, SCTP_INTERLEAVING_SUPPORTED,
			&assoc, sizeof(assoc));

	tst_resm(TPASS, "setsockopt(SCTP_INTERLEAVING_SUPPORTED)");


	memset(&get_assoc, 0x00, sizeof(struct sctp_assoc_value));
	optlen = sizeof(get_assoc);
	error = test_getsockopt(sk1, SCTP_INTERLEAVING_SUPPORTED,
				&get_assoc, &optlen);
	if (get_assoc.assoc_value != 1)
		tst_brkm(TBROK, tst_exit,
			 "getsockopt(SCTP_INTERLEAVING_SUPPORTED) "
			 "error: %d errno: %d get_result: %d",
			 error, errno, get_assoc.assoc_value);
	error = test_getsockopt(sk2, SCTP_INTERLEAVING_SUPPORTED,
				&get_assoc, &optlen);
	if (get_assoc.assoc_value != 1)
		tst_brkm(TBROK, tst_exit,
			 "getsockopt(SCTP_INTERLEAVING_SUPPORTED) "
			 "error: %d errno: %d get_result: %d",
			 error, errno, get_assoc.assoc_value);

	tst_resm(TPASS, "getsockopt(SCTP_INTERLEAVING_SUPPORTED)");
	/* End of TEST #1 */

	/* Send the first message to create an association */
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

	/* Initialize inmessage for all receives */
	buffer = test_malloc(REALLY_BIG);
	memset(&inmessage, 0x00, sizeof(inmessage));
	iov.iov_base = buffer;
	iov.iov_len = REALLY_BIG;
	inmessage.msg_iov = &iov;
	inmessage.msg_iovlen = 1;
	inmessage.msg_control = incmsg;

	/* Get the communication up message on sk2 */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(sk2, &inmessage, MSG_WAITALL);
	test_check_msg_notification(&inmessage, error,
				    sizeof(struct sctp_assoc_change),
				    SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the communication up message on sk1 */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(sk1, &inmessage, MSG_WAITALL);
	test_check_msg_notification(&inmessage, error,
				    sizeof(struct sctp_assoc_change),
				    SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

	/* Get the first message which was sent.  */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(sk2, &inmessage, MSG_WAITALL);
	test_check_msg_data(&inmessage, error, msg_len, MSG_EOR, stream, ppid);
	free(msg_buffer);

	/* TEST #2: Verify data integrity */
	msg_len = MSG_SIZE;
	msg_buffer = test_build_msg(msg_len);
	outmessage.msg_iov->iov_base = msg_buffer;
	outmessage.msg_iov->iov_len = msg_len;
	bytes_sent = test_sendmsg(sk1, &outmessage, 0, msg_len);

	tst_resm(TINFO, "Sent %d byte message", bytes_sent);

	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(sk2, &inmessage, MSG_WAITALL);

	tst_resm(TINFO, "Received %d byte message", error);

	test_check_msg_data(&inmessage, error, bytes_sent,
			    MSG_EOR, stream, ppid);

	tst_resm(TPASS, "Received same byte of message");
	/* End of TEST #2 */

	/* Shut down the link */
	close(sk1);

	/* Get the shutdown complete notification */
	inmessage.msg_controllen = sizeof(incmsg);
	error = test_recvmsg(sk2, &inmessage, MSG_WAITALL);
	test_check_msg_notification(&inmessage, error,
				    sizeof(struct sctp_assoc_change),
				    SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_COMP);
	close(sk2);

	free(buffer);
	free(msg_buffer);
	/* Indicate successful completion */
	return 0;
}
