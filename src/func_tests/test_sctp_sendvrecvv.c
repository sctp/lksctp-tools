/* SCTP kernel Implementation
 * (C) Copyright REDHAT Corp. 2018
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
 * To compile the v6 version, set the symbol TEST_V6 to 1.
 *
 * Written or modified by:
 *    Xin Long		<lucien.xin@gmail.com>
 */

/* This is a basic functional test for the SCTP new library APIs
 * sctp_sendv() and sctp_recvv().
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <netinet/sctp.h>
#include <sctputil.h>

char *TCID = __FILE__;
int TST_TOTAL = 10;
int TST_CNT;

/* RCVBUF value, and indirectly RWND*2 */
#define SMALL_RCVBUF 3000
#define SMALL_MAXSEG 500
/* This is extra data length to ensure rwnd closes */
#define RWND_SLOP    100
static char *message = "Hello world\n";

int main(int argc, char *argv[])
{
	sockaddr_storage_t loop1, loop2, msgname;
	int sk1, sk2, error, buflen, i, addrcnt;
	socklen_t msgname_len, rn_len;
	struct sctp_authinfo authinfo;
	struct sctp_sndinfo sndinfo;
	struct sockaddr *addr_list;
	struct sctp_sendv_spa spa;
	uint32_t infotype, stream;
	struct iovec iov, iovx[3];
	struct sctp_prinfo prinfo;
	struct sctp_recvv_rn rn;
	int pf_class, msg_flags;
	socklen_t val = 1;
	char addr_str[64];

	/* Set some basic values which depend on the address family. */
#if TEST_V6
	struct sockaddr_in6 *v6addrs;

	pf_class = PF_INET6;

	loop1.v6.sin6_family = AF_INET6;
	loop1.v6.sin6_addr = in6addr_loopback;
	loop1.v6.sin6_port = htons(SCTP_TESTPORT_1);

	loop2.v6.sin6_family = AF_INET6;
	loop2.v6.sin6_addr = in6addr_loopback;
	loop2.v6.sin6_port = htons(SCTP_TESTPORT_2);

	addrcnt = 5;
	v6addrs = test_malloc(sizeof(*v6addrs) * addrcnt);
	v6addrs[0].sin6_family = PF_INET6;
	v6addrs[0].sin6_addr = in6addr_loopback;
	v6addrs[0].sin6_port = htons(SCTP_TESTPORT_2);
	for (i = 1; i < addrcnt; i++) {
		sprintf(addr_str, "2020::%d", i);
		v6addrs[i].sin6_family = PF_INET6;
		inet_pton(PF_INET6, addr_str, &v6addrs[i].sin6_addr);
	}
	addr_list = (struct sockaddr *)v6addrs;
#else
	struct sockaddr_in *v4addrs;

	pf_class = PF_INET;

	loop1.v4.sin_family = AF_INET;
	loop1.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop1.v4.sin_port = htons(SCTP_TESTPORT_1);

	loop2.v4.sin_family = AF_INET;
	loop2.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
	loop2.v4.sin_port = htons(SCTP_TESTPORT_2);

	addrcnt = 5;
	v4addrs = test_malloc(sizeof(*v4addrs) * addrcnt);
	v4addrs[0].sin_family = PF_INET;
	v4addrs[0].sin_addr.s_addr = SCTP_IP_LOOPBACK;
	v4addrs[0].sin_port = htons(SCTP_TESTPORT_2);
	for (i = 1; i < addrcnt; i++) {
		sprintf(addr_str, "172.16.1.%d", i);
		v4addrs[i].sin_family = PF_INET;
		v4addrs[i].sin_addr.s_addr = inet_addr(addr_str);
	}
	addr_list = (struct sockaddr *)v4addrs;
#endif /* TEST_V6 */

	setvbuf(stdout, NULL, _IONBF, 0);

	/* Create the two endpoints which will talk to each other.  */
	sk1 = test_socket(pf_class, SOCK_SEQPACKET, IPPROTO_SCTP);
	sk2 = test_socket(pf_class, SOCK_SEQPACKET, IPPROTO_SCTP);

	/* Bind these sockets to the test ports.  */
	test_bind(sk1, &loop1.sa, sizeof(loop1));
	test_bind(sk2, &loop2.sa, sizeof(loop2));

	/* Mark sk2 as being able to accept new associations.  */
	test_listen(sk2, 1);


	/* Testing for sctp_sendv */
	iov.iov_base = message;
	iov.iov_len = strlen(message) + 1;
	test_sctp_sendv(sk1, &iov, 1, addr_list, addrcnt, NULL, 0, 0, 0);
	tst_resm(TPASS, "sctp_sendv addr info");

	stream = 1;
	memset(&sndinfo, 0, sizeof(sndinfo));
	sndinfo.snd_flags = SCTP_UNORDERED;
	sndinfo.snd_sid = stream;
	test_sctp_sendv(sk1, &iov, 1, addr_list, addrcnt, &sndinfo,
			sizeof(sndinfo), SCTP_SENDV_SNDINFO, 0);
	tst_resm(TPASS, "sctp_sendv sndinfo with stream %d", stream);

	iovx[0].iov_base = message;
	iovx[0].iov_len = strlen(message) + 1;
	iovx[1].iov_base = message;
	iovx[1].iov_len = strlen(message) + 1;
	iovx[2].iov_base = message;
	iovx[2].iov_len = strlen(message) + 1;

	stream = 2;
	sndinfo.snd_sid = stream;
	test_sctp_sendv(sk1, iovx, 3, addr_list, addrcnt, &sndinfo,
			sizeof(sndinfo), SCTP_SENDV_SNDINFO, 0);
	tst_resm(TPASS, "sctp_sendv sndinfo with stream %d", stream);

	prinfo.pr_policy = SCTP_PR_SCTP_RTX;
	prinfo.pr_value = 10;
	test_sctp_sendv(sk1, iovx, 3, addr_list, addrcnt, &prinfo,
			sizeof(prinfo), SCTP_SENDV_PRINFO, 0);
	tst_resm(TPASS, "sctp_sendv prinfo");

	authinfo.auth_keynumber = 0;
	test_sctp_sendv(sk1, iovx, 3, addr_list, addrcnt, &authinfo,
			sizeof(authinfo), SCTP_SENDV_AUTHINFO, 0);
	tst_resm(TPASS, "sctp_sendv authinfo");


	spa.sendv_sndinfo = sndinfo;
	spa.sendv_prinfo = prinfo;
	spa.sendv_authinfo = authinfo;

	stream = 3;
	spa.sendv_sndinfo.snd_sid = stream;
	spa.sendv_flags = SCTP_SEND_SNDINFO_VALID | SCTP_SEND_PRINFO_VALID;
	test_sctp_sendv(sk1, iovx, 3, addr_list, addrcnt, &spa,
			sizeof(spa), SCTP_SENDV_SPA, 0);
	tst_resm(TPASS, "sctp_sendv spa with stream %d", stream);

	stream = 4;
	spa.sendv_sndinfo.snd_sid = stream;
	spa.sendv_flags = SCTP_SEND_SNDINFO_VALID | SCTP_SEND_PRINFO_VALID |
			  SCTP_SEND_AUTHINFO_VALID;
	test_sctp_sendv(sk1, iovx, 3, addr_list, addrcnt, &spa,
			sizeof(spa), SCTP_SENDV_SPA, 0);
	tst_resm(TPASS, "sctp_sendv spa with stream %d", stream);

	/* Testing for sctp_recvv */
	buflen = REALLY_BIG;
	msgname_len = sizeof(msgname);
	msg_flags = 0;
	iov.iov_base = test_malloc(buflen);
	iov.iov_len = buflen;
	rn_len = sizeof(rn);

	error = test_sctp_recvv(sk2, &iov, 1, (struct sockaddr *)&msgname,
				&msgname_len, &rn, &rn_len, &infotype,
				&msg_flags);
	if (infotype != SCTP_RECVV_NOINFO)
		tst_brkm(TBROK, tst_exit, "sctp_recvv infotype %d != %d",
			 infotype, SCTP_RECVV_NOINFO);
	tst_resm(TPASS, "sctp_recvv SCTP_RECVV_NOINFO");

	error = setsockopt(sk2, SOL_SCTP, SCTP_RECVRCVINFO,
			   &val, sizeof(val));
	if (error)
		tst_brkm(TBROK, tst_exit, "setsockopt(SCTP_RECVRCVINFO): %s",
			 strerror(errno));

	error = test_sctp_recvv(sk2, &iov, 1, (struct sockaddr *)&msgname,
				&msgname_len, &rn, &rn_len, &infotype,
				&msg_flags);
	if (infotype != SCTP_RECVV_RCVINFO ||
	    rn.recvv_rcvinfo.rcv_sid != 1)
		tst_brkm(TBROK, tst_exit, "sctp_recvv infotype %d != %d",
			 infotype, SCTP_RECVV_NOINFO);
	tst_resm(TPASS, "sctp_recvv SCTP_RECVV_RCVINFO");

	error = setsockopt(sk2, SOL_SCTP, SCTP_RECVNXTINFO,
			   &val, sizeof(val));
	if (error)
		tst_brkm(TBROK, tst_exit, "setsockopt(SCTP_RECVNXTINFO): %s",
			 strerror(errno));

	rn_len = 1;
	error = test_sctp_recvv(sk2, &iov, 1, (struct sockaddr *)&msgname,
				&msgname_len, &rn, &rn_len, &infotype,
				&msg_flags);
	if (infotype != SCTP_RECVV_NOINFO)
		tst_brkm(TBROK, tst_exit, "sctp_recvv infotype %d != %d",
			 infotype, SCTP_RECVV_NOINFO);
	tst_resm(TPASS, "sctp_recvv SCTP_RECVV_NOINFO due to small size");

	rn_len = sizeof(struct sctp_nxtinfo);
	error = test_sctp_recvv(sk2, &iov, 1, (struct sockaddr *)&msgname,
				&msgname_len, &rn, &rn_len, &infotype,
				&msg_flags);
	if (infotype != SCTP_RECVV_NXTINFO)
		tst_brkm(TBROK, tst_exit, "sctp_recvv infotype %d != %d",
			 infotype, SCTP_RECVV_NXTINFO);
	tst_resm(TPASS, "sctp_recvv SCTP_RECVV_NXTINFO due to small size");

	rn_len = sizeof(rn);
	error = test_sctp_recvv(sk2, &iov, 1, (struct sockaddr *)&msgname,
				&msgname_len, &rn, &rn_len, &infotype,
				&msg_flags);
	if (infotype != SCTP_RECVV_RN ||
	    rn.recvv_rcvinfo.rcv_sid != 0 || rn.recvv_nxtinfo.nxt_sid != 3)
		tst_brkm(TBROK, tst_exit, "sctp_recvv infotype %d != %d",
			 infotype, SCTP_RECVV_RN);
	tst_resm(TPASS, "sctp_recvv SCTP_RECVV_RN");

	close(sk1);
	close(sk2);

	return 0;
}
