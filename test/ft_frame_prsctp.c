/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2004
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
 * Written or modified by:
 *    Sridhar Samudrala		<sri@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* This is a testframe functional test to verify
 * PR-SCTP Support. 
 */

#include <net/sctp/sctp.h>
#include <funtest.h>

int
main(int argc, char *argv[])
{
	struct sock *svr_sk, *clt_sk;
	union sctp_addr svr_loop, clt_loop;
	void *msg_buf;
	int error;
	struct list_head *lchunk1, *lchunk2, *lchunk3;
	struct sctp_chunk *chunk1, *chunk2, *chunk3;
	struct sctp_endpoint *clt_ep, *svr_ep;
	struct sctp_association *clt_asoc, *svr_asoc;
	struct sctp_transport *clt_trans;

	/* Do all that random stuff needed to make a sensible universe. */
	sctp_init();

	/* Initialize the server and client addresses. */ 
        svr_loop.v4.sin_family = AF_INET;
        svr_loop.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        svr_loop.v4.sin_port = htons(SCTP_TESTPORT_1);
        clt_loop.v4.sin_family = AF_INET;
        clt_loop.v4.sin_addr.s_addr = SCTP_ADDR_LO;
        clt_loop.v4.sin_port = htons(SCTP_TESTPORT_2);

	/* Create the 2 sockets.  */
	svr_sk = sctp_socket(PF_INET, SOCK_SEQPACKET);
	clt_sk = sctp_socket(PF_INET, SOCK_SEQPACKET);

	/* Bind these sockets to the test ports.  */
	error = test_bind(svr_sk, (struct sockaddr *)&svr_loop,
			  sizeof(svr_loop));
	if (error != 0) { DUMP_CORE; }
	error = test_bind(clt_sk, (struct sockaddr *)&clt_loop,
			  sizeof(clt_loop));
	if (error != 0) { DUMP_CORE; }

	/* Mark svr_sk as being able to accept new associations. */
	if (0 != sctp_seqpacket_listen(svr_sk, 1)) { DUMP_CORE; }

	msg_buf = test_build_msg(1000);
	/* Send a big message.  This will create the association.  */
	test_frame_send_message(clt_sk, (struct sockaddr *)&svr_loop, msg_buf);

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        /* Get the communication up message from clt_sk.  */
        test_frame_get_event(clt_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
        /* Get the communication up message from svr_sk.  */
        test_frame_get_event(svr_sk, SCTP_ASSOC_CHANGE, SCTP_COMM_UP);

        test_frame_get_message(svr_sk, msg_buf);

	clt_ep = sctp_sk(clt_sk)->ep;
	svr_ep = sctp_sk(svr_sk)->ep;
	clt_asoc = test_ep_first_asoc(clt_ep);
	svr_asoc = test_ep_first_asoc(svr_ep);
	clt_trans = clt_asoc->peer.primary_path;

	test_frame_send_message(clt_sk, (struct sockaddr *)&svr_loop, msg_buf);
	test_frame_send_message(clt_sk, (struct sockaddr *)&svr_loop, msg_buf);
	test_frame_send_message(clt_sk, (struct sockaddr *)&svr_loop, msg_buf);

	lchunk1 = sctp_list_dequeue(&clt_trans->transmitted);
	lchunk2 = sctp_list_dequeue(&clt_trans->transmitted);
	lchunk3 = sctp_list_dequeue(&clt_trans->transmitted);
	chunk1 = list_entry(lchunk1, struct sctp_chunk, transmitted_list);
	chunk2 = list_entry(lchunk2, struct sctp_chunk, transmitted_list);
	chunk3 = list_entry(lchunk3, struct sctp_chunk, transmitted_list);
	chunk2->msg->expires_at = jiffies+2;
	chunk2->msg->can_abandon = 1;
	list_add_tail(&chunk1->transmitted_list, &clt_trans->transmitted);
	list_add_tail(&chunk2->transmitted_list, &clt_trans->transmitted);
	list_add_tail(&chunk3->transmitted_list, &clt_trans->transmitted);

	if (test_step(SCTP_CID_DATA, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	test_kill_next_packet(SCTP_CID_DATA);
	if (test_step(SCTP_CID_DATA, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	if (test_step(SCTP_CID_SACK, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}
	jiffies += 4;
	if (test_step(SCTP_CID_FWD_TSN, TEST_NETWORK0) <= 0) {
		DUMP_CORE;
	}

	error = test_run_network();
	if (0 != error) { DUMP_CORE; }

	/* Move time forward by a SACK timeout.  */
        jiffies += svr_asoc->timeouts[SCTP_EVENT_TIMEOUT_SACK] + 1;
        error = test_run_timeout();
	if (0 != error) { DUMP_CORE; }
        if (!test_for_chunk(SCTP_CID_SACK, TEST_NETWORK0)) {
                DUMP_CORE;
        }

        error = test_run_network();
	if (0 != error) { DUMP_CORE; }

        test_frame_get_message(svr_sk, msg_buf);
        test_frame_get_message(svr_sk, msg_buf);

        sctp_close(clt_sk, 0);
        sctp_close(svr_sk, 0);

	printk("\n\n%s passed\n\n\n", argv[0]);

        /* Indicate successful completion.  */
        exit(error);
}
