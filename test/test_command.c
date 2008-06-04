/* SCTP kernel Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999-2001 Cisco, Motorola
 * 
 * This file is part of the SCTP kernel Implementation
 * 
 * This program tests the sctp command sequences object.
 * 
 * Command sequences are short programs built by the core state
 * machine for the side effect interpreter to execute.
 * 
 * The SCTP implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * the SCTP implementation  is distributed in the hope that it 
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
 * Please send any bug reports or fixes you make to one of the
 * following email addresses:
 * 
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <linux/types.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <funtest.h>

/* We need this now to ru the test. The kernel has been using the _sf
 * version which BUGed out in the overflow case, so this fuction has
 * be removed to de-bloat the kernel.
 */
static int sctp_add_cmd(sctp_cmd_seq_t *seq, sctp_verb_t verb, sctp_arg_t obj)
{
	if (seq->next_free_slot >= SCTP_MAX_NUM_COMMANDS)
		return 0;

	sctp_add_cmd_sf(seq, verb, obj);
	return 1;
}

int
main(int argc, char * const argv[])
{
	sctp_cmd_seq_t seq1;
	sctp_cmd_seq_t *seq2;
	sctp_cmd_seq_t seq2_buf;
	sctp_cmd_t *command;
	struct sctp_transport *transport =
		(struct sctp_transport *) 1;
	int i;

	/* This is just a handy list of verbs to try out.  */
	sctp_verb_t verbs[] = {
		SCTP_CMD_CHUNK_ULP,
		SCTP_CMD_ECN_CE,
		SCTP_CMD_ECN_ECNE,
		SCTP_CMD_EVENT_ULP,
		SCTP_CMD_GEN_COOKIE_ECHO,
		SCTP_CMD_GEN_INIT_ACK,
		SCTP_CMD_GEN_SACK,
		SCTP_CMD_NEW_ASOC,
		SCTP_CMD_NEW_STATE,
		SCTP_CMD_NOP,
		SCTP_CMD_PROCESS_SACK,
		SCTP_CMD_REPLY,
		SCTP_CMD_REPORT_TSN,
		SCTP_CMD_RETRAN,
		SCTP_CMD_SEND_PKT,
	};

	/* Init 2 command sequences.  */
	if (!sctp_init_cmd_seq(&seq1)) { DUMP_CORE; }
	if (!sctp_init_cmd_seq(&seq2_buf)) { DUMP_CORE; }
	seq2 = &seq2_buf;

	/* These tests assume something about the internal
	 * implementation of sctp_cmd_seq_t.
	 */
	if (0 != seq2->next_free_slot) { DUMP_CORE; }
	if (0 != seq2->next_cmd) { DUMP_CORE; }

	/* Add a couple commands and then read them out again.  */
	if (!sctp_add_cmd(&seq1, SCTP_CMD_RETRAN,
			  SCTP_TRANSPORT(transport))) {
		DUMP_CORE;
	}
	if (!sctp_add_cmd(&seq1, SCTP_CMD_NEW_STATE,
			  SCTP_STATE(SCTP_STATE_COOKIE_WAIT))) {
		DUMP_CORE;
	}
	
	/* Rewind a sequence and make sure we can read it out again.  */
	if (!sctp_rewind_sequence(&seq1)) { DUMP_CORE; }
	/* The next test is implementation-specific.  */
	if (0 != seq2->next_cmd) { DUMP_CORE; }

	if (NULL == (command = sctp_next_cmd(&seq1))) { DUMP_CORE; }
	if (SCTP_CMD_RETRAN != command->verb) { DUMP_CORE; }
	if (transport != command->obj.transport) { DUMP_CORE; }

	if (NULL == (command = sctp_next_cmd(&seq1))) { DUMP_CORE; }
	if (SCTP_CMD_NEW_STATE != command->verb) { DUMP_CORE; }
	if (SCTP_STATE_COOKIE_WAIT != command->obj.state) { DUMP_CORE; }

	if (NULL != (command = sctp_next_cmd(&seq1))) { DUMP_CORE; }

	/* Make sure that the init sequence blots everything out.  */
	if (!sctp_rewind_sequence(&seq1)) { DUMP_CORE; }
	if (!sctp_init_cmd_seq(&seq1)) { DUMP_CORE; }
	/* The next test is implementation-specific.  */
	if (0 != seq2->next_free_slot) { DUMP_CORE; }
	if (NULL != (command = sctp_next_cmd(&seq1))) { DUMP_CORE; }

	/* Make sure that we can fill a command sequence.  */
	for (i = 0; i < SCTP_MAX_NUM_COMMANDS; ++i) {
		if (!sctp_add_cmd(seq2, verbs[i], SCTP_I32(i))) {
			DUMP_CORE;
		}
	}
	/* This next wafer-thin mint should fail.  */
	if (sctp_add_cmd(seq2, verbs[i], SCTP_I32(i))) {
		DUMP_CORE;
	}

	/* Can we still recover everything after filling the sequence?  */
	if (!sctp_rewind_sequence(seq2)) { DUMP_CORE; }
	
	for (i = 0; i < SCTP_MAX_NUM_COMMANDS; ++i) {
		if (NULL == (command = sctp_next_cmd(seq2))) { DUMP_CORE; }
		if (verbs[i] != command->verb) { DUMP_CORE; }
		if (i != command->obj.i32) { DUMP_CORE; }
	}
	if (NULL != (command = sctp_next_cmd(seq2))) { DUMP_CORE; }

	printk("%s passes...\n", argv[0]);
	exit(0);
} /* main() */
