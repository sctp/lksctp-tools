/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999 Cisco
 * Copyright (c) 1999,2000,2001 Motorola
 * Copyright (c) 2001 Nokia
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * This is a standalone program to test SCTP related CMSG parsing.  
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ^^^^^^^^^^^^^^^^^^^^^^^^
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.  
 *
 * Please send any bug reports or fixes you make to one of the following
 * email addresses:
 * 
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Jon Grimm <jgrimm@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <linux/types.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <funtest.h>

int
main(int argc, char **argv)
{
	sctp_cmsgs_t cmsgs = {0};
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	struct sctp_initmsg *initmsg;
	struct sctp_sndrcvinfo *sndrcvinfo;
        size_t msglen;
	char buf[CMSG_SPACE_INITMSG + CMSG_SPACE_SNDRCVINFO];
	int error;
			 

	printk("Exercise SCTP CMSG parsing.\n");


	/* Testing too small msg size. */
	printk("Testing too small msg size.\n");

	msg.msg_control = buf;        
	msg.msg_controllen = sizeof(struct cmsghdr) - 1;
	
	/* No error should occur. */
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 != error) { DUMP_CORE; }

	
	/* Testing too small cmsglen. */
	printk("Testing too small cmsglen.\n");

	msg.msg_controllen = CMSG_SPACE(0);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_INIT;
	cmsg->cmsg_len = sizeof(struct cmsghdr) - 1;

	/* Follow the example of SCM code where this is 
	 * an error. 
	 */
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 == error) { DUMP_CORE; }

	/* Testing too small initmsg. */
	printk("Testing too small initmsg.\n");

	msg.msg_controllen = sizeof(buf);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_initmsg)-4);
	msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_initmsg));
	

	/* Follow the example of SCM code where this is 
	 * an error. 
	 */
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 == error) { DUMP_CORE; }

	/* Test simple initmsg. */
	printk("Testing initmsg.\n");

	msg.msg_controllen = sizeof(buf);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_initmsg));
	msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_initmsg));
	initmsg = (struct sctp_initmsg *)CMSG_DATA(cmsg);
	
	memset(&cmsgs, 0x00, sizeof(sctp_cmsgs_t));
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 != error) { DUMP_CORE; }
	if (initmsg != cmsgs.init) { DUMP_CORE; }
	if (NULL != cmsgs.info) { DUMP_CORE; }

	/* Testing too small sndrcvinfo. */
	printk("Testing too small sndrcvinfo.\n");

	msg.msg_controllen = sizeof(buf);
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo)-4);
	msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));

	/* Follow the example of SCM code where this is 
	 * an error. 
	 */
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 == error) { DUMP_CORE; }

	/* Testing simple sndrcvinfo. */
	printk("Testing simple sndrcvinfo.\n");

	msg.msg_controllen = sizeof(buf);
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));

	sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	memset(sndrcvinfo, 0x00, sizeof(struct sctp_sndrcvinfo));
	memset(&cmsgs, 0x00, sizeof(sctp_cmsgs_t));

	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 != error) { DUMP_CORE; }	
	if (NULL != cmsgs.init) { DUMP_CORE; }
	if (sndrcvinfo != cmsgs.info) { DUMP_CORE; }

	/* Test sndrcvinfo with valid sinfo_flags. */
	printk("Testing valid sinfo_flags.\n");

	sndrcvinfo->sinfo_flags = SCTP_UNORDERED;
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 != error) { DUMP_CORE; }	
		
	/* Test sndrcvinfo with invalid sinfo_flags. */
	printk("Testing invalid sinfo_flags.\n");

	sndrcvinfo->sinfo_flags = SCTP_ABORT<<1;
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 == error) { DUMP_CORE; }	

	/* Test non-SCTP CMSG level. */
	printk("Testing non-SCTP CMSG level.\n");

	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(0);
	msg.msg_controllen = CMSG_SPACE(0);
	memset(&cmsgs, 0x00, sizeof(sctp_cmsgs_t));

	/* No error should occur, as thisis not an SCTP CMSG. */
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 != error) { DUMP_CORE; }
	if (NULL != cmsgs.init) { DUMP_CORE; }
	if (NULL != cmsgs.info) { DUMP_CORE; }

	/* Testing simple sndrcvinfo as second CMSG. */
	printk("Testing simple sndrcvinfo as second CMSG.\n");

	msg.msg_controllen = sizeof(buf);
      	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(0);
	msglen = CMSG_SPACE(0);
	
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	msg.msg_controllen = msglen 
		+ CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));

	sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	memset(sndrcvinfo, 0x00, sizeof(struct sctp_sndrcvinfo));
	memset(&cmsgs, 0x00, sizeof(sctp_cmsgs_t));

	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 != error) { DUMP_CORE; }	
	if (NULL != cmsgs.init) { DUMP_CORE; }
	if (sndrcvinfo != cmsgs.info) { DUMP_CORE; }

	/* Test unknown SCTP CMSG type. */
	printk("Testing unknown SCTP CMSG type.\n");

	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV + 1;
	cmsg->cmsg_len = CMSG_LEN(0);
	msg.msg_controllen = CMSG_SPACE(0);
	error = sctp_msghdr_parse(&msg, &cmsgs);
	if (0 == error) { DUMP_CORE; }
	
	printk("%s passes...\n", argv[0]);
	return 0;

} /* main() */






