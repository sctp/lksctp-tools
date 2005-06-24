/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (C) 1999, 2001 Cisco, Motorola
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * This is a standalone program to test serial number arithmetic comparisons
 * 
 * The SCTP reference implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * the SCTP reference implementation  is distributed in the hope that it 
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *                 ************************
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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
 * Karl Knutson <karl@athena.chicago.il.us>
 * Jon Grimm <jgrimm@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <linux/types.h>
#include <funtest.h>

int
main(int argc, char **argv)
{
	
	printk("Now let's exercise TSN_lt and TSN_lte with interesting conditions.\n");
	printk("We will DUMP CORE if there are unexpected results.\n");

	
	printk("Compare TSN 0 < 1\n");
	if (!TSN_lt(0, 1))
		DUMP_CORE;

	printk("Compare TSN 1 < 0 \n");
	if (TSN_lt(1, 0))
		DUMP_CORE;

	printk("Compare TSN 0 < 0xffffffff\n");
	if (TSN_lt(0, 0xffffffff))
		DUMP_CORE;

	printk("Compare TSN 0xffffffff < 0\n");
	if (!TSN_lt(0xffffffff, 0))
		DUMP_CORE;

	printk("Compare TSN 0 <= 0xffffffff\n");
	if (TSN_lte(0, 0xffffffff))
		DUMP_CORE;

	printk("Compare TSN 0xffffffff <= 0\n");
	if (!TSN_lte(0xffffffff, 0))
		DUMP_CORE;


        printk("Compare TSN 0 < 0x7fffffff\n");
	if (!TSN_lt(0, 0x7fffffff))
		DUMP_CORE;

        printk("Compare TSN 0x7fffffff < 0\n");
	if (TSN_lt(0x7fffffff, 0))
		DUMP_CORE;

	printk("Compare TSN 0 <= 0x7fffffff\n");
	if (!TSN_lte(0, 0x7fffffff))
		DUMP_CORE;

	printk("Compare TSN 0x7fffffff <= 0\n");
	if (TSN_lte(0x7fffffff, 0))
		DUMP_CORE;

	printk("Compare TSN 0x7fffffff < 0x7fffffff\n");
	if (TSN_lt(0x7fffffff, 0x7fffffff))
		DUMP_CORE;

	printk("Compare TSN 0x7fffffff <= 0x7fffffff\n");
	if (!TSN_lte(0x7fffffff, 0x7fffffff))
		DUMP_CORE;

	printk("Exercise SSN_lt and SSN_lte with interesting conditions.\n");
	printk("CORE DUMP if there are unexpected results.\n");

	printk("Compare SSN 0 < 1\n");
	if (!SSN_lt(0, 1))
		DUMP_CORE;

	printk("Compare SSN 1 < 0\n");
	if (SSN_lt(1, 0))
		DUMP_CORE;

	printk("Compare SSN 0 < 0xffff\n");
	if (SSN_lt(0, 0xffff))
		DUMP_CORE;

	printk("Compare SSN 0xffff < 0\n");
	if (!SSN_lt(0xffff, 0))
		DUMP_CORE;

	printk("Compare SSN 0 <= 0xffff\n");
	if (SSN_lte(0, 0xffff))
		DUMP_CORE;

	printk("Compare SSN 0xffff <= 0\n");
	if (!SSN_lte(0xffff, 0))
		DUMP_CORE;


        printk("Compare SSN 0 < 0x7fff\n");
	if (!SSN_lt(0, 0x7fff))
		DUMP_CORE;

        printk("Compare SSN 0x7fff < 0\n");
	if (SSN_lt(0x7fff, 0))
		DUMP_CORE;

	printk("Compare SSN 0 <= 0x7fff\n");
	if (!SSN_lte(0, 0x7fff))
		DUMP_CORE;

	printk("Compare SSN 0x7fff <= 0\n");
	if (SSN_lte(0x7fff, 0))
		DUMP_CORE;

	printk("Compare SSN 0x7fff < 0x7fff\n");
	if (SSN_lt(0x7fff, 0x7fff))
		DUMP_CORE;

	printk("Compare SSN 0x7fff <= 0x7fff\n");
	if (!SSN_lte(0x7fff, 0x7fff))
		DUMP_CORE;

	printk("%s Passed!\n", argv[0]);

	return 0;
} /* main() */
