/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999-2001 Cisco, Motorola
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * This program tests the sctp tsn mapping array 
 * 
 * From RFC 2960 12.2 Parameters necessary per association (i.e. the TCB):
 *
 *   Mapping     : An array of bits or bytes indicating which out of
 *   Array       : order TSN's have been received (relative to the
 *               : Last Rcvd TSN).  If no gaps exist, i.e. no out of order
 *               : packets have been received, this array will be set to
 *               : all zero.  This structure may be in the form of a
 *               : circular buffer or bit array.
 * 
 * The SCTP reference implementation  is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * the SCTP reference implementation  is distributed in the hope that it 
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
 * Jon Grimm <jgrimm@us.ibm.com>
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

#define TEST_TSNMAP_LEN 64
#define MAGIC_NUMBER 0x42424242

struct {
	struct sctp_tsnmap global_map;
	unsigned char storage[sctp_tsnmap_storage_size(TEST_TSNMAP_LEN)];
	uint32_t scribble;
} storage;

/* Function prototypes */
void test_tsnmap(uint32_t initial_tsn, uint16_t size);


int
main(int argc, char * const argv[])
{
	/* Test normally. */
	printf("\nTesting full length of map.\n");
	test_tsnmap(0x12345678, TEST_TSNMAP_LEN);

	/* Test map with odd length. */
	printf("\nTesting odd length map.\n");
	test_tsnmap(0x12345678, TEST_TSNMAP_LEN-1);

	/* Test with initial TSN around TSN rollover */
	printf("\nTesting with initial tsn around rollover 0xffffffff.\n");
	test_tsnmap(0xffffffff, TEST_TSNMAP_LEN);

        /* Test with initial TSN around TSN rollover */
	printf("\nTesting with initial tsn around rollover %x.\n", 
	       0xffffffff - TEST_TSNMAP_LEN * 2);
	test_tsnmap(0xffffffff - TEST_TSNMAP_LEN * 2, TEST_TSNMAP_LEN);

	printk("%s passes...\n", argv[0]);
	exit(0);

} /* main( ) */


/* This is the main test function.   Its input parameters can be 
 * manipulated to run this set of tests with multiple configurations of
 * initial_tsn and map size.
 */  
void 
test_tsnmap(uint32_t initial_tsn, uint16_t size)
{
	struct sctp_tsnmap *map;
	__u8 map_buf[sizeof(struct sctp_tsnmap) + sctp_tsnmap_storage_size(SCTP_TSN_MAP_SIZE)];
	int i;
	struct sctp_tsnmap_iter iter;
	uint16_t start, end;

	/* Phase 1
	 *
	 */

	printf("Testing new tsnmap\n");

	map = sctp_tsnmap_init((struct sctp_tsnmap *)&map_buf, size,
			       initial_tsn);
	if (NULL == map) { DUMP_CORE; }
	
	printf("Testing initial ctsn\n");

	/* Verify cumulative tsn ack point */
	if (!(initial_tsn-1 == sctp_tsnmap_get_ctsn(map))) {
		DUMP_CORE;
	}

	/* Make sure that we can mark out-of-range things and not
	 * die.
	 */
	sctp_tsnmap_mark(map, initial_tsn - 10);
	sctp_tsnmap_mark(map, initial_tsn + 2*size + 10);
	

	/* Check that mark does not move ctsn if there is a gap. */
	printf("Testing with missing tsns\n");

	sctp_tsnmap_mark(map, initial_tsn + 1);
	sctp_tsnmap_mark(map, initial_tsn + size);	

	/* Cumulative TSN ack point shouldn't have moved.  */
	/* Verify cumulative tsn ack point.  */
	if (!(initial_tsn-1 == sctp_tsnmap_get_ctsn(map))) {
		DUMP_CORE;
	}

        

        /* Simple checks */

	printf("Testing tsnmap_check\n");

        /*  Has tsn been seen? We haven't marked it, so no.  */
	if (0 != sctp_tsnmap_check(map, initial_tsn)) {
		DUMP_CORE;
	}

	/* Duplicate Checks */
	/*   Check what happens if tsn arrives lower than what
	 *   we are tracking.   We should see this as a dup.
	 */
	if (sctp_tsnmap_check(map, initial_tsn-1) <= 0) {
		DUMP_CORE;
	}

	/* We marked this tsn so we should see this as a dup.  */
	if (sctp_tsnmap_check(map, initial_tsn+1) <= 0) {
		DUMP_CORE;
	}

	
        /* Lets get the cumulative tsn ack point to move.  */
	printf("Testing ctsn movement\n");

	sctp_tsnmap_mark(map, initial_tsn);
	if (!(initial_tsn+1 == sctp_tsnmap_get_ctsn(map))) {
		DUMP_CORE;
	}

	/* Simple rollover test.  This should force a switch
	 * and then switch back and then once again.  
	 */
	printf("Testing simple rollover\n");

	for (i = 0; i <= size*3; i++){
		if (sctp_tsnmap_check(map, initial_tsn + i) < 0) {
			DUMP_CORE;
		}
		sctp_tsnmap_mark(map, initial_tsn + i);
	}

	/* The cumulative tsn ack point should have moved with us. */
	if (initial_tsn + size*3 != sctp_tsnmap_get_ctsn(map)) {
		DUMP_CORE;
	}


	/* Phase 2 
	 *	
	 * Okay now let's allocate a tsnmap from our own memory.  
	 * As a first test let's just try to go initialize the tsnmap.
	 * This should fail as we have not allocated any memory to back
	 * the mapping array. 
	 */

	printf("Testing statically allocated map\n");

	map = &storage.global_map;
	storage.scribble = MAGIC_NUMBER;
	if (NULL == sctp_tsnmap_init(map, size, initial_tsn)){
		DUMP_CORE;
	}
	
        /* This is a more interesting rollover test, lets fill
	 * overflow first, followed by filling the first mapping.
	 */
	printf("Testing rollover to a full overflow\n");

	/* Fill the overflow.  */
	for (i = size; i < size*2; i++){
		if (sctp_tsnmap_check(map, initial_tsn + i) < 0) {
			printf("check=%d\n", sctp_tsnmap_check(map, initial_tsn + i));
			DUMP_CORE;
		}
		sctp_tsnmap_mark(map, initial_tsn + i);
	}

	if (MAGIC_NUMBER != storage.scribble) {
		DUMP_CORE;
	}
	
	/* Verify the cumulative tsn ack point. */
	if (initial_tsn - 1 != sctp_tsnmap_get_ctsn(map)) {
		DUMP_CORE;
	}

	/* Fill the first map, except for initial_tsn. */
	for (i = 1; i < size; i++){
		if (sctp_tsnmap_check(map, initial_tsn + i) < 0) {
			DUMP_CORE;
		}
		sctp_tsnmap_mark(map, initial_tsn+i);		
	}

	if (MAGIC_NUMBER != storage.scribble) {
		DUMP_CORE;
	}

	/* Verify that the cumulative tsn ack point has not moved. */
	if (!(initial_tsn - 1 == sctp_tsnmap_get_ctsn(map))) {
		DUMP_CORE;
	}


	/* Mark the initial TSN, both maps should be full and the
	 * Cumulative TSN ACK Point should move ahead finally.
	 */
	sctp_tsnmap_mark(map, initial_tsn);
	
	/* Verify that the cumulative tsn ack point has moved */
	if (!(initial_tsn + size*2 - 1 == sctp_tsnmap_get_ctsn(map))) {
		DUMP_CORE;
	}

	
	/* Big Gap Test 
	 *
	 */
	
	printf("Testing big gap\n");

	/* At this point, the first map should be full and the overflow
	 * is empty.  Let's check beyond what we can handle, this check
	 * is very specific to the implementation but this seems fair
	 * given this is a unittest.
	 */ 
	if (0 <= sctp_tsnmap_check(map, initial_tsn + size*4)) {
		DUMP_CORE;
	}
       
	/* Now check one under the previously checked tsn.  This 
	 * new tsn should show up as new 
	 */
	if (0 != sctp_tsnmap_check(map, initial_tsn+size*4-1)) {
		DUMP_CORE;
	}


	/* Phase 3 
	 *
	 */

	/* Reinit the tsnmap back to sanity.  */
	if (NULL == sctp_tsnmap_init(map,
				     size, initial_tsn)) {
		DUMP_CORE;
	}


	/* Let's test getting the gap ack blocks.  */

	printf("Testing gap ack blocks\n");
	sctp_tsnmap_iter_init(map, &iter);

	if (0 != sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	/* Create a small gap and test.  */

	printf("Testing for single ack block\n");
	sctp_tsnmap_mark(map, initial_tsn+2);
	

	/* Count the number of Gap Ack Blocks.  */
	sctp_tsnmap_iter_init(map, &iter);
	for (i = 0; 
	     sctp_tsnmap_next_gap_ack(map, &iter, &start, &end); 
	     i++) {
		/* There should only be one ack. */
		if (i > 1) {
			DUMP_CORE;
		}
	}

	/* Check the start and end of the gap.  */
	if (   3 != start
	    || 3 != end ) {
		DUMP_CORE;
	}

	/* Lets create two more ack blocks.  */
	printf("Testing with 2 more blocks\n");

	/* Add to the existing block. */
	sctp_tsnmap_mark(map, initial_tsn + 3);
	sctp_tsnmap_mark(map, initial_tsn + 4);
	

	/* Create another block. */
	sctp_tsnmap_mark(map, initial_tsn + size - 3);
	sctp_tsnmap_mark(map, initial_tsn + size - 2);

        /* Create a gap across maps.  */
	sctp_tsnmap_mark(map, initial_tsn + size + 3);

	    
	/* Let's hand check each of the blocks. */
	sctp_tsnmap_iter_init(map, &iter);
	
	/* Block #1 */
	printf("Testing Block #1\n");
	if (!sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}
	if ((3 != start) || (5 != end)) {
		DUMP_CORE;
	}
	
	/* Block #2 */

	printf("Testing Block #2\n");
	if (!sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}
	if (((size - 3 + 1) != start) || ((size - 2 + 1) != end)){
		DUMP_CORE;
	}


	/* Block #3 */
	printf("Testing Block #3 (in the overflow map)\n");
	if (!sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	if (((size + 3 + 1) != start) || ((size + 3 + 1) != end)) {
		DUMP_CORE;
	}

	/* There should be no more gaps.  */
	if (sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	printf("Testing block after ctsn moves beyond previous ack block.\n");

	/* Test block when ctsn is in the map.  */
	/* Let's blow away the first block by moving ctsn into it.  */
	sctp_tsnmap_mark(map, initial_tsn);
	sctp_tsnmap_mark(map, initial_tsn + 1);

	if (initial_tsn + 4 != sctp_tsnmap_get_ctsn(map)) {
		DUMP_CORE;
	}

	sctp_tsnmap_iter_init(map, &iter);
	if (0 == sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	/* The ctsn jumped by 5; the block previously started at size - 2 + 1
	 * and ended at size - 3 + 1. 
	 */
        if ( size - 3 - 4 != start
	     || size - 2 - 4 != end) {
		DUMP_CORE;
	}

	
	/* Check that we don't lose ack information when we switch maps.
	 * Check this by filling up the first map. 
	 * The first two tsns of the overflow_map are empty--we will
	 * force a switch by filling the first map and the first entry
	 * of the overflow map.
	 */
	printf("Test rollover not losing overflow's ack information\n");
	for (i = 0; i <= size; i++) {
		sctp_tsnmap_mark(map, initial_tsn + i);
	}
		
	if (MAGIC_NUMBER != storage.scribble) {
		DUMP_CORE;
	}

	/* Sanity check the Cumulative TSN Ack Point */
	if (initial_tsn + size != sctp_tsnmap_get_ctsn(map)) {
		DUMP_CORE;
	}

	/* Check that the ack block that we know exists gets returned. */
	sctp_tsnmap_iter_init(map, &iter);
	if (0 == sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	/* Now hand check that the ack block looks correct.  */
	if ((3 != start) || (3 != end)) {
		DUMP_CORE;
	}

	if (MAGIC_NUMBER != storage.scribble) {
		DUMP_CORE;
	}


        /* Phase 4
	 *
	 */

	/* Reinit the tsnmap back to sanity.  */
	if (NULL == sctp_tsnmap_init(map,
				     size, initial_tsn)) {
		DUMP_CORE;
	}


        /* Test with a gap ack block precisely at the end of the overflow. */
	printf("Testing block ending precisely at end of overflow map.\n");
	sctp_tsnmap_mark(map, initial_tsn + 2 * size - 1);	
	
        /* Check that we find the gap ack block we expect. */
	sctp_tsnmap_iter_init(map, &iter);
	if (0 == sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

        /* Now hand check that the gap ack block looks correct.  */
	if ((size * 2 != start)
	    || (size * 2 != end)) {
		DUMP_CORE;
	}

	/* Test with a gap ack block precisely at the end of the tsnmap. */
	printf("Testing block ending precisely at end of first map.\n");
	sctp_tsnmap_mark(map, initial_tsn + size-1);	
	
        /* Check for the first ack block. */
	sctp_tsnmap_iter_init(map, &iter);
	if (0 == sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	
	/* Now hand check that the ack block looks correct.  */
	if (size != start
	    || size != end) {
		DUMP_CORE;
	}

	/* Check the second block */
	if (0 == sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	/* Now hand check that the ack block looks correct.  */
	if (size * 2 != start
	    || size * 2 != end) {
		DUMP_CORE;
	}


        /* Now create a gap ack block across the maps.   We've previously
	 * tested having a gap across the maps. 
	 */
	printf("Testing block across map boundaries.\n");
	sctp_tsnmap_mark(map, initial_tsn + size);	
	
        /* Check that the first ack block. */
	sctp_tsnmap_iter_init(map, &iter);
	if (0 == sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	
	/* Now hand check that the ack block looks correct.  */
	if (size != start || 
	    size + 1 != end) {
		DUMP_CORE;
	}

	/* Check the second block */
	if (0 == sctp_tsnmap_next_gap_ack(map, &iter, &start, &end)) {
		DUMP_CORE;
	}

	
	/* Now hand check that the ack block looks correct.  */
	if (size * 2 != start || 
	    size * 2 != end) {
		DUMP_CORE;
	}
	        

	if (MAGIC_NUMBER != storage.scribble) {
		DUMP_CORE;
	}

} /* test_tsnmap() */
