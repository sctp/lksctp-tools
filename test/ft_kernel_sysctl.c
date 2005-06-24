/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2002, 2003
 * 
 * This is a functional test to verify the access to SCTP sysctl variables.
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
 *    Jon Grimm   <jgrimm@us.ibm.com>
 *
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <linux/compiler.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <linux/sysctl.h> 

#define SIZE(x) sizeof(x)/sizeof(x[0])
#define OSNAMESZ 100

#define test_sctp_sysctl_var(name, readonly) \
test_var((name), (#name),(readonly))

extern int sysctl(int *, int, void *, size_t *, void *, size_t);

/* Test the given 'varnam' SCTP sysctl variable. */
int test_var(int varname, char *strname, int readonly)
{
	int newval, oldval, err;
	size_t newlen, oldlen;
	int name[] = { CTL_NET, NET_SCTP, 0};

	name[2] = varname;

	printf("Testing sysctl var %s(%d)\n", strname, varname);

	oldlen = sizeof(oldlen);

	err = sysctl(name, SIZE(name), &oldval, &oldlen, 0, 0);
	if (err) {
		printf("sysctl: %s\n", strerror(errno));
		return err;
	} else {
		printf("%s(%d) = %d\n", strname, varname, oldval);
	}

	if (readonly) { return err; }

	newval = oldval+1;
	newlen = sizeof(newval);

	printf("Write test.\n");
	err = sysctl(name, SIZE(name), &oldval, &oldlen, &newval, newlen);
	if (err) {
		printf("sysctl: %s\n", strerror(errno));
		return err;
	}

	err = sysctl(name, SIZE(name), &newval, &newlen, 0, 0);
	if (err) {
		printf("sysctl: %s\n", strerror(errno));
		return err;
	}  else {
		printf("%s(%d) = %d\n", strname, varname, newval);
	}

	
	/* Put back the original value. */
	printf("Put back original value %d\n", oldval);
	err = sysctl(name, SIZE(name), 0, 0, &oldval, oldlen);

	if (err) {
		printf("sysctl: %s\n", strerror(errno));
		printf("Could not put back original value.\n");
	}

	return err;

} /* test_var() */


int main(int argc, char **argv)
{
	int err, readonly;
	char osname[OSNAMESZ];
	int osnamelth;
	int name[] = { CTL_KERN, KERN_OSTYPE};

	/* Rather than fflush() throughout the code, set stdout to 
	 * be unbuffered. 
	 */
	setvbuf(stdout, NULL, _IONBF, 0); 
	
	printf("Test setting getting the various SCTP sysctl variables.\n");

	/* Simple test to test sysctl access.  This comes from the
	 * sysctl(2) man pages.
	 */
	osnamelth = SIZE(osname);
	if (sysctl(name, SIZE(name), osname, &osnamelth, 0, 0)) {
		printf("sysctl: %s\n", strerror(errno));
		/* Don't bother running this test if sysctl doesn't 
		 * even work.
		 */
		return 0;
	} else {
		printf("This machine is running %*s.\n", osnamelth, osname);
	}

	/* Quick test to see if we should do a readonly test.  Only
	 * root is going to be able to write to these vars.
	 */
	readonly = 0;
	err = test_sctp_sysctl_var(NET_SCTP_RTO_INITIAL, readonly);

	if (err) {
		if ((EPERM == errno) || (EACCES == errno)) {
			printf("Permission error.  Try readonly testing.\n");
			readonly = 1;
		} else {
			exit(err);
		}
	}

	test_sctp_sysctl_var(NET_SCTP_RTO_MIN, readonly);
	test_sctp_sysctl_var(NET_SCTP_RTO_MAX, readonly);
	test_sctp_sysctl_var(NET_SCTP_RTO_ALPHA, readonly);
	test_sctp_sysctl_var(NET_SCTP_RTO_BETA, readonly);
	test_sctp_sysctl_var(NET_SCTP_VALID_COOKIE_LIFE, readonly);
	test_sctp_sysctl_var(NET_SCTP_ASSOCIATION_MAX_RETRANS, readonly);
	test_sctp_sysctl_var(NET_SCTP_PATH_MAX_RETRANS, readonly);
	test_sctp_sysctl_var(NET_SCTP_MAX_INIT_RETRANSMITS, readonly);
	test_sctp_sysctl_var(NET_SCTP_HB_INTERVAL, readonly);
	test_sctp_sysctl_var(NET_SCTP_MAX_BURST, readonly);	

	return 0;

} /* main() */ 

