  /* -*-c-*-
  **
  ** sctp-tools: Another bindx test.
  ** 
  ** $Id: bindx_test.c,v 1.1.1.1 2002/08/06 22:31:05 inaky Exp $
  **
  ** Distributed under the terms of the GPL v2.0 as described in
  ** $top_srcdir/COPYING. 
  **
  ** (C) Copyright IBM Corp. 2003
  ** (C) 2002 Intel Corporation
  **    Iñaky Pérez-González <inaky.perez-gonzalez@intel.com>:
  **    Sridhar Samudrala <sri@us.ibm.com>
  */

#define _GNU_SOURCE /* GNU extensions */

#include <stdlib.h>     /* malloc() */
#include <arpa/inet.h>  /* inet_pton() */
#include <errno.h>
#include <sys/socket.h> /* socket() */
#include <stdio.h>      /* fprintf */
#include <netinet/in.h> /* sockaddr_in */
#include <unistd.h>     /* close() */
#include <string.h>     /* strchr() */
#include <netinet/sctp.h>   /* bindx() */

  /* Global stuff */

#ifndef IPPROTO_SCTP 
#define IPPROTO_SCTP 132
#endif

  /*! Main function: initialize, setup, run the main loop
  **
  **
  */

int main (int argc, char **argv)
{
	void *addr_buf, *buf_ptr;
	void *addr_buf_size = 0;
	size_t addrs, cnt;
	int sd, result, port;
	int domain = PF_INET6;

	if (argc < 3) {
		fprintf(stderr,
			"Usage: bindx_test PORT IPADDR1 [IPADDR2 [...]]\n");
		return 1;
	}
  
	port = atoi(argv[1]);
	printf("bindx_test: INFO: Port is %d\n", port);

	/* Allocate the maximum space for the specified no. of  addresses.
	 * Assume all of them are v6 addresses.
	 */
	addr_buf = malloc((argc -2) * sizeof(struct sockaddr_in6));
	if (addr_buf == NULL) {
		perror("bindx_test: ERROR: addr buf allocation failed");
		return 1;
	}
  
	/* Get the addresses from the cmd line */
	addrs = 0;  /* healthy address iterator [and total counter] */
	cnt = 2;    /* argument iterator */
	buf_ptr = addr_buf;
	while (cnt < argc) {
		printf("bindx_test: INFO: Arg %zu: %s", cnt, argv[cnt]);
		fflush(stderr);
		if (strchr(argv[cnt], ':')) {
			struct sockaddr_in6 *sa6; 

			sa6 = (struct sockaddr_in6 *)buf_ptr;
			printf(" IPv6 address number %zu", addrs);
			sa6->sin6_family = AF_INET6;
			sa6->sin6_port = port;
			if (inet_pton(AF_INET6, argv[cnt], &sa6->sin6_addr)) {
				addrs++;
				addr_buf_size += sizeof(struct sockaddr_in6);
				buf_ptr += sizeof(struct sockaddr_in6);
			} else
				printf(" error");
		} else if (strchr(argv[cnt], '.')) {
			struct sockaddr_in *sa; 

			domain = PF_INET;
			sa = (struct sockaddr_in *)buf_ptr;
			printf (" IPv4 address number %zu", addrs);
			sa->sin_family = AF_INET;
			sa->sin_port = port;
			if (inet_pton (AF_INET, argv[cnt], &sa->sin_addr)) {
				addrs++;
				addr_buf_size += sizeof(struct sockaddr_in);
				buf_ptr += sizeof(struct sockaddr_in);
			} else
				printf (" error");
		} else
			printf (" Unknown");
		putchar ('\n');
		cnt++;
	}

	printf ("bindx_test: INFO: Got %zu addrs\n", addrs);
  
	/* Create the socket */
	sd = socket(domain, SOCK_SEQPACKET, IPPROTO_SCTP);
	if (sd == -1) {
		perror("bindx_test: ERROR: Cannot open socket");
		return 1;
	}

	/* add all */
	result = sctp_bindx(sd, (struct sockaddr *)addr_buf, addrs,
			    SCTP_BINDX_ADD_ADDR);
	if (result == -1)
		perror("bindx_test: ERROR: bindx addition error");
	else {
		printf("bindx_test: OK: bindx address addition\n");

		/* remove all but the last */
		result = sctp_bindx(sd, (struct sockaddr *)addr_buf, addrs-1,
				     SCTP_BINDX_REM_ADDR);
		if (result == -1)
			perror("bindx_test: ERROR: bindx address removal");
		else
			printf("bindx_test: OK: bindx address removal\n");
	}
  
	close(sd);
	free(addr_buf);
	return result;
}
