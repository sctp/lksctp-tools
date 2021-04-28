dnl -*-autoconf-*-

dnl lksctp-tools: Autoconf script
dnl
dnl $Id: configure.in,v 1.1.1.2 2002/08/06 23:55:45 inaky Exp $

dnl (C) 2002 Intel Corporation
dnl     Iñaky Pérez-González <inaky.perez-gonzalez@intel.com>
dnl      - Initial packaging

dnl Package info
dnl (CONFIG_AUX_DIR is for putting stuff in $TOPSRCDIR/bin, so we
dnl reduce clutter in the root; if we put it below AM_INIT_AUTOMAKE,
dnl configure will fail ...)

AC_INIT([lksctp-tools], [1.0.19], [], [], [http://www.lksctp.org/])
AC_SUBST(LIBSCTP_CURRENT, 1)
AC_SUBST(LIBSCTP_REVISION, 19)
AC_SUBST(LIBSCTP_AGE, 0)
AC_SUBST(LIBWITHSCTP_CURRENT, 1)
AC_SUBST(LIBWITHSCTP_REVISION, 19)
AC_SUBST(LIBWITHSCTP_AGE, 0)

AC_CONFIG_AUX_DIR(bin)
AC_CONFIG_SRCDIR([src/apps/sctp_darn.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_REVISION($Revision: 1.1.1.2 $)
AM_INIT_AUTOMAKE
m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])
AM_SILENT_RULES([yes])

dnl Set defaults
dnl CFLAGS="$CFLAGS -g -Wall"

dnl Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_ISC_POSIX

dnl Checks for libraries.
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h netinet/in.h stdint.h \
		  stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h \
		  sys/time.h unistd.h])
AC_CHECK_HEADERS([linux/sctp.h], [], [], [AC_INCLUDES_DEFAULT
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday memmove memset select socket \
		strchr strerror strtol strtoul])

# Support for stream reset even, added on v4.11, 35ea82d611da
LKSCTP_CHECK_MEMBER([struct sctp_event_subscribe.sctp_stream_reset_event],
		    [HAVE_SCTP_STREAM_RESET_EVENT])

# RFC 6525 (Stream Reconf), finished on v4.12, c0d8bab6ae51
LKSCTP_CHECK_DECL([SCTP_RECONFIG_SUPPORTED], [HAVE_SCTP_STREAM_RECONFIG])

# sctp_peeloff_flags was added on v4.13, 2cb5c8e378d1
LKSCTP_CHECK_TYPE([sctp_peeloff_flags_arg_t], [HAVE_SCTP_PEELOFF_FLAGS])

# New members to sctp_pdapi_event, added on v4.16, 65f5e357839e
LKSCTP_CHECK_MEMBER([struct sctp_pdapi_event.pdapi_stream],
		    [HAVE_SCTP_PDAPI_EVENT_PDAPI_STREAM])
LKSCTP_CHECK_MEMBER([struct sctp_pdapi_event.pdapi_seq],
		    [HAVE_SCTP_PDAPI_EVENT_PDAPI_SEQ])

# PR-SCTP struct used to probe for sendv/recvv support, added on v4.17
LKSCTP_CHECK_TYPE([struct sctp_prinfo], [HAVE_SCTP_SENDV])

# This event indicates that the peer does not support SCTP authentication,
# added on v4.16, 30f6ebf65bc4
LKSCTP_CHECK_DECL([SCTP_AUTH_NO_AUTH], [HAVE_SCTP_AUTH_NO_AUTH])

# New members to sctp_paddrparams, added on v4.19, 0b0dce7a36fb
LKSCTP_CHECK_MEMBER([struct sctp_paddrparams.spp_ipv6_flowlabel],
		    [HAVE_SCTP_SPP_IPV6_FLOWLABEL])
LKSCTP_CHECK_MEMBER([struct sctp_paddrparams.spp_dscp],
		    [HAVE_SCTP_SPP_DSCP])

AC_CONFIG_HEADERS([src/include/netinet/sctp.h])
AC_CONFIG_FILES([lksctp-tools.spec
		Makefile
		bin/Makefile
		man/Makefile
		src/Makefile
		src/apps/Makefile
		src/func_tests/Makefile
		src/include/Makefile
		src/include/netinet/Makefile
		src/lib/Makefile
		src/testlib/Makefile
		src/withsctp/Makefile
		doc/Makefile
		libsctp.pc])

# Build options
AC_ARG_ENABLE(tests,
	AS_HELP_STRING([--disable-tests],
	[Build tests (default: yes)]),,
	[enable_tests=yes])
AM_CONDITIONAL(BUILD_TESTS, [test $enable_tests != no])

# GCC tries to be "helpful" and only issue a warning for unrecognized
# attributes.  So we compile the test with Werror, so that if the
# attribute is not recognized the compilation fails
AC_LANG(C)
AC_LANG_WERROR
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[__attribute__ ((symver ("foo@foo_1"))) void frob (void) { }]])],
                  [AC_DEFINE([HAVE_ATTRIBUTE_SYMVER], [1], [Checking for symver attribute])], [])

AC_OUTPUT
