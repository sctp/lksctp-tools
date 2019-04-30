# -*- Makefile -*-
#
# The author (La Monte H.P. Yarroll) disclaims copyright on this file.
#

include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.dirs
include $(top_srcdir)/Makefile.rules

bin_PROGRAMS = checksctp
bin_SCRIPTS = withsctp

AM_CPPFLAGS=-I$(top_builddir)/src/include
pkglib_LTLIBRARIES = libwithsctp.la
libwithsctp_la_SOURCES = sctp_load_libs.c sctp_socket.c sctp_bind.c \
	sctp_sockopt.c sctp_socket.h
libwithsctp_la_LDFLAGS = -version-info \
	@LIBWITHSCTP_CURRENT@:@LIBWITHSCTP_REVISION@:@LIBWITHSCTP_AGE@ -ldl

pkgdoc_DATA = sctp_load_libs.c sctp_socket.c sctp_bind.c \
	sctp_sockopt.c sctp_socket.h checksctp.c

withsctp: withsctp.in
	$(edit) $< >$@

EXTRA_DIST += withsctp.in

CLEANFILES += withsctp
