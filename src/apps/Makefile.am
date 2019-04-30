# Include these two in all the Makefile.am's!!!
include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.rules
include $(top_srcdir)/Makefile.dirs

# General compilation flags
AM_CPPFLAGS = -I. -I$(top_builddir)/src/include -I$(top_srcdir)/src/testlib \
              -g -O2 -fno-strict-aliasing -Wall -Wstrict-prototypes \
              -Wimplicit-function-declaration

AM_LDFLAGS = 

LDADD = $(top_builddir)/src/testlib/libsctputil.la \
	$(top_builddir)/src/lib/libsctp.la

# programs to be installed with the distriubution
bin_PROGRAMS = sctp_darn sctp_test sctp_status

# Test programs and libraries to build
noinst_PROGRAMS = bindx_test nagle_snd nagle_rcv myftp sctp_xconnect \
	peel_server peel_client sctp_test sctp_status

$(top_builddir)/src/lib/libsctp.la:
	$(MAKE) -C $(top_builddir)/src/lib libsctp.la

$(top_builddir)/src/testlib/libsctputil.la:
	$(MAKE) -C $(top_builddir)/src/testlib libsctputil.la

# Specifying the sources
bindx_test_SOURCES = bindx_test.c
sctp_darn_SOURCES = sctp_darn.c sctp_darn.h
sctp_test_SOURCES = sctp_test.c
sctp_status_SOURCES = sctp_status.c
nagle_rcv_SOURCES = nagle_rcv.c 
nagle_snd_SOURCES = nagle_snd.c 
myftp_SOURCES = myftp.c
sctp_xconnect_SOURCES = sctp_xconnect.c
peel_server_SOURCES = peel_server.c
peel_client_SOURCES = peel_client.c

# Tutorials
pkgdoc_DATA = sctp_darn.c sctp_darn.h sctp_test.c sctp_status.c
