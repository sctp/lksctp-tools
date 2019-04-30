# Include these two in all the Makefile.am's!!!
include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.rules
include $(top_srcdir)/Makefile.dirs

# General compilation flags
AM_CPPFLAGS = -I$(top_builddir)/src/include

lib_LTLIBRARIES = libsctp.la

libsctp_la_SOURCES = bindx.c connectx.c peeloff.c opt_info.c \
		addrs.c sendmsg.c recvmsg.c Versions.map
libsctp_la_LDFLAGS = -version-info \
		@LIBSCTP_CURRENT@:@LIBSCTP_REVISION@:@LIBSCTP_AGE@ \
		-Wl,--version-script=$(srcdir)/Versions.map
