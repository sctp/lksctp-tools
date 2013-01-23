# Include these two in all the Makefile.am's!!!
include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.rules

include $(top_srcdir)/Makefile.dirs

# General compilation flags
INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = libsctp.la
libsctp_la_SOURCES = bindx.c connectx.c peeloff.c opt_info.c addrs.c sendmsg.c recvmsg.c Versions.map
libsctp_la_LDFLAGS = -version-info 1:13:0 -Wl,--version-script=$(srcdir)/Versions.map
