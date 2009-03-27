# Include these two in all the Makefile.am's!!!
include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.rules

include $(top_srcdir)/Makefile.dirs

# General compilation flags
INCLUDES = -I$(top_srcdir)/src/include

noinst_LTLIBRARIES = libsctputil.la
libsctputil_la_SOURCES = sctputil.c sctputil.h
libsctputil_la_LDFLAGS = -version-info 1:10:0
