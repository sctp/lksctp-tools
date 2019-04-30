# Include these two in all the Makefile.am's!!!
include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.rules

include $(top_srcdir)/Makefile.dirs

# General compilation flags
AM_CPPFLAGS = -I$(top_builddir)/src/include

noinst_LTLIBRARIES = libsctputil.la
libsctputil_la_SOURCES = sctputil.c sctputil.h
libsctputil_la_LDFLAGS =
