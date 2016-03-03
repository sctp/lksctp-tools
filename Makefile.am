include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.rules

DISTCLEANFILES += config.h stamp-h libtool
MAINTAINERCLEANFILES += aclocal.m4 config.h.in configure stamp-h.in \
			config.h stamp-h

EXTRA_DIST += ChangeLog AUTHORS COPYING COPYING.lib INSTALL \
	README ROADMAP NEWS \
	Makefile.vars Makefile.rules Makefile.dirs

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsctp.pc
EXTRA_DIST += libsctp.pc.in
DISTCLEANFILES += libsctp.pc

# bin or src products may be required to generate stuff in test/
SUBDIRS = man bin src doc

ACLOCAL_AMFLAGS=-I m4

# Libtool support
LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

## FIXME: Your stuff here
