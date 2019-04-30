# Include these two in all the Makefile.am's!!!
include $(top_srcdir)/Makefile.vars
include $(top_srcdir)/Makefile.rules
include $(top_srcdir)/Makefile.dirs

# General compilation flags
AM_CPPFLAGS = -I. -I$(top_builddir)/src/include -I$(top_srcdir)/src/testlib \
              -g -O2 -fno-strict-aliasing -Wall -Wstrict-prototypes \
              -Wimplicit-function-declaration

AM_LDFLAGS = -lpthread

LDADD = $(top_builddir)/src/testlib/libsctputil.la \
	$(top_builddir)/src/lib/libsctp.la

V6FLAGS = -DCONFIG_IPV6=1 -DTEST_V6=1 ${DEFS} ${INCLUDES} ${CFLAGS}

# Test programs and libraries to build
PASSING_KERN_TESTS = \
	test_assoc_abort \
	test_assoc_shutdown \
	test_autoclose \
	test_basic \
	test_fragments \
	test_inaddr_any \
	test_peeloff \
	test_sockopt \
	test_connect \
	test_connectx \
	test_recvmsg \
	test_timetolive \
	test_sctp_sendrecvmsg \
	test_getname \
	test_tcp_style\
	test_1_to_1_socket_bind_listen \
	test_1_to_1_accept_close \
	test_1_to_1_connect \
	test_1_to_1_connectx \
	test_1_to_1_send \
	test_1_to_1_sendto \
	test_1_to_1_sendmsg \
	test_1_to_1_recvfrom \
	test_1_to_1_recvmsg \
	test_1_to_1_shutdown \
	test_1_to_1_sockopt \
	test_1_to_1_addrs \
	test_1_to_1_nonblock \
	test_1_to_1_rtoinfo \
	test_1_to_1_events \
	test_1_to_1_threads \
	test_1_to_1_initmsg_connect

PASSING_V6_KERN_TESTS = \
	test_basic_v6 \
	test_sockopt_v6 \
	test_fragments_v6 \
	test_inaddr_any_v6 \
	test_peeloff_v6 \
	test_timetolive_v6 \
	test_sctp_sendrecvmsg_v6 \
	test_getname_v6 \
	test_tcp_style_v6

if HAVE_SCTP_SENDV
PASSING_KERN_TESTS += \
	test_sctp_sendvrecvv
PASSING_V6_KERN_TESTS += \
	test_sctp_sendvrecvv_v6
endif

noinst_PROGRAMS = ${PASSING_KERN_TESTS} ${PASSING_V6_KERN_TESTS}

$(top_builddir)/src/lib/libsctp.la:
	$(MAKE) -C $(top_builddir)/src/lib libsctp.la

$(top_builddir)/src/testlib/libsctputil.la:
	$(MAKE) -C $(top_builddir)/src/testlib libsctputil.la

# These are tests for live kernels which pass.
v4test: ${PASSING_KERN_TESTS}
	@for a in $^;				\
	do 					\
		echo "./$$a";			\
		if ./$$a;			\
		then				\
			echo "$$a passes";	\
			echo "";		\
		else				\
			echo "$$a fails";	\
			exit 1;			\
		fi;				\
		sleep 1;			\
	done
	@echo "Hoody hoo!"

# These are tests for live kernels which pass.
v6test: ${PASSING_V6_KERN_TESTS}
	@for a in $^;				\
	do 					\
		echo "./$$a";			\
		if ./$$a;			\
		then				\
			echo "$$a passes";	\
			echo "";		\
		else				\
			echo "$$a fails";	\
			exit 1;			\
		fi;				\
		sleep 1;			\
	done
	@echo "Hoody hoo!"

# Specifying the sources
test_assoc_abort_SOURCES = test_assoc_abort.c 
test_assoc_shutdown_SOURCES = test_assoc_shutdown.c 
test_autoclose_SOURCES = test_autoclose.c 
test_basic_SOURCES = test_basic.c 
test_fragments_SOURCES = test_fragments.c 
test_inaddr_any_SOURCES = test_inaddr_any.c 
test_peeloff_SOURCES = test_peeloff.c 
test_sockopt_SOURCES = test_sockopt.c 
test_connect_SOURCES = test_connect.c 
test_connectx_SOURCES = test_connectx.c 
test_recvmsg_SOURCES = test_recvmsg.c 
test_timetolive_SOURCES = test_timetolive.c
test_sctp_sendrecvmsg_SOURCES = test_sctp_sendrecvmsg.c
test_sctp_sendvrecvv_SOURCES = test_sctp_sendvrecvv.c
test_getname_SOURCES = test_getname.c 
test_tcp_style_SOURCES = test_tcp_style.c 

test_1_to_1_socket_bind_listen_SOURCES = test_1_to_1_socket_bind_listen.c
test_1_to_1_accept_close_SOURCES = test_1_to_1_accept_close.c
test_1_to_1_connect_SOURCES = test_1_to_1_connect.c
test_1_to_1_connectx_SOURCES = test_1_to_1_connectx.c
test_1_to_1_send_SOURCES = test_1_to_1_send.c
test_1_to_1_sendto_SOURCES = test_1_to_1_sendto.c
test_1_to_1_sendmsg_SOURCES = test_1_to_1_sendmsg.c
test_1_to_1_recvfrom_SOURCES = test_1_to_1_recvfrom.c
test_1_to_1_recvmsg_SOURCES = test_1_to_1_recvmsg.c
test_1_to_1_shutdown_SOURCES = test_1_to_1_shutdown.c
test_1_to_1_sockopt_SOURCES = test_1_to_1_sockopt.c
test_1_to_1_addrs_SOURCES = test_1_to_1_addrs.c
test_1_to_1_nonblock_SOURCES = test_1_to_1_nonblock.c
test_1_to_1_rtoinfo_SOURCES = test_1_to_1_rtoinfo.c
test_1_to_1_events_SOURCES = test_1_to_1_events.c
test_1_to_1_threads_SOURCES = test_1_to_1_threads.c
test_1_to_1_initmsg_connect_SOURCES = test_1_to_1_initmsg_connect.c

#
# Specifying objects rules for "v6test"
#
test_basic_v6_SOURCES = test_basic.c
test_basic_v6_CFLAGS = ${V6FLAGS}

test_sockopt_v6_SOURCES = test_sockopt.c
test_sockopt_v6_CFLAGS = ${V6FLAGS}

test_fragments_v6_SOURCES = test_fragments.c
test_fragments_v6_CFLAGS = ${V6FLAGS}

test_inaddr_any_v6_SOURCES = test_inaddr_any.c
test_inaddr_any_v6_CFLAGS = ${V6FLAGS}

test_peeloff_v6_SOURCES = test_peeloff.c
test_peeloff_v6_CFLAGS = ${V6FLAGS}

test_timetolive_v6_SOURCES = test_timetolive.c
test_timetolive_v6_CFLAGS = ${V6FLAGS}

test_sctp_sendrecvmsg_v6_SOURCES = test_sctp_sendrecvmsg.c
test_sctp_sendvrecvv_v6_SOURCES = test_sctp_sendvrecvv.c
test_sctp_sendrecvmsg_v6_CFLAGS = ${V6FLAGS}
test_sctp_sendvrecvv_v6_CFLAGS = ${V6FLAGS}

test_getname_v6_SOURCES = test_getname.c
test_getname_v6_CFLAGS = ${V6FLAGS}

test_tcp_style_v6_SOURCES = test_tcp_style.c
test_tcp_style_v6_CFLAGS = ${V6FLAGS}
