ifndef LKSCTP_LINUX
LKSCTP_LINUX=../../lksctp-2.6
endif
ROOT=${LKSCTP_LINUX}/net/sctp
KERN_LIB=${LKSCTP_LINUX}/lib
INCLUDE=./linux/include
INCLUDE_USR=../src/include
INCLUDE_LINUX=${LKSCTP_LINUX}/include/linux
INCLUDE_SCTP=${LKSCTP_LINUX}/include/net/sctp

MACH_INCLUDES=${LKSCTP_LINUX}/include/asm-x86/mach-default
INCLUDES=-I. -I${INCLUDE} -I${LKSCTP_LINUX}/include -I${MACH_INCLUDES}
USER_INCLUDES=-I. -I${INCLUDE_USR}

WARNINGS=-Wall -Wstrict-prototypes -Wimplicit-function-declaration

CFLAGS=-g ${INCLUDES} ${WARNINGS} -DTEST_FRAME=1 \
	-D__KERNEL__=1 -DSCTP_DEBUG=1 -DSCTP_STATIC= -DKBUILD_BASENAME= \
	-imacros ${INCLUDE_LINUX}/autoconf.h

USER_CFLAGS=-g ${WARNINGS} ${USER_INCLUDES}

LIBRARY_OBJECTS= kernel_funutil.o kernel_funutil_v6.o

include ${LKSCTP_LINUX}/.config

COMMON_OBJECTS= \
	sm_statetable.o \
	sm_statefuns.o \
	sm_sideeffect.o \
	protocol.o \
	\
	endpointola.o \
	associola.o \
	transport.o \
	sm_make_chunk.o \
	chunk.o \
	inqueue.o \
	outqueue.o \
	tsnmap.o \
	ssnmap.o \
	ulpevent.o \
	ulpqueue.o \
	\
	socket.o \
	primitive.o \
	output.o \
	input.o \
	\
	command.o \
	bind_addr.o \
	\
	debug.o \
	proc.o \
	auth.o

ifdef CONFIG_IPV6	
COMMON_OBJECTS += ipv6.o
V6FLAGS=-DCONFIG_IPV6=1 -DTEST_V6=1 
endif

KERN_LIB_OBJECTS= \
	scatterlist.o \
	libcrc32c.o \
	find_next_bit.o \
	bitmap.o \
	hweight.o \
	vsprintf.o \
	ctype.o

SCTP_HEADERS= \
	${INCLUDE_LINUX}/sctp.h \
	${INCLUDE_SCTP}/sctp.h \
	${INCLUDE_SCTP}/structs.h \
	${INCLUDE_SCTP}/constants.h \
	${INCLUDE_SCTP}/sm.h \


FRAME_OBJECTS=test_kernel.o funutil.o ${COMMON_OBJECTS} ${KERN_LIB_OBJECTS}

FRAME_V6_OBJECTS=test_kernel_v6.o funutil_v6.o ${COMMON_OBJECTS} \
		 ${KERN_LIB_OBJECTS}

PASSING_UNIT_TESTS = \
	test_inqueue \
	test_ulpqueue \
	test_packet \
	test_command \
	test_sn_compare \
	test_tsnmap \
	test_cmsgs \
	test_ulpevent \

PASSING_FRAME_TESTS = \
	ft_frame_basic \
	ft_frame_hbACK \
	ft_frame_lostpackets \
	ft_frame_lostpacket \
	ft_frame_evenpackets \
	ft_frame_abort \
	ft_frame_no_data \
	ft_frame_send_failed \
	ft_frame_ecn_negotiate \
	ft_frame_ecn_basic \
	ft_frame_init_ack \
	ft_frame_rwnd_sender \
	ft_frame_sack \
	ft_frame_port \
	ft_frame_local_addr \
	ft_frame_getfreeaddrs \
	ft_frame_sndrcvinfo \
	ft_frame_dftsndparam \
	ft_frame_bindx \
	ft_frame_nobind \
	ft_frame_addr_cookie \
	ft_frame_init_timer \
	ft_frame_rtx_timer \
	ft_frame_t2_shutdown_timer \
	ft_frame_shutdown \
	ft_frame_init_streams \
	ft_frame_sockopt \
	ft_frame_fragments \
	ft_frame_maxseg \
	ft_frame_lostlink \
	ft_frame_rto \
	ft_frame_rto_sockopt \
	ft_frame_ootb \
	ft_frame_biggap \
	ft_frame_tsnmap_rollover \
	ft_frame_congestion \
	ft_frame_assoc_shutdown \
	ft_frame_assoc_abort\
	ft_frame_autoclose \
	ft_frame_peeloff \
	ft_frame_init1 \
	ft_frame_init2 \
	ft_frame_crossinit \
	ft_frame_init4 \
	ft_frame_init5 \
	ft_frame_stale_cookie \
	ft_frame_missing_cookie \
	ft_frame_lost_cookie_ack \
	ft_frame_restart \
	ft_frame_unkparam \
	ft_frame_unkchunk \
	ft_frame_tx_bug1 \
	ft_frame_multihoming \
	ft_frame_rtx_order \
	ft_frame_rtx_gapack \
	ft_frame_source_addr \
	ft_frame_addrover \
	ft_frame_lost_cwr \
	ft_frame_heartbeat \
	ft_frame_connect \
	ft_frame_connectx \
	ft_frame_connectx_t1_timer \
	ft_frame_connectx_t1_timer_fail \
	ft_frame_connectx_collision1 \
	ft_frame_connectx_collision2 \
	ft_frame_connectx_collision3 \
	ft_frame_recvmsg \
	ft_frame_rwnd_receiver \
	ft_frame_part_delivery \
	ft_frame_renege \
	ft_frame_pmtu \
	ft_frame_bigdata \
	ft_frame_retran_path \
	ft_frame_basic_nat \
	ft_frame_tcp_style \
	ft_frame_CACC \
	ft_frame_kamikaze \
	ft_frame_addip_set_prim \
	ft_frame_addip_bindx \
	ft_frame_delip_bindx \
	ft_frame_t4_timer \
	ft_frame_prsctp \
	ft_frame_invalid_length \
	ft_frame_cookie_ports \
	ft_frame_hb_rtx \
	ft_frame_frag_interleave \
	ft_frame_bind \
	ft_frame_fast_rtx

PASSING_V6_FRAME_TESTS = \
	ft_frame_basic_v6 \
	ft_frame_sockopt_v6 \
	ft_frame_bindx_v6 \
	ft_frame_heartbeat_v6 \
	ft_frame_connectx_v6 \
	ft_frame_connectx_t1_timer_v6 \
	ft_frame_connectx_t1_timer_fail_v6 \
	ft_frame_connectx_collision1_v6 \
	ft_frame_connectx_collision2_v6 \
	ft_frame_connectx_collision3_v6 \
	ft_frame_nobind_v6 \
	ft_frame_v4_mapped_v6 \
	ft_frame_local_addr_v6 \
	ft_frame_source_addr_v6 \
	ft_frame_ecn_basic_v6 \
	ft_frame_peeloff_v6 \
	ft_frame_tcp_style_v6 \
	ft_frame_getfreeaddrs_v6 \
	ft_frame_addip_set_prim_v6 \
	ft_frame_addip_bindx_v6 \
	ft_frame_delip_bindx_v6 \
	ft_frame_t4_timer_v6 \
	ft_frame_addrover_v6 \
	ft_frame_v6only \
	ft_frame_bind

FAILING_TESTS = \
	ft_frame_init_bomb

FAILING_V6_FRAME_TESTS = \
	ft_frame_fragments_v6 \
	ft_frame_maxseg_v6

TARGETS = ${PASSING_UNIT_TESTS} ${PASSING_FRAME_TESTS}
#ifdef CONFIG_IPV6
TARGETS += ${PASSING_V6_FRAME_TESTS} ${FAILING_V6_FRAME_TESTS} \
#endif
TARGETS += ${FAILING_TESTS}

all:	${TARGETS}

run1: $(RUN1)
	@a=$^;				\
	echo "./$$a";			\
	if ./$$a;			\
	then				\
		echo "$$a passes";	\
		echo "";		\
	else				\
		echo "$$a fails";	\
		exit 1;			\
	fi;				\
	

unit_test: ${PASSING_UNIT_TESTS}
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
	done
	@echo "Yahoo!"

frame_test:  ${PASSING_FRAME_TESTS}
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
	done
	@echo "Yippee!"

ifdef CONFIG_IPV6
framev6_test:  ${PASSING_V6_FRAME_TESTS}
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
	done
	@echo "Yippee!"
else
framev6_test:
	@echo -n "IPv6 is disabled in your kernel config."
	@echo "Please enable it and rebuild your frame tests."
endif


# These are functional tests which are known to fail.
# Works In Progress
wip: ${FAILING_TESTS} ${FAILING_V6_FRAME_TESTS}
	@for a in $^;				\
	do 					\
		echo "./$$a";			\
		if ./$$a;			\
		then				\
			echo "Oh no!  $$a passes?";	\
			exit 1;			\
		else				\
			echo "Good, $$a still fails.";	\
			echo "";		\
		fi;				\
	done
	rm -f core
	@echo "They all still fail.  Great.  Just great."

# These are tests for live kernels which pass.
kern_test: ${PASSING_KERN_TESTS}
	make -C ../src/func_tests v4test			
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
	done
	@echo "Hoody hoo!"


# These are tests for live kernels which pass.
ifdef CONFIG_IPV6
kernv6_test: ${PASSING_V6_KERN_TESTS}
	make -C ../src/func_tests v6test			
	@echo "Hoody hoo!"
else
kernv6_test:
	@echo -n "IPv6 is disabled in your kernel config."
	@echo "Please enable it and rebuild your kernel tests."
endif

# These are functional tests for live kernels which are known to fail.
# Kernel Works In Progress
kwip: ${FAILING_KERN_TESTS}
	@for a in $^;				\
	do 					\
		echo "./$$a";			\
		if ./$$a;			\
		then				\
			echo "Oh no!  $$a passes?";	\
			exit 1;			\
		else				\
			echo "Good, $$a still fails.";	\
			echo "";		\
		fi;				\
	done
	rm -f core
	@echo "They all still fail.  Great.  Just great."

ft_frame_basic: ft_frame_basic.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_basic_v6: ft_frame_basic_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_basic_nat: ft_frame_basic_nat.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_abort: ft_frame_abort.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_no_data: ft_frame_no_data.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_send_failed: ft_frame_send_failed.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_init_bomb: ft_frame_init_bomb.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_init_ack: ft_frame_init_ack.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_lostpackets: ft_frame_lostpackets.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_lostpacket: ft_frame_lostpacket.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_lostlink: ft_frame_lostlink.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_evenpackets: ft_frame_evenpackets.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_init_timer: ft_frame_init_timer.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_rtx_timer: ft_frame_rtx_timer.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_t2_shutdown_timer: ft_frame_t2_shutdown_timer.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_shutdown: ft_frame_shutdown.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_rto: ft_frame_rto.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_congestion: ft_frame_congestion.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_assoc_shutdown: ft_frame_assoc_shutdown.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_assoc_abort: ft_frame_assoc_abort.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_hbACK: ft_frame_hbACK.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_init1: ft_frame_init1.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_init2: ft_frame_init2.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_crossinit: ft_frame_crossinit.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_init4: ft_frame_init4.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_init5: ft_frame_init5.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_restart: ft_frame_restart.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_stale_cookie: ft_frame_stale_cookie.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_missing_cookie: ft_frame_missing_cookie.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_lost_cookie_ack: ft_frame_lost_cookie_ack.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_port: ft_frame_port.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_local_addr: ft_frame_local_addr.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_local_addr_v6: ft_frame_local_addr_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_source_addr_v6: ft_frame_source_addr_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_ecn_negotiate: ft_frame_ecn_negotiate.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_lost_cwr: ft_frame_lost_cwr.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_ecn_basic_v6: ft_frame_ecn_basic_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_ecn_basic: ft_frame_ecn_basic.o  ${FRAME_OBJECTS}

ft_frame_tsnmap_rollover: ft_frame_tsnmap_rollover.o  ${FRAME_OBJECTS}

ft_frame_rwnd_receiver: ft_frame_rwnd_receiver.o  ${FRAME_OBJECTS}

ft_frame_rwnd_sender: ft_frame_rwnd_sender.o  ${FRAME_OBJECTS}

ft_frame_biggap: ft_frame_biggap.o  ${FRAME_OBJECTS}

ft_frame_sack: ft_frame_sack.o  ${FRAME_OBJECTS}

ft_frame_sndrcvinfo: ft_frame_sndrcvinfo.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_dftsndparam: ft_frame_dftsndparam.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_bindx: ft_frame_bindx.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_bindx_v6: ft_frame_bindx_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_heartbeat_v6: ft_frame_heartbeat_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_v6: ft_frame_connectx_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_t1_timer_v6: ft_frame_connectx_t1_timer_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_t1_timer_fail_v6: ft_frame_connectx_t1_timer_fail_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} -DTEST_FAIL=1 ${CFLAGS} -o $@ $^

ft_frame_connectx_collision1_v6: ft_frame_connectx_collision1_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_collision2_v6: ft_frame_connectx_collision2_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_collision3_v6: ft_frame_connectx_collision3_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_sockopt: ft_frame_sockopt.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_rto_sockopt: ft_frame_rto_sockopt.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_sockopt_v6: ft_frame_sockopt_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_fragments: ft_frame_fragments.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_maxseg: ft_frame_maxseg.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_autoclose: ft_frame_autoclose.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_peeloff: ft_frame_peeloff.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_peeloff_v6: ft_frame_peeloff_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_fragments_v6: ft_frame_fragments_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_maxseg_v6: ft_frame_maxseg_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_nobind: ft_frame_nobind.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_nobind_v6: ft_frame_nobind_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_init_streams: ft_frame_init_streams.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_addr_cookie: ft_frame_addr_cookie.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_source_addr: ft_frame_source_addr.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_addrover: ft_frame_addrover.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_getfreeaddrs: ft_frame_getfreeaddrs.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_addip_set_prim: ft_frame_addip_set_prim.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_delip_set_prim: ft_frame_delip_set_prim.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_ootb: ft_frame_ootb.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_unkchunk: ft_frame_unkchunk.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_unkparam: ft_frame_unkparam.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_fast_rtx: ft_frame_fast_rtx.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_tx_bug1: ft_frame_tx_bug1.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_multihoming: ft_frame_multihoming.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_rtx_order: ft_frame_rtx_order.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_rtx_gapack: ft_frame_rtx_gapack.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_tcp_style: ft_frame_tcp_style.o  ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_tcp_style_v6: ft_frame_tcp_style_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_v4_mapped_v6: ft_frame_v4_mapped_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_v6only: ft_frame_v6only.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_getfreeaddrs_v6: ft_frame_getfreeaddrs_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_addip_set_prim_v6: ft_frame_addip_set_prim_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_CACC: ft_frame_CACC.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_kamikaze: ft_frame_kamikaze.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_addrover_v6: ft_frame_addrover_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_addip_bindx: ft_frame_addip_bindx.o   ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 -o $@ $^

ft_frame_delip_bindx: ft_frame_delip_bindx.o   ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 -o $@ $^

ft_frame_addip_bindx_v6: ft_frame_addip_bindx_v6.o ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_delip_bindx_v6: ft_frame_delip_bindx_v6.o  ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_t4_timer: ft_frame_t4_timer.o   ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 -o $@ $^

ft_frame_t4_timer_v6: ft_frame_t4_timer_v6.o ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_prsctp: ft_frame_prsctp.o   ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 -o $@ $^

ft_frame_basic.o: ft_frame_basic.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_basic_v6.o: ft_frame_basic.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_basic_nat.o: ft_frame_basic_nat.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_nobind_v6.o: ft_frame_nobind.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_bindx.o: ft_frame_bindx.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_bindx_v6.o: ft_frame_bindx.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_heartbeat_v6.o: ft_frame_heartbeat.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_v6.o: ft_frame_connectx.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_t1_timer_v6.o: ft_frame_connectx_t1_timer.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_t1_timer_fail_v6.o: ft_frame_connectx_t1_timer.c
	${CC} -c ${V6FLAGS} -DTEST_FAIL=1 ${CFLAGS} -o $@ $^

ft_frame_connectx_t1_timer_fail.o: ft_frame_connectx_t1_timer.c
	${CC} -c -DTEST_FAIL=1 ${CFLAGS} -o $@ $^

ft_frame_connectx_collision1_v6.o: ft_frame_connectx_collision1.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_collision2_v6.o: ft_frame_connectx_collision2.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_connectx_collision3_v6.o: ft_frame_connectx_collision3.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_sockopt.o: ft_frame_sockopt.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_rto_sockopt.o: ft_frame_rto_sockopt.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_sockopt_v6.o: ft_frame_sockopt.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_fragments.o: ft_frame_fragments.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_maxseg.o: ft_frame_maxseg.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_autoclose.o: ft_frame_autoclose.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_peeloff.o: ft_frame_peeloff.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_peeloff_v6.o: ft_frame_peeloff.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_fragments_v6.o: ft_frame_fragments.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_maxseg_v6.o: ft_frame_maxseg.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_local_addr.o: ft_frame_local_addr.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_local_addr_v6.o: ft_frame_local_addr.c
	${CC} -c ${V6FLAGS}  ${CFLAGS} -o $@ $^

ft_frame_source_addr_v6.o: ft_frame_source_addr.c
	${CC} -c ${V6FLAGS}  ${CFLAGS} -o $@ $^

ft_frame_ecn_basic_v6.o: ft_frame_ecn_basic.c
	${CC} -c ${V6FLAGS}  ${CFLAGS} -o $@ $^

ft_frame_tcp_style.o: ft_frame_tcp_style.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_tcp_style_v6.o: ft_frame_tcp_style.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_v4_mapped_v6.o: ft_frame_v4_mapped_v6.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_getfreeaddrs_v6.o: ft_frame_getfreeaddrs.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_addip_set_prim_v6.o: ft_frame_addip_set_prim.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_addrover_v6.o: ft_frame_addrover.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_CACC.o: ft_frame_CACC.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_kamikaze.o: ft_frame_kamikaze.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

kernel_funutil.o: funutil.c
	${CC} -c ${USER_CFLAGS} -o $@ $^

kernel_funutil_v6.o: funutil.c 
	${CC} -c ${V6FLAGS} ${USER_CFLAGS} -o $@ $^

ft_frame_addip_bindx.o: ft_frame_addip_bindx.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^
	
ft_frame_delip_bindx.o: ft_frame_delip_bindx.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^
	
ft_frame_addip_bindx_v6.o: ft_frame_addip_bindx.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_delip_bindx_v6.o: ft_frame_delip_bindx.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_t4_timer.o: ft_frame_t4_timer.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

ft_frame_t4_timer_v6.o: ft_frame_t4_timer.c
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_prsctp.o: ft_frame_prsctp.c
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ $^

funutil_v6.o: funutil.c 
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ $^

ft_frame_heartbeat: ft_frame_heartbeat.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_connect: ft_frame_connect.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_connectx: ft_frame_connectx.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_connectx_t1_timer: ft_frame_connectx_t1_timer.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_connectx_t1_timer_fail: ft_frame_connectx_t1_timer_fail.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -DTEST_FAIL=1 -o $@ $^

ft_frame_connectx_collision1: ft_frame_connectx_collision1.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_connectx_collision2: ft_frame_connectx_collision2.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_connectx_collision3: ft_frame_connectx_collision3.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_recvmsg: ft_frame_recvmsg.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_pmtu: ft_frame_pmtu.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_bigdata: ft_frame_bigdata.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_retran_path: ft_frame_retran_path.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_part_delivery: ft_frame_part_delivery.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_renege: ft_frame_renege.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_invalid_length: ft_frame_invalid_length.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_cookie_ports: ft_frame_cookie_ports.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_hb_rtx: ft_frame_hb_rtx.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_frag_interleave: ft_frame_frag_interleave.o  ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

ft_frame_bind: ft_frame_bind.o   ${FRAME_OBJECTS}
	${CC} -DTEST_V6=0 -o $@ $^

ft_frame_bind_v6: ft_frame_bind_v6.o ${FRAME_V6_OBJECTS}
	${CC} ${V6FLAGS} ${CFLAGS} -o $@ $^

test_inqueue.o: test_inqueue.c ${SCTP_HEADERS}
test_packet.o: test_packet.c ${SCTP_HEADERS}
test_command.o: test_command.c ${SCTP_HEADERS}
test_sn_compare.o: test_sn_compare.c ${SCTP_HEADERS}
test_tsnmap.o: test_tsnmap.c ${SCTP_HEADERS}
test_cmsgs.o: test_cmsgs.c ${SCTP_HEADERS}
test_ulpevent.o: test_ulpevent.c ${SCTP_HEADERS}
test_ulpqueue.o: test_ulpqueue.c ${SCTP_HEADERS}
test_lock.o: test_lock.c ${SCTP_HEADERS}
funutil.o: funutil.c ${SCTP_HEADERS}
test_kernel.o: test_kernel.c ${SCTP_HEADERS}

test_inqueue: test_inqueue.o ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

test_packet: test_packet.o ${FRAME_OBJECTS} 
	${CC} ${CFLAGS} -o $@ $^

test_command: test_command.o ${FRAME_OBJECTS} 
	${CC} ${CFLAGS} -o $@ $^

test_sn_compare: test_sn_compare.o ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

test_tsnmap: test_tsnmap.o ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

test_cmsgs: test_cmsgs.o ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

test_ulpevent: test_ulpevent.o ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

test_ulpqueue: test_ulpqueue.o ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

test_lock: test_lock.o ${FRAME_OBJECTS}
	${CC} ${CFLAGS} -o $@ $^

test_kernel.o: test_kernel.c test_kernel.h \
	${SCTP_HEADERS} ${INCLUDE_LINUX}/ip.h \
	${INCLUDE_LINUX}/skbuff.h ${INCLUDE_LINUX}/errno.h
	${CC} -c -DTEST_V6=0 ${CFLAGS} -o $@ test_kernel.c

test_kernel_v6.o: test_kernel.c test_kernel.h \
	${SCTP_HEADERS} ${INCLUDE_LINUX}/ip.h \
	${INCLUDE_LINUX}/skbuff.h ${INCLUDE_LINUX}/errno.h
	${CC} -c ${V6FLAGS} ${CFLAGS} -o $@ test_kernel.c

${COMMON_OBJECTS}: %.o: ${ROOT}/%.c ${SCTP_HEADERS}
	${CC} -c ${CFLAGS} $< -o $@

${KERN_LIB_OBJECTS}: %.o: ${KERN_LIB}/%.c
	${CC} -c ${CFLAGS} $< -o $@

#%.o :	${ROOT}/%.c
#	${CC} -c ${CFLAGS} $< -o $@


.PHONY: chicken clean

chicken: clean

unittest: unit_test

frametest: frame_test

frame6: framev6_test

kerntest: kern_test

kern6: kernv6_test

cscope.out: *.c ${COMMON_OBJECTS:.o=.c}
	cscope -b ${INCLUDES} *.c ${COMMON_OBJECTS:.o=.c}

clean:
	rm -f ${TARGETS} *.o *.a core
