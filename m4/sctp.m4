# Handy references:
# https://www.gnu.org/software/autoconf/manual/autoconf.html#Generic-Structures
# AC_CHECK_MEMBER (aggregate.member, [action-if-found], [action-if-not-found], [includes = 'AC_INCLUDES_DEFAULT'])
# https://www.gnu.org/software/autoconf/manual/autoconf.html#Generic-Types
# AC_CHECK_TYPE (type, [action-if-found], [action-if-not-found], [includes = 'AC_INCLUDES_DEFAULT'])

# Macros to assist on probing kernel features
#   Probes if a type is defined
AC_DEFUN([LKSCTP_CHECK_TYPE], [
AC_CHECK_TYPE([$1],
	AC_DEFINE([$2], 1,
		  [Define if $1 is present.])
	AM_CONDITIONAL([$2], [true]),
	AM_CONDITIONAL([$2], [false]),
	[AC_INCLUDES_DEFAULT
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_LINUX_SCTP_H
# include <linux/sctp.h>
#endif
])])

#   Probes if a struct has a given member
AC_DEFUN([LKSCTP_CHECK_MEMBER], [
AC_CHECK_MEMBER([$1],
	AC_DEFINE([$2], 1,
		  [Define if $1 is present.])
	AM_CONDITIONAL([$2], [true]),
	AM_CONDITIONAL([$2], [false]),
	[AC_INCLUDES_DEFAULT
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_LINUX_SCTP_H
# include <linux/sctp.h>
#endif
])])

#   Probes if a declaration is present
AC_DEFUN([LKSCTP_CHECK_DECL], [
AC_CHECK_DECL([$1],
	AC_DEFINE([$2], 1,
		  [Define if $1 is present.])
	AM_CONDITIONAL([$2], [true]),
	AM_CONDITIONAL([$2], [false]),
	[AC_INCLUDES_DEFAULT
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_LINUX_SCTP_H
# include <linux/sctp.h>
#endif
])])
