# 
# $Id$
#

AC_PREREQ(2.57)
AC_CONFIG_AUX_DIR([aconf])
AC_INIT([gims-capture-daemon], 0.1, jsommers@colgate.edu)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([.])

AC_CONFIG_AUX_DIR([aconf])
AC_LANG(C)

AC_HEADER_STDC
AC_CHECK_HEADERS([pcap.h])
AC_CHECK_HEADERS([pcap/pcap.h])
AC_HEADER_TIME
AC_CHECK_HEADERS([sys/time.h])

# test for pcap existence and capabilities
AC_CHECK_LIB([pcap], [pcap_open_live], , AC_MSG_ERROR([libpcap wasn't found --- can't continue!]))
AC_CHECK_LIB([pcap], [pcap_next_ex], [AC_DEFINE([HAVE_PCAP_NEXT_EX], [1])] )
AC_CHECK_LIB([pcap], [pcap_create], [AC_DEFINE([HAVE_PCAP_CREATE], [1])] )
AC_CHECK_LIB([pcap], [pcap_set_buffer_size], [AC_DEFINE([HAVE_PCAP_SET_BUFFER_SIZE], [1])])

AC_CHECK_PROG([PKGCONFIG], [pkg-config], [yes])
if test -n "$ac_cv_prog_PKGCONFIG"; then
    haveyaf=`pkg-config --exists libyaf`
    if test "$haveyaf" != "0"; then
        yafver=`pkg-config libyaf --version`
        AC_MSG_NOTICE([Found libyaf version $yafver -- enabling flow aggregation])
        CFLAGS="$CFLAGS `pkg-config libyaf --cflags`"
        LIBS="$LIBS `pkg-config libyaf --libs`"
        AC_DEFINE([HAVE_YAF],[1])
        AC_DEFINE_UNQUOTED([YAF_VERSION],["$yafver"])
        fixbufver=`pkg-config libfixbuf --version`
        AC_DEFINE_UNQUOTED([FIXBUF_VERSION],["$fixbufver"])
    else
        AC_MSG_NOTICE([No libyaf found -- continuing anyway])
    fi
else
    AC_MSG_NOTICE([No pkg-config, so presumably no libyaf.])
fi

AC_CONFIG_FILES([Makefile])
AC_SUBST([HAVE_PCAP_CREATE])
AC_SUBST([HAVE_PCAP_NEXT_EX])
AC_SUBST([HAVE_PCAP_SET_BUFFER_SIZE])
AC_SUBST([HAVE_YAF])
AC_SUBST([YAF_VERSION])
AC_SUBST([FIXBUF_VERSION])
AC_OUTPUT

