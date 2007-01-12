AC_INIT([libopkele], [0.1], [libopkele-bugs@klever.net])
AC_CONFIG_SRCDIR([include/opkele/opkele-config.h])
AC_CONFIG_HEADERS([config.h include/opkele/acconfig.h])
AM_INIT_AUTOMAKE([dist-bzip2])

AC_PROG_INSTALL
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LIBTOOL

AC_HEADER_STDC

AC_PATH_PROG([XSLTPROC],[xsltproc],[true])
AC_WITH_PKGCONFIG

PKG_CHECK_MODULES([OPENSSL],[openssl],,[
 AC_MSG_ERROR([no openssl library found. get one from http://www.openssl.org/])
])

WANT_KONFORKA="yes"
AC_ARG_ENABLE([konforka],
 AC_HELP_STRING([--disable-konforka],[do not use konforka library (default: use if found)]),
 [
  test "${enableval}" = "no" && WANT_KONFORKA="no"
 ]
)
if test "${WANT_KONFORKA}" = "yes" ; then
 PKG_CHECK_MODULES([KONFORKA],[konforka],[
  AC_SUBST([KONFORKA_CFLAGS])
  AC_SUBST([KONFORKA_LIBS])
  AC_DEFINE([HAVE_KONFORKA],,[defined in presence of konforka library])
  AC_DEFINE([OPKELE_HAVE_KONFORKA],,[defined in presence of konforka library])
  AC_SUBST([KONFORKA_KONFORKA],[konforka])
 ],[true])
fi

WANT_DOXYGEN="yes"
AC_ARG_ENABLE([doxygen],
 AC_HELP_STRING([--disable-doxygen],[do not generate documentation]),
 [
  test "${enableval}" = "no" && WANT_DOXYGEN="no"
 ]
)
if test "${WANT_DOXYGEN}" = "yes" ; then
 AC_WITH_DOXYGEN
 AC_WITH_DOT
else
 AM_CONDITIONAL([HAVE_DOXYGEN],[false])
 AM_CONDITIONAL([HAVE_DOT],[false])
fi

LIBCURL_CHECK_CONFIG(,,,[
 AC_MSG_ERROR([no required libcurl library. get one from http://curl.haxx.se/])
])
AC_WITH_PCRE([
  AC_WITH_PCREPP(,[
   AC_MSG_ERROR([no pcre++ library found. get one at http://www.daemon.de/PCRE])
  ])
 ],[
  AC_MSG_ERROR([no pcre library found. get one at http://www.pcre.org/])
 ]
)

AC_CONFIG_FILES([
 Makefile
  libopkele.pc
  Doxyfile
 include/Makefile
 lib/Makefile
])
AC_OUTPUT
