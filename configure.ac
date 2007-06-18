AC_INIT([libopkele], [0.1.1], [libopkele-bugs@klever.net])
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

curl_ssl_verify_host="true"
AC_ARG_ENABLE([ssl-verify-host],
 AC_HELP_STRING([--disable-ssl-verify-host],[disable cURL cert/host relationships verification]),
 [ test "${enableval}" = "no" && curl_ssl_verify_host="false" ]
)
${curl_ssl_verify_host} || AC_DEFINE([DISABLE_CURL_SSL_VERIFYHOST],,[defined if cURL is not to verify cert/host])

curl_ssl_verify_peer="true"
AC_ARG_ENABLE([ssl-verify-peer],
 AC_HELP_STRING([--disable-ssl-verify-peer],[disable cURL cert validity verification]),
 [ test "${enableval}" = "no" && curl_ssl_verify_peer="false" ]
)
${curl_ssl_verify_peer} || AC_DEFINE([DISABLE_CURL_SSL_VERIFYPEER],,[defined if cURL is not to verify cert validity])

postels_law=true
AC_ARG_ENABLE([postels-law],
 AC_HELP_STRING([--disable-postels-law],[Be strict, do not adhere to Postel's Law ("be conservative in what you do, be liberal in what you accept from others", RFC 793)]),
 [ test "${enableval}" = "no" && postels_law=false ]
)
$postels_law && AC_DEFINE([POSTELS_LAW],,[defined if we want to adhere to Postel's Law])

AC_CONFIG_FILES([
 Makefile
  libopkele.pc
  Doxyfile
 include/Makefile
 lib/Makefile
])
AC_OUTPUT
