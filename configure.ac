AC_INIT([libopkele], [0.3], [libopkele-bugs@klever.net])
AC_CONFIG_SRCDIR([include/opkele/opkele-config.h])
AC_CONFIG_HEADERS([config.h include/opkele/acconfig.h])
AM_INIT_AUTOMAKE([dist-bzip2])

AC_PROG_INSTALL
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

AC_HEADER_STDC

AC_PATH_PROG([XSLTPROC],[xsltproc],[true])

AC_MSG_CHECKING([for source tree version])
if headrev=$(cd $srcdir && git rev-parse --verify HEAD 2>/dev/null) ; then
 PACKAGE_SRC_VERSION="${PACKAGE_VERSION}:$(cd $srcdir && git describe --tags $headrev)"
 ( cd $srcdir && git diff-index $headrev | read dirt ) && PACKAGE_SRC_VERSION="${PACKAGE_SRC_VERSION}-dirty"
else
 PACKAGE_SRC_VERSION="$PACKAGE_VERSION"
fi
AC_MSG_RESULT([$PACKAGE_SRC_VERSION])
AC_SUBST([PACKAGE_SRC_VERSION])
AC_DEFINE_UNQUOTED([PACKAGE_SRC_VERSION],["$PACKAGE_SRC_VERSION"],[more or less precise source tree version])

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

if test -n "$PCRE_LIBS" -a -n "$PCRE_CFLAGS" ; then
 AC_SUBST([PCRE_CFLAGS])
 AC_SUBST([PCRE_LIBS])
 :
else
 PKG_CHECK_MODULES([PCRE],[libpcre],,[
  AC_MSG_ERROR([no libpcre found, go get it at http://www.pcre.org/])
 ])
fi

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

AC_DEFINE_UNQUOTED([OPKELE_SRC_DIR],["$PWD"],[source directory])

AC_CONFIG_FILES([
 Makefile
  libopkele.pc
  Doxyfile
 include/Makefile
 lib/Makefile
 test/Makefile
])
AC_OUTPUT
