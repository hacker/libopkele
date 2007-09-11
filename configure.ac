AC_INIT([libopkele], [0.3], [libopkele-bugs@klever.net])
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

want_pcre_impl=""
AC_ARG_WITH([pcre-bindings],
 AC_HELP_STRING([--with-pcre-bindings=(pcrepp|none|libpcrecpp)],[Specify which pcre c++ bindings to use. 'pcrepp' stands for quite sensible library, found at http://www.daemon.de/PCRE/, 'libcrecpp' makes use of crappy bindings by google and 'none' disables internal implementation of OP discovery]),
 [
  case "$withval" in
   pcrepp) want_pcre_impl="pcrepp" ;;
   libpcrecpp) want_pcre_impl="libpcrecpp" ;;
   none) want_pcre_impl="none";;
   *) AC_MSG_ERROR([I'm not sure I understand what do you want for a pcre c++ bindings]) ;;
  esac
 ]
)

found_pcre_impl=""

if test -z "$want_pcre_impl" -o "$want_pcre_impl" = "pcrepp" ; then
 AC_WITH_PCRE([
   AC_WITH_PCREPP([
    found_pcre_impl=pcrepp
   ])
  ],[
   AC_MSG_ERROR([no pcre library found. get one at http://www.pcre.org/])
  ]
 )
 test "$want_pcre_impl,$found_pcre_impl" = "pcrepp," && AC_MSG_ERROR([no pcre++ library found. get one at http://www.daemon.de/PCRE])
fi

if test "$found_pcre_impl,$want_pcre_impl" = "," -o "$want_pcre_impl" = "libpcrecpp" ; then
 test -z "$want_pcre_impl" || AC_MSG_NOTICE([You want to use crappy libpcre c++ bindings])
 PKG_CHECK_MODULES([LIBPCRECPP],[libpcrecpp],[
   found_pcre_impl=libpcrecpp
   CXXFLAGS="$CXXFLAGS $LIBPCRECPP_CFLAGS"
   LIBS="$LIBS $LIBPCRECPP_LIBS"
  ],[
   test -z "$want_pcre_impl" || AC_MSG_ERROR([no libpcre c++ bindings found. why would you want it if you don't have it installed?])
  ]
 )
fi
test "$want_pcre_impl,$found_pcre_impl" = "," && AC_MSG_ERROR([no pcre c++ bindings found, use --with-pcre-bindings=none to disable code that makes use of it])

case "$found_pcre_impl" in
 pcrepp) AC_DEFINE([USE_PCREPP],,[defined if pcre++ is to be used]) ;;
 libpcrecpp) AC_DEFINE([USE_LIBPCRECPP],,[defined if crappy google bindings are to be used]) ;;
esac

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
