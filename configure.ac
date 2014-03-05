AC_INIT([libopkele], [2.0.4], [libopkele-bugs@klever.net])
AC_CONFIG_SRCDIR([include/opkele/opkele-config.h])
AC_CONFIG_HEADERS([config.h include/opkele/acconfig.h])
AC_CONFIG_MACRO_DIR([aclocal.d])
AC_CONFIG_AUX_DIR([aux.d])
AM_INIT_AUTOMAKE([dist-bzip2])

AC_PROG_INSTALL
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

AC_HEADER_STDC
AC_CHECK_FUNCS([timegm])
AC_CHECK_HEADERS([ext/algorithm.h])

AC_PATH_PROG([XSLTPROC],[xsltproc],[true])

AC_MSG_CHECKING([for source tree version])
if headrev=$(cd $srcdir && git rev-parse --verify HEAD 2>/dev/null) ; then
 PACKAGE_SRC_VERSION="$(cd $srcdir && git describe --tags $headrev)"
 test "$PACKAGE_SRC_VERSION" = "$PACKAGE_VERSION" \
  -o "${PACKAGE_SRC_VERSION#${PACKAGE_VERSION}-}" != "$PACKAGE_SRC_VERSION" || PACKAGE_SRC_VERSION="${PACKAGE_VERSION}:${PACKAGE_SRC_VERSION}"
 ( cd $srcdir && git diff-index $headrev | read dirt ) && PACKAGE_SRC_VERSION="${PACKAGE_SRC_VERSION}-dirty"
else
 PACKAGE_SRC_VERSION="$PACKAGE_VERSION"
fi
AC_MSG_RESULT([$PACKAGE_SRC_VERSION])
AC_SUBST([PACKAGE_SRC_VERSION])
AC_DEFINE_UNQUOTED([PACKAGE_SRC_VERSION],["$PACKAGE_SRC_VERSION"],[more or less precise source tree version])

tr1_mem_std="false"
tr1_mem_boost="false"
AC_CHECK_SHAREDPTR(std::tr1,tr1/memory,[ tr1_mem_std=true ])
AC_CHECK_SHAREDPTR(boost,boost/shared_ptr.hpp,[ tr1_mem_boost=true ])
tr1_mem=""
AC_ARG_WITH([tr1-memory],
 AC_HELP_STRING([--with-tr1-memory=<boost|std>],[select tr1/memory (shared_ptr<>) implementation to use]),
 [ tr1_mem="$withval" ]
)
AC_MSG_CHECKING([for tr1/memory implementation to use])
test -z "$tr1_mem" && $tr1_mem_std && tr1_mem=std
test -z "$tr1_mem" && $tr1_mem_boost && tr1_mem=boost
if test -z "$tr1_mem" ; then
 AC_MSG_RESULT([none found])
else
 AC_MSG_RESULT([$tr1_mem])
fi
case "$tr1_mem" in
 std)
  $tr1_mem_std || AC_MSG_ERROR([std implementation requested, but not found])
  OPKELE_TR1_MEM_NS=std::tr1
  OPKELE_TR1_MEM_HEADER=tr1/memory
  ;;
 boost)
  $tr1_mem_boost || AC_MSG_ERROR([boost implementation requested, but not found])
  OPKELE_TR1_MEM_NS=boost
  OPKELE_TR1_MEM_HEADER=boost/shared_ptr.hpp
  ;;
 *)
  AC_MSG_ERROR([no shared_ptr<> implementation found])
  ;;
esac
AC_SUBST([OPKELE_TR1_MEM_NS])
AC_SUBST([OPKELE_TR1_MEM_HEADER])

AC_MSG_CHECKING([for deprecated attribute support])
AC_COMPILE_IFELSE([
  int __attribute__((deprecated)) deprecated_function();
 ],[
  AC_MSG_RESULT([yes])
  AC_DEFINE([OPKELE_DEPRECATE],[__attribute__((deprecated))],[deprecated function attribute])
 ],[
  AC_MSG_RESULT([no])
  AC_DEFINE([OPKELE_DEPRECATE],,[deprecated function attribute])
 ]
)

AC_LANG_PUSH([C++])
AC_MSG_CHECKING([for abi::__cxa_demangle])
AC_COMPILE_IFELSE([
  #include <typeinfo>
  using namespace std;
  #include <cxxabi.h>
  int main(int c,char **v) {
   int dstat;
   char *demangled = abi::__cxa_demangle(typeid(dstat).name(),0,0,&dstat);
   return 0;
  }
 ],[
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_DEMANGLE],,[defined if abi::__cxa_demangle is available])
 ],[
  AC_MSG_RESULT([no])
 ]
)
AC_LANG_POP([C++])




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

AC_CHECK_HEADER([expat.h],[
 AC_CHECK_LIB([expat],[XML_ParserCreate],[
  EXPAT_LIBS=-lexpat
  EXPAT_CFLAGS=
  AC_SUBST([EXPAT_LIBS])
  AC_SUBST([EXPAT_CFLAGS])
 ],[
  AC_MSG_ERROR([no required expat library. get one from http://expat.sourceforge.net/])
 ])
],[
 AC_MSG_ERROR([no required expat library. get one from http://expat.sourceforge.net/])
])

AC_CHECK_HEADERS([tidy.h tidy/tidy.h],[
 test -z "$TIDY_LIBS" && AC_CHECK_LIB([tidy],[tidyParseBuffer],[
  TIDY_LIBS=-ltidy
  TIDY_CFLAGS=
  AC_SUBST([TIDY_LIBS])
  AC_SUBST([TIDY_CFLAGS])
 ],[
  AC_MSG_ERROR([no required htmltidy library found. get one from http://tidy.sourceforge.net/])
 ])
],[
 test -z "$TIDY_LIBS" -a "$ac_header" = "tidy/tidy.h" \
 && AC_MSG_ERROR([no required htmltidy library found. get one from http://tidy.sourceforge.net/])
])

PKG_CHECK_MODULES([SQLITE3],[sqlite3],[have_sqlite3=true],[have_sqlite3=false])
AM_CONDITIONAL([HAVE_SQLITE3],[$have_sqlite3])
PKG_CHECK_MODULES([KINGATE],[kingate-plaincgi],[have_kingate=true],[have_kingate=false])
AM_CONDITIONAL([HAVE_KINGATE],[$have_kingate])
PKG_CHECK_MODULES([UUID],[uuid],[have_uuid=true],[have_uuid=false])
AM_CONDITIONAL([HAVE_UUID],[$have_uuid])
if $have_uuid ; then
 AC_DEFINE([HAVE_LIBUUID],,[defined in presence of libuuid])
 AC_SUBST([UUID_UUID],[uuid])
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

nitpick=false
AC_ARG_ENABLE([nitpicking],
 AC_HELP_STRING([--enable-nitpicking],[make compiler somewhat overly fastidious about the code it deals with]),
 [ test "$enableval" = "no" || nitpick=true ]
)
if $nitpick ; then
 CPP_NITPICK="-pedantic -Wall -Wextra -Wundef -Wshadow \
  -Wunsafe-loop-optimizations -Wconversion -Wmissing-format-attribute \
  -Wredundant-decls -ansi"
 # -Wlogical-op -Wmissing-noreturn 
 C_NITPICK="$CPP_NITPICK"
 CXX_NITPICK="$C_NITPICK"

 CPPFLAGS="$CPPFLAGS $CPP_NITPICK"
 CFLAGS="$CFLAGS $C_NITPICK"
 CXXFLAGS="$CXXFLAGS $CXX_NITPICK"
fi

ndebug=true
AC_ARG_ENABLE([debug],
 AC_HELP_STRING([--enable-debug],[enable debugging code]),
 [ test "$enableval" = "no" || ndebug=false ]
)
if $ndebug ; then
 CPPFLAGS_DEBUG="-DNDEBUG"
else
 CPPFLAGS_DEBUG=""
fi
AC_SUBST([CPPFLAGS_DEBUG])

xri_proxy_url="https://xri.net/"
AC_MSG_CHECKING([for XRI resolver proxy])
AC_ARG_ENABLE([xri-proxy],
 AC_HELP_STRING([--with-xri-proxy=url],[set xri proxy for use when resolving xri identities, default is https://xri.net/]),
 [ xri_proxy_url="$withval" ]
)
AC_MSG_RESULT([$xri_proxy_url])
AC_DEFINE_UNQUOTED([XRI_PROXY_URL],["$xri_proxy_url"],[XRI proxy resolver URL])

AC_CONFIG_FILES([
 Makefile
  libopkele.pc
  Doxyfile
 include/Makefile
  include/opkele/tr1-mem.h
 lib/Makefile
 test/Makefile
])
AC_OUTPUT
