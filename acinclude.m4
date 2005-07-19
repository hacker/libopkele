dnl AC_WITH_PKGCONFIG([ACTION-IF-FOUND[,ACTION-IF-NOT-FOUND]])
dnl Outputs:
dnl AC_SUBST: PKGCONFIG_PKGCONFIG PKGCONFIG_DIR
dnl AM_CONDTIONAL: HAVE_PKGCONFIG
AC_DEFUN([AC_WITH_PKGCONFIG],[
 PKGCONFIG_PKGCONFIG=""
 PKGCONFIG_DIR=""
 HAVE_PKGCONFIG="no"
 EXPLICIT_PKGCONFIGDIR="no"
 test -z "${WANT_PKGCONFIG}" && WANT_PKGCONFIG=""
 AC_PATH_PROG([PKGCONFIG_PKGCONFIG],[pkg-config],[false])
 if test "${PKGCONFIG_PKGCONFIG}" != "false" ; then
  AC_ARG_WITH([pkgconfigdir],
   AC_HELP_STRING([--with-pkgconfigdir=dir],[Specify pkgconfig directory]),
   [
    if test "${withval}" = "no" ; then
     WANT_PKGCONFIG="no"
    else
     PKGCONFIG_DIR="${withval}"
     EXPLICIT_PKGCONFIGDIR="yes"
    fi
   ],[
    AC_MSG_CHECKING([for pkgconfig directory])
    PKGCONFIG_DIR="`${PKGCONFIG_PKGCONFIG} --debug 2>&1 | grep '^Scanning'| head -n 1 | cut -d\' -f2-|cut -d\' -f1`"
    AC_MSG_RESULT([${PKGCONFIG_DIR}])
   ]
  )
  if test -d "${PKGCONFIG_DIR}" ; then
   HAVE_PKGCONFIG=yes
   AC_SUBST([PKGCONFIG_PKGCONFIG])
   AC_SUBST([PKGCONFIG_DIR])
  else
   AC_MSG_NOTICE([unexistent pkgconfig directory: ${PKGCONFIG_DIR}])
   if test "${EXPLICIT_PKGCONFIGDIR}" = "yes" ; then
    HAVE_PKGCONFIG=yes
    AC_SUBST([PKGCONFIG_PKGCONFIG])
    AC_SUBST([PKGCONFIG_DIR])
   else
    ifelse([$2], , :, [$2])
   fi
  fi
 fi
 AM_CONDITIONAL([HAVE_PKGCONFIG],[test "${HAVE_PKGCONFIG}" = "yes"])
])

dnl AC_WITH_DOXYGEN([ACTION-IF-FOUND[,ACTION-IF-NOT-FOUND]])
dnl Outputs:
dnl AC_SUBST: DOXYGEN HAVE_DOXYGEN
dnl AM_CONDTIONAL: HAVE_DOXYGEN
AC_DEFUN([AC_WITH_DOXYGEN],[
 HAVE_DOXYGEN="no"
 AC_PATH_PROG([DOXYGEN],[doxygen],[false])
 if test "${DOXYGEN}" = "false" ; then
  ifelse([$2], , :, [$2])
 else
  HAVE_DOXYGEN="yes"
  AC_SUBST([DOXYGEN])
  $1
 fi
 AC_SUBST([HAVE_DOXYGEN])
 AM_CONDITIONAL([HAVE_DOXYGEN],[test "${HAVE_DOXYGEN}" = "yes"])
])

dnl AC_WITH_DOT([ACTION-IF-FOUND[,ACTION-IF-NOT-FOUND]])
dnl Outputs:
dnl AC_SUBST: DOT HAVE_DOT
dnl AM_CONDITIONAL: HAVE_DOT
AC_DEFUN([AC_WITH_DOT],[
 HAVE_DOT="no"
 AC_PATH_PROG([DOT],[dot],[false])
 if test "${DOT}" = "false" ; then
  ifelse([$2], , :, [$2])
 else
  HAVE_DOT="yes"
  AC_SUBST([DOT])
  $1
 fi
AC_SUBST([HAVE_DOT])
 AM_CONDITIONAL([HAVE_DOT],[test "${HAVE_DOT}" = "yes"])
])

dnl AC_WITH_PCRE([ACTION-IF-FOUND[,ACTION-IF-NOT-FOUND]])
dnl Outputs:
dnl AC_SUBST: PCRE_CONFIG PCRE_PREFIX PCRE_EXEC_PREFIX
dnl           PCRE_VERSION PCRE_CFLAGS PCRE_LIBS
dnl           PCRE_LIBS_POSIX PCRE_CFLAGS_POSIX
dnl AM_CONDITIONAL: HAVE_PCRE
dnl AC_DEFINE: HAVE_PCRE PCRE_VERSION
AC_DEFUN([AC_WITH_PCRE],[
 HAVE_PCRE="no"
 PCRE_CONFIG=""
 PCRE_PREFIX=""
 PCRE_EXEC_PREFIX=""
 PCRE_VERSION=""
 PCRE_CFLAGS=""
 PCRE_LIBS=""
 PCRE_LOCATIONS="${PATH}:/usr/local/bin:/usr/bin"
 test -z "$WANT_PCRE" && WANT_PCRE=""
 AC_ARG_WITH([pcre],
  AC_HELP_STRING([--with-pcre=location],[Look for pcre in specified locations]),
  [
   if test "${withval}" = "no" ; then
    WANT_PCRE="no"
   else
    if test -x "${withval}" ; then
     PCRE_CONFIG="${withval}"
    elif test -x "${withval}/pcre-config" ; then
     PCRE_CONFIG="${withval}/pcre-config"
    elif test -x "${withval}/bin/pcre-config" ; then
     PCRE_CONFIG="${withval}/bin/pcre-config"
    fi
   fi
  ]
 )
 if test "${WANT_PCRE}" = "no" ; then
  ifelse([$2], , :, [$2])
 else
  if test -z "${PCRE_CONFIG}" ; then
   AC_PATH_PROG(PCRE_CONFIG,[pcre-config],false,[${PCRE_LOCATIONS}])
   if test "${PCRE_CONFIG}" = "false" ; then
    ifelse([$2], , :, [$2])
   else
    HAVE_PCRE="yes"
    PCRE_PREFIX="`${PCRE_CONFIG} --prefix`"
    PCRE_EXEC_PREFIX="`${PCRE_CONFIG} --exec-prefix`"
    PCRE_VERSION="`${PCRE_CONFIG} --version`"
    PCRE_CFLAGS="`${PCRE_CONFIG} --cflags`"
    PCRE_LIBS="`${PCRE_CONFIG} --libs`"
    PCRE_CFLAGS_POSIX="`${PCRE_CONFIG} --cflags-posix`"
    PCRE_LIBS_POSIX="`${PCRE_CONFIG} --libs-posix`"
    AC_SUBST([PCRE_CONFIG])
    AC_SUBST([PCRE_PREFIX])
    AC_SUBST([PCRE_EXEC_PREFIX])
    AC_SUBST([PCRE_VERSION])
    AC_SUBST([PCRE_CFLAGS])
    AC_SUBST([PCRE_LIBS])
    AC_SUBST([PCRE_CFLAGS_POSIX])
    AC_SUBST([PCRE_LIBS_POSIX])
    AC_DEFINE([HAVE_PCRE],,[pcre support])
    AC_DEFINE_UNQUOTED([PCRE_VERSION],["${PCRE_VERSION}"],[pcre version])
    $1
   fi
  fi
 fi
 AM_CONDITIONAL([HAVE_PCRE],[test "${HAVE_PCRE}" = "yes"])
])

dnl AC_WITH_PCREPP([ACTION-IF-FOUND[,ACTION-IF-NOT-FOUND]])
dnl Outputs:
dnl AC_SUBST: PCREPP_CONFIG PCREPP_PREFIX PCREPP_EXEC_PREFIX
dnl           PCREPP_VERSION PCREPP_CFLAGS PCREPP_LIBS
dnl AM_CONDITIONAL: HAVE_PCREPP
dnl AC_DEFINE: HAVE_PCREPP PCREPP_VERSION
AC_DEFUN([AC_WITH_PCREPP],[
 HAVE_PCREPP="no"
 PCREPP_CONFIG=""
 PCREPP_PREFIX=""
 PCREPP_EXEC_PREFIX=""
 PCREPP_VERSION=""
 PCREPP_CFLAGS=""
 PCREPP_LIBS=""
 PCREPP_LOCATIONS="${PATH}:/usr/local/bin:/usr/bin"
 test -z "$WANT_PCREPP" && WANT_PCREPP=""
 AC_ARG_WITH([pcre++],
  AC_HELP_STRING([--with-pcre++=location],[Look for pcre++ in specified locations]),
  [
   if test "${withval}" = "no" ; then
    WANT_PCREPP="no"
   else
    if test -x "${withval}" ; then
     PCREPP_CONFIG="${withval}"
    elif test -x "${withval}/pcre++-config" ; then
     PCREPP_CONFIG="${withval}/pcre++-config"
    elif test -x "${withval}/bin/pcre++-config" ; then
     PCREPP_CONFIG="${withval}/bin/pcre++-config"
    fi
   fi
  ]
 )
 if test "${WANT_PCREPP}" = "no" ; then
  ifelse([$2], , :, [$2])
 else
  if test "${HAVE_PCRE}" != "yes" ; then
   ifelse([$2], , :, [$2])
  else
   if test -z "${PCREPP_CONFIG}" ; then
    AC_PATH_PROG([PCREPP_CONFIG],[pcre++-config],false,[${PCREPP_LOCATIONS}])
    if test "${PCREPP_CONFIG}" = "false" ; then
     ifelse([$2], , :, [$2])
    else
     HAVE_PCREPP="yes"
     PCREPP_PREFIX="`${PCREPP_CONFIG} --prefix`"
     PCREPP_EXEC_PREFIX="`${PCREPP_CONFIG} --exec-prefix`"
     PCREPP_VERSION="`${PCREPP_CONFIG} --version`"
     PCREPP_CFLAGS="`${PCREPP_CONFIG} --cflags` ${PCRE_CFLAGS}"
     PCREPP_LIBS="`${PCREPP_CONFIG} --libs` ${PCRE_LIBS}"
     AC_SUBST([PCREPP_CONFIG])
     AC_SUBST([PCREPP_PREFIX])
     AC_SUBST([PCREPP_EXEC_PREFIX])
     AC_SUBST([PCREPP_VERSION])
     AC_SUBST([PCREPP_CFLAGS])
     AC_SUBST([PCREPP_LIBS])
     AC_DEFINE([HAVE_PCREPP],,[pcre++ support])
     AC_DEFINE_UNQUOTED([PCREPP_VERSION],["${PCREPP_VERSION}"],[pcre++ version])
     $1
    fi
   fi
  fi
 fi
 AM_CONDITIONAL([HAVE_PCREPP],[test "${HAVE_PCREPP}" = "yes"])
])

m4_include([acinclude.d/libcurl.m4])
