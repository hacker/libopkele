noinst_PROGRAMS = test idiscover \
	${_dependent_programs_}

AM_CPPFLAGS=${CPPFLAGS_DEBUG}
DEFAULT_INCLUDES = -I${top_builddir}
INCLUDES = -I${top_srcdir}/test/ -I${top_builddir}/include/ -I${top_srcdir}/include/ ${KONFORKA_CFLAGS} ${LIBCURL_CPPFLAGS}

test_SOURCES = test.cc
test_LDADD = ${top_builddir}/lib/libopkele.la

EXTRA_DIST= \
    sqlite.h kingate_openid_message.h \
    RP-db.sql OP-db.sql

idiscover_SOURCES = idiscover.cc
idiscover_LDADD = ${top_builddir}/lib/libopkele.la

if    HAVE_SQLITE3
if     HAVE_KINGATE
if      HAVE_UUID

_dependent_programs_ = RP.cgi OP.cgi

RP_cgi_SOURCES = RP.cc
nodist_RP_cgi_SOURCES = RP-db.cc
RP_cgi_LDADD = ${top_builddir}/lib/libopkele.la \
	       ${SQLITE3_LIBS} ${KINGATE_LIBS} ${UUID_LIBS}
RP_cgi_CFLAGS = ${SQLITE3_CFLAGS} ${KINGATE_CFLAGS} ${UUID_CFLAGS}

RP-db.cc: RP-db.sql
	( \
	  echo 'const char * __RP_db_bootstrap = ' && \
	  sed -e 's/^/"/' -e 's/$$/"/' $< && \
	  echo ';' \
	) >$@

OP_cgi_SOURCES = OP.cc
nodist_OP_cgi_SOURCES = OP-db.cc
OP_cgi_LDADD = ${RP_cgi_LDADD}
OP_cgi_CFLAGS = ${RP_cgi_CFLAGS}

OP-db.cc: OP-db.sql
	( \
	  echo 'const char * __OP_db_bootstrap = ' && \
	  sed -e 's/^/"/' -e 's/$$/"/' $< && \
	  echo ';' \
	) >$@

clean-local:
	rm -f RP-db.cc OP-db.cc

endif   #HAVE_UUID
endif  #HAVE_KINGATE
endif #HAVE_SQLITE3
