lib_LTLIBRARIES = libopkele.la

AM_CPPFLAGS = ${CPPFLAGS_DEBUG}
DEFAULT_INCLUDES = -I${top_builddir}
INCLUDES = \
	   -I${top_builddir}/include/ -I${top_srcdir}/include/ \
	   ${KONFORKA_CFLAGS} \
	   ${OPENSSL_CFLAGS} \
	   ${LIBCURL_CPPFLAGS} \
	   ${EXPAT_CFLAGS} ${TIDY_CFLAGS}
libopkele_la_LIBADD = \
	${LIBCURL} \
	${EXPAT_LIBS} \
	${OPENSSL_LIBS} \
	${KONFORKA_LIBS} ${TIDY_LIBS}

libopkele_la_SOURCES = \
		       params.cc \
		       util.cc \
		       secret.cc \
		       data.cc \
		       exception.cc \
		       extension.cc \
		       sreg.cc \
		       extension_chain.cc \
		       curl.cc expat.cc \
		       discovery.cc \
		       basic_rp.cc prequeue_rp.cc \
		       fields.cc message.cc \
		       basic_op.cc verify_op.cc \
		       ax.cc oauth_ext.cc
libopkele_la_LDFLAGS = \
	-version-info 3:0:0
