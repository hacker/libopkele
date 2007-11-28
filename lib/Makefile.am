lib_LTLIBRARIES = libopkele.la

DEFAULT_INCLUDES = -I${top_builddir}
INCLUDES = \
	   -I${top_srcdir}/include/ \
	   ${KONFORKA_CFLAGS} \
	   ${OPENSSL_CFLAGS} \
	   ${LIBCURL_CPPFLAGS} \
	   ${PCRE_CFLAGS} ${EXPAT_CFLAGS}
libopkele_la_LIBADD = \
	${LIBCURL} \
	${PCRE_LIBS} ${EXPAT_LIBS} \
	${OPENSSL_LIBS} \
	${KONFORKA_LIBS}

libopkele_la_SOURCES = \
		       params.cc \
		       util.cc \
		       server.cc \
		       secret.cc \
		       data.cc \
		       consumer.cc \
		       exception.cc \
		       extension.cc \
		       sreg.cc \
		       extension_chain.cc \
		       curl.cc expat.cc
libopkele_la_LDFLAGS = \
	-version-info 2:0:0
