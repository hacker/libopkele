lib_LTLIBRARIES = libopkele.la

INCLUDES = \
	   -I${top_srcdir}/include/ \
	   ${KONFORKA_CFLAGS} \
	   ${OPENSSL_CFLAGS} \
	   ${MIMETIC_CFLAGS} \
	   ${LIBCURL_CPPFLAGS} \
	   ${PCREPP_CFLAGS}
LDADD = \
	${LIBCURL} \
	${PCREPP_LIBS} \
	${MIMETIC_LIBS} \
	${OPENSSL_LIBS} \
	${KONFORKA_LIBS}

libopkele_la_SOURCES = \
		       params.cc \
		       util.cc \
		       server.cc \
		       secret.cc \
		       data.cc \
		       consumer.cc \
		       exception.cc
