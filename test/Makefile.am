noinst_PROGRAMS = test

DEFAULT_INCLUDES = -I${top_builddir}
INCLUDES = -I${top_srcdir}/include/ ${KONFORKA_CFLAGS} ${LIBCURL_CPPFLAGS}

test_SOURCES = test.cc
test_LDADD = ${top_builddir}/lib/libopkele.la

EXTRA_DIST=$(addsuffix .html,$(addprefix html/, \
	empty head-in-body hkn-delegate hkn-server hkn in-body \
	unclosed-head spaced-links spaced-link-attrs 2rels \
	))
