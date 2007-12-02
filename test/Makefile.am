noinst_PROGRAMS = test openid_resolve

DEFAULT_INCLUDES = -I${top_builddir}
INCLUDES = -I${top_srcdir}/include/ ${KONFORKA_CFLAGS}

test_SOURCES = test.cc
test_LDADD = ${top_builddir}/lib/libopkele.la

EXTRA_DIST=$(addsuffix .html,$(addprefix html/, \
	empty head-in-body hkn-delegate hkn-server hkn in-body \
	unclosed-head spaced-links spaced-link-attrs 2rels \
	))

openid_resolve_SOURCES = openid_resolve.cc
openid_resolve_LDADD = ${top_builddir}/lib/libopkele.la
