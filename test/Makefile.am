noinst_PROGRAMS = test

INCLUDES = -I${top_srcdir}/include/

test_SOURCES = test.cc
test_LDADD = ${top_builddir}/lib/libopkele.la

EXTRA_DIST=$(addsuffix .html,$(addprefix html/, \
	empty head-in-body hkn-delegate hkn-server hkn in-body \
	unclosed-head spaced-links spaced-link-attrs \
	))
