noinst_PROGRAMS = test idiscover

AM_CPPFLAGS=${CPPFLAGS_DEBUG}
DEFAULT_INCLUDES = -I${top_builddir}
INCLUDES = -I${top_srcdir}/include/ ${KONFORKA_CFLAGS}

test_SOURCES = test.cc
test_LDADD = ${top_builddir}/lib/libopkele.la

EXTRA_DIST=$(addsuffix .html,$(addprefix html/, \
	empty head-in-body hkn-delegate hkn-server hkn in-body \
	unclosed-head spaced-links spaced-link-attrs 2rels \
	))

idiscover_SOURCES = idiscover.cc
idiscover_LDADD = ${top_builddir}/lib/libopkele.la
