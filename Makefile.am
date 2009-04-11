SUBDIRS=include lib test
EXTRA_DIST= NEWS NEWS.xml NEWS.xsl

ACLOCAL_AMFLAGS=-I aclocal.d

pkgconfigdir=${libdir}/pkgconfig
pkgconfig_DATA=libopkele.pc

all-local: NEWS
if HAVE_DOXYGEN
clean-local:
	rm -rf doxydox
endif

NEWS: NEWS.xsl NEWS.xml
	${XSLTPROC} -o $@ NEWS.xsl NEWS.xml

if HAVE_DOXYGEN
dox: Doxyfile
	${DOXYGEN}
endif

ISSUEFILES = $$(find ${top_srcdir} -type f '(' \
	-name '*.cc' -or -name '*.h' \
	')' ) \
	${top_srcdir}/configure.ac
issues: todo fixme xxx
todo fixme xxx:
	@grep --color=auto -in '$@:' ${ISSUEFILES} || true
