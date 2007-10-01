
SUBDIRS=include lib test
EXTRA_DIST= NEWS NEWS.xml NEWS.xsl

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
