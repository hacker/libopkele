
SUBDIRS=include lib
EXTRA_DIST= NEWS NEWS.xml NEWS.xsl

DISTCHECK_CONFIGURE_FLAGS=--with-pkgconfigdir=$${dc_install_base}/lib/pkgconfig
if HAVE_PKGCONFIG
pkgconfigdir=@PKGCONFIG_DIR@
pkgconfig_DATA=libopkele.pc
endif

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
